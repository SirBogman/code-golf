package hole

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code-golf/code-golf/config"
	"github.com/google/nftables/expr"
)

func BenchmarkArabicToRoman(b *testing.B)   { benchHole(b, "arabic-to-roman") }
func BenchmarkArrows(b *testing.B)          { benchHole(b, "arrows") }
func BenchmarkISBN(b *testing.B)            { benchHole(b, "isbn") }
func BenchmarkOrdinalNumbers(b *testing.B)  { benchHole(b, "ordinal-numbers") }
func BenchmarkRomanToArabic(b *testing.B)   { benchHole(b, "roman-to-arabic") }
func BenchmarkSet(b *testing.B)             { benchHole(b, "set") }
func BenchmarkSIUnits(b *testing.B)         { benchHole(b, "si-units") }
func BenchmarkSpellingNumbers(b *testing.B) { benchHole(b, "spelling-numbers") }
func BenchmarkSudoku(b *testing.B)          { benchHole(b, "sudoku") }
func BenchmarkSudokuFillIn(b *testing.B)    { benchHole(b, "sudoku-fill-in") }

func benchHole(b *testing.B, id string) {
	answerFunc := config.AllHoleByID[id].AnswerFunc

	for b.Loop() {
		answerFunc()
	}
}

func TestSandboxEgressFromEnv(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port string
		want bool
		bad  bool
	}{
		{name: "disabled by default"},
		{name: "documentation address", ip: "203.0.113.10", port: "443"},
		{name: "documentation address without port", ip: "203.0.113.10"},
		{name: "configured", ip: "8.8.8.8", port: "1", want: true},
		{name: "partial configuration", ip: "8.8.8.8", bad: true},
		{name: "IPv6", ip: "2001:db8::1", port: "443", bad: true},
		{name: "multicast", ip: "224.0.0.1", port: "443", bad: true},
		{name: "unspecified", ip: "0.0.0.0", port: "443", bad: true},
		{name: "sandbox address", ip: "198.18.0.1", port: "443", bad: true},
		{name: "invalid port", ip: "8.8.8.8", port: "65536", bad: true},
		{name: "zero port", ip: "8.8.8.8", port: "0", bad: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(sandboxEgressIPEnv, test.ip)
			t.Setenv(sandboxEgressPortEnv, test.port)

			got, err := sandboxEgressFromEnv()
			if test.bad {
				if err == nil {
					t.Fatal("expected invalid configuration error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (got != nil) != test.want {
				t.Fatalf("enabled = %t, want %t", got != nil, test.want)
			}
		})
	}
}

func TestSandboxEgressExpressions(t *testing.T) {
	egress := &sandboxEgress{ip: net.ParseIP("192.0.2.42").To4(), port: 4242}
	expressions := sandboxEgressExpressions(egress)
	if len(expressions) != 9 {
		t.Fatalf("expression count = %d, want 9", len(expressions))
	}
	addressMatch, ok := expressions[5].(*expr.Cmp)
	if !ok || !net.IP(addressMatch.Data).Equal(egress.ip) {
		t.Fatalf("destination address match = %#v, want %s", expressions[5], egress.ip)
	}
	portMatch, ok := expressions[7].(*expr.Cmp)
	if !ok || binary.BigEndian.Uint16(portMatch.Data) != egress.port {
		t.Fatalf("destination port match = %#v, want %d", expressions[7], egress.port)
	}
	verdict, ok := expressions[8].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictAccept {
		t.Fatalf("final expression = %#v, want accept verdict", expressions[8])
	}
}

func TestSandboxToSandboxDropExpressions(t *testing.T) {
	expressions := sandboxToSandboxDropExpressions()
	verdict, ok := expressions[len(expressions)-1].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictDrop {
		t.Fatalf("final expression = %#v, want drop verdict", expressions[len(expressions)-1])
	}
}

func TestSandboxEgressLive(t *testing.T) {
	if os.Getenv("SANDBOX_EGRESS_LIVE_CHILD") == "1" {
		testSandboxEgressLiveChild(t)
		return
	}
	if os.Getenv("SANDBOX_EGRESS_LIVE_TEST") != "1" {
		t.Skip("set SANDBOX_EGRESS_LIVE_TEST=1 to run the privileged network test")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("live sandbox egress test requires root on Linux")
	}

	egress, err := sandboxEgressFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if egress == nil {
		t.Fatal("live test requires a non-placeholder egress IP and port")
	}

	setupRead, setupWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer setupRead.Close()
	defer setupWrite.Close()

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestSandboxEgressLive$")
	cmd.Env = append(os.Environ(),
		"SANDBOX_EGRESS_LIVE_CHILD=1",
		"RUN_LANG_NETWORK_SETUP_FD=3",
	)
	cmd.ExtraFiles = []*os.File{setupRead}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	setupRead.Close()

	cleanup, err := setupSandboxNetworking(cmd.Process.Pid, egress)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal(err)
	}
	if _, err := setupWrite.Write([]byte{1}); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		cleanup()
		t.Fatal(err)
	}
	setupWrite.Close()
	waitErr := cmd.Wait()
	cleanupErr := cleanup()
	if waitErr != nil {
		t.Fatalf("sandbox probe failed: %v\nstdout: %s\nstderr: %s", waitErr, stdout.String(), stderr.String())
	}
	if cleanupErr != nil {
		t.Fatalf("sandbox network cleanup failed: %v", cleanupErr)
	}
}

func testSandboxEgressLiveChild(t *testing.T) {
	t.Helper()
	fd, err := strconv.Atoi(os.Getenv("RUN_LANG_NETWORK_SETUP_FD"))
	if err != nil {
		t.Fatal(err)
	}
	ready := os.NewFile(uintptr(fd), "network-setup")
	defer ready.Close()
	var signal [1]byte
	if _, err := io.ReadFull(ready, signal[:]); err != nil || signal[0] != 1 {
		t.Fatalf("network setup handshake failed: %v", err)
	}
	egress, err := sandboxEgressFromEnv()
	if err != nil || egress == nil {
		t.Fatalf("invalid live-test endpoint: %v", err)
	}

	client := http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := "http://" + net.JoinHostPort(egress.ip.String(), strconv.Itoa(int(egress.port))) + "/"
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("allowed endpoint request failed: %v", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/html") || !strings.Contains(strings.ToLower(string(body)), "<html") {
		t.Fatalf("expected a small HTML response, got status %d, content-type %q, body %q", response.StatusCode, response.Header.Get("Content-Type"), body)
	}

	connection, err := net.DialTimeout("tcp", "1.1.1.1:80", time.Second)
	if err == nil {
		connection.Close()
		t.Fatal("unexpectedly connected to a non-allowlisted endpoint")
	}
}
