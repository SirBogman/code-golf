package hole

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	sandboxEgressIPEnv   = "RUN_LANG_EGRESS_IP"
	sandboxEgressPortEnv = "RUN_LANG_EGRESS_PORT"
	sandboxNATTable      = "codegolf_sandbox"
)

type sandboxEgress struct {
	ip   net.IP
	port uint16
}

var (
	parentNetworkSetup sync.Once
	parentNetworkErr   error
	sandboxAddressPool = struct {
		sync.Mutex
		next int
		used map[int]struct{}
	}{used: make(map[int]struct{})}
)

func sandboxEgressFromEnv() (*sandboxEgress, error) {
	ip := strings.TrimSpace(os.Getenv(sandboxEgressIPEnv))
	port := strings.TrimSpace(os.Getenv(sandboxEgressPortEnv))
	if ip == "" && port == "" {
		return nil, nil
	}
	if isSandboxDocumentationIP(ip) {
		return nil, nil
	}
	if ip == "" || port == "" {
		return nil, fmt.Errorf("%s and %s must be set together", sandboxEgressIPEnv, sandboxEgressPortEnv)
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil || parsedIP.To4() == nil || strings.Contains(ip, ":") {
		return nil, fmt.Errorf("%s must be an IPv4 address", sandboxEgressIPEnv)
	}
	if !parsedIP.IsGlobalUnicast() {
		return nil, fmt.Errorf("%s must be a unicast address", sandboxEgressIPEnv)
	}
	_, sandboxNetwork, _ := net.ParseCIDR("198.18.0.0/15")
	if sandboxNetwork.Contains(parsedIP) {
		return nil, fmt.Errorf("%s overlaps the sandbox network", sandboxEgressIPEnv)
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return nil, fmt.Errorf("%s must be a TCP port from 1 to 65535", sandboxEgressPortEnv)
	}

	return &sandboxEgress{ip: parsedIP.To4(), port: uint16(parsedPort)}, nil
}

func isSandboxDocumentationIP(address string) bool {
	parsedIP := net.ParseIP(address)
	if parsedIP == nil || parsedIP.To4() == nil {
		return false
	}
	for _, documentationCIDR := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"} {
		_, documentationNetwork, _ := net.ParseCIDR(documentationCIDR)
		if documentationNetwork.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func setupSandboxNetworking(pid int, egress *sandboxEgress) (func() error, error) {
	parentNetworkSetup.Do(func() {
		parentNetworkErr = enableSandboxForwarding()
		if parentNetworkErr == nil {
			parentNetworkErr = installSandboxMasquerade()
		}
	})
	if parentNetworkErr != nil {
		return nil, parentNetworkErr
	}

	slot, _, gatewayIP, sandboxIP, err := acquireSandboxSubnet()
	if err != nil {
		return nil, err
	}

	hostHandle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		releaseSandboxSubnet(slot)
		return nil, err
	}
	namespace, err := netns.GetFromPid(pid)
	if err != nil {
		hostHandle.Close()
		releaseSandboxSubnet(slot)
		return nil, err
	}
	defer namespace.Close()

	hostName := fmt.Sprintf("cg%08x", uint32(pid))
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: hostName},
		PeerName:      "eth0",
		PeerNamespace: netlink.NsPid(pid),
	}
	if err := hostHandle.LinkAdd(veth); err != nil {
		hostHandle.Close()
		releaseSandboxSubnet(slot)
		return nil, err
	}

	cleanupPartial := func(cause error) (func() error, error) {
		deleteSandboxVeth(hostHandle, veth, slot)
		hostHandle.Close()
		return nil, cause
	}

	hostLink, err := hostHandle.LinkByName(hostName)
	if err != nil {
		return cleanupPartial(err)
	}
	if err := hostHandle.AddrAdd(hostLink, mustParseAddr(gatewayIP.String()+"/30")); err != nil {
		return cleanupPartial(err)
	}
	if err := hostHandle.LinkSetUp(hostLink); err != nil {
		return cleanupPartial(err)
	}

	childHandle, err := netlink.NewHandleAt(namespace, unix.NETLINK_ROUTE)
	if err != nil {
		return cleanupPartial(err)
	}
	defer childHandle.Close()
	loopback, err := childHandle.LinkByName("lo")
	if err != nil {
		return cleanupPartial(err)
	}
	if err := childHandle.LinkSetUp(loopback); err != nil {
		return cleanupPartial(err)
	}
	childLink, err := childHandle.LinkByName("eth0")
	if err != nil {
		return cleanupPartial(err)
	}
	if err := childHandle.AddrAdd(childLink, mustParseAddr(sandboxIP.String()+"/30")); err != nil {
		return cleanupPartial(err)
	}
	if err := childHandle.LinkSetUp(childLink); err != nil {
		return cleanupPartial(err)
	}
	if err := childHandle.RouteAdd(&netlink.Route{
		LinkIndex: childLink.Attrs().Index,
		Gw:        gatewayIP,
	}); err != nil {
		return cleanupPartial(err)
	}
	if err := installSandboxEgressFilter(namespace, egress); err != nil {
		return cleanupPartial(err)
	}

	return func() error {
		err := deleteSandboxVeth(hostHandle, hostLink, slot)
		hostHandle.Close()
		return err
	}, nil
}

func deleteSandboxVeth(handle *netlink.Handle, link netlink.Link, slot int) error {
	if err := handle.LinkDel(link); err != nil {
		_, lookupErr := handle.LinkByName(link.Attrs().Name)
		var notFound *netlink.LinkNotFoundError
		if !errors.As(lookupErr, &notFound) {
			return err
		}
	}
	releaseSandboxSubnet(slot)
	return nil
}

func mustParseAddr(address string) *netlink.Addr {
	parsed, err := netlink.ParseAddr(address)
	if err != nil {
		panic(err)
	}
	return parsed
}

func enableSandboxForwarding() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("enable sandbox IPv4 forwarding: %w", err)
	}
	return nil
}

func installSandboxMasquerade() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}

	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return err
	}
	for _, table := range tables {
		if table.Name == sandboxNATTable {
			return nil
		}
	}

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   sandboxNATTable,
	})
	chain := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	forwardChain := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   chainPolicy(nftables.ChainPolicyAccept),
	})
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{255, 254, 0, 0},
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{198, 18, 0, 0}},
			&expr.Masq{},
		},
	})
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardChain,
		Exprs: sandboxToSandboxDropExpressions(),
	})
	return conn.Flush()
}

func sandboxToSandboxDropExpressions() []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{255, 254, 0, 0},
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{198, 18, 0, 0}},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{255, 254, 0, 0},
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{198, 18, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

func installSandboxEgressFilter(namespace netns.NsHandle, egress *sandboxEgress) error {
	conn, err := nftables.New(nftables.WithNetNSFd(int(namespace)))
	if err != nil {
		return err
	}
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "codegolf_egress",
	})
	chain := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   chainPolicy(nftables.ChainPolicyDrop),
	})
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: sandboxEgressExpressions(egress),
	})
	return conn.Flush()
}

func chainPolicy(policy nftables.ChainPolicy) *nftables.ChainPolicy {
	return &policy
}

func sandboxEgressExpressions(egress *sandboxEgress) []expr.Any {
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, egress.port)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: egress.ip.To4()},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func acquireSandboxSubnet() (int, net.IP, net.IP, net.IP, error) {
	sandboxAddressPool.Lock()
	defer sandboxAddressPool.Unlock()

	for range 32768 {
		slot := sandboxAddressPool.next
		sandboxAddressPool.next = (sandboxAddressPool.next + 1) % 32768
		if _, exists := sandboxAddressPool.used[slot]; exists {
			continue
		}
		sandboxAddressPool.used[slot] = struct{}{}
		base := uint32(0xc6120000) + uint32(slot*4)
		return slot, ipv4FromUint32(base), ipv4FromUint32(base + 1), ipv4FromUint32(base + 2), nil
	}
	return 0, nil, nil, nil, fmt.Errorf("sandbox network address pool exhausted")
}

func releaseSandboxSubnet(slot int) {
	sandboxAddressPool.Lock()
	delete(sandboxAddressPool.used, slot)
	sandboxAddressPool.Unlock()
}

func ipv4FromUint32(value uint32) net.IP {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}
