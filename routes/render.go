package routes

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/code-golf/code-golf/golfer"
	"github.com/code-golf/code-golf/pretty"
	"github.com/code-golf/code-golf/session"
	min "github.com/tdewolff/minify/v2/minify"
)

func colour(i int) string {
	if i <= 1 {
		return "yellow"
	}
	if i <= 2 {
		return "orange"
	}
	if i <= 3 {
		return "red"
	}
	if i <= 10 {
		return "purple"
	}
	if i <= 100 {
		return "blue"
	}
	return "green"
}

var (
	css = map[string]template.CSS{}
	js  = map[string]template.JS{}
	svg = map[string]template.HTML{}

	dev bool
)

var tmpl = template.New("").Funcs(template.FuncMap{
	"bytes":     pretty.Bytes,
	"colour":    colour,
	"comma":     pretty.Comma,
	"hasPrefix": strings.HasPrefix,
	"hasSuffix": strings.HasSuffix,
	"ord":       pretty.Ordinal,
	"svg":       func(name string) template.HTML { return svg[name] },
	"symbol": func(name string) template.HTML {
		return template.HTML(strings.ReplaceAll(string(svg[name]), "svg", "symbol"))
	},
	"title": strings.Title,
	"time":  pretty.Time,
})

func init() {
	_, dev = syscall.Getenv("DEV")

	if err := filepath.Walk("views", func(file string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		b, err := ioutil.ReadFile(file)
		if err != nil {
			return err
		}

		data := string(b)
		ext := path.Ext(file)
		name := file[len("views/") : len(file)-len(ext)]

		switch ext {
		case ".css":
			data = strings.ReplaceAll(data, "fontWoff2", fontWoff2Path)
			data = strings.ReplaceAll(data, "twemojiWoff2", twemojiWoff2Path)

			if data, err = min.CSS(data); err != nil {
				return err
			}

			css[name[len("css/"):]] = template.CSS(data)
		case ".html":
			tmpl = template.Must(tmpl.New(name).Parse(data))
		case ".js":
			if data, err = min.JS(data); err != nil {
				return err
			}

			js[name[len("js/"):]] = template.JS(data)
		case ".svg":
			svg[name[len("svg/"):]] = template.HTML(data)
		}

		return nil
	}); err != nil {
		panic(err)
	}
}

func render(w http.ResponseWriter, r *http.Request, name, title string, data interface{}) {
	// The generated value SHOULD be at least 128 bits long (before encoding),
	// and SHOULD be generated via a cryptographically secure random number
	// generator - https://w3c.github.io/webappsec-csp/#security-nonces
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	args := struct {
		Beta                                bool
		CSS                                 template.CSS
		Data                                interface{}
		Golfer                              *golfer.Golfer
		GolferInfo                          *golfer.GolferInfo
		JS                                  template.JS
		JSExt, LogInURL, Nonce, Path, Title string
		Request                             *http.Request
	}{
		Beta:       session.Beta(r),
		CSS:        css["base"] + css[path.Dir(name)] + css[name],
		Data:       data,
		Golfer:     session.Golfer(r),
		GolferInfo: session.GolferInfo(r),
		JS:         js[name],
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Path:       r.URL.Path,
		Request:    r,
		Title:      title,
	}

	if name == "hole" {
		args.JSExt = holeJsPath
		args.CSS = css["vendor/codemirror"] + args.CSS
	}

	header := w.Header()

	header.Set("Content-Language", "en")
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Content-Security-Policy",
		"base-uri 'none';"+
			"connect-src 'self';"+
			"default-src 'none';"+
			"form-action 'none';"+
			"font-src 'self';"+
			"frame-ancestors 'none';"+
			"img-src 'self' data: avatars.githubusercontent.com;"+
			"script-src 'self' 'nonce-"+args.Nonce+"';"+
			"style-src 'self' 'nonce-"+args.Nonce+"'",
	)

	if args.Golfer == nil {
		// Shallow copy because we want to modify a string.
		config := config

		config.RedirectURL = "https://code.golf/callback"

		if dev {
			config.RedirectURL += "/dev"
		} else if args.Beta {
			config.RedirectURL += "/beta"
		}

		config.RedirectURL += "?redirect_uri=" + url.QueryEscape(r.RequestURI)

		// TODO State is a token to protect the user from CSRF attacks.
		args.LogInURL = config.AuthCodeURL("")
	}

	switch name {
	case "403":
		w.WriteHeader(http.StatusForbidden)
	case "404":
		w.WriteHeader(http.StatusNotFound)
	}

	if err := tmpl.ExecuteTemplate(w, name, args); err != nil {
		panic(err)
	}
}
