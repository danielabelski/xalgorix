// Package bench is an operator-run benchmark harness for Xalgorix. It runs the
// scanner against a fixed set of deliberately vulnerable, self-hosted challenge
// apps and scores the findings, so the effect of a change on real detection can
// be measured per vulnerability class instead of guessed at.
//
// The heavy part — actually running the LLM-driven agent — is injected as a
// ScanFunc (see harness.go), so the challenge apps, scoring, and aggregation are
// deterministic and unit-testable without any model calls. The real agent
// ScanFunc lives in cmd/xalgorix-bench (operator-run: it needs an LLM key and
// makes live network/tool calls, so it can never run in CI).
package bench

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Challenge is one benchmark task: a self-contained, deliberately vulnerable web
// app plus the finding a correct scan is expected to produce against it.
type Challenge struct {
	Name     string       // unique id, e.g. "reflected-xss"
	Class    string       // canonical expected vuln class (see canonicalClass)
	Endpoint string       // the vulnerable path, e.g. "/search"
	Param    string       // the vulnerable parameter, when applicable
	Desc     string       // one-line human description
	Handler  http.Handler // the deliberately vulnerable app

	// SourceFiles is the whitebox source tree for the app, as relative path →
	// file content. When set, the harness materializes it to a temp directory
	// and hands that directory to the scan as the target's source repo, so the
	// scan can use the source-to-runtime bridge (scan_source_sinks /
	// scan_source_routes / probe_hypothesis). Nil for pure black-box challenges.
	SourceFiles map[string]string

	// Negative marks a NEGATIVE CONTROL: the app handles the same kind of input
	// as a matching positive challenge but SECURELY, so a correct scan reports
	// NO finding of Class. These measure the false-positive rate — a scanner
	// that over-reports fails them. Scoring inverts for negatives (see runOne):
	// "solved" means the class was correctly NOT reported.
	Negative bool
}

// Start launches the challenge app on an ephemeral loopback server. The caller
// owns the returned server and must Close it.
func (c Challenge) Start() *httptest.Server {
	return httptest.NewServer(c.Handler)
}

// Builtin returns the starter challenge set. Each app exhibits exactly one
// unambiguous, class-canonical vulnerability on its Endpoint so scoring is
// crisp. The set is intentionally small; expand it (and, later, wire external
// suites like XBOW) in follow-ups.
//
// These handlers are deliberately vulnerable — that is the whole point of a
// detection benchmark — but they SIMULATE the dangerous outcome (no real
// outbound fetch, command execution, or filesystem read), so they exhibit a
// crisp, detectable signal while staying hermetic and free of security-lint
// findings.
func Builtin() []Challenge {
	return []Challenge{
		{
			Name: "reflected-xss", Class: "xss", Endpoint: "/search", Param: "q",
			Desc: "Reflects the q parameter into the HTML response without encoding.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.URL.Path == "/" {
					// Realistic index: a search form + example link so a crawler
					// discovers the vulnerable endpoint and its parameter.
					_, _ = fmt.Fprint(w, `<html><body><h1>Search</h1><form action="/search" method="get"><input name="q" placeholder="query"><button>Search</button></form><p><a href="/search?q=example">recent search</a></p></body></html>`)
					return
				}
				q := r.URL.Query().Get("q")
				// Deliberately unescaped reflection.
				_, _ = fmt.Fprintf(w, "<html><body><h1>Results</h1><p>You searched for: %s</p></body></html>", q)
			}),
		},
		{
			Name: "idor", Class: "idor", Endpoint: "/api/orders", Param: "id",
			Desc: "Serves any order by id under /api/orders/<id> with no authorization check.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				const prefix = "/api/orders/"
				if !strings.HasPrefix(r.URL.Path, prefix) {
					// Root/other paths: a small index that links to a concrete
					// object, so the agent's crawler discovers the endpoint.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Orders</h1><a href="/api/orders/1042">view order 1042</a></body></html>`)
					return
				}
				// Any id returns a populated record — no session/ownership check.
				id := strings.TrimPrefix(r.URL.Path, prefix)
				if id == "" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"order_id":%q,"owner":"user-%s","total":"1240.00","card_last4":"4242"}`, id, id)
			}),
		},
		{
			Name: "open-redirect", Class: "open_redirect", Endpoint: "/redirect", Param: "url",
			Desc: "Issues a 302 to an attacker-controlled url parameter.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					// Realistic index: a "continue to partner site" link exposes
					// the redirect endpoint + url parameter to a crawler.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Home</h1><p><a href="/redirect?url=https://example.com/welcome">continue to partner site</a></p></body></html>`)
					return
				}
				u := r.URL.Query().Get("url")
				if u == "" {
					u = "/"
				}
				// Deliberately unvalidated redirect. Set Location directly (rather
				// than http.Redirect) so this stays a real open redirect for the
				// scanner to detect.
				w.Header().Set("Location", u)
				w.WriteHeader(http.StatusFound)
			}),
		},
		{
			Name: "error-sqli", Class: "sqli", Endpoint: "/product", Param: "id",
			Desc: "Leaks a database syntax error when the id parameter contains a quote.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.URL.Path == "/" {
					// Realistic catalog index linking product detail pages, so a
					// crawler discovers /product?id=.
					_, _ = fmt.Fprint(w, `<html><body><h1>Catalog</h1><ul><li><a href="/product?id=1">Product #1</a></li><li><a href="/product?id=2">Product #2</a></li></ul></body></html>`)
					return
				}
				id := r.URL.Query().Get("id")
				// HTML-escape the reflected id in BOTH paths so this challenge
				// exposes exactly one unambiguous signal — the SQL error on quote
				// injection — and NOT an accidental reflected-XSS red herring that
				// pulls a scanner off the SQLi it is meant to detect.
				safeID := html.EscapeString(id)
				if containsQuote(id) {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = fmt.Fprintf(w, "Database error: You have an error in your SQL syntax; check the manual near '%s' at line 1", safeID)
					return
				}
				_, _ = fmt.Fprintf(w, "<html><body>Product #%s</body></html>", safeID)
			}),
		},
		{
			Name: "ssrf", Class: "ssrf", Endpoint: "/fetch", Param: "url",
			Desc: "Fetches a user-supplied url; internal targets return cloud-metadata-like content.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					// Realistic link-preview index: a form + example link exposes
					// the fetch endpoint + url parameter to a crawler.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Link Preview</h1><form action="/fetch" method="get"><input name="url" placeholder="https://..."><button>Preview</button></form><p><a href="/fetch?url=https://example.com/logo.png">preview example</a></p></body></html>`)
					return
				}
				raw := r.URL.Query().Get("url")
				host := ""
				if u, err := url.Parse(raw); err == nil {
					host = strings.ToLower(u.Hostname())
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				if isInternalHost(host) {
					// Simulated SSRF: the server reaches an internal-only resource
					// and returns its (fabricated) secret content.
					_, _ = fmt.Fprint(w, "ami-id: ami-0abc123\niam/security-credentials/admin: {\"AccessKeyId\":\"AKIAINTERNAL\",\"Token\":\"internal-metadata-token\"}\n")
					return
				}
				_, _ = fmt.Fprintf(w, "fetched external url: %s\n", raw)
			}),
		},
		{
			Name: "ssti", Class: "ssti", Endpoint: "/greet", Param: "name",
			Desc: "Evaluates a {{ a * b }} expression in the name parameter (template injection).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.URL.Path == "/" {
					// Realistic greeter index: a form + example link exposes the
					// greet endpoint + name parameter to a crawler.
					_, _ = fmt.Fprint(w, `<html><body><h1>Greeter</h1><form action="/greet" method="get"><input name="name" placeholder="your name"><button>Greet</button></form><p><a href="/greet?name=friend">say hi</a></p></body></html>`)
					return
				}
				name := r.URL.Query().Get("name")
				_, _ = fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", sstiRender(name))
			}),
		},
		{
			Name: "lfi", Class: "lfi", Endpoint: "/download", Param: "file",
			Desc: "Path traversal in the file parameter returns system file contents.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					// Realistic documents index linking downloadable files, so a
					// crawler discovers /download?file=.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Documents</h1><ul><li><a href="/download?file=report.pdf">report.pdf</a></li><li><a href="/download?file=invoice.txt">invoice.txt</a></li></ul></body></html>`)
					return
				}
				file := r.URL.Query().Get("file")
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				if strings.Contains(file, "..") && strings.Contains(file, "passwd") {
					// Simulated path traversal: return fabricated /etc/passwd content.
					_, _ = fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
					return
				}
				_, _ = fmt.Fprintf(w, "file not found: %s\n", file)
			}),
		},
		{
			Name: "cmdi", Class: "rce", Endpoint: "/ping", Param: "host",
			Desc: "Command injection in the host parameter (shell metacharacters execute).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					// Realistic network-tools index: a form + example link exposes
					// the ping endpoint + host parameter to a crawler.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Network Tools</h1><form action="/ping" method="get"><input name="host" placeholder="host"><button>Ping</button></form><p><a href="/ping?host=example.com">ping example.com</a></p></body></html>`)
					return
				}
				host := r.URL.Query().Get("host")
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				out := fmt.Sprintf("PING %s: 56 data bytes\n64 bytes: icmp_seq=0 ttl=64 time=0.048 ms\n", host)
				if hasShellMeta(host) {
					// Simulated command execution of the injected command.
					out += "uid=0(root) gid=0(root) groups=0(root)\n"
				}
				_, _ = fmt.Fprint(w, out)
			}),
		},
		{
			// Whitebox challenge: the command-injectable route is NOT linked from
			// any page, so black-box crawling cannot find it. Solving it requires
			// the source-to-runtime bridge — scan the attached source, discover
			// the route + the os.popen sink in the same file, probe it live, then
			// exploit it. Class rce, so it scores on the existing scale.
			Name: "whitebox-cmdi", Class: "rce", Endpoint: "/internal/run-check", Param: "host",
			Desc: "Command injection on an UNLINKED route, discoverable only via the attached source.",
			SourceFiles: map[string]string{
				"app.py": "from flask import Flask, request\n" +
					"import os\n\n" +
					"app = Flask(__name__)\n\n\n" +
					"@app.route('/')\n" +
					"def index():\n" +
					"    return '<html><body>Service</body></html>'\n\n\n" +
					"@app.route('/healthz')\n" +
					"def healthz():\n" +
					"    return 'ok'\n\n\n" +
					"# Internal diagnostics endpoint - intentionally not linked from any page.\n" +
					"@app.route('/internal/run-check')\n" +
					"def run_check():\n" +
					"    host = request.args.get('host', '')\n" +
					"    # Vulnerable: user input flows into a shell command.\n" +
					"    return os.popen('ping -c1 ' + host).read()\n",
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/healthz":
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = fmt.Fprint(w, "ok")
				case "/internal/run-check":
					host := r.URL.Query().Get("host")
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					out := fmt.Sprintf("PING %s: 56 data bytes\n64 bytes: icmp_seq=0 ttl=64 time=0.041 ms\n", host)
					if hasShellMeta(host) {
						// Simulated command execution of the injected command.
						out += "uid=0(root) gid=0(root) groups=0(root)\n"
					}
					_, _ = fmt.Fprint(w, out)
				case "/":
					// Index links only to /healthz — the vulnerable route is NOT
					// linked, so black-box crawling can't find it; only whitebox
					// source discovery can.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Service</h1><p>See <a href="/healthz">health</a>.</p></body></html>`)
				default:
					http.NotFound(w, r)
				}
			}),
		},
		{
			// Whitebox challenge (SQLi): the vulnerable reporting route is not
			// linked from any page, so it is discoverable only via the attached
			// source. Solving it exercises the source-to-runtime bridge for a
			// second injection class — the sqli sink (a raw SELECT built by
			// string concatenation) lives inside the /internal/report handler.
			Name: "whitebox-sqli", Class: "sqli", Endpoint: "/internal/report", Param: "uid",
			Desc: "SQL injection on an UNLINKED route, discoverable only via the attached source.",
			SourceFiles: map[string]string{
				"app.py": "from flask import Flask, request\n" +
					"import sqlite3\n\n" +
					"app = Flask(__name__)\n" +
					"db = sqlite3.connect(':memory:', check_same_thread=False)\n\n\n" +
					"@app.route('/')\n" +
					"def index():\n" +
					"    return '<html><body>Reports service</body></html>'\n\n\n" +
					"@app.route('/healthz')\n" +
					"def healthz():\n" +
					"    return 'ok'\n\n\n" +
					"# Internal reporting endpoint - intentionally not linked from any page.\n" +
					"@app.route('/internal/report')\n" +
					"def report():\n" +
					"    uid = request.args.get('uid', '')\n" +
					"    # Vulnerable: user input concatenated into a raw SQL query.\n" +
					"    query = \"SELECT id, name FROM users WHERE id = '\" + uid + \"'\"\n" +
					"    return str(db.execute(query).fetchall())\n",
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/healthz":
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = fmt.Fprint(w, "ok")
				case "/internal/report":
					uid := r.URL.Query().Get("uid")
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					if containsQuote(uid) {
						// Simulated SQL error revealing injectability.
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = fmt.Fprintf(w, "Database error: You have an error in your SQL syntax; check the manual near '%s' at line 1", uid)
						return
					}
					_, _ = fmt.Fprintf(w, "<html><body>report for uid %s</body></html>", uid)
				case "/":
					// Index does NOT link the vulnerable reporting route.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Reports</h1><p>See <a href="/healthz">health</a>.</p></body></html>`)
				default:
					http.NotFound(w, r)
				}
			}),
		},
		{
			// Whitebox challenge (SSTI): the vulnerable preview route is not
			// linked from any page, so it is discoverable only via the attached
			// source. Solving it exercises the source-to-runtime bridge for a
			// third injection class — the template sink (render_template_string
			// over concatenated user input) lives inside the /internal/preview
			// handler, which codesearch types as a template sink (→ ssti).
			Name: "whitebox-ssti", Class: "ssti", Endpoint: "/internal/preview", Param: "name",
			Desc: "Server-side template injection on an UNLINKED route, discoverable only via the attached source.",
			SourceFiles: map[string]string{
				"app.py": "from flask import Flask, request, render_template_string\n\n" +
					"app = Flask(__name__)\n\n\n" +
					"@app.route('/')\n" +
					"def index():\n" +
					"    return '<html><body>Preview service</body></html>'\n\n\n" +
					"@app.route('/healthz')\n" +
					"def healthz():\n" +
					"    return 'ok'\n\n\n" +
					"# Internal preview endpoint - intentionally not linked from any page.\n" +
					"@app.route('/internal/preview')\n" +
					"def preview():\n" +
					"    name = request.args.get('name', '')\n" +
					"    # Vulnerable: user input rendered as a Jinja2 template.\n" +
					"    return render_template_string('<h1>Hello ' + name + '</h1>')\n",
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/healthz":
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = fmt.Fprint(w, "ok")
				case "/internal/preview":
					name := r.URL.Query().Get("name")
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					// Simulated Jinja2 render: a {{ a * b }} expression is
					// evaluated (so {{7*7}} → 49), proving template injection.
					_, _ = fmt.Fprintf(w, "<html><body><h1>Hello %s</h1></body></html>", sstiRender(name))
				case "/":
					// Index does NOT link the vulnerable preview route.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Preview</h1><p>See <a href="/healthz">health</a>.</p></body></html>`)
				default:
					http.NotFound(w, r)
				}
			}),
		},
		{
			// Whitebox challenge (LFI): the vulnerable log-viewer route is not
			// linked from any page, so it is discoverable only via the attached
			// source. Solving it exercises the source-to-runtime bridge for a
			// fourth class — the file-read sink (open() over a concatenated user
			// path) lives inside the /internal/logs handler, which codesearch
			// types as a fileio sink (→ lfi).
			Name: "whitebox-lfi", Class: "lfi", Endpoint: "/internal/logs", Param: "file",
			Desc: "Local file inclusion / path traversal on an UNLINKED route, discoverable only via the attached source.",
			SourceFiles: map[string]string{
				"app.py": "from flask import Flask, request\n\n" +
					"app = Flask(__name__)\n\n\n" +
					"@app.route('/')\n" +
					"def index():\n" +
					"    return '<html><body>Logs service</body></html>'\n\n\n" +
					"@app.route('/healthz')\n" +
					"def healthz():\n" +
					"    return 'ok'\n\n\n" +
					"# Internal log viewer - intentionally not linked from any page.\n" +
					"@app.route('/internal/logs')\n" +
					"def logs():\n" +
					"    name = request.args.get('file', 'app.log')\n" +
					"    # Vulnerable: user input concatenated into a filesystem path.\n" +
					"    return open('/var/log/app/' + name).read()\n",
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/healthz":
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = fmt.Fprint(w, "ok")
				case "/internal/logs":
					file := r.URL.Query().Get("file")
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					if looksLikePasswdTraversal(file) {
						// Simulated path traversal reading /etc/passwd.
						_, _ = fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
						return
					}
					_, _ = fmt.Fprint(w, "2026-09-03 12:00:00 INFO app started\n2026-09-03 12:00:01 INFO request served\n")
				case "/":
					// Index does NOT link the vulnerable log-viewer route.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Logs</h1><p>See <a href="/healthz">health</a>.</p></body></html>`)
				default:
					http.NotFound(w, r)
				}
			}),
		},
		{
			// Whitebox challenge (RCE, Node/Express source): validates the
			// source-to-runtime bridge on a SECOND language. The vulnerable
			// diagnostics route is not linked from any page, so it is discoverable
			// only via the attached JS source — the command-exec sink
			// (child_process exec over concatenated user input) lives inside the
			// app.get('/internal/ping') handler, which codesearch types as an rce
			// sink and the Express route pattern discovers.
			Name: "whitebox-node-rce", Class: "rce", Endpoint: "/internal/ping", Param: "host",
			Desc: "Command injection on an UNLINKED Express route, discoverable only via the attached Node source.",
			SourceFiles: map[string]string{
				"app.js": "const express = require('express');\n" +
					"const { exec } = require('child_process');\n" +
					"const app = express();\n\n" +
					"app.get('/', (req, res) => {\n" +
					"  res.send('<html><body>Service</body></html>');\n" +
					"});\n\n" +
					"app.get('/healthz', (req, res) => {\n" +
					"  res.send('ok');\n" +
					"});\n\n" +
					"// Internal diagnostics endpoint - intentionally not linked from any page.\n" +
					"app.get('/internal/ping', (req, res) => {\n" +
					"  const host = req.query.host || '';\n" +
					"  // Vulnerable: user input flows into a shell command.\n" +
					"  exec('ping -c1 ' + host, (err, stdout) => {\n" +
					"    res.type('text/plain').send(stdout);\n" +
					"  });\n" +
					"});\n\n" +
					"app.listen(3000);\n",
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/healthz":
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = fmt.Fprint(w, "ok")
				case "/internal/ping":
					host := r.URL.Query().Get("host")
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					out := fmt.Sprintf("PING %s: 56 data bytes\n64 bytes: icmp_seq=0 ttl=64 time=0.041 ms\n", host)
					if hasShellMeta(host) {
						// Simulated command execution of the injected command.
						out += "uid=0(root) gid=0(root) groups=0(root)\n"
					}
					_, _ = fmt.Fprint(w, out)
				case "/":
					// Index does NOT link the vulnerable diagnostics route.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Service</h1><p>See <a href="/healthz">health</a>.</p></body></html>`)
				default:
					http.NotFound(w, r)
				}
			}),
		},
		{
			// NEGATIVE CONTROL (xss): reflects q but HTML-escapes it, so there is
			// no XSS to report. A precise scanner reports nothing here.
			Name: "safe-search", Class: "xss", Endpoint: "/search", Param: "q", Negative: true,
			Desc: "NEGATIVE CONTROL: reflects q but HTML-escapes it (no XSS).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.URL.Path == "/" {
					_, _ = fmt.Fprint(w, `<html><body><h1>Search</h1><form action="/search" method="get"><input name="q" placeholder="query"><button>Search</button></form><p><a href="/search?q=example">recent search</a></p></body></html>`)
					return
				}
				q := r.URL.Query().Get("q")
				// SAFE: user input is HTML-escaped before reflection.
				_, _ = fmt.Fprintf(w, "<html><body><h1>Results</h1><p>You searched for: %s</p></body></html>", html.EscapeString(q))
			}),
		},
		{
			// NEGATIVE CONTROL (open_redirect): only relative same-origin targets
			// are honored; absolute/scheme-relative URLs are rejected.
			Name: "safe-redirect", Class: "open_redirect", Endpoint: "/redirect", Param: "url", Negative: true,
			Desc: "NEGATIVE CONTROL: only redirects to relative same-origin paths (no open redirect).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Home</h1><p><a href="/redirect?url=/welcome">continue</a></p></body></html>`)
					return
				}
				u := r.URL.Query().Get("url")
				// SAFE: allow only relative, same-origin paths. Reject absolute
				// URLs and scheme-relative ("//host") targets.
				if !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprint(w, "invalid redirect target")
					return
				}
				w.Header().Set("Location", u)
				w.WriteHeader(http.StatusFound)
			}),
		},
		{
			// NEGATIVE CONTROL (sqli): parameterized; a non-numeric id yields a
			// generic 400 with no database error text, so there is no SQLi signal.
			Name: "safe-sqli", Class: "sqli", Endpoint: "/product", Param: "id", Negative: true,
			Desc: "NEGATIVE CONTROL: parameterized query; invalid id -> generic 400, no DB error (no SQLi).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.URL.Path == "/" {
					_, _ = fmt.Fprint(w, `<html><body><h1>Catalog</h1><ul><li><a href="/product?id=1">Product #1</a></li><li><a href="/product?id=2">Product #2</a></li></ul></body></html>`)
					return
				}
				id := r.URL.Query().Get("id")
				// SAFE: parameterized. Non-numeric ids are rejected generically —
				// no SQL string is built and no DBMS error is ever leaked.
				if _, err := strconv.Atoi(strings.TrimSpace(id)); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprint(w, "invalid product id")
					return
				}
				_, _ = fmt.Fprintf(w, "<html><body>Product #%s</body></html>", id)
			}),
		},
		{
			// NEGATIVE CONTROL (ssrf): an allowlist refuses internal/link-local/
			// metadata hosts with 403, so no internal resource is ever reached.
			Name: "safe-fetch", Class: "ssrf", Endpoint: "/fetch", Param: "url", Negative: true,
			Desc: "NEGATIVE CONTROL: SSRF allowlist blocks internal/metadata hosts (403); only external fetches succeed.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Link Preview</h1><form action="/fetch" method="get"><input name="url" placeholder="https://..."><button>Preview</button></form><p><a href="/fetch?url=https://example.com/logo.png">preview example</a></p></body></html>`)
					return
				}
				raw := r.URL.Query().Get("url")
				host := ""
				if u, err := url.Parse(raw); err == nil {
					host = strings.ToLower(u.Hostname())
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				// SAFE: refuse internal/metadata destinations.
				if isInternalHost(host) {
					w.WriteHeader(http.StatusForbidden)
					_, _ = fmt.Fprint(w, "blocked: destination not allowed")
					return
				}
				_, _ = fmt.Fprintf(w, "fetched external url: %s\n", raw)
			}),
		},
		{
			// NEGATIVE CONTROL (lfi): rejects path traversal; only plain
			// filenames are served, so /etc/passwd is never reachable.
			Name: "safe-lfi", Class: "lfi", Endpoint: "/download", Param: "file", Negative: true,
			Desc: "NEGATIVE CONTROL: rejects '..' and path separators (no path traversal).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Documents</h1><ul><li><a href="/download?file=report.pdf">report.pdf</a></li><li><a href="/download?file=invoice.txt">invoice.txt</a></li></ul></body></html>`)
					return
				}
				file := r.URL.Query().Get("file")
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				// SAFE: reject traversal and any path separators; only a plain
				// filename from the fixed documents directory is served.
				if strings.ContainsAny(file, "/\\") || strings.Contains(file, "..") {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprint(w, "invalid file name")
					return
				}
				_, _ = fmt.Fprintf(w, "contents of document %q\n", file)
			}),
		},
		{
			// NEGATIVE CONTROL (rce): validates the host and refuses shell
			// metacharacters, so no injected command ever runs.
			Name: "safe-cmdi", Class: "rce", Endpoint: "/ping", Param: "host", Negative: true,
			Desc: "NEGATIVE CONTROL: rejects shell metacharacters in host (no command injection).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Network Tools</h1><form action="/ping" method="get"><input name="host" placeholder="host"><button>Ping</button></form><p><a href="/ping?host=example.com">ping example.com</a></p></body></html>`)
					return
				}
				host := r.URL.Query().Get("host")
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				// SAFE: refuse shell metacharacters — the value is never handed to
				// a shell, so nothing executes.
				if hasShellMeta(host) {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprint(w, "invalid host")
					return
				}
				_, _ = fmt.Fprintf(w, "PING %s: 56 data bytes\n64 bytes: icmp_seq=0 ttl=64 time=0.050 ms\n", host)
			}),
		},
		{
			// NEGATIVE CONTROL (ssti): the name is inserted as literal (HTML-
			// escaped) text, never evaluated, so {{7*7}} stays {{7*7}} (never 49).
			Name: "safe-ssti", Class: "ssti", Endpoint: "/greet", Param: "name", Negative: true,
			Desc: "NEGATIVE CONTROL: name is rendered as literal text, not evaluated (no template injection).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.URL.Path == "/" {
					_, _ = fmt.Fprint(w, `<html><body><h1>Greeter</h1><form action="/greet" method="get"><input name="name" placeholder="your name"><button>Greet</button></form><p><a href="/greet?name=friend">say hi</a></p></body></html>`)
					return
				}
				name := r.URL.Query().Get("name")
				// SAFE: literal, HTML-escaped text — the template engine never
				// evaluates it, so a {{7*7}} probe is echoed as-is.
				_, _ = fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", html.EscapeString(name))
			}),
		},
		{
			// NEGATIVE CONTROL (idor): ownership is enforced, so every order
			// object is forbidden without the owner's session — no cross-object read.
			Name: "safe-idor", Class: "idor", Endpoint: "/api/orders", Param: "id", Negative: true,
			Desc: "NEGATIVE CONTROL: object access is authorized; other users' orders return 403 (no IDOR).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				const prefix = "/api/orders/"
				if !strings.HasPrefix(r.URL.Path, prefix) {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Orders</h1><a href="/api/orders/1042">view order 1042</a></body></html>`)
					return
				}
				// SAFE: the caller has no session establishing ownership of this
				// object, so access is refused — no record (no card/owner data) is
				// ever returned.
				w.WriteHeader(http.StatusForbidden)
				_, _ = fmt.Fprint(w, "forbidden: not your order")
			}),
		},
		{
			// XXE: POST an XML document to /import. A DOCTYPE that declares an
			// external entity pointing at a local file is resolved, and the file
			// content comes back in the response (simulated /etc/passwd read).
			Name: "xxe", Class: "xxe", Endpoint: "/import", Param: "",
			Desc: "Resolves external XML entities in a posted document (XXE file read).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Data Import</h1><p>POST an XML document to <a href="/import">/import</a> to import records.</p><form action="/import" method="post"><textarea name="xml"></textarea><button>Import</button></form></body></html>`)
					return
				}
				body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				if hasXXEPayload(string(body)) {
					// Simulated external-entity resolution: the referenced local
					// file is read and echoed back in the import result.
					_, _ = fmt.Fprint(w, "imported 1 record: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
					return
				}
				_, _ = fmt.Fprint(w, "imported 0 records\n")
			}),
		},
		{
			// NEGATIVE CONTROL (xxe): the XML parser has external-entity
			// resolution disabled, so a DOCTYPE/SYSTEM entity is never expanded
			// and no file content is ever returned.
			Name: "safe-import", Class: "xxe", Endpoint: "/import", Param: "", Negative: true,
			Desc: "NEGATIVE CONTROL: external entities disabled; DOCTYPE ignored (no XXE).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Data Import</h1><p>POST an XML document to <a href="/import">/import</a> to import records.</p><form action="/import" method="post"><textarea name="xml"></textarea><button>Import</button></form></body></html>`)
					return
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				// SAFE: external entities are disabled — a DOCTYPE is ignored and
				// never expanded, so no local file is ever read.
				_, _ = fmt.Fprint(w, "imported 0 records\n")
			}),
		},
		{
			// CSRF: a state-changing POST (change the account email) protected by
			// nothing — the form carries no anti-CSRF token and the handler
			// requires none, so a form auto-submitted from any origin silently
			// changes the victim's email. Discoverable via the "/" index form.
			Name: "csrf", Class: "csrf", Endpoint: "/account/email", Param: "",
			Desc: "State-changing POST /account/email accepts requests with no anti-CSRF token (CSRF).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					_ = r.ParseForm()
					// VULNERABLE: the email change is applied with no anti-CSRF
					// token and no Origin/Referer check — any site can submit it.
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = fmt.Fprint(w, "account email updated\n")
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				// The change-email form carries NO anti-CSRF token field.
				_, _ = fmt.Fprint(w, `<html><body><h1>Account settings</h1><p>Change the email on your account.</p><form action="/account/email" method="post"><input name="email" type="email"><button>Save</button></form></body></html>`)
			}),
		},
		{
			// NEGATIVE CONTROL (csrf): the change-email form embeds a per-session
			// anti-CSRF token and the handler rejects any POST whose token is
			// missing or wrong, so a forged cross-site submission cannot change
			// state.
			Name: "safe-account", Class: "csrf", Endpoint: "/account/email", Param: "", Negative: true,
			Desc: "NEGATIVE CONTROL: change-email POST requires a valid anti-CSRF token (no CSRF).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				const csrfToken = "sess-csrf-7f3a9c2e"
				if r.Method == http.MethodPost {
					_ = r.ParseForm()
					// SAFE: a missing or incorrect anti-CSRF token is refused, so
					// a cross-site request cannot change the account email.
					if r.PostFormValue("csrf_token") != csrfToken {
						w.WriteHeader(http.StatusForbidden)
						_, _ = fmt.Fprint(w, "invalid csrf token\n")
						return
					}
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = fmt.Fprint(w, "account email updated\n")
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = fmt.Fprintf(w, `<html><body><h1>Account settings</h1><p>Change the email on your account.</p><form action="/account/email" method="post"><input type="hidden" name="csrf_token" value="%s"><input name="email" type="email"><button>Save</button></form></body></html>`, csrfToken)
			}),
		},
	}
}

// hasXXEPayload reports whether an XML document declares an external entity that
// pulls in a local file — the classic XXE payload: a DOCTYPE with a SYSTEM
// identifier referencing a file: URL (or /etc/passwd directly). A benign
// document declares no such external entity.
func hasXXEPayload(body string) bool {
	b := strings.ToLower(body)
	return strings.Contains(b, "<!doctype") && strings.Contains(b, "system") &&
		(strings.Contains(b, "file:") || strings.Contains(b, "/etc/passwd"))
}

// looksLikePasswdTraversal reports whether a file parameter uses ../ traversal to
// reach /etc/passwd — the classic LFI probe this challenge is designed to catch
// (the sink concatenates the value onto /var/log/app/, so only traversal escapes
// to a sensitive file).
func looksLikePasswdTraversal(file string) bool {
	f := strings.ToLower(file)
	return strings.Contains(f, "..") && strings.Contains(f, "etc/passwd")
}

func containsQuote(s string) bool {
	for _, r := range s {
		if r == '\'' || r == '"' {
			return true
		}
	}
	return false
}

// isInternalHost reports whether a host points at loopback, link-local cloud
// metadata, or private space — the targets that make a server-side fetch SSRF.
func isInternalHost(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254", "metadata.google.internal", "metadata":
		return true
	}
	return strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") || strings.HasSuffix(host, ".internal")
}

// sstiExpr matches a simple "{{ a * b }}" arithmetic template expression.
var sstiExpr = regexp.MustCompile(`\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}`)

// sstiRender evaluates any {{ a * b }} expressions in s (returning the product),
// simulating a template engine that evaluates attacker input — so the classic
// {{7*7}} → 49 probe is confirmable.
func sstiRender(s string) string {
	return sstiExpr.ReplaceAllStringFunc(s, func(m string) string {
		parts := sstiExpr.FindStringSubmatch(m)
		a, _ := strconv.Atoi(parts[1])
		b, _ := strconv.Atoi(parts[2])
		return strconv.Itoa(a * b)
	})
}

// hasShellMeta reports whether s carries a shell metacharacter that would chain
// a command in a naive system() call.
func hasShellMeta(s string) bool {
	return strings.ContainsAny(s, ";|&`$\n")
}
