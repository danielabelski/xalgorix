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

// Auth carries per-account credential headers for an AUTHENTICATED challenge.
// A is the primary session (role A) — auto-applied to the scan's requests; B is
// a SECOND account (role B) the scanner uses to prove horizontal access-control
// flaws (BOLA/IDOR/BFLA) by replaying role A's requests as role B. Both are
// nil for a stateless, single-user challenge. The values are header name→value
// (e.g. {"Authorization": "Bearer alice-token"}).
type Auth struct {
	A map[string]string
	B map[string]string
}

// Challenge is one benchmark task: a self-contained, deliberately vulnerable web
// app plus the finding a correct scan is expected to produce against it.
type Challenge struct {
	Name     string       // unique id, e.g. "reflected-xss"
	Class    string       // canonical expected vuln class (see canonicalClass)
	Endpoint string       // the vulnerable path, e.g. "/search"
	Param    string       // the vulnerable parameter, when applicable
	Desc     string       // one-line human description
	Handler  http.Handler // the deliberately vulnerable app

	// Auth seeds the scan with authenticated identities (role A, and optionally a
	// second account role B) so a challenge can exercise real authorization
	// flaws: the harness wires A as the scan's session and B as the matrix's
	// comparison identity. Zero value = stateless/single-user challenge.
	Auth Auth

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
		{
			// Authenticated BOLA (Broken Object Level Authorization): every order
			// is readable by ANY logged-in user — the handler authenticates the
			// caller but never checks the order belongs to them. Role A (alice)
			// owns order 1001; role B (bob) owns 1002. The scan is seeded with
			// BOTH sessions (Auth), so authz_matrix can replay a request for
			// alice's own order (1001, surfaced on the index) as bob and see bob
			// get alice's data. Anonymous is refused, so the ONLY flaw is the
			// cross-account read. Class idor (BOLA canonicalizes to idor).
			Name: "bola", Class: "idor", Endpoint: "/api/orders", Param: "id",
			Desc: "Any authenticated user can read any order by id (no per-object ownership check).",
			Auth: Auth{
				A: map[string]string{"Authorization": "Bearer alice-token-a1"},
				B: map[string]string{"Authorization": "Bearer bob-token-b2"},
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				const prefix = "/api/orders/"
				if !strings.HasPrefix(r.URL.Path, prefix) {
					// Index links the CALLER's own order so an authenticated crawl
					// discovers a concrete object id to test cross-account.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Your orders</h1><a href="/api/orders/1001">view your recent order #1001</a></body></html>`)
					return
				}
				user := bolaUser(r)
				if user == "" {
					// No/unrecognized session — orders require authentication.
					w.Header().Set("WWW-Authenticate", "Bearer")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = fmt.Fprint(w, `{"error":"authentication required"}`)
					return
				}
				id := strings.TrimPrefix(r.URL.Path, prefix)
				if id == "" {
					http.NotFound(w, r)
					return
				}
				// VULNERABLE: any authenticated user gets any order — no check that
				// the order's owner matches the caller, so bob reading order 1001
				// (alice's) returns alice's data verbatim.
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"order_id":%q,"owner":%q,"total":"1240.00","card_last4":"4242"}`, id, orderOwner(id))
			}),
		},
		{
			// NEGATIVE CONTROL (idor/BOLA): the handler enforces per-object
			// ownership — a logged-in user may read ONLY their own orders; another
			// user's order returns 403. Replaying alice's request for 1001 as bob
			// is denied, so a precise scanner reports nothing.
			Name: "safe-bola", Class: "idor", Endpoint: "/api/orders", Param: "id", Negative: true,
			Desc: "NEGATIVE CONTROL: orders enforce per-object ownership; other users' orders return 403 (no BOLA).",
			Auth: Auth{
				A: map[string]string{"Authorization": "Bearer alice-token-a1"},
				B: map[string]string{"Authorization": "Bearer bob-token-b2"},
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				const prefix = "/api/orders/"
				if !strings.HasPrefix(r.URL.Path, prefix) {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Your orders</h1><a href="/api/orders/1001">view your recent order #1001</a></body></html>`)
					return
				}
				user := bolaUser(r)
				if user == "" {
					w.Header().Set("WWW-Authenticate", "Bearer")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = fmt.Fprint(w, `{"error":"authentication required"}`)
					return
				}
				id := strings.TrimPrefix(r.URL.Path, prefix)
				if id == "" {
					http.NotFound(w, r)
					return
				}
				// SAFE: enforce ownership — only the order's owner may read it.
				if orderOwner(id) != user {
					w.WriteHeader(http.StatusForbidden)
					_, _ = fmt.Fprint(w, `{"error":"forbidden"}`)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"order_id":%q,"owner":%q,"total":"1240.00","card_last4":"4242"}`, id, user)
			}),
		},
		{
			// Authenticated BFLA (Broken Function Level Authorization): an
			// admin-only function is reachable by ANY authenticated user. The
			// handler checks authentication but never the caller's ROLE — role A
			// (admin) is meant to use it, but role B (a regular user) gets the
			// same privileged response, which is vertical privilege escalation.
			// Anonymous is refused, so the flaw is strictly the missing role
			// check. Class idor (BFLA canonicalizes to idor).
			Name: "bfla", Class: "idor", Endpoint: "/api/admin/users", Param: "",
			Desc: "An admin-only user-list function is reachable by any authenticated user (no role check).",
			Auth: Auth{
				A: map[string]string{"Authorization": "Bearer admin-token-a1"},
				B: map[string]string{"Authorization": "Bearer user-token-b2"},
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/admin/users" {
					// Index (crawled as the admin session) links the admin function.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Admin console</h1><a href="/api/admin/users">manage users</a></body></html>`)
					return
				}
				if bflaRole(r) == "" {
					w.Header().Set("WWW-Authenticate", "Bearer")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = fmt.Fprint(w, `{"error":"authentication required"}`)
					return
				}
				// VULNERABLE: any authenticated caller gets the admin user list —
				// no check that the caller's role is admin, so a regular user (role
				// B) sees the same privileged data (emails, SSN fragments).
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"users":[{"id":1,"email":"alice@corp.example","role":"admin","ssn_last4":"6789"},{"id":2,"email":"bob@corp.example","role":"user","ssn_last4":"4321"}]}`)
			}),
		},
		{
			// NEGATIVE CONTROL (idor/BFLA): the admin function enforces a role
			// check — a regular user (role B) is refused with 403 — so there is no
			// privilege escalation to report.
			Name: "safe-bfla", Class: "idor", Endpoint: "/api/admin/users", Param: "", Negative: true,
			Desc: "NEGATIVE CONTROL: admin function enforces a role check; regular users get 403 (no BFLA).",
			Auth: Auth{
				A: map[string]string{"Authorization": "Bearer admin-token-a1"},
				B: map[string]string{"Authorization": "Bearer user-token-b2"},
			},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/admin/users" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Admin console</h1><a href="/api/admin/users">manage users</a></body></html>`)
					return
				}
				role := bflaRole(r)
				if role == "" {
					w.Header().Set("WWW-Authenticate", "Bearer")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = fmt.Fprint(w, `{"error":"authentication required"}`)
					return
				}
				// SAFE: enforce the role — only an admin may call the admin function.
				if role != "admin" {
					w.WriteHeader(http.StatusForbidden)
					_, _ = fmt.Fprint(w, `{"error":"forbidden: admin role required"}`)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"users":[{"id":1,"email":"alice@corp.example","role":"admin","ssn_last4":"6789"},{"id":2,"email":"bob@corp.example","role":"user","ssn_last4":"4321"}]}`)
			}),
		},
		{
			// Business-logic flaw: /checkout computes total = quantity * unit price
			// with NO validation that quantity is positive, so a NEGATIVE quantity
			// yields a NEGATIVE total the store still "places" — a refund/credit
			// exploit (the buyer is effectively paid to order). Class
			// business_logic. The item is HTML-escaped and quantity is parsed as an
			// int, so the ONLY signal is the negative total (no XSS/injection red
			// herring).
			Name: "business-logic-negative-qty", Class: "business_logic", Endpoint: "/checkout", Param: "quantity",
			Desc: "Checkout accepts a negative quantity, producing a negative order total (refund abuse).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.URL.Path == "/" {
					_, _ = fmt.Fprint(w, `<html><body><h1>Widget Store</h1><p>Widget — $100 each.</p><form action="/checkout" method="get"><input type="hidden" name="item" value="widget"><input name="quantity" value="1"><button>Buy</button></form><p><a href="/checkout?item=widget&quantity=1">buy one widget</a></p></body></html>`)
					return
				}
				item := html.EscapeString(r.URL.Query().Get("item"))
				qty, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("quantity")))
				const unit = 100
				// VULNERABLE: no check that qty > 0, so a negative quantity yields a
				// negative total and the order is still placed.
				_, _ = fmt.Fprintf(w, `<html><body><h1>Checkout</h1><p>Order placed: %d x %s @ $%d each = total $%d.00</p></body></html>`, qty, item, unit, qty*unit)
			}),
		},
		{
			// NEGATIVE CONTROL (business_logic): checkout validates that quantity is
			// a positive integer, rejecting non-positive/non-numeric values with
			// 400, so no negative/zero total is ever produced.
			Name: "safe-checkout", Class: "business_logic", Endpoint: "/checkout", Param: "quantity", Negative: true,
			Desc: "NEGATIVE CONTROL: checkout rejects non-positive quantity (400); no business-logic flaw.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if r.URL.Path == "/" {
					_, _ = fmt.Fprint(w, `<html><body><h1>Widget Store</h1><p>Widget — $100 each.</p><form action="/checkout" method="get"><input type="hidden" name="item" value="widget"><input name="quantity" value="1"><button>Buy</button></form><p><a href="/checkout?item=widget&quantity=1">buy one widget</a></p></body></html>`)
					return
				}
				item := html.EscapeString(r.URL.Query().Get("item"))
				qty, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("quantity")))
				const unit = 100
				// SAFE: reject non-positive or non-numeric quantities before pricing.
				if err != nil || qty <= 0 {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprint(w, "invalid quantity")
					return
				}
				_, _ = fmt.Fprintf(w, `<html><body><h1>Checkout</h1><p>Order placed: %d x %s @ $%d each = total $%d.00</p></body></html>`, qty, item, unit, qty*unit)
			}),
		},
		{
			// NoSQL injection: the login endpoint feeds the request's password
			// straight into a Mongo-style query, so an operator object (JSON
			// {"$ne": null} or the bracketed form password[$ne]=) matches ANY
			// password and authenticates without knowing it — a classic auth
			// bypass. Normal (wrong) credentials the attacker doesn't know are
			// rejected with 401, so the ONLY way in is the operator injection.
			Name: "nosqli-auth-bypass", Class: "nosqli", Endpoint: "/api/login", Param: "password",
			Desc: "Login is vulnerable to NoSQL operator injection ({\"$ne\":...}), bypassing authentication.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Login</h1><form action="/api/login" method="post"><input name="username" placeholder="username"><input name="password" type="password"><button>Sign in</button></form></body></html>`)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if hasNoSQLOperator(r) {
					// VULNERABLE: the operator matches any password → authenticated.
					_, _ = fmt.Fprint(w, `{"authenticated":true,"user":"admin","token":"sess_9f2a3c_admin"}`)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = fmt.Fprint(w, `{"authenticated":false,"error":"invalid credentials"}`)
			}),
		},
		{
			// NEGATIVE CONTROL (nosqli): the login validates that credentials are
			// plain strings and rejects operator objects with 400, so operator
			// injection cannot bypass authentication.
			Name: "safe-login", Class: "nosqli", Endpoint: "/api/login", Param: "password", Negative: true,
			Desc: "NEGATIVE CONTROL: login rejects operator/non-string credentials (400); no NoSQL injection.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Login</h1><form action="/api/login" method="post"><input name="username" placeholder="username"><input name="password" type="password"><button>Sign in</button></form></body></html>`)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if hasNoSQLOperator(r) {
					// SAFE: input validation rejects operator objects / non-strings.
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprint(w, `{"error":"invalid input: credentials must be strings"}`)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = fmt.Fprint(w, `{"authenticated":false,"error":"invalid credentials"}`)
			}),
		},
		{
			// CORS misconfiguration: the account API reflects ANY request Origin
			// into Access-Control-Allow-Origin AND sets
			// Access-Control-Allow-Credentials: true, so a page on any attacker
			// origin can make a credentialed cross-origin request to /api/account
			// and read the victim's authenticated data (email + API token). This
			// is the classic EXPLOITABLE CORS bug — reflected origin + credentials
			// — as opposed to a harmless wildcard without credentials. The
			// response carries a token so an exploit PoC naturally proves theft.
			// Class cors.
			Name: "cors-credentialed-reflect", Class: "cors", Endpoint: "/api/account", Param: "",
			Desc: "Reflects any Origin into ACAO with Access-Control-Allow-Credentials: true (credentialed cross-origin read of authenticated data).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					// Index tells a crawler the SPA reads the account API
					// cross-origin, exposing /api/account as the surface to test.
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Account</h1><p>Our single-page app loads your profile from <a href="/api/account">/api/account</a> with a credentialed cross-origin fetch.</p></body></html>`)
					return
				}
				// VULNERABLE: echo the caller's Origin back and allow credentials,
				// so ANY origin can read this authenticated response. With no
				// Origin header (e.g. a bare curl) fall back to "*" so the
				// reflection is still observable.
				origin := r.Header.Get("Origin")
				if origin == "" {
					origin = "*"
				}
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"user":"admin","email":"admin@corp.example","api_token":"sk_live_9f2a3c7b1e"}`)
			}),
		},
		{
			// NEGATIVE CONTROL (cors): the account API allows credentialed
			// cross-origin reads ONLY from a single fixed, trusted origin and
			// never reflects an arbitrary caller Origin, so an attacker page
			// cannot read the response — there is no CORS flaw to report.
			Name: "safe-cors", Class: "cors", Endpoint: "/api/account", Param: "", Negative: true,
			Desc: "NEGATIVE CONTROL: ACAO is a single fixed trusted origin; arbitrary origins are never reflected (no CORS flaw).",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprint(w, `<html><body><h1>Account</h1><p>Our single-page app loads your profile from <a href="/api/account">/api/account</a> with a credentialed cross-origin fetch.</p></body></html>`)
					return
				}
				// SAFE: only ever allow the one trusted first-party origin; an
				// arbitrary attacker Origin is not reflected and is granted no
				// credentialed access.
				const trusted = "https://app.corp.example"
				if r.Header.Get("Origin") == trusted {
					w.Header().Set("Access-Control-Allow-Origin", trusted)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{"user":"admin","email":"admin@corp.example","api_token":"sk_live_9f2a3c7b1e"}`)
			}),
		},
	}
}

// hasNoSQLOperator reports whether the request smuggles a MongoDB-style query
// operator into its credentials — via a JSON object ({"$ne": null}), the
// bracketed form-encoding (password[$ne]=), or a URL-encoded variant. A normal
// string login never contains these tokens, so their presence is the NoSQL
// operator-injection signal both nosqli challenges key off.
func hasNoSQLOperator(r *http.Request) bool {
	parts := []string{r.URL.RawQuery}
	if dec, err := url.QueryUnescape(r.URL.RawQuery); err == nil {
		parts = append(parts, dec)
	}
	if r.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		parts = append(parts, string(b))
	}
	s := strings.ToLower(strings.Join(parts, "\n"))
	for _, op := range []string{"$ne", "$gt", "$gte", "$lt", "$lte", "$regex", "$where", "$in", "$nin", "$exists"} {
		if strings.Contains(s, op) {
			return true
		}
	}
	return false
}

// bflaRole maps the Bearer token on a request to a role for the BFLA
// challenges, or "" when the request carries no recognized session.
func bflaRole(r *http.Request) string {
	switch strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")) {
	case "admin-token-a1":
		return "admin"
	case "user-token-b2":
		return "user"
	}
	return ""
}

// bolaUser maps the Bearer token on a request to a user name for the BOLA
// challenges, or "" when the request carries no recognized session.
func bolaUser(r *http.Request) string {
	switch strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")) {
	case "alice-token-a1":
		return "alice"
	case "bob-token-b2":
		return "bob"
	}
	return ""
}

// orderOwner returns the owner of an order id for the BOLA challenges. Order
// 1001 belongs to alice (role A) and 1002 to bob (role B); any other id maps to
// a distinct synthetic user so it is never coincidentally the caller's.
func orderOwner(id string) string {
	switch id {
	case "1001":
		return "alice"
	case "1002":
		return "bob"
	}
	return "user-" + id
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
// {{7*7}} → 49 probe is confirmable. The input is HTML-escaped FIRST so the
// challenge exposes ONLY its template-injection signal and not an accidental
// reflected-XSS red herring (html.EscapeString leaves {, }, *, digits, and
// spaces untouched, so a {{7*7}} payload still matches and evaluates, while any
// injected markup like <script> is neutralized).
func sstiRender(s string) string {
	escaped := html.EscapeString(s)
	return sstiExpr.ReplaceAllStringFunc(escaped, func(m string) string {
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
