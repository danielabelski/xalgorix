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
				q := r.URL.Query().Get("q")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
				id := r.URL.Query().Get("id")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if containsQuote(id) {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = fmt.Fprintf(w, "Database error: You have an error in your SQL syntax; check the manual near '%s' at line 1", id)
					return
				}
				_, _ = fmt.Fprintf(w, "<html><body>Product #%s</body></html>", id)
			}),
		},
		{
			Name: "ssrf", Class: "ssrf", Endpoint: "/fetch", Param: "url",
			Desc: "Fetches a user-supplied url; internal targets return cloud-metadata-like content.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				name := r.URL.Query().Get("name")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", sstiRender(name))
			}),
		},
		{
			Name: "lfi", Class: "lfi", Endpoint: "/download", Param: "file",
			Desc: "Path traversal in the file parameter returns system file contents.",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}
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
