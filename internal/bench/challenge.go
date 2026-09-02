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
// detection benchmark — so the security-lint warnings they would otherwise
// attract are avoided by construction (e.g. the open redirect sets Location
// directly) rather than by shipping exploitable helpers.
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
				// Any id returns a populated record — no session/ownership check.
				id := r.URL.Path[len("/api/orders/"):]
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
