package bench

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func challengeByName(t *testing.T, name string) Challenge {
	t.Helper()
	for _, c := range Builtin() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no builtin challenge %q", name)
	return Challenge{}
}

// noRedirectClient captures 3xx instead of following them.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestBuiltinChallengesExhibitVuln(t *testing.T) {
	// reflected-xss: payload reflected unescaped.
	xss := challengeByName(t, "reflected-xss").Start()
	defer xss.Close()
	if body := httpGet(t, xss.URL+"/search?q=<script>alert(1)</script>"); !strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("reflected-xss did not reflect payload: %q", body)
	}

	// idor: arbitrary id returns a populated record.
	idor := challengeByName(t, "idor").Start()
	defer idor.Close()
	if body := httpGet(t, idor.URL+"/api/orders/999"); !strings.Contains(body, "user-999") {
		t.Fatalf("idor did not serve arbitrary id: %q", body)
	}

	// open-redirect: 302 to attacker url.
	orc := challengeByName(t, "open-redirect").Start()
	defer orc.Close()
	resp, err := noRedirectClient().Get(orc.URL + "/redirect?url=https://evil.example/")
	if err != nil {
		t.Fatalf("open-redirect request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://evil.example/" {
		t.Fatalf("open-redirect: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// error-sqli: quote triggers a SQL error.
	sqli := challengeByName(t, "error-sqli").Start()
	defer sqli.Close()
	if body := httpGet(t, sqli.URL+"/product?id=1'"); !strings.Contains(strings.ToLower(body), "sql syntax") {
		t.Fatalf("error-sqli did not leak a SQL error: %q", body)
	}
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestClassifyFinding(t *testing.T) {
	cases := []struct {
		title, desc, cwe, want string
	}{
		{"Reflected XSS in search", "", "", "xss"},
		{"Injection issue", "SQL injection via id", "", "sqli"},
		{"Open Redirect on /redirect", "", "", "open_redirect"},
		{"Access another user's order", "insecure direct object reference", "", "idor"},
		{"SSRF in the fetch endpoint", "", "", "ssrf"},
		{"Server-Side Template Injection via name", "template injection", "", "ssti"},
		{"Path traversal in download", "local file inclusion", "", "lfi"},
		{"Command injection in ping", "os command executed", "", "rce"},
		{"Mystery bug", "no class keyword", "CWE-79", "xss"},   // CWE fallback
		{"Mystery bug", "no class keyword", "CWE-639", "idor"}, // CWE fallback
		{"Mystery bug", "no class keyword", "CWE-99999", ""},   // unmapped
		{"Mystery bug", "no class keyword", "", ""},            // nothing
		// An SSTI finding whose description mentions the RCE it can escalate to
		// must classify as ssti via its CWE, not rce via the "remote code
		// execution" keyword (which precedes ssti in classKeywords).
		{"Server-Side Template Injection via name", "confirmed {{7*7}}=49; can be escalated to remote code execution", "CWE-1336", "ssti"},
		// CWE wins over a conflicting description keyword generally.
		{"Template injection", "the payload triggers command injection style impact", "CWE-1336", "ssti"},
	}
	for _, c := range cases {
		got := classifyFinding(reporting.Vulnerability{Title: c.title, Description: c.desc, CWE: c.cwe})
		if got != c.want {
			t.Errorf("classifyFinding(%q,%q,%q) = %q, want %q", c.title, c.desc, c.cwe, got, c.want)
		}
	}
}

func TestSolved(t *testing.T) {
	// Right class → solved (endpoint/path is not part of the criterion).
	f := []reporting.Vulnerability{{ID: "XALG-1", Title: "Reflected XSS", Endpoint: "https://h/?q=x"}}
	if ok, id := Solved("xss", f); !ok || id != "XALG-1" {
		t.Fatalf("expected an xss finding to solve, got ok=%v id=%q", ok, id)
	}
	// Canonicalization: a BOLA finding solves the idor challenge.
	if ok, _ := Solved("idor", []reporting.Vulnerability{{ID: "XALG-2", Title: "BOLA", Description: "broken object level authorization"}}); !ok {
		t.Fatal("expected a BOLA finding to solve the idor challenge")
	}
	// Wrong class → not solved.
	if ok, _ := Solved("xss", []reporting.Vulnerability{{Title: "SQL injection in id"}}); ok {
		t.Fatal("a sqli finding must not solve an xss challenge")
	}
	// No findings → not solved.
	if ok, _ := Solved("xss", nil); ok {
		t.Fatal("no findings must not solve")
	}
}

func TestRunWithFakeScanFunc(t *testing.T) {
	// Fake solves xss and idor, leaves open-redirect and error-sqli unsolved,
	// and errors on nothing.
	fake := func(_ context.Context, target, _, scanID string) ([]reporting.Vulnerability, error) {
		switch scanID {
		case "bench-reflected-xss":
			return []reporting.Vulnerability{{ID: "XALG-1", Title: "Reflected XSS in search", Endpoint: target + "/search"}}, nil
		case "bench-idor":
			return []reporting.Vulnerability{{ID: "XALG-1", Title: "IDOR", Description: "insecure direct object reference", Endpoint: target + "/api/orders/1042"}}, nil
		default:
			return nil, nil
		}
	}

	card := Run(context.Background(), Builtin(), fake)
	if card.Total() != len(Builtin()) {
		t.Fatalf("expected %d challenges, got %d", len(Builtin()), card.Total())
	}
	if card.SolvedCount() != 2 {
		t.Fatalf("expected 2 solved (xss+idor), got %d\n%s", card.SolvedCount(), card.String())
	}
	byClass := card.ByClass()
	if byClass["xss"] != [2]int{1, 1} || byClass["idor"] != [2]int{1, 1} {
		t.Fatalf("expected xss 1/1 and idor 1/1, got %v", byClass)
	}
	// Every other single-challenge class is present but unsolved by this fake.
	for _, c := range []string{"open_redirect", "ssrf"} {
		if byClass[c] != [2]int{0, 1} {
			t.Fatalf("expected %s 0/1, got %v", c, byClass[c])
		}
	}
	// rce has three challenges (cmdi + whitebox-cmdi + whitebox-node-rce); sqli
	// (error-sqli + whitebox-sqli), ssti (ssti + whitebox-ssti), and lfi
	// (lfi + whitebox-lfi) each have two — all unsolved by this fake.
	if byClass["rce"] != [2]int{0, 3} {
		t.Fatalf("expected rce 0/3, got %v", byClass["rce"])
	}
	if byClass["sqli"] != [2]int{0, 2} {
		t.Fatalf("expected sqli 0/2, got %v", byClass["sqli"])
	}
	if byClass["ssti"] != [2]int{0, 2} {
		t.Fatalf("expected ssti 0/2, got %v", byClass["ssti"])
	}
	if byClass["lfi"] != [2]int{0, 2} {
		t.Fatalf("expected lfi 0/2, got %v", byClass["lfi"])
	}
}

func TestNewBuiltinChallengesExhibitVuln(t *testing.T) {
	// ssrf: an internal-target url returns metadata-like secret content.
	ssrf := challengeByName(t, "ssrf").Start()
	defer ssrf.Close()
	if body := httpGet(t, ssrf.URL+"/fetch?url=http://169.254.169.254/latest/meta-data/"); !strings.Contains(body, "security-credentials") {
		t.Fatalf("ssrf did not return internal metadata: %q", body)
	}

	// ssti: {{7*7}} evaluates to 49.
	ssti := challengeByName(t, "ssti").Start()
	defer ssti.Close()
	if body := httpGet(t, ssti.URL+"/greet?name={{7*7}}"); !strings.Contains(body, "Hello, 49!") {
		t.Fatalf("ssti did not evaluate the template expression: %q", body)
	}

	// lfi: path traversal to passwd returns fabricated passwd content.
	lfi := challengeByName(t, "lfi").Start()
	defer lfi.Close()
	if body := httpGet(t, lfi.URL+"/download?file=../../../../etc/passwd"); !strings.Contains(body, "root:x:0:0:") {
		t.Fatalf("lfi did not leak passwd content: %q", body)
	}

	// cmdi: a shell metacharacter yields command output.
	cmdi := challengeByName(t, "cmdi").Start()
	defer cmdi.Close()
	if body := httpGet(t, cmdi.URL+"/ping?host=127.0.0.1%3Bid"); !strings.Contains(body, "uid=0(root)") {
		t.Fatalf("cmdi did not execute the injected command: %q", body)
	}
}

func TestRunWithTimeoutMarksTimedOut(t *testing.T) {
	// A scan that blocks past the per-challenge deadline is stopped and marked
	// timed out (and, with no findings, not solved).
	blocking := func(ctx context.Context, _, _, _ string) ([]reporting.Vulnerability, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	card := RunWithTimeout(context.Background(), []Challenge{Builtin()[0]}, blocking, 50*time.Millisecond)
	if len(card.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(card.Results))
	}
	if !card.Results[0].TimedOut {
		t.Fatalf("expected the challenge to be marked timed out, got %+v", card.Results[0])
	}
	if card.Results[0].Solved {
		t.Fatal("a timed-out scan with no findings must not be solved")
	}
}

func TestWhiteboxChallengeExhibitsVuln(t *testing.T) {
	wb := challengeByName(t, "whitebox-cmdi")

	// The whitebox source carries the sink and the (unlinked) vulnerable route
	// in the same file, so the source→route↔sink bridge can find it.
	src, ok := wb.SourceFiles["app.py"]
	if !ok {
		t.Fatal("whitebox-cmdi must ship app.py source")
	}
	if !strings.Contains(src, "os.popen") || !strings.Contains(src, "/internal/run-check") {
		t.Fatalf("app.py must contain the os.popen sink and the /internal/run-check route:\n%s", src)
	}

	srv := wb.Start()
	defer srv.Close()

	// The vulnerable route executes injected commands (shell metacharacter).
	if body := httpGet(t, srv.URL+"/internal/run-check?host=127.0.0.1%3Bid"); !strings.Contains(body, "uid=0(root)") {
		t.Fatalf("whitebox route did not execute the injected command: %q", body)
	}
	// A benign host does not.
	if body := httpGet(t, srv.URL+"/internal/run-check?host=127.0.0.1"); strings.Contains(body, "uid=0(root)") {
		t.Fatalf("benign host must not yield command output: %q", body)
	}
	// Health endpoint is benign.
	if body := httpGet(t, srv.URL+"/healthz"); !strings.Contains(body, "ok") {
		t.Fatalf("healthz should return ok, got %q", body)
	}
	// The index must NOT link the vulnerable route — black-box crawling can't
	// reach it, so the win genuinely requires whitebox source discovery.
	if body := httpGet(t, srv.URL+"/"); strings.Contains(body, "/internal/run-check") {
		t.Fatalf("index must not link the vulnerable route (whitebox-only), got %q", body)
	}
}

func TestHarnessMaterializesSourceFiles(t *testing.T) {
	// Capture the sourceDir handed to each challenge's scan.
	seen := map[string]string{}
	fake := func(_ context.Context, _, sourceDir, scanID string) ([]reporting.Vulnerability, error) {
		seen[scanID] = sourceDir
		// While the scan runs, each of the challenge's OWN declared source files
		// must exist on disk (language-agnostic: app.py for Flask, app.js for
		// Express, etc.).
		if sourceDir != "" {
			name := strings.TrimPrefix(scanID, "bench-")
			for _, c := range Builtin() {
				if c.Name != name {
					continue
				}
				for f := range c.SourceFiles {
					if _, err := os.Stat(filepath.Join(sourceDir, f)); err != nil {
						t.Errorf("expected %s in materialized source dir %q: %v", f, sourceDir, err)
					}
				}
			}
		}
		return nil, nil
	}

	Run(context.Background(), Builtin(), fake)

	if seen["bench-whitebox-cmdi"] == "" {
		t.Fatal("whitebox-cmdi must receive a non-empty, materialized source dir")
	}
	if seen["bench-reflected-xss"] != "" {
		t.Fatalf("a black-box challenge must receive an empty source dir, got %q", seen["bench-reflected-xss"])
	}
}

func TestWhiteboxSqliChallengeExhibitsVuln(t *testing.T) {
	wb := challengeByName(t, "whitebox-sqli")

	// The whitebox source carries the sqli sink (a raw SELECT built by string
	// concatenation) inside the unlinked reporting route's handler.
	src, ok := wb.SourceFiles["app.py"]
	if !ok {
		t.Fatal("whitebox-sqli must ship app.py source")
	}
	if !strings.Contains(src, "/internal/report") || !strings.Contains(src, "SELECT id, name FROM users") {
		t.Fatalf("app.py must contain the /internal/report route and the raw SELECT sink:\n%s", src)
	}

	srv := wb.Start()
	defer srv.Close()

	// A quote in uid triggers a SQL syntax error (injectable).
	if body := httpGet(t, srv.URL+"/internal/report?uid=1%27"); !strings.Contains(strings.ToLower(body), "sql syntax") {
		t.Fatalf("whitebox-sqli did not leak a SQL error on quote injection: %q", body)
	}
	// A benign uid does not.
	if body := httpGet(t, srv.URL+"/internal/report?uid=1"); strings.Contains(strings.ToLower(body), "sql syntax") {
		t.Fatalf("benign uid must not yield a SQL error: %q", body)
	}
	// Health endpoint is benign.
	if body := httpGet(t, srv.URL+"/healthz"); !strings.Contains(body, "ok") {
		t.Fatalf("healthz should return ok, got %q", body)
	}
	// The index must NOT link the vulnerable route (whitebox-only discovery).
	if body := httpGet(t, srv.URL+"/"); strings.Contains(body, "/internal/report") {
		t.Fatalf("index must not link the vulnerable route (whitebox-only), got %q", body)
	}
}

func TestWhiteboxSstiChallengeExhibitsVuln(t *testing.T) {
	wb := challengeByName(t, "whitebox-ssti")

	// The whitebox source carries the template sink (render_template_string over
	// concatenated user input) inside the unlinked preview route's handler.
	src, ok := wb.SourceFiles["app.py"]
	if !ok {
		t.Fatal("whitebox-ssti must ship app.py source")
	}
	if !strings.Contains(src, "/internal/preview") || !strings.Contains(src, "render_template_string") {
		t.Fatalf("app.py must contain the /internal/preview route and the render_template_string sink:\n%s", src)
	}

	srv := wb.Start()
	defer srv.Close()

	// A {{7*7}} expression is evaluated server-side to 49 (template injection).
	if body := httpGet(t, srv.URL+"/internal/preview?name=%7B%7B7*7%7D%7D"); !strings.Contains(body, "49") {
		t.Fatalf("whitebox-ssti did not evaluate the template expression to 49: %q", body)
	}
	// A benign name is echoed literally, not evaluated.
	if body := httpGet(t, srv.URL+"/internal/preview?name=alice"); !strings.Contains(body, "alice") || strings.Contains(body, "49") {
		t.Fatalf("benign name must be echoed literally, not evaluated: %q", body)
	}
	// Health endpoint is benign.
	if body := httpGet(t, srv.URL+"/healthz"); !strings.Contains(body, "ok") {
		t.Fatalf("healthz should return ok, got %q", body)
	}
	// The index must NOT link the vulnerable route (whitebox-only discovery).
	if body := httpGet(t, srv.URL+"/"); strings.Contains(body, "/internal/preview") {
		t.Fatalf("index must not link the vulnerable route (whitebox-only), got %q", body)
	}
}

func TestWhiteboxLfiChallengeExhibitsVuln(t *testing.T) {
	wb := challengeByName(t, "whitebox-lfi")

	// The whitebox source carries the file-read sink (open() over a concatenated
	// user path) inside the unlinked log-viewer route's handler.
	src, ok := wb.SourceFiles["app.py"]
	if !ok {
		t.Fatal("whitebox-lfi must ship app.py source")
	}
	if !strings.Contains(src, "/internal/logs") || !strings.Contains(src, "open('/var/log/app/'") {
		t.Fatalf("app.py must contain the /internal/logs route and the open() file-read sink:\n%s", src)
	}

	srv := wb.Start()
	defer srv.Close()

	// A ../ traversal to /etc/passwd leaks the passwd file (path traversal).
	if body := httpGet(t, srv.URL+"/internal/logs?file=../../../../etc/passwd"); !strings.Contains(body, "root:") {
		t.Fatalf("whitebox-lfi did not leak /etc/passwd on traversal: %q", body)
	}
	// A benign file name returns ordinary log lines, not passwd.
	if body := httpGet(t, srv.URL+"/internal/logs?file=app.log"); strings.Contains(body, "root:") {
		t.Fatalf("benign file must not leak passwd: %q", body)
	}
	// Health endpoint is benign.
	if body := httpGet(t, srv.URL+"/healthz"); !strings.Contains(body, "ok") {
		t.Fatalf("healthz should return ok, got %q", body)
	}
	// The index must NOT link the vulnerable route (whitebox-only discovery).
	if body := httpGet(t, srv.URL+"/"); strings.Contains(body, "/internal/logs") {
		t.Fatalf("index must not link the vulnerable route (whitebox-only), got %q", body)
	}
}

func TestWhiteboxNodeRceChallengeExhibitsVuln(t *testing.T) {
	wb := challengeByName(t, "whitebox-node-rce")

	// The whitebox source is a Node/Express app: the command-exec sink
	// (child_process exec over concatenated user input) lives inside the unlinked
	// diagnostics route's handler, discovered via the Express route pattern.
	src, ok := wb.SourceFiles["app.js"]
	if !ok {
		t.Fatal("whitebox-node-rce must ship app.js source")
	}
	if !strings.Contains(src, "child_process") || !strings.Contains(src, "app.get('/internal/ping'") {
		t.Fatalf("app.js must contain the Express /internal/ping route and the child_process exec sink:\n%s", src)
	}

	srv := wb.Start()
	defer srv.Close()

	// A shell metacharacter in host triggers simulated command execution.
	if body := httpGet(t, srv.URL+"/internal/ping?host=127.0.0.1%3Bid"); !strings.Contains(body, "uid=0") {
		t.Fatalf("whitebox-node-rce did not execute the injected command: %q", body)
	}
	// A benign host does not.
	if body := httpGet(t, srv.URL+"/internal/ping?host=localhost"); strings.Contains(body, "uid=0") {
		t.Fatalf("benign host must not yield command output: %q", body)
	}
	// Health endpoint is benign.
	if body := httpGet(t, srv.URL+"/healthz"); !strings.Contains(body, "ok") {
		t.Fatalf("healthz should return ok, got %q", body)
	}
	// The index must NOT link the vulnerable route (whitebox-only discovery).
	if body := httpGet(t, srv.URL+"/"); strings.Contains(body, "/internal/ping") {
		t.Fatalf("index must not link the vulnerable route (whitebox-only), got %q", body)
	}
}
