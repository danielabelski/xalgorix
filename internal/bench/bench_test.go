package bench

import (
	"context"
	"io"
	"net/http"
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
	fake := func(_ context.Context, target, scanID string) ([]reporting.Vulnerability, error) {
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
	// Every other class is present but unsolved by this fake.
	for _, c := range []string{"open_redirect", "sqli", "ssrf", "ssti", "lfi", "rce"} {
		if byClass[c] != [2]int{0, 1} {
			t.Fatalf("expected %s 0/1, got %v", c, byClass[c])
		}
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
	blocking := func(ctx context.Context, _, _ string) ([]reporting.Vulnerability, error) {
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
