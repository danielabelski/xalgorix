package browser

import (
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestExecSignalSinkRecordClearAndBound(t *testing.T) {
	ctxID := "xss-sink-" + t.Name()
	clearExecSignals(ctxID)

	recordExecSignal(ctxID, ExecSignal{Kind: "dialog:alert", Message: "hello", At: time.Now()})
	if got := execSignalsFor(ctxID); len(got) != 1 || got[0].Message != "hello" {
		t.Fatalf("expected 1 recorded signal, got %#v", got)
	}

	// Bounded to maxExecSignalsPerCtx.
	for i := 0; i < maxExecSignalsPerCtx+10; i++ {
		recordExecSignal(ctxID, ExecSignal{Kind: "dialog:alert", Message: "m"})
	}
	if got := len(execSignalsFor(ctxID)); got != maxExecSignalsPerCtx {
		t.Fatalf("expected sink bounded to %d, got %d", maxExecSignalsPerCtx, got)
	}

	clearExecSignals(ctxID)
	if got := execSignalsFor(ctxID); got != nil {
		t.Fatalf("expected empty sink after clear, got %#v", got)
	}
}

func TestMatchExecNonce(t *testing.T) {
	signals := []ExecSignal{
		{Kind: "dialog:alert", Message: "some other dialog"},
		{Kind: "dialog:alert", Message: "payload fired: XV-8f3a done"},
	}
	if _, ok := matchExecNonce(signals, ""); ok {
		t.Fatal("empty nonce must never match")
	}
	if _, ok := matchExecNonce(signals, "NOPE"); ok {
		t.Fatal("unrelated nonce must not match")
	}
	// Case-insensitive substring.
	m, ok := matchExecNonce(signals, "xv-8f3a")
	if !ok || !strings.Contains(m.Message, "XV-8f3a") {
		t.Fatalf("expected case-insensitive nonce match, got ok=%v msg=%q", ok, m.Message)
	}
}

func TestFinalizeXSSVerdictConfirmedRecordsLedger(t *testing.T) {
	ctxID := "xss-confirm-" + t.Name()
	sc := scanctx.New(ctxID, "")
	scanctx.Activate(sc)
	defer scanctx.Deactivate(ctxID)

	signals := []ExecSignal{{Kind: "dialog:alert", Message: "XV-abc123", URL: "https://app/x"}}
	res := finalizeXSSVerdict(ctxID, "https://app/search?q=payload", "XV-abc123", "q", signals)

	if ok, _ := res.Metadata["xss_confirmed"].(bool); !ok {
		t.Fatalf("expected xss_confirmed=true, got metadata %#v (output: %s)", res.Metadata, res.Output)
	}
	if !strings.Contains(res.Output, "Browser-confirmed XSS") {
		t.Fatalf("expected a confirmation message, got: %s", res.Output)
	}

	all := sc.Ledger.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 ledger hypothesis, got %d", len(all))
	}
	h := all[0]
	if h.VulnClass != "xss" || h.Parameter != "q" || h.Endpoint != "/search" {
		t.Fatalf("unexpected hypothesis identity: class=%q param=%q endpoint=%q", h.VulnClass, h.Parameter, h.Endpoint)
	}
	if len(h.Evidence) != 1 || h.Evidence[0].Kind != "exploit" {
		t.Fatalf("expected one exploit evidence, got %#v", h.Evidence)
	}
	if h.Status != scanctx.HypothesisTesting {
		t.Fatalf("expected status testing (agent still reports/verifies), got %q", h.Status)
	}
}

func TestFinalizeXSSVerdictNotConfirmed(t *testing.T) {
	ctxID := "xss-noconfirm-" + t.Name()
	sc := scanctx.New(ctxID, "")
	scanctx.Activate(sc)
	defer scanctx.Deactivate(ctxID)

	// Unrelated dialog fired, but not our nonce.
	res := finalizeXSSVerdict(ctxID, "https://app/x", "XV-zzz", "q",
		[]ExecSignal{{Kind: "dialog:alert", Message: "cookie consent"}})
	if ok, _ := res.Metadata["xss_confirmed"].(bool); ok {
		t.Fatal("expected xss_confirmed=false when the nonce did not fire")
	}
	if !strings.Contains(res.Output, "unrelated dialog") {
		t.Fatalf("expected mention of unrelated dialogs, got: %s", res.Output)
	}
	if sc.Ledger.Len() != 0 {
		t.Fatalf("expected no ledger writes when unconfirmed, got %d", sc.Ledger.Len())
	}

	// No dialogs at all → guidance to use a dialog payload.
	res2 := finalizeXSSVerdict(ctxID, "https://app/x", "XV-zzz", "q", nil)
	if ok, _ := res2.Metadata["xss_confirmed"].(bool); ok {
		t.Fatal("expected xss_confirmed=false with no signals")
	}
	if !strings.Contains(res2.Output, "alert('XV-zzz')") {
		t.Fatalf("expected a suggested dialog payload carrying the nonce, got: %s", res2.Output)
	}
}

func TestFinalizeXSSVerdictConfirmsConsoleAndDOMSignals(t *testing.T) {
	// verify_xss now accepts dialog, console, and DOM-marker execution oracles.
	// Each flows through the same sink + verdict + ledger path, so a signal of
	// any kind carrying the nonce confirms XSS and records evidence.
	for _, kind := range []string{"console:log", "console:error", "dom:marker"} {
		t.Run(kind, func(t *testing.T) {
			ctxID := "xss-kind-" + strings.ReplaceAll(kind, ":", "-")
			sc := scanctx.New(ctxID, "")
			scanctx.Activate(sc)
			defer scanctx.Deactivate(ctxID)

			signals := []ExecSignal{{Kind: kind, Message: "prefix XV-kind-9 suffix"}}
			res := finalizeXSSVerdict(ctxID, "https://app/search?q=1", "XV-kind-9", "q", signals)
			if ok, _ := res.Metadata["xss_confirmed"].(bool); !ok {
				t.Fatalf("expected confirmed for kind %s, got metadata %#v (%s)", kind, res.Metadata, res.Output)
			}
			all := sc.Ledger.All()
			if len(all) != 1 || all[0].VulnClass != "xss" {
				t.Fatalf("expected 1 xss hypothesis for kind %s, got %d", kind, len(all))
			}
			if len(all[0].Evidence) != 1 {
				t.Fatalf("expected one evidence entry for kind %s", kind)
			}
		})
	}
}

func TestVerifyXSSErrorPaths(t *testing.T) {
	ctxID := "xss-err-" + t.Name()

	// Missing nonce → corrective error, no browser needed.
	if res, _ := verifyXSS(ctxID, "https://app/x", "", "", "", ""); res.Error == "" || !strings.Contains(res.Error, "nonce is required") {
		t.Fatalf("expected nonce-required error, got %#v", res)
	}
	// Nonce present but no browser launched → clear "launch first" error.
	if res, _ := verifyXSS(ctxID, "https://app/x", "XV-1", "", "", ""); res.Error == "" || !strings.Contains(res.Error, "browser not launched") {
		t.Fatalf("expected browser-not-launched error, got %#v", res)
	}
}

func TestParseFormBody(t *testing.T) {
	// Order + duplicates preserved; empty pairs skipped; leading '?' tolerated.
	got := parseFormBody("?a=1&b=2&a=3&&c=")
	want := [][2]string{{"a", "1"}, {"b", "2"}, {"a", "3"}, {"c", ""}}
	if len(got) != len(want) {
		t.Fatalf("expected %d pairs, got %d (%#v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pair %d: expected %v, got %v", i, want[i], got[i])
		}
	}

	// A percent-encoded value is decoded once (so the browser re-encodes cleanly).
	if got := parseFormBody("q=%3Cscript%3E"); len(got) != 1 || got[0] != [2]string{"q", "<script>"} {
		t.Fatalf("expected single-decoded value, got %#v", got)
	}

	// A bare key with no '=' is a present-but-empty field.
	if got := parseFormBody("flag"); len(got) != 1 || got[0] != [2]string{"flag", ""} {
		t.Fatalf("expected bare key as empty-valued field, got %#v", got)
	}

	if got := parseFormBody("   "); got != nil {
		t.Fatalf("expected nil for blank body, got %#v", got)
	}
}

func TestBuildXSSFormHTMLPOST(t *testing.T) {
	// The action and a payload carrying '<', '>', quotes must be HTML-escaped in
	// the attribute context so the markup stays well-formed (the browser decodes
	// the attribute back to the raw payload and URL-encodes it at submit).
	h := buildXSSFormHTML("https://app/search", `q=<svg onload=alert('XV-1')>`)
	for _, want := range []string{
		`method="POST"`,
		`action="https://app/search"`,
		`id="xssverify"`,
		`name="q"`,
		`value="&lt;svg onload=alert(&#39;XV-1&#39;)&gt;"`,
	} {
		if !strings.Contains(h, want) {
			t.Fatalf("expected form HTML to contain %q, got:\n%s", want, h)
		}
	}
	// The raw, unescaped payload must NOT leak into the markup (that would break
	// the attribute and change what gets submitted).
	if strings.Contains(h, "<svg onload=") {
		t.Fatalf("payload must be HTML-escaped in the attribute, got:\n%s", h)
	}
}
