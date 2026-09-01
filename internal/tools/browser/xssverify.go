package browser

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// verifyXSS confirms that an XSS payload actually EXECUTES in the browser
// (rather than merely being reflected). The caller injects a payload that
// raises a JavaScript dialog carrying a unique nonce — e.g. alert('XV-8f3a') —
// and passes that nonce here. We clear prior signals, navigate to the payload
// URL (dialogs are captured + auto-dismissed by setupDialogHandler), then poll
// briefly for a dialog whose message carries the nonce. A match is concrete
// proof of execution and is recorded as browser-confirmed XSS evidence in the
// shared ledger. This directly addresses the low XSS precision of
// reflection-only scanners.
func verifyXSS(ctxID, rawURL, nonce, parameter string) (tools.Result, error) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return tools.Result{Error: "nonce is required — inject a unique marker via alert()/confirm()/prompt() (e.g. alert('XV-8f3a')) and pass that same marker as nonce so execution can be confirmed unambiguously."}, nil
	}

	s := getBrowserStoreByID(ctxID)
	if s == nil || s.page == nil {
		return tools.Result{Error: "browser not launched — run browser_action command=launch first, then verify_xss with the URL carrying your payload."}, nil
	}

	// Clear stale signals so only this navigation can satisfy the match.
	clearExecSignals(ctxID)

	if strings.TrimSpace(rawURL) != "" {
		if err := s.page.Timeout(20 * time.Second).Navigate(rawURL); err != nil {
			return tools.Result{Error: fmt.Sprintf("navigation to %q failed: %v", rawURL, err)}, nil
		}
		_ = s.page.Timeout(10 * time.Second).WaitStable(time.Second)
	}

	// Dialogs fire asynchronously during/after load; poll a short window until
	// the nonce matches or the deadline elapses, then decide on what we saw.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := matchExecNonce(execSignalsFor(ctxID), nonce); ok {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}

	return finalizeXSSVerdict(ctxID, rawURL, nonce, parameter, execSignalsFor(ctxID)), nil
}

// finalizeXSSVerdict decides confirmed/not from the captured signals and, when
// confirmed, records browser-confirmed XSS evidence in the ledger. Split out
// from verifyXSS so the verdict + ledger logic is unit-testable without a real
// browser (the caller supplies the signals).
func finalizeXSSVerdict(ctxID, rawURL, nonce, parameter string, signals []ExecSignal) tools.Result {
	matched, ok := matchExecNonce(signals, nonce)
	if !ok {
		msg := fmt.Sprintf("XSS NOT confirmed: no JavaScript dialog carrying the nonce %q fired.", nonce)
		if len(signals) > 0 {
			msg += fmt.Sprintf(" %d unrelated dialog(s) did fire — check that your payload raises a dialog containing exactly this nonce.", len(signals))
		} else {
			msg += " The payload may be reflected but not executing (encoded/sanitized/CSP-blocked), or it uses a non-dialog sink. Try a dialog payload such as \"'><script>alert('" + nonce + "')</script>\"."
		}
		return tools.Result{Output: msg, Metadata: map[string]any{"xss_confirmed": false}}
	}

	endpoint := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		endpoint = u.EscapedPath()
	}
	confirm := fmt.Sprintf("Browser-confirmed XSS: a %s dialog carrying the nonce %q fired while loading %s.", matched.Kind, nonce, rawURL)

	if l := ledgerForCtx(ctxID); l != nil {
		h := l.Upsert(scanctx.Hypothesis{
			Title:      "Browser-confirmed XSS at " + endpoint,
			VulnClass:  "xss",
			Endpoint:   endpoint,
			Parameter:  parameter,
			Confidence: 0.9,
			Status:     scanctx.HypothesisTesting,
			Origin:     "verify_xss",
			NextAction: "Report as XSS using the browser-confirmed dialog execution as proof, then link the finding via add_hypothesis_evidence(kind=finding_ref).",
		})
		l.AddEvidence(h.ID, scanctx.Evidence{
			Kind:       "exploit",
			Summary:    confirm,
			Request:    rawURL,
			Response:   matched.Kind + " message: " + matched.Message,
			Confidence: 0.9,
			AgentID:    "browser",
		})
	}

	return tools.Result{
		Output:   confirm + " Recorded in the ledger — report it and link the finding.",
		Metadata: map[string]any{"xss_confirmed": true},
	}
}

// ledgerForCtx resolves the shared hypothesis ledger for a scan context, or nil
// when the context is not active (mirrors ledger access elsewhere).
func ledgerForCtx(ctxID string) *scanctx.LedgerStore {
	if sc := scanctx.Get(ctxID); sc != nil {
		return sc.Ledger
	}
	return nil
}
