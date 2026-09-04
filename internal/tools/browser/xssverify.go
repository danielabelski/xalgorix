package browser

import (
	"fmt"
	"html"
	"net/url"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// verifyXSS confirms that an XSS payload actually EXECUTES in the browser
// (rather than merely being reflected). The caller injects a payload that
// raises a JavaScript dialog carrying a unique nonce — e.g. alert('XV-8f3a') —
// and passes that nonce here. We clear prior signals, drive the browser to the
// payload (dialogs are captured + auto-dismissed by setupDialogHandler), then
// poll briefly for a dialog whose message carries the nonce. A match is
// concrete proof of execution and is recorded as browser-confirmed XSS evidence
// in the shared ledger. This directly addresses the low XSS precision of
// reflection-only scanners.
//
// Both request methods are supported. For GET (the default when no body is
// given) we navigate to rawURL. For POST — set method=POST or just pass a body
// via data — we stage a self-submitting cross-origin form and let the browser
// perform a real top-level POST, rendering the response as a document so a
// POST-reflected payload runs. Without this, POST-based reflected XSS could not
// be confirmed and the agent burned large budgets hand-building form
// submissions with dozens of browser_action calls.
func verifyXSS(ctxID, rawURL, nonce, parameter, data, method string) (tools.Result, error) {
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

	// Decide GET vs POST. A request body (data) implies POST unless method says
	// otherwise. The POST path is what lets verify_xss confirm POST-reflected XSS
	// in a single call instead of the agent hand-driving dozens of browser_action
	// steps to build and submit a form.
	method = strings.ToUpper(strings.TrimSpace(method))
	data = strings.TrimSpace(data)
	if method == "" {
		if data != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	if method == "GET" {
		// Navigate directly to the payload URL (original behavior).
		if strings.TrimSpace(rawURL) != "" {
			if err := s.page.Timeout(20 * time.Second).Navigate(rawURL); err != nil {
				return tools.Result{Error: fmt.Sprintf("navigation to %q failed: %v", rawURL, err)}, nil
			}
			_ = s.page.Timeout(10 * time.Second).WaitStable(time.Second)
		}
	} else {
		// Perform a real top-level POST navigation via a self-submitting,
		// cross-origin form. The browser renders the response as a document, so a
		// POST-reflected payload executes exactly as it would for a victim — which
		// a fetch()/XHR cannot reproduce (those never render or run the response).
		if strings.TrimSpace(rawURL) == "" {
			return tools.Result{Error: "url is required for a POST verify_xss — pass the form's action URL and the body via data (e.g. data=\"search=<payload>\")."}, nil
		}
		if err := s.page.Timeout(20 * time.Second).SetDocumentContent(buildXSSFormHTML(rawURL, data)); err != nil {
			return tools.Result{Error: fmt.Sprintf("could not stage the POST form for %q: %v", rawURL, err)}, nil
		}
		// Submit on a 0ms timer so this Eval returns before navigation tears down
		// the JS context (avoids a spurious "context destroyed" error).
		if _, err := s.page.Timeout(10 * time.Second).Eval(`() => { const f = document.forms['xssverify']; if (!f) { return false; } setTimeout(() => f.submit(), 0); return true; }`); err != nil {
			return tools.Result{Error: fmt.Sprintf("could not submit the POST form to %q: %v", rawURL, err)}, nil
		}
		_ = s.page.Timeout(15 * time.Second).WaitStable(time.Second)
	}

	// Dialogs and console messages fire asynchronously during/after load; poll a
	// short window until the nonce matches (a dialog or console signal) or the
	// deadline elapses.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := matchExecNonce(execSignalsFor(ctxID), nonce); ok {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}

	// DOM-marker fallback: some payloads prove execution by mutating the DOM
	// (e.g. document.title=nonce or window.name=nonce) rather than firing a
	// dialog or logging to the console. If nothing matched yet, read those
	// markers once and record a signal when the nonce is present.
	if _, ok := matchExecNonce(execSignalsFor(ctxID), nonce); !ok && s.page != nil {
		if res, err := s.page.Timeout(5 * time.Second).Eval(`() => [document.title, window.name, (window.__xss || "")].join("\u0001")`); err == nil {
			if v := res.Value.String(); strings.Contains(strings.ToLower(v), strings.ToLower(nonce)) {
				recordExecSignal(ctxID, ExecSignal{Kind: "dom:marker", Message: v, At: time.Now()})
			}
		}
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
			msg += " The payload may be reflected but not executing (encoded/sanitized/CSP-blocked). Try an execution oracle carrying the nonce: a dialog (\"'><script>alert('" + nonce + "')</script>\"), a console call (console.log('" + nonce + "')), or a DOM marker (document.title='" + nonce + "')."
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

// buildXSSFormHTML builds a self-submitting HTML form that POSTs `data` (a
// urlencoded request body, exactly what an application/x-www-form-urlencoded
// POST carries) to `action`. Loaded via SetDocumentContent and submitted from
// verifyXSS, the browser performs a real top-level POST navigation and renders
// the response as a document — the only context in which a POST-reflected
// payload executes. Field names/values are HTML-escaped for the attribute
// context; the browser URL-encodes them again at submit time, so the server
// receives the intended body (single-encoded).
func buildXSSFormHTML(action, data string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"></head><body>`)
	b.WriteString(`<form id="xssverify" method="POST" action="`)
	b.WriteString(html.EscapeString(action))
	b.WriteString(`">`)
	for _, kv := range parseFormBody(data) {
		b.WriteString(`<input type="hidden" name="`)
		b.WriteString(html.EscapeString(kv[0]))
		b.WriteString(`" value="`)
		b.WriteString(html.EscapeString(kv[1]))
		b.WriteString(`">`)
	}
	b.WriteString(`</form></body></html>`)
	return b.String()
}

// parseFormBody splits a urlencoded form body ("a=1&b=2") into ordered
// key/value pairs, URL-decoding each side once (so a payload the agent already
// percent-encoded is decoded now and re-encoded by the browser at submit,
// avoiding double-encoding). Order and duplicates are preserved so the request
// matches what the agent specified. Typical XSS payloads contain no '%' or '+'
// and pass through verbatim.
func parseFormBody(data string) [][2]string {
	data = strings.TrimSpace(data)
	data = strings.TrimPrefix(data, "?")
	if data == "" {
		return nil
	}
	var out [][2]string
	for _, pair := range strings.Split(data, "&") {
		if pair == "" {
			continue
		}
		key, val := pair, ""
		if i := strings.IndexByte(pair, '='); i >= 0 {
			key, val = pair[:i], pair[i+1:]
		}
		if dk, err := url.QueryUnescape(key); err == nil {
			key = dk
		}
		if dv, err := url.QueryUnescape(val); err == nil {
			val = dv
		}
		out = append(out, [2]string{key, val})
	}
	return out
}
