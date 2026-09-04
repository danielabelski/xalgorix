// Package agent — verify_csrf.go implements verify_csrf: a Cross-Site Request
// Forgery confirmer, rounding out the deterministic verifier family
// (verify_sqli/verify_ssti/verify_xss/verify_xxe/verify_oob).
//
// CSRF is the one common class black-box scanners flag by shape ("this form has
// no anti-CSRF token") but rarely PROVE, because proving it means showing the
// server actually honors a forged cross-site request. verify_csrf does exactly
// that in one call: it replays the state-changing request the way an attacker's
// page would — a forged Origin/Referer and NO anti-CSRF token, reusing the scan
// session's cookies — and reads the outcome:
//
//   - the server ACCEPTS it (2xx/3xx, no token/forbidden rejection) → confirmed
//   - it is rejected (401/403/419, or a csrf/token/forbidden message) → NOT
//
// It deliberately declines when the scan's session auth is an Authorization
// header (Bearer/Basic): a cross-site attacker's browser auto-sends cookies but
// NOT Authorization headers, so a header-authenticated endpoint is not
// CSRF-able and confirming it would be a false positive. This keeps the
// confirmer honest on modern token-auth APIs.
//
// On confirmation it records evidence in the shared ledger (CWE-352); it does
// NOT auto-report. Same safety envelope as the other verifiers: it scope-checks
// the resolved host and refuses the operator's own machine/local network,
// honors the request-rate policy and cancellation, does not follow redirects,
// and is disabled in passive mode.
package agent

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

func (a *Agent) registerVerifyCSRFTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "verify_csrf",
		Description: "CONFIRM Cross-Site Request Forgery on a state-changing endpoint (the CSRF member of the verifier family). Give it a url (or ledger hypothesis_id) and the form body (data) of the state change. It replays the request the way an attacker's page would — a forged Origin/Referer and NO anti-CSRF token, reusing the scan session cookies — and confirms CSRF when the server ACCEPTS it (2xx/3xx, no token/forbidden rejection): the action fires from any origin with no unpredictable token. It declines when the endpoint is protected by an Authorization header (Bearer/Basic), which a cross-site attacker cannot forge — so it will not false-positive on token-auth APIs. On success it records CWE-352 evidence in the ledger; report it with the accepted cross-site request as proof. Uses the scan session auth, does not follow redirects, disabled in passive mode. Reach for it on any password/email change, role or permission update, delete, funds transfer, or settings write.",
		Parameters: []tools.Parameter{
			{Name: "url", Description: "Absolute URL (scheme://host/path) or path of the state-changing endpoint. One of url or hypothesis_id is required.", Required: false},
			{Name: "hypothesis_id", Description: "Optional ledger hypothesis id carrying an HTTP path; used when 'url' is not given.", Required: false},
			{Name: "method", Description: "HTTP method (default POST).", Required: false},
			{Name: "data", Description: "The state-change request body an attacker would forge, e.g. email=attacker@evil.example — WITHOUT any anti-CSRF token. URL-encoded form by default.", Required: false},
			{Name: "content_type", Description: "Content-Type for the body (default application/x-www-form-urlencoded).", Required: false},
		},
		Execute: a.verifyCSRFTool,
	})
}

func (a *Agent) verifyCSRFTool(args map[string]string) (tools.Result, error) {
	l := a.ledger()
	if l == nil {
		return tools.Result{Error: "ledger unavailable in this context"}, nil
	}
	if normalizeActivityMode(a.scanIntensity) == activityModePassive {
		return tools.Result{Error: "verify_csrf issues a live state-changing request and is disabled in passive scan mode."}, nil
	}

	rawEP := strings.TrimSpace(args["url"])
	baseHint := ""
	if rawEP == "" {
		id := strings.TrimSpace(args["hypothesis_id"])
		if id == "" {
			return tools.Result{Error: "one of url or hypothesis_id is required — pass the state-changing endpoint url, or a ledger hypothesis id carrying an HTTP path."}, nil
		}
		h, ok := l.Get(id)
		if !ok {
			return tools.Result{Error: fmt.Sprintf("unknown hypothesis id %q — use read_ledger to list ids", id)}, nil
		}
		rawEP = strings.TrimSpace(h.Endpoint)
		baseHint = strings.TrimSpace(h.Target)
	}

	absURL, err := a.resolveInjectionURL(rawEP, baseHint)
	if err != nil {
		return tools.Result{Error: "verify_csrf: " + err.Error()}, nil
	}
	u, perr := url.Parse(absURL)
	if perr != nil || u.Host == "" {
		return tools.Result{Error: fmt.Sprintf("verify_csrf: could not form a valid URL from %q", absURL)}, nil
	}

	// PRIMARY scope protection: the loop gate can't see this internally-resolved
	// host, so refuse the operator's own machine/listener here.
	if scopeguard.IsLocalOrListener(a.localGuard, u.Host) {
		return tools.Result{Error: fmt.Sprintf("verify_csrf refused: %q resolves to the operator's own machine or local network, not the engagement target.", u.Host)}, nil
	}

	method := strings.ToUpper(strings.TrimSpace(args["method"]))
	if method == "" {
		method = "POST"
	}
	data := args["data"]
	contentType := strings.TrimSpace(args["content_type"])
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
	}

	headers := a.probeAuthHeaders()
	if headers == nil {
		headers = map[string]string{}
	}
	// CSRF rides ambient cookie auth. If the session authenticates with an
	// Authorization header (Bearer/Basic), the endpoint is NOT CSRF-able — a
	// cross-site attacker's browser never attaches that header — so decline
	// rather than emit a false positive on a token-auth API.
	for k := range headers {
		if strings.EqualFold(k, "Authorization") {
			return tools.Result{
				Output:   "CSRF NOT applicable: this scan authenticates with an Authorization header (Bearer/Basic), which a cross-site attacker cannot forge — the endpoint is not CSRF-able. CSRF requires ambient cookie auth.",
				Metadata: map[string]any{"csrf_confirmed": false, "reason": "header-auth"},
			}, nil
		}
	}

	const attackerOrigin = "https://csrf-attacker.example"
	headers["Origin"] = attackerOrigin
	headers["Referer"] = attackerOrigin + "/"
	headers["Content-Type"] = contentType

	status, body, reqLine, sErr := a.sendStateChangeProbe(method, absURL, headers, data)
	if sErr != nil {
		return tools.Result{Error: fmt.Sprintf("verify_csrf: request failed: %v", sErr)}, nil
	}

	confirmed, note := csrfVerdict(status, body)
	endpoint := u.EscapedPath()

	if !confirmed {
		return tools.Result{
			Output:   fmt.Sprintf("CSRF NOT confirmed at %s: %s", endpoint, note),
			Metadata: map[string]any{"csrf_confirmed": false, "endpoint": endpoint, "status": status},
		}, nil
	}

	confirm := fmt.Sprintf("Cross-Site Request Forgery CONFIRMED at %s: the server accepted a state-changing %s with a forged cross-site Origin (%s) and no anti-CSRF token — the action can be triggered from any origin against an authenticated victim (CWE-352).", endpoint, method, attackerOrigin)
	proof := fmt.Sprintf("Forged request (cross-site Origin, no CSRF token):\n%s\nData: %s\n→ HTTP %d (accepted). %s", reqLine, boundedText(data, 200), status, note)

	h := l.Upsert(scanctx.Hypothesis{
		Title:      "Cross-Site Request Forgery at " + endpoint,
		VulnClass:  "csrf",
		Endpoint:   endpoint,
		Target:     baseURLOf(u),
		Confidence: 0.75,
		Status:     scanctx.HypothesisTesting,
		Origin:     "verify_csrf",
		NextAction: "Report as CSRF (CWE-352) using the accepted cross-site request as proof; strengthen impact by chaining the state change (email/password takeover) and link the finding via add_hypothesis_evidence(kind=finding_ref).",
	})
	l.AddEvidence(h.ID, scanctx.Evidence{
		Kind:       "exploit",
		Summary:    confirm,
		Request:    reqLine,
		Response:   boundedText(body, 400),
		Confidence: 0.75,
		AgentID:    a.ledgerOrigin(),
	})

	return tools.Result{
		Output:   confirm + fmt.Sprintf(" Recorded in the ledger (%s) — report it as CWE-352 and link the finding.\n\n%s", h.ID, proof),
		Metadata: map[string]any{"csrf_confirmed": true, "endpoint": endpoint, "hypothesis_id": h.ID, "status": status},
	}, nil
}

// sendStateChangeProbe issues one state-changing request (the host was
// scope-checked by the caller) and returns the status code, response body, and a
// compact request line.
func (a *Agent) sendStateChangeProbe(method, rawURL string, headers map[string]string, body string) (status int, respBody, reqLine string, err error) {
	reqLine = fmt.Sprintf("%s %s (forged cross-site Origin, no CSRF token)", method, rawURL)
	resp, e := httpclient.SendRaw(httpclient.RawRequest{
		Method:          method,
		URL:             rawURL,
		Headers:         headers,
		Body:            body,
		FollowRedirects: false,
		TimeoutSec:      30,
	})
	if e != nil {
		return 0, "", reqLine, e
	}
	return resp.StatusCode, string(resp.Body), reqLine, nil
}

// csrfVerdict decides CSRF from the forged request's status and body. A success
// with no anti-CSRF rejection means the state change fired from a foreign
// origin with no token; a 401/403/419 or a token/forbidden message means a
// defense (token or Origin/Referer check) blocked it.
func csrfVerdict(status int, body string) (confirmed bool, note string) {
	lb := strings.ToLower(body)
	if status == 401 || status == 403 || status == 419 || csrfRejectionMarker(lb) {
		return false, fmt.Sprintf("the forged cross-site request was rejected (HTTP %d / anti-CSRF or authorization check) — the endpoint validates a token or the request origin, so it is NOT CSRF-able.", status)
	}
	if status >= 200 && status < 400 {
		return true, "the forged cross-site request was accepted with no anti-CSRF token."
	}
	return false, fmt.Sprintf("the request returned HTTP %d (not a success) — could not confirm the state change was accepted; retry with a valid body and method.", status)
}

// csrfRejectionMarker reports whether a response body signals an anti-CSRF /
// authorization rejection.
func csrfRejectionMarker(lb string) bool {
	for _, m := range []string{
		"csrf", "xsrf", "invalid token", "missing token", "token mismatch",
		"token required", "invalid csrf", "forbidden", "not allowed",
		"access denied", "unauthorized", "authentication required",
	} {
		if strings.Contains(lb, m) {
			return true
		}
	}
	return false
}
