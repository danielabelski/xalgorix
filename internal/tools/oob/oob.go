// Package oob registers the out-of-band (OAST) callback tool. It lets the
// agent mint a unique callback URL, plant it in payloads, and poll for
// interactions. A callback proves that some system reached the URL; protocol
// and assessed origin must be considered before attributing it to a target.
package oob

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	oobsrv "github.com/xalgord/xalgorix/v4/internal/oob"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// Consecutive empty polls per callback token are tracked so the tool can tell
// the agent to STOP polling a dead callback and pivot to in-band confirmation.
// Filtered egress is common on real targets, and unbounded OOB polling is a
// recurring black-box budget sink (a real scan burned ~18 probes for zero
// callbacks; a benchmark run polled a dead token repeatedly instead of
// reporting). Keyed by token (unique per callback), reset when a hit finally
// arrives, and bounded so a long-lived server process cannot grow it without
// limit.
var (
	pollMu         sync.Mutex
	emptyPollCount = map[string]int{}
)

const (
	// First gentle "egress may be filtered, consider pivoting" hint.
	emptyPollNudgeAt = 3
	// Hard "stop polling, pivot now" directive.
	emptyPollStopAt = 5
	// Cap on distinct tracked tokens; cleared wholesale when exceeded (the
	// counts are advisory, so dropping them is harmless).
	emptyPollTokenCap = 512
)

// recordEmptyPoll increments and returns the consecutive-empty-poll count for a
// token.
func recordEmptyPoll(token string) int {
	pollMu.Lock()
	defer pollMu.Unlock()
	if len(emptyPollCount) > emptyPollTokenCap {
		emptyPollCount = map[string]int{}
	}
	emptyPollCount[token]++
	return emptyPollCount[token]
}

// resetEmptyPoll clears the counter once a callback finally lands, so a later
// dry spell on the same token is judged fresh.
func resetEmptyPoll(token string) {
	pollMu.Lock()
	defer pollMu.Unlock()
	delete(emptyPollCount, token)
}

// emptyPollGuidance returns escalating guidance appended to a no-interaction
// poll result. It steers the agent off a dead callback and toward in-band
// confirmation once polling has clearly stopped paying off.
func emptyPollGuidance(consecutiveEmpty int) string {
	switch {
	case consecutiveEmpty >= emptyPollStopAt:
		return fmt.Sprintf("\n\n🛑 STOP polling this callback — %d empty polls means the target almost certainly cannot reach the OAST oracle (filtered egress is common on real targets). Do NOT poll it again. Pivot now to IN-BAND confirmation: differential timing or error-based injection (verify_sqli), a reflected internal resource returned BY THE TARGET (e.g. 169.254.169.254 in the response body), or drop this blind lead and move to the next-ranked attack surface.", consecutiveEmpty)
	case consecutiveEmpty >= emptyPollNudgeAt:
		return fmt.Sprintf("\n\n⚠️ %d empty polls on this callback. Egress may be filtered. If you JUST planted the payload, wait briefly and poll once more; otherwise stop polling and pivot to in-band confirmation instead of waiting on a callback you may never get.", consecutiveEmpty)
	default:
		return ""
	}
}

// Register adds the oob_callback tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "oob_callback",
		Description: "Out-of-band (OAST) callback oracle for investigating blind vulnerabilities (blind SSRF, blind RCE, blind XSS, XXE, blind SQLi, blind CMDi). Workflow: (1) action=generate to mint a callback; (2) plant it in the target-side payload; (3) action=poll with the token. IMPORTANT: an interaction proves only that some system contacted the callback. For SSRF, send the injection request with redirects disabled and require an origin-assessed, non-scanner HTTP interaction. DNS-only, scanner-origin, or origin-unassessed hits are leads, not SSRF proof.",
		Parameters: []tools.Parameter{
			{Name: "action", Description: "'generate' to mint a new callback URL (default if omitted), or 'poll' to check for interactions on a token.", Required: false},
			{Name: "token", Description: "For action=poll: the token returned by generate.", Required: false},
		},
		Execute: execute,
	})
}

func execute(args map[string]string) (tools.Result, error) {
	action := strings.ToLower(strings.TrimSpace(args["action"]))
	switch action {
	case "generate", "gen", "new", "":
		url, token, err := oobsrv.Generate()
		host := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
		if err != nil {
			return tools.Result{Output: "❌ OOB unavailable: " + err.Error() +
				"\nOOB is not configured on this server. Fall back to in-band verification (differential timing, error-based, or a reflected internal resource like 169.254.169.254 returned BY THE TARGET)."}, nil
		}
		return tools.Result{
			Output: fmt.Sprintf(`✅ OOB callback ready.
Callback URL: %s
Token: %s

Plant the URL in your payload, then poll with this token. Examples:
- SSRF:      set a url/webhook param to %s and send the INJECTION request with redirects disabled (`+"`curl -sk --max-redirs 0 ...`"+`). A 30x Location pointing here is redirect behavior, NOT SSRF.
- Blind RCE: inject `+"`curl %s`"+` or `+"`wget %s`"+`
- XXE:       <!ENTITY x SYSTEM "%s">
- Blind XSS: <script src=%s></script>
- DNS-only:  a bare lookup such as `+"`nslookup %s`"+` is captured, but DNS alone is ambiguous and does NOT prove SSRF.

When polling, HTTP interactions are labeled as scanner-origin, origin-unassessed, or assessed non-scanner. Only the last category can support callback-based SSRF verification.`,
				url, token, url, url, url, url, url, host),
			Metadata: map[string]any{"oob_url": url, "oob_token": token},
		}, nil

	case "poll", "check", "read":
		token := strings.TrimSpace(args["token"])
		if token == "" {
			return tools.Result{Output: "❌ poll requires 'token' (from a previous generate call)."}, nil
		}
		hits := oobsrv.Poll(token)
		if len(hits) == 0 {
			consecutiveEmpty := recordEmptyPoll(token)
			base := fmt.Sprintf("No OOB interactions for token %s yet. If you just sent the payload, wait a few seconds and poll again. No callback after several tries = the sink is not reaching us (not blind-exploitable via HTTP egress, or egress is filtered).", token)
			return tools.Result{
				Output:   base + emptyPollGuidance(consecutiveEmpty),
				Metadata: map[string]any{"oob_hits": 0, "oob_token": token, "consecutive_empty_polls": consecutiveEmpty},
			}, nil
		}
		// A callback finally arrived — clear the dry-spell counter for this token.
		resetEmptyPoll(token)
		var sb strings.Builder
		scannerOriginHTTPCount := 0
		dnsOnlyCount := 0
		originUnassessedHTTPCount := 0
		nonScannerHTTPCount := 0
		calibrated := oobsrv.ScannerOriginCalibrated()
		sb.WriteString(fmt.Sprintf("⚠️ %d OOB interaction(s) observed for token %s. An interaction alone does NOT identify which system initiated it:\n", len(hits), token))
		for i, h := range hits {
			protocol := strings.ToLower(strings.TrimSpace(h.Protocol))
			originLabel := "provenance not applicable to this protocol"
			switch protocol {
			case "dns":
				originLabel = "DNS-ONLY — AMBIGUOUS"
				dnsOnlyCount++
			case "http", "https":
				switch {
				case !h.OriginAssessed:
					originLabel = "ORIGIN UNASSESSED — CALIBRATION PENDING/UNAVAILABLE"
					originUnassessedHTTPCount++
				case h.ScannerOrigin:
					originLabel = "SCANNER ORIGIN — NOT TARGET PROOF"
					scannerOriginHTTPCount++
				default:
					originLabel = "ASSESSED NON-SCANNER HTTP"
					nonScannerHTTPCount++
				}
			}
			sb.WriteString(fmt.Sprintf("\n[%d] %s %s%s\n    from %s at %s\n    provenance: %s\n    User-Agent: %s\n",
				i+1, h.Method, h.Path, queryStr(h.Query), h.RemoteAddr, h.Time.Format("2006-01-02T15:04:05Z07:00"), originLabel, h.UserAgent))
			if len(h.Headers) > 0 {
				keys := make([]string, 0, len(h.Headers))
				for k := range h.Headers {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					sb.WriteString(fmt.Sprintf("    %s: %s\n", k, h.Headers[k]))
				}
			}
			if strings.TrimSpace(h.Body) != "" {
				sb.WriteString(fmt.Sprintf("    body: %s\n", truncate(h.Body, 500)))
			}
		}
		if nonScannerHTTPCount > 0 {
			sb.WriteString("\nFor SSRF, the assessed non-scanner HTTP interaction can support verification only if the injection request used redirects disabled and a baseline did not produce it. Pass this exact token as oob_token to report_vulnerability.")
		} else {
			sb.WriteString("\n❌ No assessed non-scanner HTTP interaction is available; do not report callback-confirmed SSRF.")
		}
		if originUnassessedHTTPCount > 0 {
			sb.WriteString(" Origin calibration is pending or unavailable, so remote HTTP interactions are not attributable and must fail closed.")
		}
		if scannerOriginHTTPCount > 0 {
			sb.WriteString(" Scanner-origin HTTP interactions indicate the scanner followed or directly requested its callback and are not SSRF proof.")
		}
		if dnsOnlyCount > 0 {
			sb.WriteString(" DNS-only interactions may come from the scanner or a recursive resolver and are only leads.")
		}
		return tools.Result{Output: sb.String(), Metadata: map[string]any{
			"oob_hits":                         len(hits),
			"oob_token":                        token,
			"scanner_origin_http_hits":         scannerOriginHTTPCount,
			"dns_only_hits":                    dnsOnlyCount,
			"origin_unassessed_http_hits":      originUnassessedHTTPCount,
			"non_scanner_http_hits":            nonScannerHTTPCount,
			"scanner_origin_calibrated":        calibrated,
			"scanner_origin_calibration_state": oobsrv.ScannerOriginCalibrationState(),
		}}, nil

	default:
		return tools.Result{Output: "❌ Unknown action '" + action + "'. Use 'generate' or 'poll'."}, nil
	}
}

func queryStr(q string) string {
	if q == "" {
		return ""
	}
	return "?" + q
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
