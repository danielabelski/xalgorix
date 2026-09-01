// Package agent — surface_seed.go turns a parsed scan-context artifact
// (OpenAPI/Swagger, HAR, Postman, Burp) into schedulable ledger hypotheses.
//
// internal/attacksurface already parses those artifacts into a normalized,
// deduplicated endpoint surface plus any captured session auth, and
// prepareScanEnvironment already registers that auth and builds a text
// briefing. But a briefing is passive: it does not, on its own, become
// schedulable work in the evidence-driven loop. seedLedgerFromSurface closes
// that gap — every endpoint the operator handed us becomes a role-scoped
// authorization hypothesis (the prime IDOR/BOLA surface) that authz_matrix and
// the specialists can pick up from the ledger, exactly as ingest_har does for a
// HAR supplied mid-scan.
package agent

import (
	"net/url"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/attacksurface"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// maxSurfaceSeed bounds how many endpoints from an uploaded context artifact are
// seeded into the ledger. The parser caps the merged surface at 500 endpoints;
// seeding every one would swamp the scheduler and the LLM context window, so we
// take the first N (the parser returns them sorted and deduplicated) and leave
// the remainder described in the text briefing. The scheduler picks the
// highest-confidence hypotheses first, so a bounded seed still surfaces the most
// promising work.
const maxSurfaceSeed = 40

// seedLedgerFromSurface seeds the shared ledger with role-scoped authorization
// hypotheses for the endpoints in a parsed attack surface. Role is
// "authenticated" when the artifact carried a live session (so these are
// post-auth IDOR/BOLA candidates), otherwise "anonymous". It returns the number
// of NEW hypotheses inserted.
//
// Idempotent: the ledger deduplicates by (vuln_class, endpoint, parameter,
// role), so calling this more than once for the same scan (root coordinator and
// any sub-agents that also parse the context) never creates duplicates — the
// repeat calls simply insert nothing new.
func (a *Agent) seedLedgerFromSurface(res *attacksurface.Result) int {
	if res == nil || a.scanCtx == nil {
		return 0
	}
	l := a.ledger()
	if l == nil {
		return 0
	}

	role := "anonymous"
	if len(res.AuthHeaders) > 0 {
		role = "authenticated"
	}

	seeded := 0
	for _, e := range res.Endpoints {
		if seeded >= maxSurfaceSeed {
			break
		}
		host, path := splitSurfaceEndpoint(e.Path, res.BaseURLs)
		if path == "" {
			continue
		}
		param := ""
		if len(e.Params) > 0 {
			param = e.Params[0]
		}

		title := "Endpoint"
		if role == "authenticated" {
			title = "Authenticated endpoint"
		}
		if m := strings.ToUpper(strings.TrimSpace(e.Method)); m != "" {
			title += " " + m
		}
		title += " " + path

		origin := "context"
		if s := strings.TrimSpace(e.Source); s != "" {
			origin = "context:" + s
		}

		before := l.Len()
		l.Upsert(scanctx.Hypothesis{
			Title:      title,
			VulnClass:  "idor",
			Target:     host,
			Endpoint:   path,
			Parameter:  param,
			Role:       role,
			Confidence: 0.4,
			Status:     scanctx.HypothesisQueued,
			Origin:     origin,
			NextAction: "Probe this endpoint from the uploaded context; if it exposes an object/action by id, test cross-role access with authz_matrix (role A vs role B vs anonymous).",
		})
		if l.Len() > before {
			seeded++
		}
	}
	return seeded
}

// splitSurfaceEndpoint returns (host, path) for an attack-surface endpoint whose
// Path may be a full URL or a bare path. For a bare path the host is taken from
// the first usable base URL so the ledger entry still names a concrete host when
// one is known. An empty path (which cannot be tested) yields ("", "").
func splitSurfaceEndpoint(raw string, baseURLs []string) (host, path string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			p := u.Path
			if p == "" {
				p = "/"
			}
			return u.Host, p
		}
	}
	for _, b := range baseURLs {
		if u, err := url.Parse(strings.TrimSpace(b)); err == nil && u.Host != "" {
			return u.Host, raw
		}
	}
	return "", raw
}
