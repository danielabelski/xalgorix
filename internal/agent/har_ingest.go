// Package agent — har_ingest.go implements ingest_har: it turns a recorded,
// logged-in HAR into live authenticated scan context.
//
// Starting from a real session is the single biggest practical advantage an
// autonomous web scanner can have: the HAR hands over the exact endpoints,
// parameters, and session credentials a real user exercised, so the agent tests
// authenticated, business-logic surface instead of rediscovering everything
// from an unauthenticated URL. ingest_har (1) registers the HAR's session auth
// so subsequent http_request / authz_matrix calls are authenticated, and
// (2) seeds the ledger with authorization hypotheses for the authenticated
// endpoints — the prime IDOR/BOLA surface — so the authz specialist has
// concrete, role-scoped targets to work.
package agent

import (
	"fmt"
	"os"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/har"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

const (
	maxHARBytes    = 64 << 20 // 64 MB cap on the HAR file
	maxHARSeed     = 25       // cap on ledger hypotheses seeded from a HAR
	authRole       = "authenticated"
	harHypEndpoint = "idor" // authenticated endpoints are the IDOR/BOLA surface
)

// harIngestSummary is the structured outcome of an ingest.
type harIngestSummary struct {
	Endpoints       int
	AuthHeaderNames []string
	Seeded          int
}

func (a *Agent) registerHARIngestTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "ingest_har",
		Description: "Ingest a recorded, logged-in HAR file to test from a real authenticated session. Give it the path to a HAR captured while logged in and exercising the app. For the PRIMARY session (default, role=a) it (1) registers the session credentials (Authorization/Cookie/API-key headers) so your subsequent http_request and authz_matrix calls are authenticated, and (2) seeds the ledger with authenticated endpoints (the prime IDOR/BOLA surface) as role-scoped hypotheses. To prove IDOR/BOLA you also want a SECOND account: capture a HAR while logged in as a different user and ingest it with role=b — authz_matrix will then replay each request as BOTH accounts and flag any resource role B can reach that belongs to role A. Use at the start of an authenticated assessment.",
		Parameters: []tools.Parameter{
			{Name: "path", Description: "Filesystem path to the HAR file captured from the authenticated session.", Required: true},
			{Name: "target", Description: "Optional target host to scope endpoints to (e.g. app.example.com). Endpoints on other hosts in the HAR are ignored. Omit to ingest all.", Required: false},
			{Name: "role", Description: "Which identity this HAR is for: 'a' (default) = your primary session (registered + seeds the ledger); 'b' = a SECOND account used only as the cross-account identity for authz_matrix IDOR/BOLA testing (credentials registered, not auto-applied, no ledger seeding).", Required: false},
		},
		Execute: a.harIngestTool,
	})
}

func (a *Agent) harIngestTool(args map[string]string) (tools.Result, error) {
	path := strings.TrimSpace(args["path"])
	if path == "" {
		return tools.Result{Error: "path is required (the HAR file captured from the authenticated session)"}, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("cannot read HAR %q: %v", path, err)}, nil
	}
	if info.Size() > maxHARBytes {
		return tools.Result{Error: fmt.Sprintf("HAR is too large (%d bytes, max %d)", info.Size(), maxHARBytes)}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return tools.Result{Error: fmt.Sprintf("cannot read HAR %q: %v", path, err)}, nil
	}
	h, err := har.Parse(data)
	if err != nil {
		return tools.Result{Error: err.Error()}, nil
	}

	if normalizeIngestRole(args["role"]) == "b" {
		return a.ingestHARRoleB(h, strings.TrimSpace(args["target"])), nil
	}

	sum := a.seedFromHAR(h, strings.TrimSpace(args["target"]))

	var b strings.Builder
	fmt.Fprintf(&b, "Ingested HAR: %d authenticated endpoint(s).\n", sum.Endpoints)
	if len(sum.AuthHeaderNames) > 0 {
		fmt.Fprintf(&b, "Session auth registered (%s) — your http_request and authz_matrix calls are now authenticated for this scan.\n", strings.Join(sum.AuthHeaderNames, ", "))
	} else {
		b.WriteString("No session credentials found in the HAR — testing continues unauthenticated. Re-capture the HAR while logged in if authenticated coverage is needed.\n")
	}
	if sum.Seeded > 0 {
		fmt.Fprintf(&b, "Seeded %d authorization hypotheses (role=%s) into the ledger. Use read_ledger(filter=schedulable) and authz_matrix to test cross-role access on these endpoints.", sum.Seeded, authRole)
	}
	return tools.Result{Output: b.String(), Metadata: map[string]any{"endpoints": sum.Endpoints, "seeded": sum.Seeded}}, nil
}

// normalizeIngestRole maps a free-form role argument to "a" (primary session)
// or "b" (second account). Anything role-B-shaped selects B; everything else,
// including an empty value, defaults to the primary session.
func normalizeIngestRole(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "b", "role-b", "role_b", "roleb", "account-b", "second", "2":
		return "b"
	default:
		return "a"
	}
}

// ingestHARRoleB registers the HAR's session as the SECOND account (role B) for
// cross-account authorization testing. It does NOT seed the ledger — role B is
// a comparison identity, not new attack surface — and its credentials are not
// auto-applied to http_request (only authz_matrix uses them, deliberately, as
// the "other user").
func (a *Agent) ingestHARRoleB(h *har.HAR, targetHost string) tools.Result {
	endpoints := h.InScopeEndpoints(targetHost)
	auth := h.AuthHeaders()
	var names []string
	if a.scanCtx != nil && len(auth) > 0 {
		httpclient.SetSessionAuthB(a.scanCtx.ID, auth)
		for name := range auth {
			names = append(names, name)
		}
		sortStrings(names)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Ingested HAR as the SECOND account (role B): %d endpoint(s) seen.\n", len(endpoints))
	if len(names) > 0 {
		fmt.Fprintf(&b, "Role-B session registered (%s). Now run authz_matrix on role A's objects — it will replay each request as role B (this account) and flag any of role A's resources that role B can reach (IDOR/BOLA).\n", strings.Join(names, ", "))
	} else {
		b.WriteString("No session credentials found in this HAR — nothing was registered for role B. Re-capture it while logged in as the second account.\n")
	}
	return tools.Result{Output: b.String(), Metadata: map[string]any{"role": "b", "endpoints": len(endpoints), "auth_registered": len(names) > 0}}
}

// seedFromHAR registers the HAR's session auth and seeds the ledger with
// bounded, role-scoped authorization hypotheses. Split from harIngestTool so it
// is unit-testable with a parsed HAR and no filesystem.
func (a *Agent) seedFromHAR(h *har.HAR, targetHost string) harIngestSummary {
	var sum harIngestSummary

	// (1) Register session auth for this scan context.
	if a.scanCtx != nil {
		if auth := h.AuthHeaders(); len(auth) > 0 {
			httpclient.SetSessionAuth(a.scanCtx.ID, auth)
			for name := range auth {
				sum.AuthHeaderNames = append(sum.AuthHeaderNames, name)
			}
			sortStrings(sum.AuthHeaderNames)
		}
	}

	// (2) Seed authorization hypotheses for the authenticated endpoints.
	endpoints := h.InScopeEndpoints(targetHost)
	sum.Endpoints = len(endpoints)
	l := a.ledger()
	if l == nil {
		return sum
	}
	for _, e := range endpoints {
		if sum.Seeded >= maxHARSeed {
			break
		}
		param := ""
		if len(e.Params) > 0 {
			param = e.Params[0]
		}
		before := l.Len()
		l.Upsert(scanctx.Hypothesis{
			Title:      "Authenticated endpoint " + e.Method + " " + e.Path,
			VulnClass:  harHypEndpoint,
			Target:     e.Host,
			Endpoint:   e.Path,
			Parameter:  param,
			Role:       authRole,
			Confidence: 0.4,
			Status:     scanctx.HypothesisQueued,
			Origin:     "har",
			NextAction: "Test cross-role/object access with authz_matrix (role A vs role B vs anonymous) on this authenticated endpoint.",
		})
		if l.Len() > before {
			sum.Seeded++
		}
	}
	return sum
}

// sortStrings is a tiny helper to keep summaries deterministic without pulling
// sort into this file's import set for a single call site.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
