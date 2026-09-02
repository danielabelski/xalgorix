package agent

import (
	"strconv"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/codesearch"
)

// TestSeedRoutesCorrelatedAndUncorrelated verifies a route whose file has a
// dangerous sink is typed by that vuln class at confidence 0.45, while a route
// with no co-located sink seeds as an idor/attack-surface lead at 0.3 — both
// carrying a real HTTP path Endpoint, source-route Origin, and queued status.
func TestSeedRoutesCorrelatedAndUncorrelated(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("routes-corr-"+t.Name(), "")}
	routes := []codesearch.RouteMatch{
		{Method: "POST", Path: "/admin/exec", File: "handlers.py", Line: 12, Framework: "flask"},
		{Method: "GET", Path: "/profile", File: "views.py", Line: 3, Framework: "flask/fastapi"},
	}
	byFile := map[string][]string{
		"handlers.py": {"rce"}, // correlated
		// views.py has no sink -> uncorrelated
	}

	seeded, correlated := ag.seedRoutes(routes, byFile)
	if seeded != 2 || correlated != 1 {
		t.Fatalf("expected seeded=2 correlated=1, got seeded=%d correlated=%d", seeded, correlated)
	}

	byEndpoint := map[string]scanctx.Hypothesis{}
	for _, h := range ag.scanCtx.Ledger.All() {
		byEndpoint[h.Endpoint] = h
		if h.Origin != "source-route" {
			t.Fatalf("endpoint %s: origin=%q want source-route", h.Endpoint, h.Origin)
		}
		if h.Status != scanctx.HypothesisQueued {
			t.Fatalf("endpoint %s: status=%q want queued", h.Endpoint, h.Status)
		}
		if !strings.HasPrefix(h.DataFlow, "source-route:") {
			t.Fatalf("endpoint %s: DataFlow=%q want source-route: prefix", h.Endpoint, h.DataFlow)
		}
	}

	exec, ok := byEndpoint["/admin/exec"]
	if !ok {
		t.Fatal("missing /admin/exec hypothesis")
	}
	if exec.VulnClass != "rce" {
		t.Fatalf("/admin/exec vuln=%q want rce", exec.VulnClass)
	}
	if exec.Confidence != 0.45 {
		t.Fatalf("/admin/exec confidence=%v want 0.45", exec.Confidence)
	}
	prof, ok := byEndpoint["/profile"]
	if !ok {
		t.Fatal("missing /profile hypothesis")
	}
	if prof.VulnClass != "idor" {
		t.Fatalf("/profile vuln=%q want idor", prof.VulnClass)
	}
	if prof.Confidence != 0.3 {
		t.Fatalf("/profile confidence=%v want 0.3", prof.Confidence)
	}
}

// TestSeedRoutesHighestSeverity verifies a route whose file has several sink
// classes is typed by the most-dangerous one.
func TestSeedRoutesHighestSeverity(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("routes-sev-"+t.Name(), "")}
	routes := []codesearch.RouteMatch{{Method: "GET", Path: "/x", File: "app.py", Line: 1, Framework: "flask"}}
	byFile := map[string][]string{"app.py": {"sqli", "rce", "lfi"}}

	if seeded, correlated := ag.seedRoutes(routes, byFile); seeded != 1 || correlated != 1 {
		t.Fatalf("seeded=%d correlated=%d want 1,1", seeded, correlated)
	}
	all := ag.scanCtx.Ledger.All()
	if len(all) != 1 || all[0].VulnClass != "rce" {
		t.Fatalf("expected 1 hypothesis typed rce (highest severity), got %+v", all)
	}
}

// TestSeedRoutesIdempotent verifies re-seeding the same routes adds nothing.
func TestSeedRoutesIdempotent(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("routes-idem-"+t.Name(), "")}
	routes := []codesearch.RouteMatch{
		{Method: "POST", Path: "/a", File: "a.py", Line: 1, Framework: "flask"},
		{Method: "GET", Path: "/b", File: "b.py", Line: 2, Framework: "flask"},
	}
	if s, _ := ag.seedRoutes(routes, nil); s != 2 {
		t.Fatalf("first seed=%d want 2", s)
	}
	if s, _ := ag.seedRoutes(routes, nil); s != 0 {
		t.Fatalf("second seed=%d want 0 (idempotent)", s)
	}
	if n := ag.scanCtx.Ledger.Len(); n != 2 {
		t.Fatalf("ledger len=%d want 2", n)
	}
}

// TestSeedRoutesBounded verifies a large sweep cannot flood the ledger past
// maxRouteSeed.
func TestSeedRoutesBounded(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("routes-bound-"+t.Name(), "")}
	routes := make([]codesearch.RouteMatch, 0, maxRouteSeed*2)
	for i := 0; i < maxRouteSeed*2; i++ {
		routes = append(routes, codesearch.RouteMatch{Method: "GET", Path: "/r" + strconv.Itoa(i), File: "big.py", Line: i + 1, Framework: "flask"})
	}
	seeded, _ := ag.seedRoutes(routes, nil)
	if seeded > maxRouteSeed {
		t.Fatalf("seedRoutes must cap at maxRouteSeed=%d, seeded %d", maxRouteSeed, seeded)
	}
	if n := ag.scanCtx.Ledger.Len(); n > maxRouteSeed {
		t.Fatalf("ledger must not exceed %d, got %d", maxRouteSeed, n)
	}
}

// TestSeedRoutesNilLedger verifies the helper is safe with no scan context.
func TestSeedRoutesNilLedger(t *testing.T) {
	ag := &Agent{}
	if s, c := ag.seedRoutes([]codesearch.RouteMatch{{Path: "/x", File: "a", Line: 1}}, nil); s != 0 || c != 0 {
		t.Fatalf("nil ledger must seed 0,0; got %d,%d", s, c)
	}
}

// TestSinkVulnsByFileSkipsDiscoveryOnly verifies the file->vuln inversion maps
// via the sinkClassToVuln allowlist and skips discovery-only classes.
func TestSinkVulnsByFileSkipsDiscoveryOnly(t *testing.T) {
	found := map[string][]codesearch.SinkMatch{
		"rce":    {{File: "a.py", Line: 1, Text: "os.system(x)"}},
		"crypto": {{File: "a.py", Line: 2, Text: "MD5(x)"}}, // discovery-only, skipped
		"sqli":   {{File: "b.py", Line: 3, Text: "cursor.execute(q)"}},
	}
	byFile := sinkVulnsByFile(found)
	if got := byFile["a.py"]; len(got) != 1 || got[0] != "rce" {
		t.Fatalf("a.py vulns=%v want [rce] (crypto skipped)", got)
	}
	if got := byFile["b.py"]; len(got) != 1 || got[0] != "sqli" {
		t.Fatalf("b.py vulns=%v want [sqli]", got)
	}
}

// TestScanSourceRoutesToolNoSource verifies the tool degrades to a black-box
// fallback message (no error, no seeds) when whitebox source is not configured.
func TestScanSourceRoutesToolNoSource(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("routes-tool-nosrc-"+t.Name(), "")}
	res, err := ag.scanSourceRoutesTool(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Output, "Whitebox source not configured") {
		t.Fatalf("expected black-box fallback message, got: %s", res.Output)
	}
	if ag.scanCtx.Ledger.Len() != 0 {
		t.Fatal("no source configured -> nothing should be seeded")
	}
}
