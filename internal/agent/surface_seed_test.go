package agent

import (
	"fmt"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/attacksurface"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func newSurfaceAgent(t *testing.T) *Agent {
	t.Helper()
	return &Agent{scanCtx: scanctx.New("surface-"+t.Name(), "")}
}

// findHyp returns the first hypothesis with the given endpoint path.
func findHyp(hyps []scanctx.Hypothesis, endpoint string) (scanctx.Hypothesis, bool) {
	for _, h := range hyps {
		if h.Endpoint == endpoint {
			return h, true
		}
	}
	return scanctx.Hypothesis{}, false
}

func TestSeedLedgerFromSurfaceAuthenticated(t *testing.T) {
	res := &attacksurface.Result{
		AuthHeaders: map[string]string{"Authorization": "Bearer X"},
		BaseURLs:    []string{"https://app.example.com"},
		Endpoints: []attacksurface.Endpoint{
			{Method: "GET", Path: "https://app.example.com/api/orders", Params: []string{"id"}, Source: "openapi"},
			{Method: "POST", Path: "/api/users", Params: []string{"role", "name"}, Source: "har"},
		},
	}
	ag := newSurfaceAgent(t)

	n := ag.seedLedgerFromSurface(res)
	if n != 2 {
		t.Fatalf("expected 2 hypotheses seeded, got %d", n)
	}
	l := ag.scanCtx.Ledger
	if l.Len() != 2 {
		t.Fatalf("expected ledger len 2, got %d", l.Len())
	}
	all := l.All()

	h1, ok := findHyp(all, "/api/orders")
	if !ok {
		t.Fatalf("missing /api/orders hypothesis; got %+v", all)
	}
	if h1.Role != "authenticated" || h1.VulnClass != "idor" {
		t.Fatalf("expected authenticated idor, got role=%q class=%q", h1.Role, h1.VulnClass)
	}
	if h1.Target != "app.example.com" {
		t.Fatalf("expected host from full URL, got %q", h1.Target)
	}
	if h1.Parameter != "id" {
		t.Fatalf("expected first param 'id', got %q", h1.Parameter)
	}
	if h1.Origin != "context:openapi" {
		t.Fatalf("expected origin context:openapi, got %q", h1.Origin)
	}
	if h1.Status != scanctx.HypothesisQueued {
		t.Fatalf("expected queued status, got %q", h1.Status)
	}

	h2, ok := findHyp(all, "/api/users")
	if !ok {
		t.Fatalf("missing /api/users hypothesis; got %+v", all)
	}
	if h2.Target != "app.example.com" {
		t.Fatalf("expected host derived from base URL, got %q", h2.Target)
	}
	if h2.Parameter != "role" {
		t.Fatalf("expected first param 'role', got %q", h2.Parameter)
	}
	if h2.Origin != "context:har" {
		t.Fatalf("expected origin context:har, got %q", h2.Origin)
	}
}

func TestSeedLedgerFromSurfaceAnonymous(t *testing.T) {
	res := &attacksurface.Result{
		Endpoints: []attacksurface.Endpoint{
			{Method: "GET", Path: "https://api.example.com/status", Source: "openapi"},
		},
	}
	ag := newSurfaceAgent(t)

	if n := ag.seedLedgerFromSurface(res); n != 1 {
		t.Fatalf("expected 1 seeded, got %d", n)
	}
	all := ag.scanCtx.Ledger.All()
	if len(all) != 1 || all[0].Role != "anonymous" {
		t.Fatalf("expected a single anonymous hypothesis, got %+v", all)
	}
}

func TestSeedLedgerFromSurfaceIdempotent(t *testing.T) {
	res := &attacksurface.Result{
		AuthHeaders: map[string]string{"Cookie": "s=1"},
		Endpoints: []attacksurface.Endpoint{
			{Method: "GET", Path: "https://app.example.com/api/orders", Params: []string{"id"}, Source: "openapi"},
		},
	}
	ag := newSurfaceAgent(t)

	if n := ag.seedLedgerFromSurface(res); n != 1 {
		t.Fatalf("first seed expected 1, got %d", n)
	}
	if n := ag.seedLedgerFromSurface(res); n != 0 {
		t.Fatalf("second seed expected 0 (dedup), got %d", n)
	}
	if got := ag.scanCtx.Ledger.Len(); got != 1 {
		t.Fatalf("expected ledger len 1 after re-seed, got %d", got)
	}
}

func TestSeedLedgerFromSurfaceBounded(t *testing.T) {
	res := &attacksurface.Result{}
	for i := 0; i < maxSurfaceSeed+10; i++ {
		res.Endpoints = append(res.Endpoints, attacksurface.Endpoint{
			Method: "GET",
			Path:   fmt.Sprintf("https://app.example.com/api/e%d", i),
			Source: "openapi",
		})
	}
	ag := newSurfaceAgent(t)

	n := ag.seedLedgerFromSurface(res)
	if n != maxSurfaceSeed {
		t.Fatalf("expected seeding bounded to %d, got %d", maxSurfaceSeed, n)
	}
	if got := ag.scanCtx.Ledger.Len(); got != maxSurfaceSeed {
		t.Fatalf("expected ledger len %d, got %d", maxSurfaceSeed, got)
	}
}

func TestSplitSurfaceEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		bases    []string
		wantHost string
		wantPath string
	}{
		{"full url", "https://app.example.com/api/orders", nil, "app.example.com", "/api/orders"},
		{"full url no path", "https://app.example.com", nil, "app.example.com", "/"},
		{"bare path with base", "/api/users", []string{"https://app.example.com"}, "app.example.com", "/api/users"},
		{"bare path no base", "/api/users", nil, "", "/api/users"},
		{"empty", "", nil, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, path := splitSurfaceEndpoint(c.raw, c.bases)
			if host != c.wantHost || path != c.wantPath {
				t.Fatalf("splitSurfaceEndpoint(%q,%v) = (%q,%q), want (%q,%q)", c.raw, c.bases, host, path, c.wantHost, c.wantPath)
			}
		})
	}
}
