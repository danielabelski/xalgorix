package agent

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/har"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

const harIngestSample = `{"log":{"entries":[
 {"request":{"method":"GET","url":"https://app.example.com/api/orders?id=42","headers":[{"name":"Authorization","value":"Bearer TOKEN"}],"queryString":[{"name":"id","value":"42"}]}},
 {"request":{"method":"GET","url":"https://app.example.com/api/users/7","headers":[{"name":"Cookie","value":"session=abc"}]}},
 {"request":{"method":"GET","url":"https://cdn.other.com/lib.js","headers":[]}}
]}}`

func TestSeedFromHAR(t *testing.T) {
	ctxID := "har-seed-" + t.Name()
	ag := &Agent{scanCtx: scanctx.New(ctxID, "")}

	h, err := har.Parse([]byte(harIngestSample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sum := ag.seedFromHAR(h, "app.example.com")

	// Two in-scope endpoints (cdn .js skipped).
	if sum.Endpoints != 2 {
		t.Fatalf("expected 2 in-scope endpoints, got %d", sum.Endpoints)
	}
	if sum.Seeded != 2 {
		t.Fatalf("expected 2 seeded hypotheses, got %d", sum.Seeded)
	}

	// Session auth registered for the context (Authorization + Cookie merged).
	auth := httpclient.SessionAuthForContext(ctxID)
	if auth["Authorization"] != "Bearer TOKEN" || auth["Cookie"] != "session=abc" {
		t.Fatalf("expected merged session auth registered, got %#v", auth)
	}

	// Ledger seeded with role-scoped authorization hypotheses.
	all := ag.scanCtx.Ledger.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 ledger hypotheses, got %d", len(all))
	}
	for _, hyp := range all {
		if hyp.Role != authRole {
			t.Fatalf("expected role %q, got %q", authRole, hyp.Role)
		}
		if hyp.VulnClass != harHypEndpoint {
			t.Fatalf("expected class %q, got %q", harHypEndpoint, hyp.VulnClass)
		}
		if hyp.Origin != "har" {
			t.Fatalf("expected origin har, got %q", hyp.Origin)
		}
	}
}

func TestHarIngestToolMissingPath(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("har-nopath-"+t.Name(), "")}
	if res, _ := ag.harIngestTool(map[string]string{}); res.Error == "" {
		t.Fatal("expected an error when path is missing")
	}
	if res, _ := ag.harIngestTool(map[string]string{"path": "/nonexistent/does-not-exist.har"}); res.Error == "" {
		t.Fatal("expected an error when the HAR file cannot be read")
	}
}
