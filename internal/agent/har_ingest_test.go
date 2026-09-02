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

func TestIngestHARRoleB(t *testing.T) {
	ctxID := "har-roleb-" + t.Name()
	ag := &Agent{scanCtx: scanctx.New(ctxID, "")}
	defer httpclient.SetSessionAuthB(ctxID, nil)

	h, err := har.Parse([]byte(harIngestSample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res := ag.ingestHARRoleB(h, "app.example.com")

	// Role-B credentials registered (merged Authorization + Cookie).
	b := httpclient.SessionAuthBForContext(ctxID)
	if b["Authorization"] != "Bearer TOKEN" || b["Cookie"] != "session=abc" {
		t.Fatalf("expected role-B session merged+registered, got %#v", b)
	}
	// Role B must NOT register a role-A session, and must NOT seed the ledger.
	if httpclient.SessionAuthForContext(ctxID) != nil {
		t.Fatal("role B ingestion must not register the role A session")
	}
	if n := ag.scanCtx.Ledger.Len(); n != 0 {
		t.Fatalf("role B ingestion must not seed the ledger, got %d", n)
	}
	if role, _ := res.Metadata["role"].(string); role != "b" {
		t.Fatalf("expected metadata role=b, got %v", res.Metadata["role"])
	}
	if ok, _ := res.Metadata["auth_registered"].(bool); !ok {
		t.Fatal("expected auth_registered=true")
	}
}

func TestNormalizeIngestRole(t *testing.T) {
	for _, in := range []string{"b", "B", "role-b", "second", "2", " b "} {
		if normalizeIngestRole(in) != "b" {
			t.Fatalf("expected %q -> b", in)
		}
	}
	for _, in := range []string{"", "a", "primary", "x"} {
		if normalizeIngestRole(in) != "a" {
			t.Fatalf("expected %q -> a", in)
		}
	}
}
