package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// probeTestServer serves /live (200), /secure (200 only with Bearer AAA, else
// 403), and returns 404 for anything else (unregistered on the mux).
func probeTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello world body padding padding padding"))
	})
	mux.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer AAA" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("owner data"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	})
	return httptest.NewServer(mux)
}

func newProbeAgent(t *testing.T, targetURL string, allowLocal bool) *Agent {
	t.Helper()
	return &Agent{
		localGuard: scopeguard.Config{AllowLocalTargets: allowLocal},
		scanCtx:    scanctx.New("probe-test-"+t.Name(), ""),
		ctx:        context.Background(),
		targets:    []string{targetURL},
	}
}

func seedProbeHypothesis(ag *Agent, endpoint, origin, vuln string) string {
	h := ag.scanCtx.Ledger.Upsert(scanctx.Hypothesis{
		VulnClass:  vuln,
		Endpoint:   endpoint,
		Origin:     origin,
		Status:     scanctx.HypothesisQueued,
		Confidence: 0.3,
	})
	return h.ID
}

func lastEvidence(h scanctx.Hypothesis) scanctx.Evidence {
	if len(h.Evidence) == 0 {
		return scanctx.Evidence{}
	}
	return h.Evidence[len(h.Evidence)-1]
}

func TestProbeHypothesisLiveRoute(t *testing.T) {
	srv := probeTestServer()
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, true)
	id := seedProbeHypothesis(ag, "/live", "source-route", "rce")

	res, err := ag.probeHypothesisTool(map[string]string{"hypothesis_id": id})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Error != "" {
		t.Fatalf("unexpected tool error: %s", res.Error)
	}
	if code, _ := res.Metadata["status_code"].(int); code != 200 {
		t.Fatalf("expected status_code 200, got %v", res.Metadata["status_code"])
	}
	h, _ := ag.scanCtx.Ledger.Get(id)
	if h.Status != scanctx.HypothesisTesting {
		t.Fatalf("expected status testing, got %s", h.Status)
	}
	if lastEvidence(h).Kind != "probe" {
		t.Fatalf("expected a probe evidence record, got %q", lastEvidence(h).Kind)
	}
	if h.Confidence < 0.6 {
		t.Fatalf("expected confidence raised to >=0.6 for a live route, got %.2f", h.Confidence)
	}
}

func TestProbeHypothesisNotFoundBlocks(t *testing.T) {
	srv := probeTestServer()
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, true)
	id := seedProbeHypothesis(ag, "/missing", "source-route", "idor")

	res, err := ag.probeHypothesisTool(map[string]string{"hypothesis_id": id})
	if err != nil || res.Error != "" {
		t.Fatalf("unexpected: err=%v toolError=%s", err, res.Error)
	}
	if code, _ := res.Metadata["status_code"].(int); code != 404 {
		t.Fatalf("expected 404, got %v", res.Metadata["status_code"])
	}
	h, _ := ag.scanCtx.Ledger.Get(id)
	if h.Status != scanctx.HypothesisBlocked {
		t.Fatalf("expected status blocked for 404, got %s", h.Status)
	}
}

func TestProbeHypothesisProtectedFlagsAuthz(t *testing.T) {
	srv := probeTestServer()
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, true) // no auth configured -> /secure returns 403
	id := seedProbeHypothesis(ag, "/secure", "source-route", "idor")

	res, _ := ag.probeHypothesisTool(map[string]string{"hypothesis_id": id})
	if code, _ := res.Metadata["status_code"].(int); code != 403 {
		t.Fatalf("expected 403, got %v", res.Metadata["status_code"])
	}
	h, _ := ag.scanCtx.Ledger.Get(id)
	if h.Status != scanctx.HypothesisTesting {
		t.Fatalf("expected status testing for a protected route, got %s", h.Status)
	}
	if !strings.Contains(strings.ToLower(lastEvidence(h).Summary), "access-controlled") {
		t.Fatalf("expected access-controlled evidence, got %q", lastEvidence(h).Summary)
	}
}

func TestProbeHypothesisUsesTargetAuth(t *testing.T) {
	srv := probeTestServer()
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, true)
	ag.targetAuth = "Authorization: Bearer AAA"
	id := seedProbeHypothesis(ag, "/secure", "source-route", "idor")

	res, err := ag.probeHypothesisTool(map[string]string{"hypothesis_id": id})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code, _ := res.Metadata["status_code"].(int); code != 200 {
		t.Fatalf("authenticated probe should get 200 from /secure, got %v", res.Metadata["status_code"])
	}
	if authed, _ := res.Metadata["authenticated"].(bool); !authed {
		t.Fatal("expected authenticated=true when target auth is configured")
	}
}

func TestProbeHypothesisSkipsSourceLocation(t *testing.T) {
	srv := probeTestServer()
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, true)
	id := seedProbeHypothesis(ag, "handlers.py:42", "source-sink", "rce")

	res, err := ag.probeHypothesisTool(map[string]string{"hypothesis_id": id})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Error == "" || !strings.Contains(res.Error, "source location") {
		t.Fatalf("expected a source-location refusal, got error=%q output=%q", res.Error, res.Output)
	}
	h, _ := ag.scanCtx.Ledger.Get(id)
	if h.Status != scanctx.HypothesisQueued {
		t.Fatalf("expected status unchanged (queued), got %s", h.Status)
	}
	if len(h.Evidence) != 0 {
		t.Fatal("no request should have been made for a source-location endpoint")
	}
}

func TestProbeHypothesisRefusesOperatorMachine(t *testing.T) {
	srv := probeTestServer()
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, false) // allowLocal=false -> loopback refused
	id := seedProbeHypothesis(ag, "/live", "source-route", "rce")

	res, err := ag.probeHypothesisTool(map[string]string{"hypothesis_id": id})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Error == "" || !strings.Contains(res.Error, "operator") {
		t.Fatalf("expected a scope refusal for the operator's machine, got error=%q", res.Error)
	}
	h, _ := ag.scanCtx.Ledger.Get(id)
	if len(h.Evidence) != 0 {
		t.Fatal("no request should have been made when scope-refused")
	}
}

func TestProbeHypothesisUnknownID(t *testing.T) {
	ag := newProbeAgent(t, "https://example.com", true)
	if res, _ := ag.probeHypothesisTool(map[string]string{"hypothesis_id": "H-999"}); res.Error == "" {
		t.Fatal("expected an error for an unknown hypothesis id")
	}
}

func TestProbeHypothesisPassiveDisabled(t *testing.T) {
	ag := newProbeAgent(t, "https://example.com", true)
	ag.scanIntensity = "passive"
	res, _ := ag.probeHypothesisTool(map[string]string{"hypothesis_id": "H-1"})
	if res.Error == "" || !strings.Contains(res.Error, "passive") {
		t.Fatalf("expected a passive-mode refusal, got %q", res.Error)
	}
}
