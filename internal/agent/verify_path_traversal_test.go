package agent

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

const testPasswdBody = "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

func TestPathTraversalLeakVerdict(t *testing.T) {
	for _, tc := range []struct {
		name, baseline, probe string
		want                  bool
	}{
		{"leak only in probe", "not found", testPasswdBody, true},
		{"no leak", "not found", "not found", false},
		{"baseline already leaks", testPasswdBody, testPasswdBody, false},
		{"literal path only", "not found", "requested /etc/passwd", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathTraversalLeakVerdict(tc.baseline, tc.probe); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestVerifyPathTraversalSendsRawSegmentsAndRecordsProof(t *testing.T) {
	var sawRawPath bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "/../") {
			sawRawPath = true
			_, _ = fmt.Fprint(w, testPasswdBody)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.verifyPathTraversalTool(map[string]string{"url": srv.URL + "/public/plugins/alertlist/"})
	if err != nil || result.Error != "" || result.Metadata["path_traversal_confirmed"] != true {
		t.Fatalf("expected captured file-read confirmation, result=%+v err=%v", result, err)
	}
	if !sawRawPath {
		t.Fatal("the HTTP request lost the literal ../ segments")
	}
	if !strings.Contains(result.Output, "root:x:0:0") {
		t.Fatalf("response proof missing actual file content: %q", result.Output)
	}
	if !strings.Contains(result.Output, "verification_method=data_extracted") {
		t.Fatalf("confirmation must give the agent the required report method: %q", result.Output)
	}
	id, _ := result.Metadata["hypothesis_id"].(string)
	h, ok := ag.scanCtx.Ledger.Get(id)
	if !ok || h.VulnClass != "lfi" || h.Status != scanctx.HypothesisProven ||
		lastEvidence(h).Kind != "exploit" || !strings.Contains(lastEvidence(h).Request, "/../") {
		t.Fatalf("missing request-bound ledger evidence: %+v", h)
	}
}

func TestVerifyPathTraversalRejectsPatchedAndOutOfScope(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.NotFound(w, r)
	}))
	defer srv.Close()
	url := srv.URL + "/public/plugins/alertlist/"
	ag := newProbeAgent(t, srv.URL, true)
	result, err := ag.verifyPathTraversalTool(map[string]string{"url": url})
	if err != nil || result.Error != "" || result.Metadata["path_traversal_confirmed"] != false || requests != 4 {
		t.Fatalf("fixed response must not confirm; result=%+v err=%v requests=%d", result, err, requests)
	}
	blocked := newProbeAgent(t, srv.URL, false)
	result, _ = blocked.verifyPathTraversalTool(map[string]string{"url": url})
	if result.Error == "" || requests != 4 {
		t.Fatalf("out-of-scope loopback must be rejected before requests: %+v requests=%d", result, requests)
	}
}

// Opt-in integration oracle for the digest-pinned Grafana pair. The test never
// targets a public deployment and does not spend LLM tokens.
func TestVerifyPathTraversalGrafanaPair(t *testing.T) {
	vulnerable := os.Getenv("XALGORIX_GRAFANA_VULN_URL")
	fixed := os.Getenv("XALGORIX_GRAFANA_FIXED_URL")
	if vulnerable == "" && fixed == "" {
		t.Skip("set both XALGORIX_GRAFANA_VULN_URL and XALGORIX_GRAFANA_FIXED_URL for the local Docker oracle")
	}
	for _, raw := range []string{vulnerable, fixed} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || net.ParseIP(u.Hostname()) == nil {
			t.Fatalf("Grafana integration URLs must be loopback HTTP, got %q", raw)
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
			ag := newProbeAgent(t, tc.raw, true)
			result, err := ag.verifyPathTraversalTool(map[string]string{"url": tc.raw + "/public/plugins/alertlist/"})
			if err != nil || result.Error != "" || result.Metadata["path_traversal_confirmed"] != tc.want {
				t.Fatalf("unexpected Grafana oracle result=%+v err=%v", result, err)
			}
		})
	}
}
