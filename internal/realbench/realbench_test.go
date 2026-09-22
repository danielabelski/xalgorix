package realbench

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

const testManifest = `{
  "schema_version": 1,
  "name": "test suite",
  "ground_truth_scope": "one documented CVE",
  "targets": [
    {
      "id": "grafana-vulnerable",
      "mode": "vulnerable",
      "product": "Grafana OSS",
      "version": "8.2.6",
      "container": {
        "image_ref": "grafana/grafana:8.2.6@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "default_url": "http://127.0.0.1:3300"
      },
      "expectations": [{
        "id": "CVE-2021-43798",
        "class": "lfi",
        "cwe": "CWE-22",
        "severity": "high",
        "endpoints": ["/public/plugins/"],
        "methods": ["GET"],
        "require_proof": true
      }]
    },
    {
      "id": "grafana-fixed",
      "mode": "fixed-control",
      "product": "Grafana OSS",
      "version": "8.2.7",
      "container": {
        "image_ref": "grafana/grafana:8.2.7@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "default_url": "http://127.0.0.1:3301"
      },
      "control_for": ["CVE-2021-43798"]
    }
  ]
}`

func loadTestSuite(t *testing.T) Suite {
	t.Helper()
	suite, err := Load(strings.NewReader(testManifest))
	if err != nil {
		t.Fatal(err)
	}
	return suite
}

func grafanaFinding(id string, proven bool) reporting.Vulnerability {
	finding := reporting.Vulnerability{
		ID:       id,
		Title:    "Grafana plugin path traversal",
		CWE:      "CWE-22",
		Endpoint: "http://127.0.0.1:3300/public/plugins/alertlist/../../etc/passwd",
		Method:   "GET",
	}
	if proven {
		finding.Tags = []string{reporting.TagExploitProven}
	}
	return finding
}

func TestLoadRejectsUnpinnedImage(t *testing.T) {
	bad := strings.Replace(testManifest, "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", 1)
	if _, err := Load(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "pin container.image_ref") {
		t.Fatalf("expected immutable-image validation error, got %v", err)
	}
}

func TestLoadRejectsMalformedImageDigest(t *testing.T) {
	bad := strings.Replace(testManifest,
		"@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"@sha256:abcd", 1)
	if _, err := Load(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "pin container.image_ref") {
		t.Fatalf("expected full sha256 digest validation error, got %v", err)
	}
}

func TestLoadRejectsNonLoopbackTarget(t *testing.T) {
	bad := strings.Replace(testManifest, "http://127.0.0.1:3300", "https://grafana.example.com", 1)
	if _, err := Load(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback-only validation error, got %v", err)
	}
}

func TestLoadRejectsExpectationWithoutProof(t *testing.T) {
	bad := strings.Replace(testManifest, `"require_proof": true`, `"require_proof": false`, 1)
	if _, err := Load(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "must require exploit proof") {
		t.Fatalf("expected exploit-proof validation error, got %v", err)
	}
}

func TestLoadRejectsTrailingJSONValue(t *testing.T) {
	if _, err := Load(strings.NewReader(testManifest + `{}`)); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("expected trailing JSON validation error, got %v", err)
	}
}

func TestLoadRejectsInvalidHealthFingerprint(t *testing.T) {
	bad := strings.Replace(testManifest,
		`"default_url": "http://127.0.0.1:3300"`,
		`"default_url": "http://127.0.0.1:3300", "health_path": "/api/health", "health_body_regexp": "["`, 1)
	if _, err := Load(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "health_body_regexp") {
		t.Fatalf("expected invalid health fingerprint error, got %v", err)
	}
}

func TestPreflightTargetChecksHealthAndVersionFingerprint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"database":"ok","version":"8.2.6"}`))
	}))
	defer server.Close()

	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	target.Container.DefaultURL = server.URL
	target.Container.HealthPath = "/api/health"
	target.Container.HealthStatus = http.StatusOK
	target.Container.HealthBodyRegexp = `"version"\s*:\s*"8\.2\.6"`
	result, err := PreflightTarget(context.Background(), target, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusOK || result.URL != server.URL+"/api/health" {
		t.Fatalf("unexpected preflight result: %+v", result)
	}

	target.Container.HealthBodyRegexp = `"version"\s*:\s*"8\.2\.7"`
	if _, err := PreflightTarget(context.Background(), target, server.URL); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected version fingerprint mismatch, got %v", err)
	}
}

func TestPreflightTargetDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer server.Close()

	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	target.Container.HealthPath = "/api/health"
	if _, err := PreflightTarget(context.Background(), target, server.URL); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}

func TestScorePositiveRequiresExploitProof(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")

	miss := Score(suite, target, []reporting.Vulnerability{grafanaFinding("XALG-1", false)})
	if miss.Matched != 0 || len(miss.Expectations[0].UnprovenIDs) != 1 {
		t.Fatalf("unproven candidate must not count as found: %+v", miss)
	}

	found := Score(suite, target, []reporting.Vulnerability{grafanaFinding("XALG-1", true)})
	if found.Matched != 1 || found.TargetedRecall != 1 || found.Expectations[0].FindingID != "XALG-1" {
		t.Fatalf("expected proven finding to match: %+v", found)
	}
}

func TestScoreAllowsOmittedOptionalMethodForExactSignature(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	finding := grafanaFinding("XALG-1", true)
	finding.Method = ""
	finding.CVE = "CVE-2021-43798"

	result := Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 1 || result.TargetedRecall != 1 {
		t.Fatalf("empty optional method must not erase an exact proven signature: %+v", result)
	}

	finding.Method = "POST"
	result = Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 0 {
		t.Fatalf("an explicitly wrong method must still fail the signature: %+v", result)
	}
}

func TestScoreExactCVEAllowsOmittedClassMetadata(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	finding := reporting.Vulnerability{
		ID:       "XALG-1",
		Title:    "CVE-2021-43798: Unauthenticated arbitrary file read",
		CVE:      "CVE-2021-43798",
		Endpoint: "http://127.0.0.1:3300/public/plugins/alertlist/../../etc/passwd",
		Verified: true,
	}

	result := Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 1 || result.TargetedRecall != 1 {
		t.Fatalf("exact CVE with matching endpoint and proof must survive omitted CWE/method metadata: %+v", result)
	}

	finding.Endpoint = "http://127.0.0.1:3300/api/health"
	result = Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 0 {
		t.Fatalf("exact CVE must not bypass the endpoint signature: %+v", result)
	}
}

func TestScoreCVETextDoesNotMatchAnotherIdentifier(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	finding := reporting.Vulnerability{
		ID:       "XALG-1",
		Title:    "CVE-2021-43799: Different issue",
		CVE:      "CVE-2021-43799",
		Endpoint: "http://127.0.0.1:3300/public/plugins/alertlist/file",
		Verified: true,
	}

	result := Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 0 {
		t.Fatalf("a different CVE identifier must not satisfy the expectation: %+v", result)
	}
}

func TestGrafanaDualManifestScoresIndependentBugClasses(t *testing.T) {
	suite, err := LoadFile("../../benchmarks/real-world/grafana-dual/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	vulnerable, ok := suite.Target("grafana-8.2.2-two-cves")
	if !ok {
		t.Fatal("missing vulnerable Grafana 8.2.2 target")
	}
	control, ok := suite.Target("grafana-8.2.7-two-cve-control")
	if !ok {
		t.Fatal("missing patched Grafana 8.2.7 control")
	}
	if len(vulnerable.Expectations) != 2 || len(suite.ExpectationsFor(control)) != 2 {
		t.Fatalf("the dual corpus must score both CVEs against both versions: %+v %+v", vulnerable, control)
	}

	lfi := reporting.Vulnerability{
		ID: "XALG-1", CVE: "CVE-2021-43798", CWE: "CWE-22", Method: "GET",
		Endpoint: "http://127.0.0.1:3310/public/plugins/alertlist/../../../../etc/passwd",
		Tags:     []string{reporting.TagExploitProven},
	}
	xss := reporting.Vulnerability{
		ID: "XALG-2", CVE: "CVE-2021-41174", CWE: "CWE-79", Method: "GET",
		Endpoint: "http://127.0.0.1:3310/dashboard/snapshot/%7B%7Bconstructor.constructor(1)()%7D%7D",
		Tags:     []string{reporting.TagExploitProven},
	}
	result := Score(suite, vulnerable, []reporting.Vulnerability{lfi, xss})
	if result.Matched != 2 || result.TargetedRecall != 1 || result.Expectations[0].FindingID != lfi.ID || result.Expectations[1].FindingID != xss.ID {
		t.Fatalf("both independently documented classes should match: %+v", result)
	}
	xss.Tags = nil
	xss.Verified = false
	result = Score(suite, vulnerable, []reporting.Vulnerability{lfi, xss})
	if result.Matched != 1 || len(result.Expectations[1].UnprovenIDs) != 1 {
		t.Fatalf("an unproven XSS must not inflate recall: %+v", result)
	}
	result = Score(suite, control, nil)
	if result.ControlRegressions != 0 || result.Expected != 2 {
		t.Fatalf("the patched control must check both signatures: %+v", result)
	}
}

func TestMetabaseRCEManifestScoresProofAndControl(t *testing.T) {
	suite, err := LoadFile("../../benchmarks/real-world/metabase-rce/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	vulnerable, ok := suite.Target("metabase-0.46.6-cve-2023-38646")
	if !ok {
		t.Fatal("missing vulnerable Metabase 0.46.6 target")
	}
	control, ok := suite.Target("metabase-0.46.6.4-rce-control")
	if !ok {
		t.Fatal("missing patched Metabase 0.46.6.4 control")
	}

	rce := reporting.Vulnerability{
		ID:       "XALG-1",
		Title:    "CVE-2023-38646 pre-auth H2 connection-string RCE",
		CVE:      "CVE-2023-38646",
		CWE:      "CWE-94",
		Method:   "POST",
		Endpoint: "http://127.0.0.1:3320/api/setup/validate",
		Tags:     []string{reporting.TagExploitProven},
	}
	result := Score(suite, vulnerable, []reporting.Vulnerability{rce})
	if result.Matched != 1 || result.TargetedRecall != 1 {
		t.Fatalf("proof-bearing Metabase RCE should match: %+v", result)
	}
	rce.Tags = nil
	result = Score(suite, vulnerable, []reporting.Vulnerability{rce})
	if result.Matched != 0 || len(result.Expectations[0].UnprovenIDs) != 1 {
		t.Fatalf("version-only/unproven RCE must not inflate recall: %+v", result)
	}
	result = Score(suite, control, nil)
	if result.ControlRegressions != 0 || result.Expected != 1 {
		t.Fatalf("patched Metabase control should check one signature: %+v", result)
	}
}

func TestScoreTracksDuplicatesAndLeavesUnknownsUnclassified(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	unknown := reporting.Vulnerability{ID: "XALG-3", Title: "Different issue", CWE: "CWE-79", Endpoint: "/login", Method: "GET"}
	result := Score(suite, target, []reporting.Vulnerability{
		grafanaFinding("XALG-1", true),
		grafanaFinding("XALG-2", true),
		unknown,
	})
	if result.Matched != 1 || result.DuplicateFindings != 1 {
		t.Fatalf("expected one match plus one duplicate: %+v", result)
	}
	if len(result.UnclassifiedFindings) != 1 || result.UnclassifiedFindings[0] != "XALG-3" {
		t.Fatalf("unknown real-product finding must remain unclassified: %+v", result.UnclassifiedFindings)
	}
}

func TestFixedControlCountsMatchingSignatureAsRegression(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-fixed")
	result := Score(suite, target, []reporting.Vulnerability{grafanaFinding("XALG-1", true)})
	if result.ControlRegressions != 1 || result.Matched != 1 {
		t.Fatalf("expected a fixed-control regression: %+v", result)
	}
}

func TestScoreRejectsExpectedEndpointEmbeddedInAnotherRoute(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	finding := grafanaFinding("XALG-1", true)
	finding.Endpoint = "http://127.0.0.1:3300/redirect/public/plugins/alertlist/file"
	result := Score(suite, target, []reporting.Vulnerability{finding})
	if result.Matched != 0 {
		t.Fatalf("embedded endpoint must not satisfy the expected route family: %+v", result)
	}
}

func TestAggregateExposesIntermittentRecall(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-vulnerable")
	results := []Result{
		Score(suite, target, []reporting.Vulnerability{grafanaFinding("XALG-1", true)}),
		Score(suite, target, nil),
	}
	agg, err := Aggregate(results)
	if err != nil {
		t.Fatal(err)
	}
	if agg.MeanTargetedRecall != 0.5 || agg.MinimumTargetedRecall != 0 || agg.MaximumTargetedRecall != 1 {
		t.Fatalf("unexpected recall distribution: %+v", agg)
	}
	if agg.ExpectationsFoundAnyRun != 1 || agg.ExpectationsFoundEveryRun != 0 || agg.Stable {
		t.Fatalf("intermittent finding must not be stable: %+v", agg)
	}
	if len(agg.Expectations) != 1 || agg.Expectations[0].Matches != 1 || agg.Expectations[0].MatchRate != 0.5 {
		t.Fatalf("unexpected per-expectation stability: %+v", agg.Expectations)
	}
}

func TestAggregateTracksControlRegressionRuns(t *testing.T) {
	suite := loadTestSuite(t)
	target, _ := suite.Target("grafana-fixed")
	results := []Result{
		Score(suite, target, nil),
		Score(suite, target, []reporting.Vulnerability{grafanaFinding("XALG-1", true)}),
	}
	agg, err := Aggregate(results)
	if err != nil {
		t.Fatal(err)
	}
	if agg.ControlRunsWithRegressions != 1 || agg.Stable {
		t.Fatalf("expected one unstable control regression run: %+v", agg)
	}
}

func TestAggregateRejectsMixedTargets(t *testing.T) {
	suite := loadTestSuite(t)
	vulnerable, _ := suite.Target("grafana-vulnerable")
	fixed, _ := suite.Target("grafana-fixed")
	if _, err := Aggregate([]Result{Score(suite, vulnerable, nil), Score(suite, fixed, nil)}); err == nil {
		t.Fatal("expected mixed-target aggregation error")
	}
}
