package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentsgraph"
)

func TestSystemPromptIncludesCollectableMultiAgentWorkflow(t *testing.T) {
	registry := tools.NewRegistry()
	graph := agentsgraph.New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		return "done", nil
	})
	t.Cleanup(graph.Stop)
	graph.Register(registry)

	agent := &Agent{
		cfg:      &config.Config{RateLimitRPS: 2},
		registry: registry,
	}
	prompt := agent.buildSystemPrompt(
		[]string{"https://example.test"},
		"Perform a full authorized assessment.",
		scanctx.RequestRatePolicy{MaxRPS: 2, Source: "test"},
	)

	for _, expected := range []string{
		"## Multi-Agent Coordinator",
		"NON-OVERLAPPING specialists",
		"Authorization & business logic",
		"call wait_agent/check_agent for EVERY delegation",
		`<tool name="spawn_agent">`,
		`<tool name="wait_agent">`,
	} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("prompt missing %q", expected)
		}
	}
	if strings.Contains(prompt, "%!") {
		t.Fatalf("prompt contains fmt diagnostic, likely a placeholder/argument mismatch")
	}
}

// TestWhiteboxGuidanceText verifies the live-target whitebox modes teach the
// source-to-runtime bridge (work the auto-seeded ledger first, then confirm
// deterministically), while the source-review mode — which has no live target —
// does not push live-only tools.
func TestWhiteboxGuidanceText(t *testing.T) {
	const root = "/tmp/src"

	bridge := []string{"claim_next_hypothesis", "probe_hypothesis", "verify_sqli", "verify_ssti", "verify_xss", "verify_oob", "seeded"}
	for _, mode := range []CodeScanMode{CodeScanNone, CodeScanProvision} {
		g := whiteboxGuidanceText(mode, root, "127.0.0.1:8080")
		if !strings.Contains(g, root) {
			t.Errorf("mode %d: guidance should mention the source root %q", mode, root)
		}
		for _, want := range bridge {
			if !strings.Contains(g, want) {
				t.Errorf("mode %d: guidance must mention %q", mode, want)
			}
		}
	}

	// Provision mode must embed the loopback bind host:port for build-and-run.
	if prov := whiteboxGuidanceText(CodeScanProvision, root, "127.0.0.1:8080"); !strings.Contains(prov, "127.0.0.1:8080") {
		t.Errorf("provision guidance must embed the bind host:port")
	}

	// Source-review mode has NO live target: it must NOT push live-only tools,
	// but should retain the static code_search methodology.
	rev := whiteboxGuidanceText(CodeScanReview, root, "")
	for _, unwanted := range []string{"probe_hypothesis", "verify_sqli", "verify_ssti", "verify_xss", "verify_oob"} {
		if strings.Contains(rev, unwanted) {
			t.Errorf("source-review guidance must NOT mention live-only tool %q", unwanted)
		}
	}
	if !strings.Contains(rev, "code_search") {
		t.Errorf("source-review guidance should retain the code_search methodology")
	}
}
