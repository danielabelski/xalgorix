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
