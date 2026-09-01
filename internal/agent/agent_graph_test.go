package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/agentsgraph"
)

func TestCoordinatorFinishGateRequiresDelegatedResultCollection(t *testing.T) {
	release := make(chan struct{})
	graph := agentsgraph.New(context.Background(), func(context.Context, string, string, []string, string) (string, error) {
		<-release
		return "specialist evidence", nil
	})
	t.Cleanup(graph.Stop)
	registry := tools.NewRegistry()
	graph.Register(registry)

	spawned, err := registry.Execute("spawn_agent", map[string]string{
		"name": "authorization specialist",
		"task": "test account boundaries with baseline controls",
	})
	if err != nil {
		t.Fatal(err)
	}
	agentID, _ := spawned.Metadata["agent_id"].(string)
	if agentID == "" {
		t.Fatalf("spawn result missing agent ID: %#v", spawned)
	}

	coordinator := &Agent{agentGraph: graph}
	if gate := coordinator.delegatedWorkFinishGate(nil, nil); !gate.Block || !strings.Contains(gate.BlockReason, "still running") {
		t.Fatalf("running delegation did not block finish: %+v", gate)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for graph.RunningCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if gate := coordinator.delegatedWorkFinishGate(nil, nil); !gate.Block || !strings.Contains(gate.BlockReason, "not been collected") {
		t.Fatalf("uncollected delegation did not block finish: %+v", gate)
	}

	if _, err := registry.Execute("check_agent", map[string]string{"agent_id": agentID}); err != nil {
		t.Fatal(err)
	}
	if gate := coordinator.delegatedWorkFinishGate(nil, nil); gate.Block {
		t.Fatalf("collected delegation still blocked finish: %+v", gate)
	}
}
