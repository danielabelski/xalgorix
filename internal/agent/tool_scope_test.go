package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

func newScopedSpecialist(t *testing.T, agentName string, scoped bool) *Agent {
	t.Helper()
	cfg := &config.Config{RoleScopedTools: scoped}
	sctx := scanctx.New("tool-scope-test", t.TempDir())
	scanctx.Activate(sctx)
	t.Cleanup(sctx.Close)
	a := NewAgent(cfg, agentName, make(chan Event, 8), scopeguard.Config{}, sctx)
	a.delegatedAgentID = "delegated-1"
	return a
}

// TestRoleScopedToolsOffKeepsFullSchema proves the flag-off path is
// byte-identical to today: no hidden set on any registry.
func TestRoleScopedToolsOffKeepsFullSchema(t *testing.T) {
	a := newScopedSpecialist(t, "specialist-authz-logic", false)
	a.applyRoleToolScope()
	if hidden := a.registry.SchemaHiddenNames(); len(hidden) != 0 {
		t.Fatalf("flag off must not hide tools, got %v", hidden)
	}
}

// TestRoleScopedToolsPerRole verifies each specialist role gets its
// contract-aligned scope and hidden tools stay callable.
func TestRoleScopedToolsPerRole(t *testing.T) {
	cases := []struct {
		name     string
		mustHide []string
		mustKeep []string
	}{
		{"specialist-authz-logic", []string{"browser_action", "page_agent", "code_search", "spawn_agent"}, []string{"http_request", "terminal_execute", "report_vulnerability", "finish"}},
		{"specialist-injection-serverside", []string{"browser_action", "page_agent", "code_search", "spawn_agent"}, []string{"http_request", "terminal_execute", "report_vulnerability"}},
		{"specialist-client-source", []string{"verify_sqli", "spawn_agent", "ingest_har"}, []string{"browser_action", "code_search", "http_request", "report_vulnerability"}},
		{"specialist-somethingelse", []string{"spawn_agent"}, []string{"http_request", "terminal_execute"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newScopedSpecialist(t, tc.name, true)
			a.applyRoleToolScope()
			hidden := map[string]bool{}
			for _, n := range a.registry.SchemaHiddenNames() {
				hidden[n] = true
			}
			for _, n := range tc.mustHide {
				if !hidden[n] {
					t.Fatalf("%s: expected %s hidden; hidden set = %v", tc.name, n, hidden)
				}
				// Hidden tools must remain registered and callable.
				if tool, ok := a.registry.Get(n); !ok || tool.Name != n {
					t.Fatalf("%s: hidden tool %s must stay registered", tc.name, n)
				}
			}
			for _, n := range tc.mustKeep {
				if hidden[n] {
					t.Fatalf("%s: %s must stay documented for this role", tc.name, n)
				}
			}
		})
	}
}

// TestRoleScopedToolsSchemaHasIndexNote verifies the schema carries the
// hidden-tools index so no phantom gaps exist in the model's view.
func TestRoleScopedToolsSchemaHasIndexNote(t *testing.T) {
	a := newScopedSpecialist(t, "specialist-authz-logic", true)
	a.applyRoleToolScope()
	schema := a.registry.SchemaXML()
	if !strings.Contains(schema, "<hidden_tools>") {
		t.Fatal("scoped schema must carry the hidden-tools index")
	}
	if !strings.Contains(schema, "browser_action") {
		t.Fatal("hidden tool names must be indexed in the schema")
	}
	if strings.Contains(schema, "browser_action description") {
		t.Fatal("hidden tool full documentation must not be serialized")
	}
}

// TestRootCoordinatorNeverScoped: a root agent (delegatedAgentID == "") must
// never have tools hidden even if the method is called on it.
func TestRootCoordinatorNeverScoped(t *testing.T) {
	cfg := &config.Config{RoleScopedTools: true}
	sctx := scanctx.New("root-scope-test", t.TempDir())
	scanctx.Activate(sctx)
	t.Cleanup(sctx.Close)
	root := NewAgent(cfg, "XalgorixRoot", make(chan Event, 8), scopeguard.Config{}, sctx)
	root.applyRoleToolScope()
	if hidden := root.registry.SchemaHiddenNames(); len(hidden) != 0 {
		t.Fatalf("root coordinator must keep full schema, got %v", hidden)
	}
	_ = llm.Message{}
}
