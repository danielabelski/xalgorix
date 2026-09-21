package agent

import "github.com/xalgord/xalgorix/v4/internal/scanctx"

// roleToolScope maps a delegated specialist's canonical role to the tools whose
// DOCUMENTATION is withheld from its system prompt. Hidden tools stay fully
// registered and callable; SchemaXML emits a one-line index of hidden names so
// the model stays aware they exist (no phantom gaps), and the coordinator
// retains full documentation. Contract-aligned: the delegated-specialist
// prompt already bounds the agent to its lane and forbids nested delegation.
var roleToolScope = map[string][]string{
	scanctx.AgentTypeAuthzLogic: {
		// Multi-agent coordinator tools (forbidden for specialists by prompt).
		"spawn_agent", "create_agent", "check_agent", "wait_agent",
		// Client-side / source-review lane tools foreign to runtime authz work.
		"browser_action", "page_agent", "code_search",
		"scan_source_routes", "scan_source_sinks",
		// Root-level asset ingestion.
		"ingest_har",
	},
	scanctx.AgentTypeInjectionServer: {
		"spawn_agent", "create_agent", "check_agent", "wait_agent",
		// Browser/DOM and source-review tools belong to the client lane.
		"browser_action", "page_agent", "code_search",
		"scan_source_routes", "scan_source_sinks",
		"ingest_har",
	},
	scanctx.AgentTypeClientSource: {
		"spawn_agent", "create_agent", "check_agent", "wait_agent",
		"ingest_har",
		// Server-side injection confirmers belong to the injection lane;
		// client-side findings are confirmed in-browser by this lane.
		"verify_sqli", "verify_ssti", "verify_xxe",
	},
	scanctx.AgentTypeVerifier: nil, // verifier registry is intentionally unscoped
	scanctx.AgentTypeOther:    {"spawn_agent", "create_agent", "check_agent", "wait_agent"},
}

// applyRoleToolScope withholds role-foreign tool documentation from this
// DELEGATED agent's system prompt when XALGORIX_ROLE_SCOPED_TOOLS is enabled.
// Only called for delegated specialists — the root coordinator and the
// independent verifier keep their full schemas unconditionally.
func (a *Agent) applyRoleToolScope() {
	if a == nil || a.cfg == nil || !a.cfg.RoleScopedTools {
		return
	}
	if a.delegatedAgentID == "" {
		return // root coordinator: full schema always
	}
	role := determineAgentType(a.Name, true)
	hidden, ok := roleToolScope[role]
	if !ok || len(hidden) == 0 {
		hidden = roleToolScope[scanctx.AgentTypeOther]
	}
	if a.registry != nil {
		a.registry.SetSchemaHidden(hidden)
	}
}
