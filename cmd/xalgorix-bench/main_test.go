package main

import (
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/realbench"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func TestRealWorldRunDiagnosticsAggregatesWithoutRawEvidence(t *testing.T) {
	diagnostics := newRealWorldRunDiagnostics(time.Now().Add(-time.Second))
	diagnostics.observe(agent.Event{Type: "tool_call", ToolName: "terminal_execute"})
	diagnostics.observe(agent.Event{Type: "tool_call", ToolName: "report_vulnerability"})
	diagnostics.observe(agent.Event{
		Type:       "tool_result",
		ToolName:   "report_vulnerability",
		ToolResult: tools.Result{Output: "REJECTED (claim consistency): proof missing"},
	})
	diagnostics.observe(agent.Event{Type: "tool_call", ToolName: "report_vulnerability"})
	diagnostics.observe(agent.Event{
		Type:       "tool_result",
		ToolName:   "report_vulnerability",
		ToolResult: tools.Result{Output: "Vulnerability saved"},
	})
	diagnostics.observe(agent.Event{Type: "tool_call", ToolName: "report_vulnerability"})
	diagnostics.observe(agent.Event{
		Type:       "tool_result",
		ToolName:   "report_vulnerability",
		ToolResult: tools.Result{Output: "DUPLICATE: finding already reported"},
	})
	diagnostics.observe(agent.Event{Type: "finished", Aborted: true, AbortReason: "deadline"})

	if diagnostics.ToolCallCounts["report_vulnerability"] != 3 || diagnostics.ToolCallCounts["terminal_execute"] != 1 {
		t.Fatalf("unexpected tool counts: %+v", diagnostics.ToolCallCounts)
	}
	if diagnostics.RejectedReports != 1 || diagnostics.SuccessfulReports != 1 || diagnostics.DuplicateReports != 1 {
		t.Fatalf("unexpected report counts: rejected=%d successful=%d duplicate=%d", diagnostics.RejectedReports, diagnostics.SuccessfulReports, diagnostics.DuplicateReports)
	}
	if diagnostics.ToolErrorCounts["report_vulnerability"] != 1 {
		t.Fatalf("semantic report rejection should count as a tool error: %+v", diagnostics.ToolErrorCounts)
	}
	if diagnostics.FirstSuccessfulReportElapsedMS <= 0 {
		t.Fatalf("expected first successful report timing, got %d", diagnostics.FirstSuccessfulReportElapsedMS)
	}
	if diagnostics.FinishedEvents != 1 || diagnostics.AbortedEvents != 1 || diagnostics.AbortReasons["deadline"] != 1 {
		t.Fatalf("unexpected finish diagnostics: %+v", diagnostics)
	}
}

func TestVulnerableTargetCompleteRequiresEveryProofBearingExpectation(t *testing.T) {
	target := realbench.Target{
		ID:      "app-vulnerable",
		Mode:    realbench.ModeVulnerable,
		Product: "App",
		Version: "1.0",
		Expectations: []realbench.Expectation{
			{ID: "CVE-2026-12345", Class: "rce", CWE: "CWE-94", Endpoints: []string{"/api/validate"}, Methods: []string{"POST"}, RequireProof: true},
		},
	}
	suite := realbench.Suite{Name: "suite", Targets: []realbench.Target{target}}
	finding := reporting.Vulnerability{
		ID:       "XALG-1",
		Title:    "CVE-2026-12345 RCE",
		CVE:      "CVE-2026-12345",
		CWE:      "CWE-94",
		Endpoint: "/api/validate",
		Method:   "POST",
		Verified: true,
	}

	if vulnerableTargetComplete(suite, target, nil) {
		t.Fatal("empty findings must not complete a vulnerable target")
	}
	unproven := finding
	unproven.Verified = false
	if vulnerableTargetComplete(suite, target, []reporting.Vulnerability{unproven}) {
		t.Fatal("an unproven signature must not complete the target")
	}
	if !vulnerableTargetComplete(suite, target, []reporting.Vulnerability{finding}) {
		t.Fatal("the proof-bearing expected finding should complete the target")
	}

	control := target
	control.Mode = realbench.ModeFixedControl
	control.Expectations = nil
	control.ControlFor = []string{"CVE-2026-12345"}
	if vulnerableTargetComplete(suite, control, []reporting.Vulnerability{finding}) {
		t.Fatal("fixed controls must never stop on a finding match")
	}
}
