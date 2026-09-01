package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// newTestCtxState creates an active ScanContext (with an in-memory ledger, no
// persist path) and a ScanState wired to it. The context is deactivated on
// cleanup so tests do not leak active contexts into one another.
func newTestCtxState(t *testing.T) (*scanctx.ScanContext, *ScanState) {
	t.Helper()
	id := "ledger-hooks-test-" + t.Name()
	ctx := scanctx.New(id, "")
	scanctx.Activate(ctx)
	t.Cleanup(func() { scanctx.Deactivate(id) })
	state := NewScanState()
	state.ScanContextID = id
	return ctx, state
}

func TestSeedLedgerFromPlan(t *testing.T) {
	ctx, state := newTestCtxState(t)
	plan := NewPlan()
	plan.add(&Task{ID: "recon", Title: "Recon", Phase: 1, Status: TaskPending})
	plan.add(&Task{ID: "test-sqli", Title: "Test SQLi", Phase: 6, VulnClass: "sqli", Status: TaskPending})
	plan.add(&Task{ID: "test-xss", Title: "Test XSS", Phase: 7, VulnClass: "xss", Status: TaskPending})
	plan.add(&Task{ID: "report", Title: "Report", Phase: 22, Status: TaskPending})
	state.Plan = plan

	n := seedLedgerFromPlan(state, ctx.Ledger)
	if n != 2 {
		t.Fatalf("expected 2 class hypotheses seeded (structural tasks skipped), got %d", n)
	}
	if ctx.Ledger.Len() != 2 {
		t.Fatalf("expected ledger length 2, got %d", ctx.Ledger.Len())
	}
	// Idempotent: re-seeding the same plan dedups to zero new.
	if again := seedLedgerFromPlan(state, ctx.Ledger); again != 0 {
		t.Fatalf("expected 0 new hypotheses on reseed, got %d", again)
	}
}

func TestHookLedgerSeedLifecycle(t *testing.T) {
	ctx, state := newTestCtxState(t)

	// No plan yet -> no-op, not marked seeded.
	if r := hookLedgerSeed(state, nil); r.Nudge != "" || state.LedgerSeeded {
		t.Fatal("expected no-op before a plan exists")
	}

	plan := NewPlan()
	plan.add(&Task{ID: "test-idor", VulnClass: "idor", Status: TaskPending})
	state.Plan = plan

	hookLedgerSeed(state, nil)
	if !state.LedgerSeeded {
		t.Fatal("expected LedgerSeeded to be set")
	}
	if ctx.Ledger.Len() != 1 {
		t.Fatalf("expected 1 hypothesis after seed, got %d", ctx.Ledger.Len())
	}

	// Second call is a no-op (already seeded).
	before := ctx.Ledger.Len()
	hookLedgerSeed(state, nil)
	if ctx.Ledger.Len() != before {
		t.Fatal("expected a second hookLedgerSeed call to be a no-op")
	}
}

func TestHookLedgerSeedNoActiveContext(t *testing.T) {
	state := NewScanState()
	state.ScanContextID = "no-such-active-context"
	plan := NewPlan()
	plan.add(&Task{ID: "test-sqli", VulnClass: "sqli", Status: TaskPending})
	state.Plan = plan

	if r := hookLedgerSeed(state, nil); r.Nudge != "" {
		t.Fatal("expected no nudge without an active context")
	}
	if state.LedgerSeeded {
		t.Fatal("expected LedgerSeeded to stay false when no ledger is reachable")
	}
}

func TestProvenUnreportedHypotheses(t *testing.T) {
	ctx, _ := newTestCtxState(t)
	l := ctx.Ledger

	l.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/a"}) // queued — ignored

	proven := l.Upsert(scanctx.Hypothesis{VulnClass: "idor", Endpoint: "/b"})
	l.SetStatus(proven.ID, scanctx.HypothesisProven, "") // proven, no finding — listed

	reported := l.Upsert(scanctx.Hypothesis{VulnClass: "ssrf", Endpoint: "/c"})
	l.SetStatus(reported.ID, scanctx.HypothesisProven, "")
	l.AddEvidence(reported.ID, scanctx.Evidence{Kind: scanctx.EvidenceFindingRef, FindingID: "XALG-1", Summary: "confirmed"})

	un := provenUnreportedHypotheses(l)
	if len(un) != 1 || un[0] != proven.ID {
		t.Fatalf("expected only %s unreported, got %v", proven.ID, un)
	}
}

func TestHookLedgerFinishGate(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.FinishAttempts = 1
	l := ctx.Ledger

	p := l.Upsert(scanctx.Hypothesis{VulnClass: "rce", Endpoint: "/x"})
	l.SetStatus(p.ID, scanctx.HypothesisProven, "")

	r := hookLedgerFinishGate(state, nil)
	if !r.Block {
		t.Fatal("expected finish blocked while a proven hypothesis is unreported")
	}
	if !strings.Contains(r.BlockReason, p.ID) {
		t.Fatalf("expected block reason to name %s, got: %s", p.ID, r.BlockReason)
	}

	// Linking a finding clears the gate.
	l.AddEvidence(p.ID, scanctx.Evidence{Kind: scanctx.EvidenceFindingRef, FindingID: "XALG-2", Summary: "poc"})
	if hookLedgerFinishGate(state, nil).Block {
		t.Fatal("expected gate to clear after linking a finding")
	}

	// Even with a fresh proven-unreported hypothesis, the gate must release once
	// the attempt bound is exceeded so it can never deadlock the scan.
	p2 := l.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/y"})
	l.SetStatus(p2.ID, scanctx.HypothesisProven, "")
	state.FinishAttempts = 4
	if hookLedgerFinishGate(state, nil).Block {
		t.Fatal("expected gate to release after FinishAttempts exceeds the bound")
	}
}

func TestHookLedgerFinishGateDiscoveryModeBypass(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.DiscoveryMode = true
	state.FinishAttempts = 1
	p := ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "idor", Endpoint: "/x"})
	ctx.Ledger.SetStatus(p.ID, scanctx.HypothesisProven, "")

	if hookLedgerFinishGate(state, nil).Block {
		t.Fatal("expected discovery mode to bypass the ledger finish gate")
	}
}

func TestBuildDelegationNudgeIsLedgerDriven(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.DetectedTechs = map[string]bool{"php": true}
	state.DiscoveredEndpoints = []string{"/api/users", "/login"}
	ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "sqli", Endpoint: "/api/users", Parameter: "id", Confidence: 0.6})

	nudge := buildDelegationNudge(state)
	for _, want := range []string{
		"authz-logic", "injection-serverside", "client-source", // specialist roles
		"read_ledger", "assigned_to", // ledger-driven assignment
		"detected stack: php", "/api/users", // recon context + schedulable hypothesis
	} {
		if !strings.Contains(nudge, want) {
			t.Fatalf("expected delegation nudge to contain %q\n---\n%s", want, nudge)
		}
	}
}

func TestSpecialistProfilesCoverWeakClasses(t *testing.T) {
	covered := map[string]bool{}
	for _, p := range defaultSpecialistProfiles {
		if p.Role == "" || p.EvidenceContract == "" || p.StoppingRule == "" {
			t.Fatalf("specialist profile %q is missing required fields", p.Role)
		}
		for _, c := range p.VulnClasses {
			covered[c] = true
		}
	}
	// The classes autonomous scanners are weakest at must be owned by a profile.
	for _, want := range []string{"blind-sqli", "xss", "idor", "ssrf"} {
		if !covered[want] {
			t.Fatalf("expected specialist profiles to cover %q", want)
		}
	}
}

func TestHookDelegationCoordinatorFiresOnceWithLedger(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.ReconDone = true
	state.Iteration = 6
	ctx.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "idor", Endpoint: "/api/orders", Confidence: 0.7})

	r := hookDelegationCoordinator(state, nil)
	if r.Nudge == "" {
		t.Fatal("expected a delegation nudge once recon is mature")
	}
	if !strings.Contains(r.Nudge, "read_ledger") || !strings.Contains(r.Nudge, "injection-serverside") {
		t.Fatalf("expected a ledger-driven, profile-based nudge, got:\n%s", r.Nudge)
	}
	if !state.DelegationNudgeFired {
		t.Fatal("expected DelegationNudgeFired to be set")
	}
	// One-time: subsequent calls are silent.
	if hookDelegationCoordinator(state, nil).Nudge != "" {
		t.Fatal("expected the delegation nudge to fire only once")
	}
}
