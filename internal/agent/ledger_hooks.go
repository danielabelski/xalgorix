// Package agent — ledger_hooks.go makes the durable hypothesis/evidence ledger
// (internal/scanctx.LedgerStore) actually DRIVE the scan, rather than just being
// a store the model may or may not touch. It provides:
//
//   - hookLedgerSeed: once a plan exists, seed the shared ledger with one
//     hypothesis per planned vuln class so the graph is populated deterministically
//     (not solely dependent on the LLM calling record_hypothesis).
//   - buildDelegationNudge + specialist profiles: the coordinator's one-time
//     delegation prompt now assigns work from the ledger to well-defined
//     specialists, each with an explicit evidence contract and stopping rule.
//   - hookLedgerFinishGate: a precision gate that refuses to finish while a
//     hypothesis is marked proven but has no linked finding — enforcing
//     verify-by-execution and precision-over-volume.
//
// Hooks receive only *ScanState, so the ledger is resolved through the shared
// ScanContext via ScanContextID (nil-safe: unit tests without an active context
// simply no-op).
package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// ledgerForState resolves the durable ledger for a scan state, or nil when the
// state has no owning context or the context is not active (e.g. unit tests).
func ledgerForState(state *ScanState) *scanctx.LedgerStore {
	if state == nil || state.ScanContextID == "" {
		return nil
	}
	if sc := scanctx.Get(state.ScanContextID); sc != nil {
		return sc.Ledger
	}
	return nil
}

// ── Deterministic specialist profiles ───────────────────────────────────────
//
// These formalize the three non-overlapping roles the coordinator delegates to.
// Encoding them as data (rather than free prose) makes the decomposition
// deterministic and testable, and lets each specialist carry an explicit
// evidence contract + stopping rule — the mechanism that turns "run more agents"
// into precise, verify-by-execution work. The class coverage deliberately targets
// the classes autonomous scanners are weakest at (blind injection via OOB, XSS
// via browser confirmation, multi-role authorization).
type specialistProfile struct {
	Role             string
	Focus            string
	VulnClasses      []string
	EvidenceContract string
	StoppingRule     string
}

var defaultSpecialistProfiles = []specialistProfile{
	{
		Role:             "authz-logic",
		Focus:            "Authorization, access control, and business-logic abuse",
		VulnClasses:      []string{"idor", "bola", "bfla", "privilege-escalation", "auth-bypass", "business-logic"},
		EvidenceContract: "a baseline request as the legitimate role AND the same request as another/lower-privileged role, showing a concrete cross-role difference (cross-user/cross-tenant data or a state-changing action)",
		StoppingRule:     "stop once a cross-role difference is proven, or reject with the baseline when both roles behave identically across the object/action set",
	},
	{
		Role:             "injection-serverside",
		Focus:            "Injection and server-side behavior",
		VulnClasses:      []string{"sqli", "blind-sqli", "nosqli", "ssti", "cmdi", "ssrf", "xxe", "lfi", "deserialization"},
		EvidenceContract: "a concrete exploitation outcome — extracted data, command/template output, or an out-of-band (interactsh/OAST) callback for blind classes — not merely a reflected payload or a timing hunch",
		StoppingRule:     "stop after one class is proven on an endpoint with a reproducible PoC, or reject when control payloads confirm the input is safely handled",
	},
	{
		Role:             "client-source",
		Focus:            "Client/API surface, and source-to-sink data flow when source is available",
		VulnClasses:      []string{"xss", "dom-xss", "csrf", "open-redirect", "cors", "secret-exposure", "api-auth"},
		EvidenceContract: "for XSS/DOM: browser-confirmed script execution (dialog fired or DOM mutation), not just reflection; for source review: an attacker-input→sensitive-sink path plus a live request that exercises it",
		StoppingRule:     "stop after browser-confirmed execution or a proven source-to-sink path; reject when output encoding / framework defenses demonstrably block the vector",
	},
}

// renderSpecialistProfiles formats the profiles as a numbered contract list.
func renderSpecialistProfiles() string {
	var b strings.Builder
	for i, p := range defaultSpecialistProfiles {
		fmt.Fprintf(&b, "%d. %s (role \"%s\") — classes: %s.\n   Required proof: %s.\n   Stop rule: %s.\n",
			i+1, p.Focus, p.Role, strings.Join(p.VulnClasses, ", "), p.EvidenceContract, p.StoppingRule)
	}
	return b.String()
}

// buildDelegationNudge builds the coordinator's one-time multi-agent
// decomposition prompt. It assigns work from the shared ledger to the
// deterministic specialist profiles, each with an evidence contract, and points
// the coordinator at concrete schedulable hypotheses when the ledger is already
// populated.
func buildDelegationNudge(state *ScanState) string {
	var b strings.Builder
	b.WriteString(`🧭 MULTI-AGENT DECOMPOSITION: Recon is mature enough to split the assessment. Act as coordinator now: launch 2–3 NON-OVERLAPPING specialists with spawn_agent, each owning a bounded set of hypotheses from the shared ledger.

Specialist roles (use these exact roles and hold each to its evidence contract):
`)
	b.WriteString(renderSpecialistProfiles())
	b.WriteString(`
Drive the work from the shared hypothesis ledger so specialists never overlap:
- Call read_ledger(filter=schedulable) to see the open hypotheses.
- Give each specialist a DISJOINT set and mark ownership with update_hypothesis(assigned_to=<agent_id>).
- Require each specialist to record findings as they go with add_hypothesis_evidence, and to set a final status: proven (with a linked finding via kind=finding_ref) or rejected (with the baseline that ruled it out).
- Keep coordinating while they run: incorporate every result with wait_agent/check_agent, independently verify candidates, and do not finish with an uncollected delegation or a proven-but-unreported hypothesis.
Do not delegate three generic scans or duplicate your own work.`)

	// Surface concrete schedulable hypotheses if the ledger is already seeded,
	// so the coordinator has something specific to assign.
	if l := ledgerForState(state); l != nil {
		if sched := l.Schedulable(8); len(sched) > 0 {
			b.WriteString("\n\nCurrently schedulable hypotheses:\n")
			for _, h := range sched {
				loc := strings.TrimSpace(h.VulnClass + " " + h.Endpoint)
				if h.Parameter != "" {
					loc += " [" + h.Parameter + "]"
				}
				fmt.Fprintf(&b, "  • %s: %s (confidence %.2f)\n", h.ID, loc, h.Confidence)
			}
		}
	}

	// Preserve the original recon context line (detected stack + surface).
	contextParts := []string{}
	if len(state.DetectedTechs) > 0 {
		techs := make([]string, 0, len(state.DetectedTechs))
		for tech := range state.DetectedTechs {
			techs = append(techs, tech)
		}
		sort.Strings(techs)
		contextParts = append(contextParts, "detected stack: "+strings.Join(techs, ", "))
	}
	if len(state.DiscoveredEndpoints) > 0 {
		end := minInt(4, len(state.DiscoveredEndpoints))
		contextParts = append(contextParts, "representative surface: "+strings.Join(state.DiscoveredEndpoints[:end], ", "))
	}
	if len(contextParts) > 0 {
		b.WriteString("\nCurrent context: " + strings.Join(contextParts, "; ") + ".")
	}
	return b.String()
}

// ── hookLedgerSeed ───────────────────────────────────────────────────────────
// Once a plan exists, seed the shared ledger with one hypothesis per planned
// vuln class so the graph is populated deterministically. This is a side effect
// only (no nudge) and runs once per agent; the ledger dedups, so the coordinator
// and any specialist that also seeds cannot create duplicates.
func hookLedgerSeed(state *ScanState, args map[string]string) HookResult {
	if state == nil || state.ReconOnlyMode || state.LedgerSeeded || state.Plan == nil {
		return HookResult{}
	}
	if l := ledgerForState(state); l != nil {
		seedLedgerFromPlan(state, l)
		state.LedgerSeeded = true
	}
	return HookResult{}
}

// seedLedgerFromPlan creates a class-level hypothesis for every planned task
// that targets a vuln class (structural tasks like recon/dirbust/verify/report
// carry no VulnClass and are skipped). Returns the number of new hypotheses.
func seedLedgerFromPlan(state *ScanState, l *scanctx.LedgerStore) int {
	if state == nil || state.Plan == nil || l == nil {
		return 0
	}
	seeded := 0
	for _, t := range state.Plan.Tasks {
		if strings.TrimSpace(t.VulnClass) == "" {
			continue
		}
		before := l.Len()
		l.Upsert(scanctx.Hypothesis{
			Title:      t.Title,
			VulnClass:  t.VulnClass,
			Endpoint:   t.Endpoint,
			Status:     scanctx.HypothesisQueued,
			Confidence: 0.4,
			Origin:     "auto-plan",
			NextAction: "Probe " + t.VulnClass + " across the discovered surface; record specific endpoints/params as their own hypotheses.",
		})
		if l.Len() > before {
			seeded++
		}
	}
	return seeded
}

// ── hookLedgerFinishGate ─────────────────────────────────────────────────────
// Precision gate: refuse to finish while a hypothesis is marked proven but has
// no linked finding. A proven hypothesis must become a reported, evidence-backed
// finding (or be downgraded if it was not actually exploitable). Registered
// AFTER hookFinishGatekeeper, so when both block the coverage reason surfaces
// first; self-bounded by FinishAttempts so it can never deadlock the scan.
func hookLedgerFinishGate(state *ScanState, args map[string]string) HookResult {
	if state == nil || state.DiscoveryMode || state.ReconOnlyMode {
		return HookResult{}
	}
	// hookFinishGatekeeper has already incremented FinishAttempts for this
	// attempt. Give the model a few chances to report, then get out of the way.
	if state.FinishAttempts > 3 {
		return HookResult{}
	}
	l := ledgerForState(state)
	if l == nil {
		return HookResult{}
	}
	unreported := provenUnreportedHypotheses(l)
	if len(unreported) == 0 {
		return HookResult{}
	}
	return HookResult{
		Block: true,
		BlockReason: "⚠️ PROVEN BUT UNREPORTED: ledger hypotheses " + strings.Join(unreported, ", ") +
			" are marked proven but have no linked finding. Either file each with report_vulnerability and then link it via add_hypothesis_evidence(kind=finding_ref, finding_id=XALG-...), or — if a hypothesis is not actually exploitable — downgrade it with update_hypothesis(status=rejected). Do not finish with proven work unreported.",
	}
}

// provenUnreportedHypotheses returns the IDs of hypotheses marked proven that
// carry no finding reference (no finding_ref evidence and no evidence FindingID).
func provenUnreportedHypotheses(l *scanctx.LedgerStore) []string {
	if l == nil {
		return nil
	}
	var out []string
	for _, h := range l.All() {
		if h.Status != scanctx.HypothesisProven {
			continue
		}
		linked := false
		for _, ev := range h.Evidence {
			if ev.Kind == scanctx.EvidenceFindingRef || strings.TrimSpace(ev.FindingID) != "" {
				linked = true
				break
			}
		}
		if !linked {
			out = append(out, h.ID)
		}
	}
	return out
}
