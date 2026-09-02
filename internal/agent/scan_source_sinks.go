// Package agent — scan_source_sinks.go implements scan_source_sinks: the first
// source-to-runtime bridge. It deterministically sweeps the attached whitebox
// source tree for dangerous sinks (reusing codesearch's curated patterns +
// ripgrep/grep) and seeds each hit into the shared ledger as a source->sink
// hypothesis — the first automated populator of Hypothesis.DataFlow.
//
// Why this matters: black-box recon finds routes; whitebox sink discovery finds
// the DANGEROUS code behind them. Bridging the two — "here is a call to
// os.system at handlers.py:42; find the route that reaches it and prove RCE on
// the live target" — is how the agent lands the high-severity classes (RCE,
// SQLi, SSTI, deserialization) that pure black-box testing misses. Each seeded
// hypothesis carries the sink location (Endpoint=file:line) and a source->sink
// DataFlow so a specialist can trace it back to a reachable HTTP route and
// build a PoC against the running target.
package agent

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/codesearch"
)

// maxSinkSeed caps how many hypotheses a single sink sweep seeds so a large
// codebase cannot flood the ledger.
const maxSinkSeed = 40

// sinkClassToVuln maps a codesearch sink class to the canonical vuln class used
// across the ledger/reporting. Only classes that map to a testable runtime
// vulnerability are seeded; discovery-only classes (secrets, auth, crypto) are
// intentionally omitted — a matched secret/auth/crypto line is a lead for a
// human or a different tool, not a source->sink runtime hypothesis.
var sinkClassToVuln = map[string]string{
	"rce":             "rce",
	"cmdi":            "rce",
	"sqli":            "sqli",
	"ssrf":            "ssrf",
	"fileio":          "lfi",
	"template":        "ssti",
	"deserialization": "deserialization",
	"redirect":        "open_redirect",
}

func (a *Agent) registerScanSourceSinksTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "scan_source_sinks",
		Description: "Whitebox source-to-runtime bridge. Sweeps the target's attached source tree for dangerous sinks (RCE/command-injection, SQLi, SSRF, file I/O→LFI, template→SSTI, deserialization, open-redirect) and seeds each as a source→sink hypothesis in the shared ledger, tagged with its file:line so you can trace it to a reachable HTTP route and prove it against the LIVE target. Run this once at the start of a whitebox assessment (after source is configured), then use read_ledger(filter=schedulable) / claim_next_hypothesis to work the highest-value sinks. Only available when source is configured for the scan; otherwise fall back to black-box discovery.",
		Parameters: []tools.Parameter{
			{Name: "max_per_class", Description: "Max sink matches to seed per vuln class (default 20, hard cap 100).", Required: false},
		},
		Execute: a.scanSourceSinksTool,
	})
}

func (a *Agent) scanSourceSinksTool(args map[string]string) (tools.Result, error) {
	if a.scanCtx == nil {
		return tools.Result{Error: "no scan context — scan_source_sinks needs a scan to seed hypotheses into"}, nil
	}
	if codesearch.GetSourceRoot(a.scanCtx.ID) == "" {
		return tools.Result{Output: "❌ Whitebox source not configured for this scan (set XALGORIX_SOURCE_REPO to a git URL or local path). Fall back to black-box discovery: fetch and read client-side JS bundles and map routes with http_request/browser."}, nil
	}

	maxPerClass := 20
	if raw := strings.TrimSpace(args["max_per_class"]); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			maxPerClass = n
		}
	}

	found, err := codesearch.SinkScan(a.scanCtx.ID, maxPerClass)
	if err != nil {
		return tools.Result{Error: "scan_source_sinks: " + err.Error()}, nil
	}
	if len(found) == 0 {
		return tools.Result{Output: "Swept the source for dangerous sinks and found none of the curated classes. The app may be small or use uncommon APIs — try code_search with a custom regex, or proceed with black-box testing."}, nil
	}

	seeded := a.seedSinks(found)

	// Deterministic summary: classes sorted, counts and vuln mapping shown.
	classes := make([]string, 0, len(found))
	total := 0
	for c, ms := range found {
		classes = append(classes, c)
		total += len(ms)
	}
	sort.Strings(classes)

	var b strings.Builder
	fmt.Fprintf(&b, "Swept source for dangerous sinks: %d match(es) across %d class(es).\n", total, len(classes))
	for _, c := range classes {
		vuln, mapped := sinkClassToVuln[c]
		note := ""
		switch {
		case !mapped:
			note = " (discovery-only, not seeded)"
		case vuln != c:
			note = " → " + vuln
		}
		fmt.Fprintf(&b, "  • %s: %d%s\n", c, len(found[c]), note)
	}
	if seeded > 0 {
		fmt.Fprintf(&b, "Seeded %d source→sink hypotheses into the ledger (origin=source-sink). Use read_ledger(filter=schedulable) or claim_next_hypothesis, then trace each sink back to a reachable route and prove it on the live target.", seeded)
	} else {
		b.WriteString("No new hypotheses seeded (these sinks are already in the ledger).")
	}
	return tools.Result{Output: b.String(), Metadata: map[string]any{"matches": total, "classes": len(classes), "seeded": seeded}}, nil
}

// seedSinks upserts bounded, deduplicated source->sink hypotheses from a sink
// sweep and returns how many NEW hypotheses were created. It maps each sink
// class to its canonical vuln class (skipping discovery-only classes), stamps
// the sink location as Endpoint=file:line and a source->sink DataFlow, and caps
// the total at maxSinkSeed. Idempotent: the ledger dedups by
// vuln_class+endpoint, so re-seeding the same sinks merges onto the existing
// hypotheses and a second call adds 0.
func (a *Agent) seedSinks(found map[string][]codesearch.SinkMatch) int {
	l := a.ledger()
	if l == nil {
		return 0
	}
	// Deterministic order: classes sorted, matches in scan order.
	classes := make([]string, 0, len(found))
	for c := range found {
		classes = append(classes, c)
	}
	sort.Strings(classes)

	seeded := 0
	for _, class := range classes {
		vuln, ok := sinkClassToVuln[class]
		if !ok {
			continue // discovery-only class (secrets/auth/crypto) — skip.
		}
		for _, m := range found[class] {
			if seeded >= maxSinkSeed {
				return seeded
			}
			loc := fmt.Sprintf("%s:%d", m.File, m.Line)
			before := l.Len()
			l.Upsert(scanctx.Hypothesis{
				Title:      fmt.Sprintf("Source sink (%s) at %s", vuln, loc),
				VulnClass:  vuln,
				Endpoint:   loc,
				DataFlow:   fmt.Sprintf("source-sink: %s — %s", loc, m.Text),
				Confidence: 0.3,
				Status:     scanctx.HypothesisQueued,
				Origin:     "source-sink",
				NextAction: "Trace this sink backward to the user-controlled input and the reachable HTTP route, then build a PoC against the live target.",
			})
			if l.Len() > before {
				seeded++
			}
		}
	}
	return seeded
}
