// Package agent — scan_source_routes.go implements scan_source_routes: the
// second half of the source-to-runtime bridge. scan_source_sinks finds the
// dangerous CODE (a sink at file:line); scan_source_routes finds the HTTP
// ROUTES declared in the same source and seeds each as a ledger hypothesis with
// a REAL, reachable path — then correlates the two by co-location so a route
// whose handler file contains a dangerous sink is seeded as a class-typed,
// higher-confidence lead.
//
// Why this matters: a source-sink hypothesis carries a file:line, not something
// the runtime tools can hit. A route hypothesis carries an actual HTTP path the
// agent can request against the live target. Discovering routes from the SOURCE
// (not just the crawlable UI) also surfaces internal/admin endpoints a
// black-box crawler never reaches. Correlating route↔sink by same-file
// proximity turns "there's an rce sink somewhere" into "POST /admin/exec is
// declared in the file that has the rce sink — attack it" — the concrete
// source→runtime lead the evidence loop needs.
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

// maxRouteSeed caps how many route hypotheses a single sweep seeds so a large
// codebase cannot flood the ledger.
const maxRouteSeed = 40

// routeVulnSeverity orders sink vuln classes most-dangerous-first, so a route
// whose file contains several sink classes is typed by the worst one.
var routeVulnSeverity = []string{"rce", "ssti", "deserialization", "sqli", "ssrf", "lfi", "open_redirect"}

func (a *Agent) registerScanSourceRoutesTool(reg *tools.Registry) {
	reg.Register(&tools.Tool{
		Name:        "scan_source_routes",
		Description: "Whitebox source-to-runtime bridge (part 2). Extracts HTTP route declarations from the target's attached source (Flask/FastAPI, Django, Express, Spring, Go routers, Rails) and seeds each as a ledger hypothesis with a REAL, reachable path — including internal/admin routes a black-box crawler can't reach. Routes whose handler file also contains a dangerous sink (see scan_source_sinks) are seeded class-typed and higher-confidence, turning 'there is an rce sink somewhere' into 'POST /admin/exec reaches it'. Run after source is configured; then use read_ledger(filter=schedulable) / claim_next_hypothesis and request each route on the live target. Only available when source is configured; otherwise fall back to black-box discovery.",
		Parameters: []tools.Parameter{
			{Name: "max", Description: "Max routes to seed (default 60, hard cap 300).", Required: false},
		},
		Execute: a.scanSourceRoutesTool,
	})
}

func (a *Agent) scanSourceRoutesTool(args map[string]string) (tools.Result, error) {
	if a.scanCtx == nil {
		return tools.Result{Error: "no scan context — scan_source_routes needs a scan to seed hypotheses into"}, nil
	}
	if codesearch.GetSourceRoot(a.scanCtx.ID) == "" {
		return tools.Result{Output: "❌ Whitebox source not configured for this scan (set XALGORIX_SOURCE_REPO to a git URL or local path). Fall back to black-box discovery: crawl the live target and read client-side JS bundles to map routes."}, nil
	}

	maxRoutes := 60
	if raw := strings.TrimSpace(args["max"]); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			maxRoutes = n
		}
	}

	routes, err := codesearch.RouteScan(a.scanCtx.ID, maxRoutes)
	if err != nil {
		return tools.Result{Error: "scan_source_routes: " + err.Error()}, nil
	}
	if len(routes) == 0 {
		return tools.Result{Output: "Swept the source for HTTP route declarations and found none of the known framework patterns (Flask/FastAPI, Django, Express, Spring, Go routers, Rails). The app may use an uncommon router — try code_search with a custom regex, or map routes by crawling the live target."}, nil
	}

	// Correlate routes with dangerous sinks in the same file (best-effort: a
	// sink-scan failure just means no correlation, not a hard error).
	byFile := map[string][]string{}
	if found, serr := codesearch.SinkScan(a.scanCtx.ID, 20); serr == nil {
		byFile = sinkVulnsByFile(found)
	}

	seeded, correlated := a.seedRoutes(routes, byFile)

	// Deterministic summary: routes grouped by framework.
	frameworks := map[string]int{}
	for _, r := range routes {
		frameworks[r.Framework]++
	}
	fwNames := make([]string, 0, len(frameworks))
	for f := range frameworks {
		fwNames = append(fwNames, f)
	}
	sort.Strings(fwNames)

	var b strings.Builder
	fmt.Fprintf(&b, "Discovered %d HTTP route(s) in source across %d framework(s):\n", len(routes), len(fwNames))
	for _, f := range fwNames {
		fmt.Fprintf(&b, "  • %s: %d\n", f, frameworks[f])
	}
	if seeded > 0 {
		fmt.Fprintf(&b, "Seeded %d route hypotheses into the ledger (origin=source-route)", seeded)
		if correlated > 0 {
			fmt.Fprintf(&b, ", %d correlated with a same-file dangerous sink (class-typed, higher confidence)", correlated)
		}
		b.WriteString(". Use read_ledger(filter=schedulable) or claim_next_hypothesis, then request each route on the live target and prove the vuln.")
	} else {
		b.WriteString("No new route hypotheses seeded (these routes are already in the ledger).")
	}
	return tools.Result{Output: b.String(), Metadata: map[string]any{"routes": len(routes), "seeded": seeded, "correlated": correlated}}, nil
}

// sinkVulnsByFile inverts a SinkScan result into file -> sorted, deduplicated
// canonical vuln classes, using the same sinkClassToVuln allowlist as
// scan_source_sinks (discovery-only classes are skipped). It is the lookup
// seedRoutes uses to type a route by the dangerous sinks in its handler file.
func sinkVulnsByFile(found map[string][]codesearch.SinkMatch) map[string][]string {
	byFile := map[string]map[string]bool{}
	for class, matches := range found {
		vuln, ok := sinkClassToVuln[class]
		if !ok {
			continue
		}
		for _, m := range matches {
			if byFile[m.File] == nil {
				byFile[m.File] = map[string]bool{}
			}
			byFile[m.File][vuln] = true
		}
	}
	out := map[string][]string{}
	for file, set := range byFile {
		for v := range set {
			out[file] = append(out[file], v)
		}
		sort.Strings(out[file])
	}
	return out
}

// highestSeverityVuln picks the most-dangerous vuln class present, falling back
// to the lexically-first when none are in the severity list.
func highestSeverityVuln(vulns []string) string {
	set := map[string]bool{}
	for _, v := range vulns {
		set[v] = true
	}
	for _, v := range routeVulnSeverity {
		if set[v] {
			return v
		}
	}
	if len(vulns) > 0 {
		sorted := append([]string(nil), vulns...)
		sort.Strings(sorted)
		return sorted[0]
	}
	return ""
}

// seedRoutes upserts bounded, deduplicated route hypotheses from a route sweep
// and returns how many NEW hypotheses were created and how many of those were
// correlated with a same-file dangerous sink. Each hypothesis carries a REAL
// HTTP path as Endpoint and Origin=source-route. A route whose handler file
// contains a dangerous sink is typed by that sink's (worst) vuln class at
// confidence 0.45; an uncorrelated route seeds as an authz/attack-surface
// (idor) lead at confidence 0.3. Idempotent: the ledger dedups by
// vuln_class+endpoint, so re-seeding the same routes adds nothing.
func (a *Agent) seedRoutes(routes []codesearch.RouteMatch, sinkVulnsByFile map[string][]string) (seeded, correlated int) {
	l := a.ledger()
	if l == nil {
		return 0, 0
	}
	for _, r := range routes {
		if seeded >= maxRouteSeed {
			break
		}
		path := strings.TrimSpace(r.Path)
		if path == "" {
			continue
		}
		loc := fmt.Sprintf("%s:%d", r.File, r.Line)
		label := path
		if r.Method != "" && r.Method != "ANY" {
			label = r.Method + " " + path
		}

		vuln := ""
		if vulns := sinkVulnsByFile[r.File]; len(vulns) > 0 {
			vuln = highestSeverityVuln(vulns)
		}

		var h scanctx.Hypothesis
		if vuln != "" {
			h = scanctx.Hypothesis{
				Title:      fmt.Sprintf("Source route %s → %s sink", label, vuln),
				VulnClass:  vuln,
				Endpoint:   path,
				DataFlow:   fmt.Sprintf("source-route: %s %s @ %s → reaches a %s sink in the same file", r.Framework, label, loc, vuln),
				Confidence: 0.45,
				Status:     scanctx.HypothesisQueued,
				Origin:     "source-route",
				NextAction: fmt.Sprintf("Request %s on the live target; its handler file %s contains a %s sink — drive user input to it and prove %s.", label, r.File, vuln, vuln),
			}
		} else {
			h = scanctx.Hypothesis{
				Title:      "Source route " + label,
				VulnClass:  "idor",
				Endpoint:   path,
				DataFlow:   fmt.Sprintf("source-route: %s %s @ %s", r.Framework, label, loc),
				Confidence: 0.3,
				Status:     scanctx.HypothesisQueued,
				Origin:     "source-route",
				NextAction: "Request this source-discovered route on the live target; probe for broken access control (IDOR/BOLA) and injection.",
			}
		}

		before := l.Len()
		l.Upsert(h)
		if l.Len() > before {
			seeded++
			if vuln != "" {
				correlated++
			}
		}
	}
	return seeded, correlated
}
