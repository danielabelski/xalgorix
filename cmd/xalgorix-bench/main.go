// Command xalgorix-bench runs the scanner against the built-in benchmark
// challenges and prints a per-class scorecard. It is an operator tool, NOT part
// of the shipped release: each challenge triggers a full LLM-driven agent run
// with live network + tool execution, so it needs XALGORIX_LLM + XALGORIX_API_KEY
// (or a provider profile) set and cannot run in CI.
//
// Usage:
//
//	XALGORIX_LLM=... XALGORIX_API_KEY=... xalgorix-bench [-only reflected-xss,idor] [-task "..."]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/bench"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

func main() {
	only := flag.String("only", "", "comma-separated challenge names to run (default: all built-in)")
	task := flag.String("task", "Perform a full security assessment of this target and prove any vulnerability you find with a concrete PoC.", "instruction passed to the agent")
	timeout := flag.Duration("timeout", bench.DefaultChallengeTimeout, "per-challenge wall-clock timeout (e.g. 5m); 0 disables")
	flag.Parse()

	cfg := config.Get()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "xalgorix-bench: config invalid — set XALGORIX_LLM and XALGORIX_API_KEY (or XALGORIX_LLM_PROFILE):", err)
		os.Exit(2)
	}

	challenges := bench.Builtin()
	if *only != "" {
		challenges = filterChallenges(challenges, *only)
		if len(challenges) == 0 {
			fmt.Fprintf(os.Stderr, "xalgorix-bench: no built-in challenges matched -only=%q\n", *only)
			os.Exit(2)
		}
	}

	fmt.Fprintf(os.Stderr, "xalgorix-bench: running %d challenge(s) with model %s (per-challenge timeout %s)\n", len(challenges), cfg.ResolveModel(), *timeout)
	card := bench.RunWithTimeout(context.Background(), challenges, realScan(*task), *timeout)
	fmt.Print(card.String())
}

func filterChallenges(all []bench.Challenge, csv string) []bench.Challenge {
	want := map[string]bool{}
	for _, n := range strings.Split(csv, ",") {
		if n = strings.TrimSpace(n); n != "" {
			want[n] = true
		}
	}
	out := make([]bench.Challenge, 0, len(want))
	for _, c := range all {
		if want[c.Name] {
			out = append(out, c)
		}
	}
	return out
}

// realScan builds the ScanFunc that drives a real agent run against one target
// and returns the findings it produced. Mirrors the production scan wiring
// (internal/web/scan_session.go) minus the dashboard plumbing.
func realScan(instruction string) bench.ScanFunc {
	return func(ctx context.Context, target, sourceDir, scanID string) ([]reporting.Vulnerability, error) {
		cfg := config.Get()

		scanDir := filepath.Join(os.TempDir(), "xalgorix-bench", scanID)
		if err := os.MkdirAll(scanDir, 0o750); err != nil {
			return nil, err
		}
		sc := scanctx.New(scanID, scanDir)
		scanctx.Activate(sc)
		defer func() {
			scanctx.Deactivate(sc.ID)
			sc.Close()
			reporting.CleanupContext(sc.ID)
		}()

		// Drain agent events. Logging the agent's tool calls, verifier/report
		// outcomes, errors, and finish reason to stderr is what makes a failing
		// challenge diagnosable — without it the run is a black box (only infra
		// logs show). Kept compact (one line per event, args/outputs truncated)
		// and prefixed with the scan id so a multi-challenge run stays readable.
		events := make(chan agent.Event, 512)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for ev := range events {
				switch ev.Type {
				case "tool_call":
					fmt.Fprintf(os.Stderr, "  [ev %s] → %s %s\n", scanID, ev.ToolName, briefArgs(ev.ToolArgs))
				case "tool_result":
					if ev.ToolResult.Error != "" {
						fmt.Fprintf(os.Stderr, "  [ev %s] ✗ %s: %s\n", scanID, ev.ToolName, truncate(oneLine(ev.ToolResult.Error), 240))
					} else if isDiagResultTool(ev.ToolName) {
						fmt.Fprintf(os.Stderr, "  [ev %s] ✓ %s: %s\n", scanID, ev.ToolName, truncate(oneLine(ev.ToolResult.Output), 240))
					}
				case "error":
					fmt.Fprintf(os.Stderr, "  [ev %s] ERROR %s\n", scanID, truncate(oneLine(ev.Content), 240))
				case "finished":
					if ev.Aborted {
						fmt.Fprintf(os.Stderr, "  [ev %s] FINISHED aborted=%s %s\n", scanID, ev.AbortReason, truncate(oneLine(ev.Content), 160))
					} else {
						fmt.Fprintf(os.Stderr, "  [ev %s] FINISHED %s\n", scanID, truncate(oneLine(ev.Content), 160))
					}
				}
			}
		}()

		// AllowLocalTargets lets the scan reach the loopback challenge server.
		guard := scopeguard.Config{BindAddr: "127.0.0.1", Port: 0, AllowLocalTargets: true}
		ag := agent.NewAgent(cfg, "XalgorixBench", events, guard, sc)
		ag.SetPhaseRestrictions(nil)
		ag.SetActivityPolicy("active", "active", []string{target})
		// Whitebox challenge: wire the materialized source tree so the scan can
		// use the source-to-runtime bridge (auto-seed + scan_source_sinks/routes
		// + probe_hypothesis), mirroring production's per-scan source repo.
		if sourceDir != "" {
			ag.SetSourceRepo(sourceDir)
			fmt.Fprintf(os.Stderr, "  [bench] %s → source %s\n", scanID, sourceDir)
		}

		fmt.Fprintf(os.Stderr, "  [bench] %s → %s\n", scanID, target)
		// Run the (blocking) scan in a goroutine so the harness's per-challenge
		// deadline can stop a wandering or stuck scan instead of hanging the run.
		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			ag.Run([]string{target}, instruction)
		}()
		select {
		case <-runDone:
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "  [bench] %s → deadline reached, stopping scan\n", scanID)
			ag.Stop()
			<-runDone
		}

		close(events)
		<-done

		findings := reporting.GetVulnerabilitiesForContext(sc.ID)
		for _, f := range findings {
			fmt.Fprintf(os.Stderr, "    finding %s: title=%q endpoint=%q target=%q cwe=%q sev=%q tags=%v\n",
				f.ID, f.Title, f.Endpoint, f.Target, f.CWE, f.Severity, f.Tags)
		}
		return findings, nil
	}
}

// isDiagResultTool reports whether a tool's successful result is worth logging
// in full for diagnosis (verifiers, reporting, OOB polling, authz) — as opposed
// to noisy recon output (curl/ffuf/nuclei) whose call args already tell the
// story.
func isDiagResultTool(name string) bool {
	switch name {
	case "verify_xss", "verify_sqli", "verify_ssti", "verify_oob",
		"report_vulnerability", "oob_callback", "probe_hypothesis", "authz_matrix":
		return true
	}
	return false
}

// briefArgs renders tool args as a compact, deterministic "k=v" list with each
// value shortened, so a tool_call line shows what mattered (the URL, payload,
// title, severity, …) without dumping large request bodies.
func briefArgs(args map[string]string) string {
	if len(args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := oneLine(args[k])
		if v == "" {
			continue
		}
		parts = append(parts, k+"="+truncate(v, 100))
	}
	return truncate(strings.Join(parts, " "), 300)
}

// oneLine collapses whitespace/newlines so a multi-line value stays on one log
// line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// truncate shortens s to at most n runes, appending an ellipsis when cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
