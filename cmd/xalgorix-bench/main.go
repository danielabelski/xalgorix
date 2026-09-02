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

	fmt.Fprintf(os.Stderr, "xalgorix-bench: running %d challenge(s) with model %s\n", len(challenges), cfg.ResolveModel())
	card := bench.Run(context.Background(), challenges, realScan(*task))
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
	return func(_ context.Context, target, scanID string) ([]reporting.Vulnerability, error) {
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

		// Drain agent events so the agent never blocks on emit.
		events := make(chan agent.Event, 512)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for range events {
			}
		}()

		// AllowLocalTargets lets the scan reach the loopback challenge server.
		guard := scopeguard.Config{BindAddr: "127.0.0.1", Port: 0, AllowLocalTargets: true}
		ag := agent.NewAgent(cfg, "XalgorixBench", events, guard, sc)
		ag.SetPhaseRestrictions(nil)
		ag.SetActivityPolicy("active", "active", []string{target})

		fmt.Fprintf(os.Stderr, "  [bench] %s → %s\n", scanID, target)
		ag.Run([]string{target}, instruction)

		close(events)
		<-done

		return reporting.GetVulnerabilitiesForContext(sc.ID), nil
	}
}
