// Command xalgorix-xbow runs a single real agent scan against one target URL
// (a running XBOW validation-benchmark container) with a flag-capture task,
// captures the FULL, untruncated tool transcript, and scores the run by
// exact-match flag capture: did the agent's activity (any tool output, any
// reported finding) surface the exact flag injected into the benchmark at build
// time. It is an operator tool (needs XALGORIX_LLM + XALGORIX_API_KEY) and is
// driven by the tmp/xbow-run.sh orchestrator, which manages the Docker
// lifecycle. It deliberately reuses the production agent wiring (mirrors
// cmd/xalgorix-bench realScan) so the score reflects the shipped scanner.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"

	"flag"
)

func main() {
	url := flag.String("url", "", "target URL of the running benchmark (e.g. http://127.0.0.1:32768)")
	task := flag.String("task", "", "instruction passed to the agent")
	expect := flag.String("flag", "", "exact flag string the app hides (e.g. FLAG{...}) for scoring")
	timeout := flag.Duration("timeout", 12*time.Minute, "wall-clock scan timeout")
	outDir := flag.String("out", "", "output dir for transcript.txt + verdict.json (default: TMPDIR/xbow/<scan-id>)")
	scanID := flag.String("scan-id", "xbow", "scan id")
	flag.Parse()

	if *url == "" || *task == "" {
		fmt.Fprintln(os.Stderr, "xalgorix-xbow: -url and -task are required")
		os.Exit(2)
	}
	cfg := config.Get()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "xalgorix-xbow: config invalid — set XALGORIX_LLM and XALGORIX_API_KEY:", err)
		os.Exit(2)
	}

	if *outDir == "" {
		*outDir = filepath.Join(os.TempDir(), "xbow", *scanID)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "xalgorix-xbow: mkdir out:", err)
		os.Exit(2)
	}
	tf, err := os.Create(filepath.Join(*outDir, "transcript.txt"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "xalgorix-xbow: create transcript:", err)
		os.Exit(2)
	}
	defer tf.Close()

	scanDir := filepath.Join(*outDir, "scan")
	_ = os.MkdirAll(scanDir, 0o755)
	sc := scanctx.New(*scanID, scanDir)
	scanctx.Activate(sc)
	defer func() {
		scanctx.Deactivate(sc.ID)
		sc.Close()
		reporting.CleanupContext(sc.ID)
	}()

	// flagSeen is set the instant the injected flag appears in ANY tool output,
	// tool argument, or agent message — this is the ground-truth capture signal
	// (the agent had to exploit the app to surface it). Guarded by a closure so
	// the drain goroutine and the post-run findings sweep both feed it.
	flagSeen := false
	seenWhere := ""
	captured := make(chan struct{})
	var captureOnce sync.Once
	note := func(where string) {
		if !flagSeen {
			flagSeen = true
			seenWhere = where
		}
		// Signal the run loop to stop the moment the flag is first seen: the
		// benchmark is solved (exact-match flag capture) so there is nothing to
		// gain from letting the agent keep probing until the timeout. This is
		// what keeps a 100+ benchmark run's wall-clock sane.
		captureOnce.Do(func() { close(captured) })
	}
	contains := func(s string) bool { return *expect != "" && strings.Contains(s, *expect) }

	events := make(chan agent.Event, 512)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range events {
			switch ev.Type {
			case "tool_call":
				fmt.Fprintf(tf, "\n>>> TOOL %s %s\n", ev.ToolName, fullArgs(ev.ToolArgs))
				if argsContain(ev.ToolArgs, *expect) {
					note("tool_call:" + ev.ToolName)
				}
			case "tool_result":
				if ev.ToolResult.Error != "" {
					fmt.Fprintf(tf, "<<< ERR %s: %s\n", ev.ToolName, ev.ToolResult.Error)
					if contains(ev.ToolResult.Error) {
						note("tool_error:" + ev.ToolName)
					}
				} else {
					fmt.Fprintf(tf, "<<< OUT %s: %s\n", ev.ToolName, ev.ToolResult.Output)
					if contains(ev.ToolResult.Output) {
						note("tool_output:" + ev.ToolName)
					}
				}
			case "message", "thinking":
				if ev.Content != "" {
					fmt.Fprintf(tf, "--- %s: %s\n", ev.Type, ev.Content)
					if contains(ev.Content) {
						note("agent_" + ev.Type)
					}
				}
			case "error":
				fmt.Fprintf(tf, "!!! ERROR %s\n", ev.Content)
			case "finished":
				fmt.Fprintf(tf, "=== FINISHED aborted=%v reason=%s %s\n", ev.Aborted, ev.AbortReason, ev.Content)
			}
		}
	}()

	guard := scopeguard.Config{BindAddr: "127.0.0.1", Port: 0, AllowLocalTargets: true}
	ag := agent.NewAgent(cfg, "XalgorixXBOW", events, guard, sc)
	ag.SetPhaseRestrictions(nil)
	ag.SetActivityPolicy("active", "active", []string{*url})

	fmt.Fprintf(os.Stderr, "xalgorix-xbow: scanning %s (model %s, timeout %s)\n", *url, cfg.ResolveModel(), *timeout)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	aborted, abortReason := false, ""
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		ag.Run([]string{*url}, *task)
	}()
	select {
	case <-runDone:
	case <-captured:
		fmt.Fprintln(os.Stderr, "xalgorix-xbow: flag captured — stopping scan early")
		ag.Stop()
		<-runDone
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "xalgorix-xbow: timeout reached, stopping scan")
		ag.Stop()
		<-runDone
		aborted, abortReason = true, "timeout"
	}
	elapsed := time.Since(start)

	close(events)
	<-done

	// Post-run sweep: the flag may also be embedded in a reported finding's
	// prose (proof / PoC / technical analysis) even if the live drain missed it.
	findings := reporting.GetVulnerabilitiesForContext(sc.ID)
	for _, f := range findings {
		blob := strings.Join([]string{
			f.Title, f.Description, f.Impact, f.TechnicalAnalysis,
			f.PoCDescription, f.PoCScript, f.ExploitationProof,
		}, "\n")
		if contains(blob) {
			note("finding:" + f.ID)
		}
	}

	verdict := map[string]any{
		"scan_id":      *scanID,
		"url":          *url,
		"flag":         *expect,
		"solved":       flagSeen,
		"seen_where":   seenWhere,
		"findings":     len(findings),
		"aborted":      aborted,
		"abort_reason": abortReason,
		"elapsed_s":    int(elapsed.Seconds()),
	}
	b, _ := json.Marshal(verdict)
	_ = os.WriteFile(filepath.Join(*outDir, "verdict.json"), b, 0o644)
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "xalgorix-xbow: solved=%v where=%q findings=%d elapsed=%s\n", flagSeen, seenWhere, len(findings), elapsed.Round(time.Second))
}

// fullArgs renders tool args as a compact but UNtruncated "k=v" list (sorted),
// so the transcript preserves the exact request that captured a flag.
func fullArgs(args map[string]string) string {
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
		parts = append(parts, k+"="+strings.Join(strings.Fields(args[k]), " "))
	}
	return strings.Join(parts, " | ")
}

// argsContain reports whether any tool argument value contains sub.
func argsContain(args map[string]string, sub string) bool {
	if sub == "" {
		return false
	}
	for _, v := range args {
		if strings.Contains(v, sub) {
			return true
		}
	}
	return false
}
