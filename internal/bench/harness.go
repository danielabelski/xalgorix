package bench

import (
	"context"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// ScanFunc runs a full scan against target (the base URL of a challenge app)
// under the given scan id, and returns the findings it produced. It is injected
// so the harness stays free of the heavy, non-hermetic agent machinery: the
// real implementation (cmd/xalgorix-bench) drives the LLM agent and makes live
// calls, while tests pass a deterministic fake.
type ScanFunc func(ctx context.Context, target, scanID string) ([]reporting.Vulnerability, error)

// Run executes each challenge in order: it starts the challenge app, invokes the
// scan against its base URL, scores the findings against the expected class and
// endpoint, and aggregates a Scorecard. Challenges run sequentially so a single
// shared LLM/tool budget isn't contended and the run is reproducible.
func Run(ctx context.Context, challenges []Challenge, scan ScanFunc) Scorecard {
	card := Scorecard{Results: make([]Result, 0, len(challenges))}
	for _, c := range challenges {
		if ctx.Err() != nil {
			break
		}
		card.Results = append(card.Results, runOne(ctx, c, scan))
	}
	return card
}

func runOne(ctx context.Context, c Challenge, scan ScanFunc) Result {
	srv := c.Start()
	defer srv.Close()

	res := Result{Name: c.Name, Class: canonicalClass(c.Class)}
	start := time.Now()
	findings, err := scan(ctx, srv.URL, "bench-"+c.Name)
	res.Elapsed = time.Since(start)
	res.Findings = len(findings)
	if err != nil {
		res.Err = err
		return res
	}
	res.Solved, res.MatchedFindingID = Solved(c.Class, c.Endpoint, findings)
	return res
}
