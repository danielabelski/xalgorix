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

// DefaultChallengeTimeout bounds how long a single challenge scan may run. A
// scan against a trivial challenge app should finish quickly; without a bound a
// wandering or stuck scan can hang the whole run.
const DefaultChallengeTimeout = 8 * time.Minute

// Run executes each challenge in order with the default per-challenge timeout.
func Run(ctx context.Context, challenges []Challenge, scan ScanFunc) Scorecard {
	return RunWithTimeout(ctx, challenges, scan, DefaultChallengeTimeout)
}

// RunWithTimeout executes each challenge in order: it starts the challenge app,
// invokes the scan against its base URL under a per-challenge deadline, scores
// the findings against the expected class, and aggregates a Scorecard.
// Challenges run sequentially so a single shared LLM/tool budget isn't contended
// and the run is reproducible. A per-challenge timeout <= 0 disables the bound.
func RunWithTimeout(ctx context.Context, challenges []Challenge, scan ScanFunc, perChallenge time.Duration) Scorecard {
	card := Scorecard{Results: make([]Result, 0, len(challenges))}
	for _, c := range challenges {
		if ctx.Err() != nil {
			break
		}
		card.Results = append(card.Results, runOne(ctx, c, scan, perChallenge))
	}
	return card
}

func runOne(parent context.Context, c Challenge, scan ScanFunc, timeout time.Duration) Result {
	srv := c.Start()
	defer srv.Close()

	ctx := parent
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, timeout)
		defer cancel()
	}

	res := Result{Name: c.Name, Class: canonicalClass(c.Class)}
	start := time.Now()
	findings, err := scan(ctx, srv.URL, "bench-"+c.Name)
	res.Elapsed = time.Since(start)
	res.Findings = len(findings)
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	}
	if err != nil && !res.TimedOut {
		res.Err = err
	}
	// Score whatever findings were gathered — a scan that timed out may still
	// have reported the vulnerability before the deadline.
	res.Solved, res.MatchedFindingID = Solved(c.Class, findings)
	return res
}
