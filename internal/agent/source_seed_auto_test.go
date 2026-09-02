package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/codesearch"
)

// TestSeedLedgerFromSource exercises the full whitebox bridge end-to-end: a
// Flask app whose handler file declares a route AND contains an rce sink should
// auto-seed both a source-sink hypothesis and a route hypothesis, with the
// route correlated to the co-located sink.
func TestSeedLedgerFromSource(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("src-seed-"+t.Name(), "")}
	dir := t.TempDir()
	src := "from flask import Flask, request\n" +
		"import os\n" +
		"app = Flask(__name__)\n\n" +
		"@app.route('/run')\n" +
		"def run():\n" +
		"    os.system(request.args.get('cmd'))\n" +
		"    return 'ok'\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	codesearch.SetSourceRoot(ag.scanCtx.ID, dir)
	defer codesearch.SetSourceRoot(ag.scanCtx.ID, "")

	sum := ag.seedLedgerFromSource()
	if sum.SinkHypotheses == 0 {
		t.Fatalf("expected source-sink hypotheses seeded, got 0")
	}
	if sum.RouteHypotheses == 0 {
		t.Fatalf("expected route hypotheses seeded, got 0")
	}
	if sum.Correlated == 0 {
		t.Fatalf("expected the /run route to correlate with the rce sink in app.py, got 0")
	}

	var haveSink, haveRoute bool
	for _, h := range ag.scanCtx.Ledger.All() {
		switch h.Origin {
		case "source-sink":
			haveSink = true
		case "source-route":
			haveRoute = true
		}
	}
	if !haveSink || !haveRoute {
		t.Fatalf("expected both source-sink and source-route hypotheses in the ledger, sink=%v route=%v", haveSink, haveRoute)
	}
}

// TestSeedLedgerFromSourceNoSource verifies the auto-seed is a no-op when no
// whitebox source is configured for the scan.
func TestSeedLedgerFromSourceNoSource(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("src-seed-nosrc-"+t.Name(), "")}
	if sum := ag.seedLedgerFromSource(); sum.SinkHypotheses != 0 || sum.RouteHypotheses != 0 {
		t.Fatalf("no source configured must seed nothing, got %+v", sum)
	}
}
