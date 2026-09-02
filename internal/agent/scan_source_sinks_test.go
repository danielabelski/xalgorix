package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/tools/codesearch"
)

// TestSeedSinksMapsClassesAndStampsFields verifies the sink-class → vuln-class
// mapping, that discovery-only classes (secrets/auth/crypto) are skipped, and
// that every seeded hypothesis carries the source-sink stamp (Endpoint=file:line,
// DataFlow, Origin, queued status, confidence 0.3).
func TestSeedSinksMapsClassesAndStampsFields(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("sink-map-"+t.Name(), "")}
	found := map[string][]codesearch.SinkMatch{
		"rce":             {{File: "a.py", Line: 1, Text: "os.system(cmd)"}},
		"cmdi":            {{File: "b.py", Line: 2, Text: "subprocess.call(x)"}},
		"sqli":            {{File: "c.py", Line: 3, Text: "cursor.execute(q)"}},
		"ssrf":            {{File: "d.py", Line: 4, Text: "requests.get(u)"}},
		"fileio":          {{File: "e.py", Line: 5, Text: "open(p)"}},
		"template":        {{File: "f.py", Line: 6, Text: "render_template_string(t)"}},
		"deserialization": {{File: "g.py", Line: 7, Text: "pickle.loads(b)"}},
		"redirect":        {{File: "h.py", Line: 8, Text: "res.redirect(u)"}},
		// Discovery-only classes must be skipped (no runtime source->sink):
		"secrets": {{File: "s.py", Line: 9, Text: "api_key = 'x'"}},
		"auth":    {{File: "au.py", Line: 10, Text: "is_admin == true"}},
		"crypto":  {{File: "cr.py", Line: 11, Text: "MD5(x)"}},
	}

	seeded := ag.seedSinks(found)
	if seeded != 8 {
		t.Fatalf("expected 8 seeded (mapped classes only), got %d", seeded)
	}
	all := ag.scanCtx.Ledger.All()
	if len(all) != 8 {
		t.Fatalf("expected 8 ledger hypotheses, got %d", len(all))
	}

	// endpoint(file:line) -> expected canonical vuln class.
	wantVuln := map[string]string{
		"a.py:1": "rce",  // rce -> rce
		"b.py:2": "rce",  // cmdi -> rce
		"c.py:3": "sqli", // sqli -> sqli
		"d.py:4": "ssrf", // ssrf -> ssrf
		"e.py:5": "lfi",  // fileio -> lfi
		"f.py:6": "ssti", // template -> ssti
		"g.py:7": "deserialization",
		"h.py:8": "open_redirect", // redirect -> open_redirect
	}
	for _, h := range all {
		want, ok := wantVuln[h.Endpoint]
		if !ok {
			t.Fatalf("unexpected hypothesis (skipped class leaked?) endpoint=%q vuln=%q", h.Endpoint, h.VulnClass)
		}
		if h.VulnClass != want {
			t.Fatalf("endpoint %s: vuln = %q, want %q", h.Endpoint, h.VulnClass, want)
		}
		if h.Origin != "source-sink" {
			t.Fatalf("endpoint %s: origin = %q, want source-sink", h.Endpoint, h.Origin)
		}
		if h.Status != scanctx.HypothesisQueued {
			t.Fatalf("endpoint %s: status = %q, want queued", h.Endpoint, h.Status)
		}
		if !strings.HasPrefix(h.DataFlow, "source-sink:") {
			t.Fatalf("endpoint %s: DataFlow = %q, want a source-sink: prefix", h.Endpoint, h.DataFlow)
		}
		if h.Confidence != 0.3 {
			t.Fatalf("endpoint %s: confidence = %v, want 0.3", h.Endpoint, h.Confidence)
		}
	}
}

// TestSeedSinksIdempotent verifies re-seeding the same sinks adds nothing (the
// ledger dedups by vuln_class+endpoint).
func TestSeedSinksIdempotent(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("sink-idem-"+t.Name(), "")}
	found := map[string][]codesearch.SinkMatch{
		"rce":  {{File: "a.py", Line: 1, Text: "os.system(cmd)"}},
		"sqli": {{File: "c.py", Line: 3, Text: "cursor.execute(q)"}},
	}
	if n := ag.seedSinks(found); n != 2 {
		t.Fatalf("first seed = %d, want 2", n)
	}
	if n := ag.seedSinks(found); n != 0 {
		t.Fatalf("second seed must be idempotent (0 new), got %d", n)
	}
	if got := ag.scanCtx.Ledger.Len(); got != 2 {
		t.Fatalf("ledger should still hold 2 hypotheses, got %d", got)
	}
}

// TestSeedSinksBounded verifies a large sweep cannot flood the ledger past
// maxSinkSeed.
func TestSeedSinksBounded(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("sink-bound-"+t.Name(), "")}
	matches := make([]codesearch.SinkMatch, 0, maxSinkSeed*2)
	for i := 0; i < maxSinkSeed*2; i++ {
		matches = append(matches, codesearch.SinkMatch{File: "big.py", Line: i + 1, Text: "os.system(x)"})
	}
	seeded := ag.seedSinks(map[string][]codesearch.SinkMatch{"rce": matches})
	if seeded > maxSinkSeed {
		t.Fatalf("seedSinks must cap at maxSinkSeed=%d, seeded %d", maxSinkSeed, seeded)
	}
	if got := ag.scanCtx.Ledger.Len(); got > maxSinkSeed {
		t.Fatalf("ledger must not exceed maxSinkSeed=%d, got %d", maxSinkSeed, got)
	}
}

// TestSeedSinksNilLedger verifies the helper is safe when there is no scan
// context (some unit paths construct a bare Agent).
func TestSeedSinksNilLedger(t *testing.T) {
	ag := &Agent{}
	if n := ag.seedSinks(map[string][]codesearch.SinkMatch{"rce": {{File: "a", Line: 1}}}); n != 0 {
		t.Fatalf("nil ledger must seed 0, got %d", n)
	}
}

// TestScanSourceSinksToolNoSource verifies the tool degrades gracefully to a
// black-box fallback message (no error, no seeds) when whitebox source is not
// configured for the scan.
func TestScanSourceSinksToolNoSource(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("sink-tool-nosrc-"+t.Name(), "")}
	res, err := ag.scanSourceSinksTool(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Output, "Whitebox source not configured") {
		t.Fatalf("expected black-box fallback message, got: %s", res.Output)
	}
	if ag.scanCtx.Ledger.Len() != 0 {
		t.Fatal("no source configured → nothing should be seeded")
	}
}
