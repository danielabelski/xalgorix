package agent

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func newClaimAgent(t *testing.T) *Agent {
	t.Helper()
	return &Agent{scanCtx: scanctx.New("claim-"+t.Name(), "")}
}

// seedQueued adds a queued hypothesis and returns its stored id.
func seedQueued(l *scanctx.LedgerStore, class, endpoint string, conf float64) string {
	h := l.Upsert(scanctx.Hypothesis{
		VulnClass:  class,
		Endpoint:   endpoint,
		Confidence: conf,
		Status:     scanctx.HypothesisQueued,
		NextAction: "probe " + endpoint,
	})
	return h.ID
}

func TestClaimNextHypothesis_TopQueuedByConfidence(t *testing.T) {
	ag := newClaimAgent(t)
	l := ag.scanCtx.Ledger
	seedQueued(l, "idor", "/a", 0.5)
	topID := seedQueued(l, "sqli", "/b", 0.9)

	res, err := ag.claimNextHypothesisTool(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := res.Metadata["hypothesis_id"].(string); got != topID {
		t.Fatalf("expected to claim highest-confidence %s, got %v", topID, res.Metadata["hypothesis_id"])
	}
	if got, _ := res.Metadata["status"].(string); got != string(scanctx.HypothesisTesting) {
		t.Fatalf("expected claimed status testing, got %v", res.Metadata["status"])
	}
	// Ownership + testing transition persisted.
	h, _ := l.Get(topID)
	if h.Status != scanctx.HypothesisTesting {
		t.Fatalf("expected %s to be testing, got %q", topID, h.Status)
	}
	if h.AssignedTo != ag.ledgerOrigin() {
		t.Fatalf("expected owner %q, got %q", ag.ledgerOrigin(), h.AssignedTo)
	}
}

func TestClaimNextHypothesis_ClassFilter(t *testing.T) {
	ag := newClaimAgent(t)
	l := ag.scanCtx.Ledger
	idorID := seedQueued(l, "idor", "/a", 0.5)
	seedQueued(l, "sqli", "/b", 0.9) // higher confidence, different class

	res, err := ag.claimNextHypothesisTool(map[string]string{"vuln_class": "idor"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := res.Metadata["hypothesis_id"].(string); got != idorID {
		t.Fatalf("expected class filter to claim the idor hypothesis %s, got %v", idorID, res.Metadata["hypothesis_id"])
	}
}

func TestClaimNextHypothesis_SecondClaimExcludesFirst(t *testing.T) {
	ag := newClaimAgent(t)
	l := ag.scanCtx.Ledger
	seedQueued(l, "idor", "/a", 0.9)
	seedQueued(l, "sqli", "/b", 0.8)

	first, _ := ag.claimNextHypothesisTool(map[string]string{})
	second, _ := ag.claimNextHypothesisTool(map[string]string{})
	id1, _ := first.Metadata["hypothesis_id"].(string)
	id2, _ := second.Metadata["hypothesis_id"].(string)
	if id1 == "" || id2 == "" || id1 == id2 {
		t.Fatalf("expected two distinct claims, got %q and %q", id1, id2)
	}
}

func TestClaimNextHypothesis_NothingClaimable(t *testing.T) {
	ag := newClaimAgent(t)
	// Empty ledger.
	res, _ := ag.claimNextHypothesisTool(map[string]string{})
	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
	if _, ok := res.Metadata["hypothesis_id"]; ok {
		t.Fatal("expected no claim on an empty ledger")
	}

	// One queued but of a different class than the filter.
	seedQueued(ag.scanCtx.Ledger, "sqli", "/b", 0.9)
	res2, _ := ag.claimNextHypothesisTool(map[string]string{"vuln_class": "idor"})
	if _, ok := res2.Metadata["hypothesis_id"]; ok {
		t.Fatal("expected no claim when no queued hypothesis matches the class filter")
	}
}
