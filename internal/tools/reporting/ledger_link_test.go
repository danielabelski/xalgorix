package reporting

import (
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestLinkFindingToLedger(t *testing.T) {
	ctxID := "report-link-" + t.Name()
	sc := scanctx.New(ctxID, "")
	scanctx.Activate(sc)
	defer scanctx.Deactivate(ctxID)

	h := sc.Ledger.Upsert(scanctx.Hypothesis{
		VulnClass: "idor",
		Endpoint:  "/api/orders",
		Status:    scanctx.HypothesisTesting,
	})

	note := linkFindingToLedger(ctxID, "XALG-7", h.ID)
	if note == "" {
		t.Fatal("expected a non-empty link note when a valid hypothesis id is supplied")
	}
	got, ok := sc.Ledger.Get(h.ID)
	if !ok {
		t.Fatalf("hypothesis %s missing after link", h.ID)
	}
	if got.Status != scanctx.HypothesisProven {
		t.Fatalf("expected hypothesis marked proven, got %q", got.Status)
	}
	linked := false
	for _, ev := range got.Evidence {
		if ev.Kind == scanctx.EvidenceFindingRef && ev.FindingID == "XALG-7" {
			linked = true
		}
	}
	if !linked {
		t.Fatal("expected a finding_ref evidence entry linking XALG-7")
	}
}

func TestLinkFindingToLedgerNoOps(t *testing.T) {
	ctxID := "report-link-noop-" + t.Name()
	sc := scanctx.New(ctxID, "")
	scanctx.Activate(sc)
	defer scanctx.Deactivate(ctxID)
	h := sc.Ledger.Upsert(scanctx.Hypothesis{VulnClass: "xss", Endpoint: "/x", Status: scanctx.HypothesisTesting})

	// Empty hypothesis id → no-op, no link note, hypothesis unchanged.
	if linkFindingToLedger(ctxID, "XALG-1", "") != "" {
		t.Fatal("empty hypothesis id must be a no-op")
	}
	// Unknown hypothesis id → no-op (never fabricate a link).
	if linkFindingToLedger(ctxID, "XALG-1", "H-999") != "" {
		t.Fatal("unknown hypothesis id must be a no-op")
	}
	if got, _ := sc.Ledger.Get(h.ID); got.Status != scanctx.HypothesisTesting {
		t.Fatalf("unrelated hypothesis must stay testing, got %q", got.Status)
	}
}
