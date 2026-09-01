package agent

import (
	"testing"
	"time"

	oobsrv "github.com/xalgord/xalgorix/v4/internal/oob"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func newOOBAgent(t *testing.T) *Agent {
	t.Helper()
	// verify_oob reaches the ledger via a.scanCtx.Ledger directly (no active-
	// context registry lookup), so a bare ScanContext is enough.
	return &Agent{scanCtx: scanctx.New("oob-test-"+t.Name(), "")}
}

func httpHit(assessed, scanner bool) oobsrv.Interaction {
	return oobsrv.Interaction{Protocol: "http", Method: "GET", Path: "/", RemoteAddr: "203.0.113.9", OriginAssessed: assessed, ScannerOrigin: scanner, Time: time.Now()}
}

func dnsHit() oobsrv.Interaction {
	return oobsrv.Interaction{Protocol: "dns", Method: "DNS", RemoteAddr: "198.51.100.7", Time: time.Now()}
}

func TestFinalizeOOBVerdict(t *testing.T) {
	cases := []struct {
		name          string
		class         string
		hits          []oobsrv.Interaction
		wantConfirmed bool
	}{
		{"ssrf assessed non-scanner HTTP confirms", "blind-ssrf", []oobsrv.Interaction{httpHit(true, false)}, true},
		{"ssrf dns-only is a lead, not proof", "blind-ssrf", []oobsrv.Interaction{dnsHit()}, false},
		{"ssrf scanner-origin HTTP does not confirm", "ssrf", []oobsrv.Interaction{httpHit(true, true)}, false},
		{"ssrf origin-unassessed HTTP does not confirm", "blind-ssrf", []oobsrv.Interaction{httpHit(false, false)}, false},
		{"blind-rce non-scanner HTTP confirms", "blind-rce", []oobsrv.Interaction{httpHit(true, false)}, true},
		{"blind-rce DNS callback confirms", "blind-rce", []oobsrv.Interaction{dnsHit()}, true},
		{"blind-cmdi DNS callback confirms", "blind-cmdi", []oobsrv.Interaction{dnsHit()}, true},
		{"blind-rce scanner-origin only does not confirm", "blind-rce", []oobsrv.Interaction{httpHit(true, true)}, false},
		{"no interactions", "blind-sqli", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ag := newOOBAgent(t)
			res := ag.finalizeOOBVerdict("tok-"+tc.name, tc.class, "/api/x", "q", "user", tc.hits)
			got, _ := res.Metadata["oob_confirmed"].(bool)
			if got != tc.wantConfirmed {
				t.Fatalf("confirmed=%v want %v (output: %s)", got, tc.wantConfirmed, res.Output)
			}
			ledgerLen := ag.scanCtx.Ledger.Len()
			if tc.wantConfirmed {
				if ledgerLen != 1 {
					t.Fatalf("expected 1 ledger hypothesis on confirm, got %d", ledgerLen)
				}
				h := ag.scanCtx.Ledger.All()[0]
				if h.VulnClass != normalizeBlindClass(tc.class) {
					t.Fatalf("expected class %q, got %q", normalizeBlindClass(tc.class), h.VulnClass)
				}
				if h.Status != scanctx.HypothesisTesting {
					t.Fatalf("expected status testing (not auto-proven), got %q", h.Status)
				}
				if len(h.Evidence) != 1 || h.Evidence[0].Kind != "exploit" {
					t.Fatalf("expected one exploit evidence, got %#v", h.Evidence)
				}
			} else if ledgerLen != 0 {
				t.Fatalf("expected empty ledger when not confirmed, got %d", ledgerLen)
			}
		})
	}
}

func TestOOBVerifyToolValidation(t *testing.T) {
	ag := newOOBAgent(t)
	if res, _ := ag.oobVerifyTool(map[string]string{"vuln_class": "blind-rce"}); res.Error == "" {
		t.Fatal("expected error when token is missing")
	}
	if res, _ := ag.oobVerifyTool(map[string]string{"token": "abc"}); res.Error == "" {
		t.Fatal("expected error when vuln_class is missing")
	}
}
