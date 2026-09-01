package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// authzTestServer returns a server with a /broken endpoint (no authorization
// check — anyone gets the owner's data) and a /secure endpoint (only role A's
// token succeeds; role B is forbidden; anonymous is redirected to login).
func authzTestServer() *httptest.Server {
	const ownerData = "SECRET-ORDER-DATA-1042-owner-record-padding-padding-padding-padding"
	mux := http.NewServeMux()
	mux.HandleFunc("/broken", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ownerData))
	})
	mux.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer AAA":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(ownerData))
		case "":
			http.Redirect(w, r, "/login", http.StatusFound)
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
		}
	})
	return httptest.NewServer(mux)
}

func newAuthzAgent(t *testing.T, allowLocal bool) *Agent {
	t.Helper()
	return &Agent{
		targetAuth:  "Authorization: Bearer AAA",
		targetAuthB: "Authorization: Bearer BBB",
		localGuard:  scopeguard.Config{AllowLocalTargets: allowLocal},
		scanCtx:     scanctx.New("authz-test-"+t.Name(), ""),
		ctx:         context.Background(),
	}
}

func TestAuthzMatrixDetectsBrokenAccessControl(t *testing.T) {
	srv := authzTestServer()
	defer srv.Close()
	ag := newAuthzAgent(t, true)

	res, err := ag.authzMatrixTool(map[string]string{"url": srv.URL + "/broken", "parameter": "id"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Error != "" {
		t.Fatalf("unexpected tool error: %s", res.Error)
	}
	if !strings.Contains(res.Output, "likely broken access control") {
		t.Fatalf("expected a broken-access-control verdict, got:\n%s", res.Output)
	}
	if got, _ := res.Metadata["recorded_hypotheses"].(int); got != 2 {
		t.Fatalf("expected 2 recorded hypotheses (role B + anonymous), got %v", res.Metadata["recorded_hypotheses"])
	}

	l := ag.scanCtx.Ledger
	if l.Len() != 2 {
		t.Fatalf("expected 2 ledger hypotheses, got %d", l.Len())
	}
	var roles, classes []string
	for _, h := range l.All() {
		roles = append(roles, h.Role)
		classes = append(classes, h.VulnClass)
		if len(h.Evidence) == 0 {
			t.Fatalf("hypothesis %s has no evidence", h.ID)
		}
		if h.Status != scanctx.HypothesisTesting {
			t.Fatalf("expected status testing (not auto-proven), got %q", h.Status)
		}
	}
	if !contains(roles, "role-b") || !contains(roles, "anonymous") {
		t.Fatalf("expected role-b and anonymous hypotheses, got roles %v", roles)
	}
	if !contains(classes, "idor") || !contains(classes, "auth-bypass") {
		t.Fatalf("expected idor + auth-bypass classes, got %v", classes)
	}
}

func TestAuthzMatrixProperlyRestricted(t *testing.T) {
	srv := authzTestServer()
	defer srv.Close()
	ag := newAuthzAgent(t, true)

	res, err := ag.authzMatrixTool(map[string]string{"url": srv.URL + "/secure"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := res.Metadata["recorded_hypotheses"].(int); got != 0 {
		t.Fatalf("expected 0 recorded hypotheses for a restricted endpoint, got %v", res.Metadata["recorded_hypotheses"])
	}
	if !strings.Contains(res.Output, "No cross-identity access-control difference") {
		t.Fatalf("expected a restricted verdict, got:\n%s", res.Output)
	}
	if ag.scanCtx.Ledger.Len() != 0 {
		t.Fatalf("expected an empty ledger for a properly-restricted endpoint, got %d", ag.scanCtx.Ledger.Len())
	}
}

func TestAuthzMatrixRefusesOperatorMachine(t *testing.T) {
	srv := authzTestServer()
	defer srv.Close()
	// Default scope config (AllowLocalTargets false) must refuse loopback.
	ag := newAuthzAgent(t, false)

	res, err := ag.authzMatrixTool(map[string]string{"url": srv.URL + "/broken"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Error == "" || !strings.Contains(res.Error, "operator's machine") {
		t.Fatalf("expected refusal for a loopback target, got error=%q output=%q", res.Error, res.Output)
	}
	if ag.scanCtx.Ledger.Len() != 0 {
		t.Fatal("expected no ledger writes when the target is refused")
	}
}

func TestAuthzMatrixNeedsTwoIdentities(t *testing.T) {
	srv := authzTestServer()
	defer srv.Close()
	ag := newAuthzAgent(t, true)
	ag.targetAuth = ""  // no primary session
	ag.targetAuthB = "" // no second account → only anonymous remains

	res, err := ag.authzMatrixTool(map[string]string{"url": srv.URL + "/broken"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Output, "at least two identities") {
		t.Fatalf("expected a two-identities-required message, got:\n%s", res.Output)
	}
}
