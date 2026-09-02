package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
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

// TestAuthzIdentitiesUsesIngestedSessionAsRoleA verifies that when no operator
// account is configured, the scan's ingested authenticated session (registered
// via httpclient.SetSessionAuth, e.g. by ingest_har) becomes role A.
func TestAuthzIdentitiesUsesIngestedSessionAsRoleA(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("authz-session-"+t.Name(), ""), ctx: context.Background()}
	httpclient.SetSessionAuth(ag.scanCtx.ID, map[string]string{"Authorization": "Bearer SESSION"})
	defer httpclient.SetSessionAuth(ag.scanCtx.ID, nil)

	ids := ag.authzIdentities()
	if len(ids) != 2 {
		t.Fatalf("expected role-a (from ingested session) + anonymous, got %d identities: %+v", len(ids), ids)
	}
	if ids[0].role != "role-a" || ids[0].headers["Authorization"] != "Bearer SESSION" {
		t.Fatalf("expected role-a carrying the ingested session, got %+v", ids[0])
	}
	if ids[1].role != "anonymous" || ids[1].headers != nil {
		t.Fatalf("expected anonymous with no headers, got %+v", ids[1])
	}
}

// TestAuthzIdentitiesPrefersOperatorAuthOverSession verifies deterministic
// precedence: a configured operator account is role A even when an ingested
// session also exists, and the session is not double-added.
func TestAuthzIdentitiesPrefersOperatorAuthOverSession(t *testing.T) {
	ag := &Agent{targetAuth: "Authorization: Bearer OPERATOR", scanCtx: scanctx.New("authz-prec-"+t.Name(), ""), ctx: context.Background()}
	httpclient.SetSessionAuth(ag.scanCtx.ID, map[string]string{"Authorization": "Bearer SESSION"})
	defer httpclient.SetSessionAuth(ag.scanCtx.ID, nil)

	ids := ag.authzIdentities()
	if len(ids) != 2 {
		t.Fatalf("expected role-a (operator) + anonymous, got %d identities: %+v", len(ids), ids)
	}
	if ids[0].role != "role-a" || ids[0].headers["Authorization"] != "Bearer OPERATOR" {
		t.Fatalf("expected role-a to use the operator account, got %+v", ids[0])
	}
}

// TestAuthzMatrixRunsWithIngestedSession is the end-to-end proof: with only an
// ingested session (no operator accounts), the matrix runs and flags /broken —
// anonymous receives the same owner record as the authenticated session.
func TestAuthzMatrixRunsWithIngestedSession(t *testing.T) {
	srv := authzTestServer()
	defer srv.Close()
	ag := newAuthzAgent(t, true)
	ag.targetAuth = ""
	ag.targetAuthB = ""
	httpclient.SetSessionAuth(ag.scanCtx.ID, map[string]string{"Authorization": "Bearer AAA"})
	defer httpclient.SetSessionAuth(ag.scanCtx.ID, nil)

	res, err := ag.authzMatrixTool(map[string]string{"url": srv.URL + "/broken", "parameter": "id"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(res.Output, "at least two identities") {
		t.Fatalf("expected the matrix to run with an ingested session, got:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, "likely broken access control") {
		t.Fatalf("expected a broken-access-control verdict, got:\n%s", res.Output)
	}
	if got, _ := res.Metadata["recorded_hypotheses"].(int); got != 1 {
		t.Fatalf("expected 1 recorded hypothesis (anonymous vs ingested role A), got %v", res.Metadata["recorded_hypotheses"])
	}
}

// TestAuthzIdentitiesUsesIngestedSessionBAsRoleB verifies that a second session
// registered via ingest_har role=b (SetSessionAuthB) becomes role B when no
// operator second account is configured — enabling two-account IDOR/BOLA.
func TestAuthzIdentitiesUsesIngestedSessionBAsRoleB(t *testing.T) {
	ag := &Agent{scanCtx: scanctx.New("authz-bses-"+t.Name(), ""), ctx: context.Background()}
	httpclient.SetSessionAuth(ag.scanCtx.ID, map[string]string{"Authorization": "Bearer A"})
	httpclient.SetSessionAuthB(ag.scanCtx.ID, map[string]string{"Authorization": "Bearer B"})
	defer httpclient.SetSessionAuth(ag.scanCtx.ID, nil)
	defer httpclient.SetSessionAuthB(ag.scanCtx.ID, nil)

	ids := ag.authzIdentities()
	if len(ids) != 3 {
		t.Fatalf("expected role-a + role-b (both ingested) + anonymous, got %d: %+v", len(ids), ids)
	}
	if ids[0].role != "role-a" || ids[0].headers["Authorization"] != "Bearer A" {
		t.Fatalf("role A wrong: %+v", ids[0])
	}
	if ids[1].role != "role-b" || ids[1].headers["Authorization"] != "Bearer B" {
		t.Fatalf("role B (ingested) wrong: %+v", ids[1])
	}
	if ids[2].role != "anonymous" {
		t.Fatalf("expected anonymous last, got %+v", ids[2])
	}
}

// TestAuthzIdentitiesPrefersOperatorAuthBOverSessionB verifies operator role-B
// precedence over an ingested role-B session.
func TestAuthzIdentitiesPrefersOperatorAuthBOverSessionB(t *testing.T) {
	ag := &Agent{targetAuthB: "Authorization: Bearer OPB", scanCtx: scanctx.New("authz-bprec-"+t.Name(), ""), ctx: context.Background()}
	httpclient.SetSessionAuthB(ag.scanCtx.ID, map[string]string{"Authorization": "Bearer SESB"})
	defer httpclient.SetSessionAuthB(ag.scanCtx.ID, nil)

	var rb *authzIdentity
	ids := ag.authzIdentities()
	for i := range ids {
		if ids[i].role == "role-b" {
			rb = &ids[i]
		}
	}
	if rb == nil || rb.headers["Authorization"] != "Bearer OPB" {
		t.Fatalf("expected role B to use the operator account, got %+v", rb)
	}
}

// TestAuthzMatrixTwoIngestedAccounts is the end-to-end two-account proof: role A
// and role B both come from ingested sessions, and the matrix flags /broken
// (role B and anonymous both reach role A's owner record).
func TestAuthzMatrixTwoIngestedAccounts(t *testing.T) {
	srv := authzTestServer()
	defer srv.Close()
	ag := newAuthzAgent(t, true)
	ag.targetAuth = ""
	ag.targetAuthB = ""
	httpclient.SetSessionAuth(ag.scanCtx.ID, map[string]string{"Authorization": "Bearer AAA"})
	httpclient.SetSessionAuthB(ag.scanCtx.ID, map[string]string{"Authorization": "Bearer BBB"})
	defer httpclient.SetSessionAuth(ag.scanCtx.ID, nil)
	defer httpclient.SetSessionAuthB(ag.scanCtx.ID, nil)

	res, err := ag.authzMatrixTool(map[string]string{"url": srv.URL + "/broken", "parameter": "id"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := res.Metadata["recorded_hypotheses"].(int); got != 2 {
		t.Fatalf("expected 2 recorded (role B + anonymous), got %v", res.Metadata["recorded_hypotheses"])
	}
	var roles []string
	for _, h := range ag.scanCtx.Ledger.All() {
		roles = append(roles, h.Role)
	}
	if !contains(roles, "role-b") {
		t.Fatalf("expected a role-b hypothesis, got roles %v", roles)
	}
}
