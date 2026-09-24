package agent

import (
	"strings"
	"testing"
)

func TestRegistrableSuffix(t *testing.T) {
	cases := map[string]string{
		"www.xalgorix.com": "xalgorix.com",
		"xalgorix.com":     "xalgorix.com",
		"api.a.b.example":  "b.example",
		"bbc.co.uk":        "bbc.co.uk",
		"deep.site.co.in":  "site.co.in",
		"co.uk":            "",
		"localhost":        "",
	}
	for host, want := range cases {
		if got := registrableSuffix(host); got != want {
			t.Errorf("registrableSuffix(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestEngagementScopeTargetAndSubdomains(t *testing.T) {
	s := buildEngagementScope([]string{"https://www.xalgorix.com"}, false)
	allowed := []string{
		"www.xalgorix.com",
		"https://www.xalgorix.com/api/public/v1/findings",
		"api.xalgorix.com",
		"xalgorix.com",
		"deep.assets.xalgorix.com",
		"https://xalgorix.com:8443/login",
		"www.xalgorix.com:9000",
	}
	for _, h := range allowed {
		if !s.Authorized(h) {
			t.Errorf("expected %q to be authorized", h)
		}
	}
	blocked := []string{
		"ncdrcdylkcstetmltagu.supabase.co",
		"supabase.co",
		"evil.com",
		"xalgorix.com.evil.tld",
		"notxalgorix.com",
		"159.223.74.62",
	}
	for _, h := range blocked {
		if s.Authorized(h) {
			t.Errorf("expected %q to be OUT of scope", h)
		}
	}
}

func TestEngagementScopeMultiLevelTLD(t *testing.T) {
	s := buildEngagementScope([]string{"https://bbc.co.uk"}, false)
	if !s.Authorized("news.bbc.co.uk") {
		t.Error("subdomain of a multi-label-TLD target must be authorized")
	}
	if s.Authorized("other.co.uk") {
		t.Fatal("a bbc.co.uk target must never authorize *.co.uk")
	}
}

func TestEngagementScopeIPTarget(t *testing.T) {
	s := buildEngagementScope([]string{"http://192.0.2.10:8080"}, false)
	if !s.Authorized("192.0.2.10") || !s.Authorized("http://192.0.2.10:8080/app") {
		t.Error("the IP target itself must be authorized")
	}
	if s.Authorized("192.0.2.11") {
		t.Error("a neighboring discovered IP must NOT be authorized")
	}
}

func TestEngagementScopeWildcardTarget(t *testing.T) {
	s := buildEngagementScope([]string{"*.pentest-ground.com"}, false)
	if !s.Authorized("app.pentest-ground.com") || !s.Authorized("pentest-ground.com") {
		t.Error("wildcard target must authorize the domain and its subdomains")
	}
}

func TestEngagementScopeExemptions(t *testing.T) {
	s := buildEngagementScope([]string{"https://www.xalgorix.com"}, false)
	for _, h := range []string{
		"crt.sh", "dns.google", "1.1.1.1", "8.8.8.8",
		"proxy.golang.org", "pypi.org", "http.kali.org", "raw.githubusercontent.com",
	} {
		if !s.Authorized(h) {
			t.Errorf("third-party service %q must be exempt from the engagement scope", h)
		}
	}
}

func TestEngagementScopeNoTargetsNoEnforcement(t *testing.T) {
	s := buildEngagementScope(nil, false)
	if s.Enforces() {
		t.Fatal("empty scope must not enforce")
	}
	if !s.Authorized("anything.example") {
		t.Fatal("non-enforcing scope must allow everything")
	}
}

func TestContainsDestructiveReset(t *testing.T) {
	must := []string{
		"rails db:reset", "RAILS DB:RESET", "curl -X POST https://t/api --data 'DROP TABLE users'",
		"prisma migrate reset", "echo factory reset", "redis-cli flushall",
		"npm run db:reset", "the app's Create / Reset Database function",
		"TRUNCATE TABLE sessions;",
	}
	for _, m := range must {
		if !containsDestructiveReset(strings.ToLower(m)) {
			t.Errorf("expected %q to match", m)
		}
	}
	mustNot := []string{
		"curl https://target/reset-password",
		"POST /api/password-reset",
		"reset-password token reuse",
		"password reset flow test",
	}
	for _, m := range mustNot {
		if containsDestructiveReset(strings.ToLower(m)) {
			t.Errorf("false positive: %q must NOT match", m)
		}
	}
}

// TestShouldBlockOutOfScopeSupabasePivotIncident reproduces the VDP
// disclosure (2026-09-24) end-to-end: an agent authorized against
// www.xalgorix.com reads the target's SPA bundle, then pivots to the
// third-party Supabase backend it finds there. Every leg of that
// pivot must now be rejected.
func TestShouldBlockOutOfScopeSupabasePivotIncident(t *testing.T) {
	a := &Agent{}
	a.engagement = buildEngagementScope([]string{"https://www.xalgorix.com"}, false)

	// Reading the backend out of the target's frontend bundle: blocked.
	blocked, reason := a.shouldBlockForOutOfScope("http_request", map[string]string{
		"url":    "https://ncdrcdylkcstetmltagu.supabase.co/rest/v1/trust_pages?select=*",
		"method": "GET",
	})
	if !blocked || !strings.Contains(reason, "OUT-OF-SCOPE") {
		t.Fatalf("anon read of the third-party backend must be rejected, got blocked=%v reason=%q", blocked, reason)
	}

	// Writes against it: blocked the same way.
	for _, method := range []string{"POST", "PATCH", "DELETE"} {
		blocked, _ = a.shouldBlockForOutOfScope("http_request", map[string]string{
			"url":    "https://ncdrcdylkcstetmltagu.supabase.co/rest/v1/trust_pages",
			"method": method,
		})
		if !blocked {
			t.Fatalf("%s against the third-party backend must be rejected", method)
		}
	}

	// The throwaway-account signup leg: blocked.
	blocked, _ = a.shouldBlockForOutOfScope("http_request", map[string]string{
		"url":    "https://ncdrcdylkcstetmltagu.supabase.co/auth/v1/signup",
		"method": "POST",
	})
	if !blocked {
		t.Fatal("signup against the third-party backend must be rejected")
	}

	// A terminal pivot is blocked too.
	blocked, _ = a.shouldBlockForOutOfScope("terminal_execute", map[string]string{
		"command": "curl -sS -X PATCH https://ncdrcdylkcstetmltagu.supabase.co/rest/v1/trust_pages -H 'apikey: eyJhbGciOiJIUzI1NiJ9' -d '{\"enabled\":false}'",
	})
	if !blocked {
		t.Fatal("terminal pivot to the third-party backend must be rejected")
	}

	// The authorized target and its subdomains still work.
	blocked, _ = a.shouldBlockForOutOfScope("http_request", map[string]string{
		"url": "https://www.xalgorix.com/assets/index-abc.js",
	})
	if blocked {
		t.Fatal("reading the authorized target's own assets must stay allowed")
	}
	blocked, _ = a.shouldBlockForOutOfScope("http_request", map[string]string{
		"url": "https://api.xalgorix.com/api/public/v1/findings",
	})
	if blocked {
		t.Fatal("a subdomain of the authorized target's registrable domain must stay allowed")
	}

	// Passive recon data sources stay reachable.
	blocked, _ = a.shouldBlockForOutOfScope("terminal_execute", map[string]string{
		"command": `curl -s "https://crt.sh/?q=xalgorix.com&output=json" | jq -r '.[].name_value'`,
	})
	if blocked {
		t.Fatal("crt.sh passive recon must stay exempt")
	}
}

func TestShouldBlockOutOfScopeDestructivePrimitives(t *testing.T) {
	a := &Agent{}
	a.engagement = buildEngagementScope([]string{"https://target.example.com"}, false)

	// Even against the AUTHORIZED host, reset primitives are refused.
	blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", map[string]string{
		"command": "curl -X POST https://target.example.com/admin --data 'action=reset database'",
	})
	if !blocked || !strings.Contains(reason, "reset") {
		t.Fatalf("database reset against an authorized host must be refused, got %v %q", blocked, reason)
	}
	blocked, _ = a.shouldBlockForOutOfScope("http_request", map[string]string{
		"url":  "https://target.example.com/api/admin",
		"body": `{"operation":"truncate table sessions"}`,
	})
	if !blocked {
		t.Fatal("TRUNCATE in an http_request body must be refused")
	}

	// Ordinary traffic to the authorized target is untouched.
	blocked, _ = a.shouldBlockForOutOfScope("terminal_execute", map[string]string{
		"command": "curl -sS https://target.example.com/reset-password -d 'email=a@b.c'",
	})
	if blocked {
		t.Fatal("a password-reset endpoint on the authorized target must not trip the destructive screen")
	}

	// Evidence text in report_vulnerability never trips the destructive
	// screen — only traffic-executing tools are screened.
	blocked, _ = a.shouldBlockForOutOfScope("report_vulnerability", map[string]string{
		"title":    "SQL injection allowing DROP TABLE",
		"target":   "https://target.example.com",
		"endpoint": "https://target.example.com/search?q=1",
		"evidence": "The sqlmap output shows DROP TABLE users would succeed",
	})
	if blocked {
		t.Fatal("findings quoting hostile strings as evidence must not be refused")
	}
}

// TestShouldBlockOutOfScopeNilScopeKeepsLegacyBehavior pins the contract
// the historical guard suite depends on: without a populated engagement
// scope (agents not started via Run), third-party hosts are not blocked
// by the engagement leg. The Local_Or_Listener and destructive screens
// still apply.
func TestShouldBlockOutOfScopeNilScopeKeepsLegacyBehavior(t *testing.T) {
	a := &Agent{}
	blocked, _ := a.shouldBlockForOutOfScope("http_request", map[string]string{
		"url": "https://unrelated-third-party.example/data",
	})
	if blocked {
		t.Fatal("nil engagement scope must not block third-party hosts (legacy unit-test posture)")
	}
	// The destructive screen is scope-independent and still fires.
	blocked, _ = a.shouldBlockForOutOfScope("terminal_execute", map[string]string{
		"command": "echo db:reset",
	})
	if !blocked {
		t.Fatal("destructive screen must fire even without an engagement scope")
	}
}

// TestEngagementScopeDoesNotBlockFilenameAndEmailTokens pins the
// false-positive class the strict extractor exists for: filenames,
// version strings, and emails in commands are not network destinations.
func TestEngagementScopeDoesNotBlockFilenameAndEmailTokens(t *testing.T) {
	a := &Agent{}
	a.engagement = buildEngagementScope([]string{"https://target.example.com"}, false)

	blocked, reason := a.shouldBlockForOutOfScope("terminal_execute", map[string]string{
		"command": "cat app.js notes.txt | grep api && curl -sS https://target.example.com/reset-password -d 'email=a@b.c'",
	})
	if blocked {
		t.Fatalf("filenames/emails must not trip the scope gate: %s", reason)
	}

	// A schemeless numeric host:port destination IS extracted: authorized here.
	blocked, _ = a.shouldBlockForOutOfScope("terminal_execute", map[string]string{
		"command": "curl -sS target.example.com:8443/api/health",
	})
	if blocked {
		t.Fatal("schemeless host:port to the authorized target must pass")
	}

	// ...and a schemeless host:port third-party pivot is rejected.
	blocked, _ = a.shouldBlockForOutOfScope("terminal_execute", map[string]string{
		"command": "curl -sS ncdrcdylkcstetmltagu.supabase.co:443/rest/v1/trust_pages",
	})
	if !blocked {
		t.Fatal("schemeless host:port to a third-party backend must be rejected")
	}

	// Header-style tokens are not destinations.
	blocked, _ = a.shouldBlockForOutOfScope("http_request", map[string]string{
		"url":     "https://target.example.com/api",
		"headers": "content-type:application/json",
	})
	if blocked {
		t.Fatal("header tokens must not trip the scope gate")
	}
}
