package oob

import "testing"

func TestParseAllowedProtocols(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]bool
	}{
		{"blank means all (nil)", "", nil},
		{"whitespace means all (nil)", "   ", nil},
		{"http only", "http", map[string]bool{"http": true}},
		{"https folds into http", "https", map[string]bool{"http": true}},
		{"http and smtp", "http,smtp", map[string]bool{"http": true, "smtp": true}},
		{"mixed case and spaces", " HTTP , DNS ", map[string]bool{"http": true, "dns": true}},
		{"all three", "dns,http,smtp", map[string]bool{"dns": true, "http": true, "smtp": true}},
		{"unknown tokens are ignored", "http,ftp,foo", map[string]bool{"http": true}},
		{"all-invalid means all (nil), never drop everything", "ftp,gopher", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAllowedProtocols(tt.raw)
			if len(got) != len(tt.want) {
				t.Fatalf("parseAllowedProtocols(%q) = %v, want %v", tt.raw, got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Fatalf("parseAllowedProtocols(%q)[%q] = %v, want %v", tt.raw, k, got[k], v)
				}
			}
		})
	}
}

func TestApplyProtocolFilter(t *testing.T) {
	hits := []Interaction{
		{Protocol: "dns"},
		{Protocol: "http"},
		{Protocol: "https"},
		{Protocol: "smtp"},
	}

	// nil allow-set is a pass-through: nothing is dropped.
	if got := applyProtocolFilter(hits, nil); len(got) != len(hits) {
		t.Fatalf("nil allow-set dropped hits: got %d, want %d", len(got), len(hits))
	}

	// http-only keeps http AND https (https folds into http), drops dns/smtp.
	got := applyProtocolFilter(hits, parseAllowedProtocols("http"))
	if len(got) != 2 {
		t.Fatalf("http-only: got %d hits, want 2 (http+https)", len(got))
	}
	for _, h := range got {
		if h.Protocol != "http" && h.Protocol != "https" {
			t.Fatalf("http-only kept a %q interaction", h.Protocol)
		}
	}

	// http,smtp keeps http/https/smtp, drops dns.
	got = applyProtocolFilter(hits, parseAllowedProtocols("http,smtp"))
	if len(got) != 3 {
		t.Fatalf("http,smtp: got %d hits, want 3", len(got))
	}
	for _, h := range got {
		if h.Protocol == "dns" {
			t.Fatalf("http,smtp must drop dns interactions")
		}
	}
}

// Protocols the DNS/HTTP/SMTP selector does not cover (ldap for JNDI/Log4Shell,
// smb, ftp, or a blank protocol) are separate proof channels and must survive
// any selection.
func TestApplyProtocolFilterKeepsUnselectableProtocols(t *testing.T) {
	hits := []Interaction{
		{Protocol: "dns"},
		{Protocol: "ldap"},
		{Protocol: "smb"},
		{Protocol: "ftp"},
		{Protocol: ""},
	}

	got := applyProtocolFilter(hits, parseAllowedProtocols("http"))
	if len(got) != 4 {
		t.Fatalf("http-only: got %d hits, want 4 (ldap, smb, ftp, blank kept; dns dropped)", len(got))
	}
	for _, h := range got {
		if h.Protocol == "dns" {
			t.Fatalf("http-only must drop dns interactions")
		}
	}
}
