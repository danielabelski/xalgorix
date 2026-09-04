package agent

import (
	"strings"
	"testing"
)

// TestCsrfVerdict covers the CSRF decision logic without any HTTP: the caller
// supplies the forged request's status code and response body.
func TestCsrfVerdict(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		body          string
		wantConfirmed bool
	}{
		{
			// Vulnerable app: the forged cross-site state change is accepted.
			name: "accepted 200 state change", status: 200, body: "account email updated", wantConfirmed: true,
		},
		{
			// A 302 to a success page is still an accepted state change.
			name: "accepted 302 redirect", status: 302, body: "", wantConfirmed: true,
		},
		{
			// Protected app: tokenless request rejected with 403 + csrf message.
			name: "rejected 403 csrf", status: 403, body: "invalid csrf token", wantConfirmed: false,
		},
		{
			// Laravel-style token-mismatch status.
			name: "rejected 419", status: 419, body: "Page Expired", wantConfirmed: false,
		},
		{
			// 200 but the body itself says the token was missing → not CSRF-able.
			name: "200 with csrf rejection body", status: 200, body: "Error: CSRF token missing", wantConfirmed: false,
		},
		{
			// A server error is not a confirmed state change.
			name: "server error", status: 500, body: "internal error", wantConfirmed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confirmed, note := csrfVerdict(tt.status, tt.body)
			if confirmed != tt.wantConfirmed {
				t.Fatalf("confirmed=%v want %v (note=%s)", confirmed, tt.wantConfirmed, note)
			}
			if note == "" {
				t.Error("expected a non-empty explanation note")
			}
		})
	}
}

func TestCsrfRejectionMarker(t *testing.T) {
	reject := []string{"invalid csrf token", "CSRF verification failed", "forbidden", "missing token", "unauthorized"}
	for _, s := range reject {
		if !csrfRejectionMarker(strings.ToLower(s)) {
			t.Errorf("expected %q to be a rejection marker", s)
		}
	}
	accept := []string{"account email updated", "profile saved", "ok"}
	for _, s := range accept {
		if csrfRejectionMarker(strings.ToLower(s)) {
			t.Errorf("did not expect %q to be a rejection marker", s)
		}
	}
}
