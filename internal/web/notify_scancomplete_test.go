package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestNotifyScanComplete_DefaultsOff verifies the scan-completion summary
// toggle defaults to false, so a fresh install sends no "Scan Finished"
// summary after a scan — only per-vulnerability alerts.
func TestNotifyScanComplete_DefaultsOff(t *testing.T) {
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})
	if s.cfg.NotifyScanComplete {
		t.Fatalf("cfg.NotifyScanComplete should default to false")
	}
	if s.notifyScanComplete {
		t.Fatalf("runtime notifyScanComplete should default to false")
	}
}

// TestEnvironmentSettings_AppliesNotifyScanComplete verifies the toggle
// round-trips through the /api/settings/environment POST path into both
// cfg.NotifyScanComplete and the server runtime field, and is reported back
// (as "true") on the subsequent GET so the dashboard renders it.
func TestEnvironmentSettings_AppliesNotifyScanComplete(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	s := newTestServer(t, &config.Config{RateLimitRequests: 60, RateLimitWindow: 60})

	body := `{"values":{"XALGORIX_NOTIFY_SCAN_COMPLETE":"true"}}`
	rr := httptest.NewRecorder()
	s.handleEnvironmentSettings(rr, httptest.NewRequest(http.MethodPost, "/api/settings/environment", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("environment POST code = %d body=%s", rr.Code, rr.Body.String())
	}
	if !s.cfg.NotifyScanComplete || !s.notifyScanComplete {
		t.Fatalf("notify scan complete not applied: cfg=%v runtime=%v", s.cfg.NotifyScanComplete, s.notifyScanComplete)
	}

	rr = httptest.NewRecorder()
	s.handleEnvironmentSettings(rr, httptest.NewRequest(http.MethodGet, "/api/settings/environment", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("environment GET code = %d", rr.Code)
	}
	var resp environmentSettingsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode settings GET: %v", err)
	}
	found := false
	for _, v := range resp.Variables {
		if v.Key == "XALGORIX_NOTIFY_SCAN_COMPLETE" {
			found = true
			if v.Value != "true" {
				t.Fatalf("expected XALGORIX_NOTIFY_SCAN_COMPLETE value \"true\", got %q", v.Value)
			}
		}
	}
	if !found {
		t.Fatalf("XALGORIX_NOTIFY_SCAN_COMPLETE missing from settings GET response")
	}
}
