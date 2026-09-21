package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// tokenUsageFixtureDir creates a scan directory with a persisted token-usage
// summary + compact records, mimicking a completed scan's on-disk state.
func tokenUsageFixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	tr := scanctx.NewTokenTracker()
	tr.SetPersistDir(dir)
	tr.Record(scanctx.TokenAttribution{
		ScanID:                 "tok-scan-1",
		AgentID:                "root",
		AgentType:              scanctx.AgentTypeRoot,
		Iteration:              1,
		PromptTokens:           28000,
		CompletionTokens:       300,
		TotalTokens:            28300,
		CachedInputTokens:      24000,
		CacheReported:          true,
		UncachedInputTokens:    4000,
		MessageCount:           8,
		SerializedMessageBytes: 105000,
		RequestCategory:        scanctx.CategoryNormalReasoning,
	})
	tr.Record(scanctx.TokenAttribution{
		ScanID:                 "tok-scan-1",
		AgentID:                "sp",
		AgentType:              scanctx.AgentTypeInjectionServer,
		Iteration:              2,
		PromptTokens:           91000,
		CompletionTokens:       200,
		TotalTokens:            91200,
		MessageCount:           20,
		SerializedMessageBytes: 355000,
		RequestCategory:        scanctx.CategoryNormalReasoning,
	})
	tr.PersistSummary()
	tr.Close()
	return dir
}

func TestHandleScanTokenUsage_PersistedScan(t *testing.T) {
	s := newTestServer(t, nil)
	// Create the completed scan's on-disk state under the server's dataDir so
	// resolveScanDirByID finds it: scan.json + token-usage.json + .jsonl.
	dir := filepath.Join(s.dataDir, "tok-scan-1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rec := `{"id":"tok-scan-1","target":"t","status":"finished"}`
	if err := os.WriteFile(filepath.Join(dir, "scan.json"), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}

	tr := scanctx.NewTokenTracker()
	tr.SetPersistDir(dir)
	tr.Record(scanctx.TokenAttribution{
		ScanID:                 "tok-scan-1",
		AgentID:                "root",
		AgentType:              scanctx.AgentTypeRoot,
		Iteration:              1,
		PromptTokens:           28000,
		CompletionTokens:       300,
		TotalTokens:            28300,
		CachedInputTokens:      24000,
		CacheReported:          true,
		UncachedInputTokens:    4000,
		MessageCount:           8,
		SerializedMessageBytes: 105000,
		RequestCategory:        scanctx.CategoryNormalReasoning,
	})
	tr.Record(scanctx.TokenAttribution{
		ScanID:                 "tok-scan-1",
		AgentID:                "sp",
		AgentType:              scanctx.AgentTypeInjectionServer,
		Iteration:              2,
		PromptTokens:           91000,
		CompletionTokens:       200,
		TotalTokens:            91200,
		MessageCount:           20,
		SerializedMessageBytes: 355000,
		RequestCategory:        scanctx.CategoryNormalReasoning,
	})
	tr.PersistSummary()
	tr.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/scans/tok-scan-1/token-usage", nil)
	w := httptest.NewRecorder()
	s.handleScanTokenUsage(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Diagnostics scanctx.TokenDiagnostics    `json:"diagnostics"`
		Series      []scanctx.TokenRequestPoint `json:"series"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Diagnostics.TotalLLMRequests != 2 || resp.Diagnostics.TotalTokens != 119500 {
		t.Fatalf("diagnostics = %+v", resp.Diagnostics)
	}
	if resp.Diagnostics.CachedInputTokens == nil || *resp.Diagnostics.CachedInputTokens != 24000 {
		t.Fatalf("cached = %v", resp.Diagnostics.CachedInputTokens)
	}
	if len(resp.Series) != 2 {
		t.Fatalf("series = %d", len(resp.Series))
	}
}

func TestHandleScanTokenUsage_LiveSession(t *testing.T) {
	s := newTestServer(t, nil)
	dir := tokenUsageFixtureDir(t)

	sctx := scanctx.New("tok-live", dir)
	defer sctx.Close()
	sctx.Tokens.Record(scanctx.TokenAttribution{
		ScanID:                 "tok-live",
		AgentID:                "root",
		AgentType:              scanctx.AgentTypeRoot,
		Iteration:              3,
		PromptTokens:           50000,
		CompletionTokens:       100,
		TotalTokens:            50100,
		SerializedMessageBytes: 200000,
		RequestCategory:        scanctx.CategoryNoToolRecovery,
	})

	s.instancesMu.Lock()
	s.instances["tok-live"] = &ScanInstance{ID: "tok-live", Status: "running", sctx: sctx, scanDir: dir}
	s.instancesMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/scans/tok-live/token-usage", nil)
	w := httptest.NewRecorder()
	s.handleScanTokenUsage(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d body = %s", w.Code, w.Body.String())
	}
	var resp struct {
		Diagnostics scanctx.TokenDiagnostics    `json:"diagnostics"`
		Series      []scanctx.TokenRequestPoint `json:"series"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Diagnostics.TotalLLMRequests != 1 {
		t.Fatalf("requests = %d", resp.Diagnostics.TotalLLMRequests)
	}
	if resp.Diagnostics.Recovery.NoToolTokens != 50100 {
		t.Fatalf("recovery = %+v", resp.Diagnostics.Recovery)
	}
}

func TestHandleScanTokenUsage_MissingScan(t *testing.T) {
	s := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/scans/does-not-exist/token-usage", nil)
	w := httptest.NewRecorder()
	s.handleScanTokenUsage(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", w.Code)
	}
}

func TestHandleScanTokenUsage_RejectsBadPath(t *testing.T) {
	s := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/scans/a/b/token-usage", nil)
	w := httptest.NewRecorder()
	s.handleScanTokenUsage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", w.Code)
	}
}
