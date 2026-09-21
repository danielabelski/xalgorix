package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// tokenUsageSeriesLimit caps the per-request series returned by the
// token-usage endpoint so huge scans can't flood the dashboard.
const tokenUsageSeriesLimit = 5000

// tokenTrackerFor resolves the token tracker + scan directory for a scan ID,
// preferring the live in-memory session (running scans) and falling back to
// the persisted files in the scan directory (completed scans / restarts).
// It returns (tracker, dir). tracker may be nil when only files exist.
func (s *Server) tokenTrackerFor(scanID string) (*scanctx.TokenTracker, string) {
	s.instancesMu.RLock()
	if inst, ok := s.instances[scanID]; ok && inst != nil && inst.sctx != nil && inst.sctx.Tokens != nil {
		s.instancesMu.RUnlock()
		return inst.sctx.Tokens, inst.scanDir
	}
	s.instancesMu.RUnlock()

	dir, rec := s.findScanByID(scanID)
	if rec == nil {
		return nil, ""
	}
	s.instancesMu.RLock()
	defer s.instancesMu.RUnlock()
	for _, id := range []string{rec.InstanceID, rec.ID} {
		if id == "" {
			continue
		}
		if inst, ok := s.instances[id]; ok && inst != nil && inst.sctx != nil && inst.sctx.Tokens != nil {
			return inst.sctx.Tokens, dir
		}
	}
	return nil, dir
}

// finalizeTokenUsage persists the aggregate token summary at scan completion
// and logs the [token-analysis] summary line. Observability only.
func (s *Server) finalizeTokenUsage(sess *scanSession) {
	if sess == nil || sess.sctx == nil || sess.sctx.Tokens == nil {
		return
	}
	sess.sctx.Tokens.PersistSummary()
	if summary := sess.sctx.Tokens.FormatLog(); summary != "" {
		log.Printf("%s", summary)
	}
}

// handleScanTokenUsage serves GET /api/scans/{id}/token-usage — the
// production token-attribution diagnostics for a completed or running scan.
func (s *Server) handleScanTokenUsage(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/scans/"), "/token-usage")
	if scanID == "" || strings.Contains(scanID, "/") {
		http.Error(w, "invalid path: expected /api/scans/{id}/token-usage", http.StatusBadRequest)
		return
	}

	tracker, dir := s.tokenTrackerFor(scanID)
	if tracker != nil {
		serveTokenUsage(w, tracker.Diagnostics(), tracker.Series(tokenUsageSeriesLimit))
		return
	}

	// Persisted fallback: aggregate summary written at completion (and
	// periodically while running). If only compact records exist (scan was
	// running at restart before a summary flush), rebuild from the records.
	if dir != "" {
		var persisted scanctx.TokenDiagnostics
		if data, err := readSmallJSONFile(filepath.Join(dir, "token-usage.json")); err == nil && len(data) > 0 {
			if json.Unmarshal(data, &persisted) == nil {
				serveTokenUsage(w, persisted, persistedSeries(dir, tokenUsageSeriesLimit))
				return
			}
		}
		rebuilt := scanctx.NewTokenTracker()
		rebuilt.SetPersistDir(dir)
		if n := rebuilt.LoadPersisted(); n > 0 {
			serveTokenUsage(w, rebuilt.Diagnostics(), rebuilt.Series(tokenUsageSeriesLimit))
			return
		}
	}

	http.Error(w, "scan not found", http.StatusNotFound)
}

// persistedSeries loads compact records from the scan directory for charting
// when only files are available.
func persistedSeries(dir string, limit int) []scanctx.TokenRequestPoint {
	if dir == "" {
		return nil
	}
	rebuilt := scanctx.NewTokenTracker()
	rebuilt.SetPersistDir(dir)
	if rebuilt.LoadPersisted() == 0 {
		return nil
	}
	return rebuilt.Series(limit)
}

// readSmallJSONFile reads a bounded file (token summaries are small docs).
func readSmallJSONFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > 4<<20 {
		return nil, fmt.Errorf("token-usage summary too large: %d bytes", info.Size())
	}
	return os.ReadFile(path)
}

func serveTokenUsage(w http.ResponseWriter, diag scanctx.TokenDiagnostics, series []scanctx.TokenRequestPoint) {
	w.Header().Set("Content-Type", "application/json")
	if series == nil {
		series = []scanctx.TokenRequestPoint{}
	}
	if err := json.NewEncoder(w).Encode(map[string]any{
		"diagnostics": diag,
		"series":      series,
	}); err != nil {
		log.Printf("[token-analysis] encode token-usage response failed: %v", err)
	}
}
