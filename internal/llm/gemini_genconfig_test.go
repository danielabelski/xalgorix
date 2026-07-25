package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestGeminiRequestSendsGenerationConfig proves that a Gemini request carries a
// generationConfig object with the operator's configured max output tokens and
// the effective temperature. Before the fix, geminiRequest had no
// GenerationConfig field, so Gemini silently used its own server-side defaults —
// truncating large tool calls (report_vulnerability) and ignoring the agent's
// per-role temperature overrides (e.g. the validator forcing temperature 0).
func TestGeminiRequestSendsGenerationConfig(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`))
	}))
	defer srv.Close()

	temp := 0.0
	cfg := &config.Config{
		LLM:             "gemini-2.5-flash",
		APIBase:         srv.URL,
		APIKey:          "test",
		MaxOutputTokens: 4096,
		Temperature:     &temp,
	}
	c := NewClient(cfg)
	c.provider = "google" // route through the native Gemini endpoint logic

	if _, err := c.Chat([]Message{{Role: "user", Content: "ping"}}); err != nil {
		t.Fatalf("Chat returned error: %v", err)
	}

	var req geminiRequest
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("request body is not valid geminiRequest JSON: %v\nbody=%s", err, gotBody)
	}
	if req.GenerationConfig == nil {
		t.Fatalf("Gemini request is missing generationConfig; body=%s", gotBody)
	}
	if req.GenerationConfig.MaxOutputTokens != 4096 {
		t.Errorf("generationConfig.maxOutputTokens = %d; want 4096 (operator config ignored)", req.GenerationConfig.MaxOutputTokens)
	}
	if req.GenerationConfig.Temperature == nil || *req.GenerationConfig.Temperature != 0.0 {
		t.Errorf("generationConfig.temperature = %v; want 0 (per-role override ignored)", req.GenerationConfig.Temperature)
	}
}
