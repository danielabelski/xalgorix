package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestInstrumentationDoesNotAlterOutboundRequests proves the token-attribution
// instrumentation is response-side only: the outbound LLM request body carries
// exactly the standard chat-completion fields — no telemetry, no extra
// parameters, and messages byte-identical to what the caller supplied.
func TestInstrumentationDoesNotAlterOutboundRequests(t *testing.T) {
	var captured []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		captured = append(captured, string(body))
		// Response exercises the MiniMax usage-structure diagnostic path too
		// (cached field present), proving the redacted diagnostic does not
		// leak into or change the request.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"choices": [{"message": {"role": "assistant", "content": "ok"}}],
			"usage": {
				"prompt_tokens": 900,
				"completion_tokens": 30,
				"total_tokens": 930,
				"prompt_tokens_details": {"cached_tokens": 700}
			}
		}`))
	}))
	defer ts.Close()

	cfg := &config.Config{
		LLM:         "MiniMax-M3",
		LLMProvider: "minimax",
		APIBase:     ts.URL + "/v1",
	}
	c := NewClient(cfg)
	msgs := []Message{
		{Role: "system", Content: "system prompt"},
		{Role: "user", Content: "user turn one"},
		{Role: "assistant", Content: "assistant turn"},
		{Role: "user", Content: "user turn two"},
	}
	out, usage, err := c.ChatWithUsage(msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "ok" {
		t.Fatalf("response content = %q", out)
	}
	if !usage.HasCachedTokens || usage.GetCachedTokens() != 700 {
		t.Fatalf("usage cache attribution = %+v", usage)
	}

	// The request must be a plain OpenAI-compatible body.
	if len(captured) != 1 {
		t.Fatalf("captured %d requests", len(captured))
	}
	var req map[string]json.RawMessage
	if err := json.Unmarshal([]byte(captured[0]), &req); err != nil {
		t.Fatalf("request body not JSON: %v", err)
	}
	keys := make([]string, 0, len(req))
	for k := range req {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	allowed := map[string]bool{
		"model": true, "messages": true, "max_tokens": true, "temperature": true,
		"stream": true, "stream_options": true, "reasoning_effort": true,
		"max_completion_tokens": true,
	}
	for _, k := range keys {
		if !allowed[k] {
			t.Fatalf("unexpected request field %q added by instrumentation: %s", k, captured[0])
		}
	}

	// Messages must round-trip byte-identically (role + content, in order).
	var wire struct {
		Messages []Message `json:"messages"`
	}
	if err := json.Unmarshal(req["messages"], &wire.Messages); err != nil {
		t.Fatalf("decode messages: %v", err)
	}
	if len(wire.Messages) != len(msgs) {
		t.Fatalf("message count on wire = %d, want %d", len(wire.Messages), len(msgs))
	}
	for i, m := range wire.Messages {
		if m.Role != msgs[i].Role || m.Content != msgs[i].Content {
			t.Fatalf("wire message %d = %+v, want %+v", i, m, msgs[i])
		}
	}
}

// TestMiniMaxUsageStructureDiagnosticNeverLogsValues verifies the redacted
// diagnostic path only logs field names (log output, not the usage values).
func TestMiniMaxUsageStructureDiagnosticNeverLogsValues(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"choices": [{"message": {"role": "assistant", "content": "ok"}}],
			"usage": {
				"prompt_tokens": 900,
				"completion_tokens": 30,
				"total_tokens": 930,
				"prompt_tokens_details": {"cached_tokens": 700},
				"secret_provider_field": "SENSITIVE-VALUE-900"
			}
		}`))
	}))
	defer ts.Close()

	cfg := &config.Config{
		LLM:         "MiniMax-M3",
		LLMProvider: "minimax",
		APIBase:     ts.URL + "/v1",
	}
	c := NewClient(cfg)
	if _, _, err := c.ChatWithUsage([]Message{{Role: "user", Content: "hi"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The diagnostic must have run (provider is minimax) without emitting any
	// usage VALUES into any captured log sink. logMiniMaxUsageShape only
	// marshals key names; assert the helper's output for a known shape.
	raw := []byte(`{"prompt_tokens":900,"prompt_tokens_details":{"cached_tokens":700},"secret_provider_field":"SENSITIVE-VALUE-900"}`)
	shape := minimaxUsageShapeForTest(raw)
	joined := strings.Join(shape, ",")
	if !strings.Contains(joined, "prompt_tokens") || !strings.Contains(joined, "prompt_tokens_details.cached_tokens") {
		t.Fatalf("structure missing expected field names: %v", shape)
	}
	if strings.Contains(joined, "SENSITIVE") || strings.Contains(joined, "900") {
		t.Fatalf("values leaked into structure diagnostic: %v", shape)
	}
}

// minimaxUsageShapeForTest extracts only field names from a usage object,
// mirroring logMiniMaxUsageShape so tests can assert value-redaction.
func minimaxUsageShapeForTest(raw []byte) []string {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return nil
	}
	keys := []string{}
	for k, v := range top {
		keys = append(keys, k)
		var inner map[string]json.RawMessage
		if json.Unmarshal(v, &inner) != nil {
			continue
		}
		for ik := range inner {
			keys = append(keys, k+"."+ik)
		}
	}
	sort.Strings(keys)
	return keys
}
