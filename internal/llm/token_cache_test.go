package llm

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

func TestProviderCacheParsing(t *testing.T) {
	t.Run("OpenAIMiniMaxPromptTokensDetailsCachedTokens", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"id": "chatcmpl-test",
				"choices": [{"message": {"role": "assistant", "content": "hello"}}],
				"usage": {
					"prompt_tokens": 1500,
					"completion_tokens": 200,
					"total_tokens": 1700,
					"prompt_tokens_details": {
						"cached_tokens": 1100
					}
				}
			}`))
		}))
		defer ts.Close()

		cfg := &config.Config{
			LLM:         "MiniMax-Text-01",
			LLMProvider: "minimax",
			APIBase:     ts.URL + "/v1",
		}
		c := NewClient(cfg)
		_, usage, err := c.ChatWithUsage([]Message{{Role: "user", Content: "hi"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if usage == nil {
			t.Fatalf("expected usage object")
			return
		}
		if usage.PromptTokens != 1500 {
			t.Errorf("prompt_tokens = %d, want 1500", usage.PromptTokens)
		}
		if usage.GetCachedTokens() != 1100 {
			t.Errorf("cached_tokens = %d, want 1100", usage.GetCachedTokens())
		}
		if c.GetCachedTokens() != 1100 {
			t.Errorf("client totalCached = %d, want 1100", c.GetCachedTokens())
		}
	})

	t.Run("DirectCachedTokensField", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"id": "chatcmpl-test",
				"choices": [{"message": {"role": "assistant", "content": "hello"}}],
				"usage": {
					"prompt_tokens": 1000,
					"completion_tokens": 50,
					"total_tokens": 1050,
					"cached_tokens": 800
				}
			}`))
		}))
		defer ts.Close()

		cfg := &config.Config{
			LLM:     "test-model",
			APIBase: ts.URL + "/v1",
		}
		c := NewClient(cfg)
		_, usage, err := c.ChatWithUsage([]Message{{Role: "user", Content: "hi"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if usage.GetCachedTokens() != 800 {
			t.Errorf("cached_tokens = %d, want 800", usage.GetCachedTokens())
		}
	})

	t.Run("CacheReadInputTokensField", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"id": "chatcmpl-test",
				"choices": [{"message": {"role": "assistant", "content": "hello"}}],
				"usage": {
					"prompt_tokens": 2000,
					"completion_tokens": 100,
					"total_tokens": 2100,
					"cache_read_input_tokens": 1400
				}
			}`))
		}))
		defer ts.Close()

		cfg := &config.Config{
			LLM:     "test-model",
			APIBase: ts.URL + "/v1",
		}
		c := NewClient(cfg)
		_, usage, err := c.ChatWithUsage([]Message{{Role: "user", Content: "hi"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if usage.GetCachedTokens() != 1400 {
			t.Errorf("cache_read_input_tokens = %d, want 1400", usage.GetCachedTokens())
		}
	})

	t.Run("GeminiCachedContentTokenCount", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"candidates": [{"content": {"parts": [{"text": "gemini ok"}], "role": "model"}}],
				"usageMetadata": {
					"promptTokenCount": 3000,
					"candidatesTokenCount": 150,
					"totalTokenCount": 3150,
					"cachedContentTokenCount": 2500
				}
			}`))
		}))
		defer ts.Close()

		cfg := &config.Config{
			LLM:         "gemini-2.5-flash",
			LLMProvider: "google",
			APIBase:     ts.URL,
		}
		c := NewClient(cfg)
		_, usage, err := c.ChatWithUsage([]Message{{Role: "user", Content: "hi"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if usage.GetCachedTokens() != 2500 {
			t.Errorf("gemini cachedContentTokenCount = %d, want 2500", usage.GetCachedTokens())
		}
	})

	t.Run("AnthropicCacheReadInputTokens", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"id": "msg_123",
				"type": "message",
				"role": "assistant",
				"content": [{"type": "text", "text": "claude ok"}],
				"model": "claude-3-5-sonnet-20241022",
				"stop_reason": "end_turn",
				"usage": {
					"input_tokens": 4000,
					"output_tokens": 200,
					"cache_read_input_tokens": 3200,
					"cache_creation_input_tokens": 800
				}
			}`))
		}))
		defer ts.Close()

		cfg := &config.Config{
			LLM:         "claude-3-5-sonnet-20241022",
			LLMProvider: "anthropic",
			APIBase:     ts.URL,
		}
		c := NewClient(cfg)
		_, usage, err := c.ChatWithUsage([]Message{{Role: "user", Content: "hi"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if usage.GetCachedTokens() != 3200 {
			t.Errorf("anthropic cache_read_input_tokens = %d, want 3200", usage.GetCachedTokens())
		}
	})

	t.Run("UnknownCacheLeavesZeroWithoutHallucinating", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"id": "chatcmpl-test",
				"choices": [{"message": {"role": "assistant", "content": "hello"}}],
				"usage": {
					"prompt_tokens": 500,
					"completion_tokens": 50,
					"total_tokens": 550
				}
			}`))
		}))
		defer ts.Close()

		cfg := &config.Config{
			LLM:     "test-model",
			APIBase: ts.URL + "/v1",
		}
		c := NewClient(cfg)
		_, usage, err := c.ChatWithUsage([]Message{{Role: "user", Content: "hi"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if usage.GetCachedTokens() != 0 {
			t.Errorf("expected 0 cached tokens when provider does not report, got: %d", usage.GetCachedTokens())
		}
	})
}

func TestPromptCachingInvariants(t *testing.T) {
	var capturedPayload map[string]any
	var capturedBetaHeader string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBetaHeader = r.Header.Get("anthropic-beta")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedPayload)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"id": "msg_123",
			"type": "message",
			"role": "assistant",
			"content": [{"type": "text", "text": "ok"}],
			"model": "claude-sonnet-4-20250514",
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 10, "output_tokens": 5}
		}`))
	}))
	defer ts.Close()

	cfg := &config.Config{
		LLM:         "claude-sonnet-4-20250514",
		LLMProvider: "anthropic",
		APIBase:     ts.URL,
	}
	c := NewClient(cfg)
	c.SetPromptCaching(true)

	msgs := []Message{
		{Role: "system", Content: "You are Xalgorix pentesting agent."},
		{Role: "user", Content: "Investigate target host."},
	}

	_, _, err := c.ChatWithUsage(msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedBetaHeader != "prompt-caching-2024-07-31" {
		t.Errorf("anthropic-beta header = %q, want prompt-caching-2024-07-31", capturedBetaHeader)
	}

	// Assert message order and roles are strictly preserved
	msgsPayload, ok := capturedPayload["messages"].([]any)
	if !ok || len(msgsPayload) != 1 {
		t.Fatalf("messages payload malformed: %v", capturedPayload["messages"])
	}
	firstMsg := msgsPayload[0].(map[string]any)
	if firstMsg["role"] != "user" || firstMsg["content"] != "Investigate target host." {
		t.Errorf("user message altered: %v", firstMsg)
	}

	// Assert system message content is strictly preserved in ephemeral block
	sysList, ok := capturedPayload["system"].([]any)
	if !ok || len(sysList) != 1 {
		t.Fatalf("system payload expected 1 ephemeral block, got: %v", capturedPayload["system"])
	}
	sysBlock := sysList[0].(map[string]any)
	if sysBlock["text"] != "You are Xalgorix pentesting agent." {
		t.Errorf("system text altered: %v", sysBlock["text"])
	}
	cacheControl, ok := sysBlock["cache_control"].(map[string]any)
	if !ok || cacheControl["type"] != "ephemeral" {
		t.Errorf("cache_control type = %v, want ephemeral", cacheControl)
	}
}

func TestNonRetryableErrors(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		body         string
		nonRetryable bool
	}{
		{
			name:         "HTTP 422 Unprocessable Entity",
			statusCode:   422,
			body:         `{"error": {"message": "Invalid parameter combination"}}`,
			nonRetryable: true,
		},
		{
			name:         "HTTP 405 Method Not Allowed",
			statusCode:   405,
			body:         `Method Not Allowed`,
			nonRetryable: true,
		},
		{
			name:         "HTTP 400 with invalid_request_error",
			statusCode:   400,
			body:         `{"error": {"type": "invalid_request_error", "message": "Unsupported parameter"}}`,
			nonRetryable: true,
		},
		{
			name:         "HTTP 400 with context_length_exceeded",
			statusCode:   400,
			body:         `{"error": {"code": "context_length_exceeded", "message": "Max tokens exceeded"}}`,
			nonRetryable: true,
		},
		{
			name:         "HTTP 401 Unauthorized",
			statusCode:   401,
			body:         `{"error": {"message": "Invalid API key"}}`,
			nonRetryable: true,
		},
		{
			name:         "HTTP 403 Forbidden",
			statusCode:   403,
			body:         `{"error": {"message": "Permission denied"}}`,
			nonRetryable: true,
		},
		{
			name:         "HTTP 429 Rate Limit (Must be retryable)",
			statusCode:   429,
			body:         `{"error": {"message": "Rate limit reached"}}`,
			nonRetryable: false,
		},
		{
			name:         "HTTP 500 Internal Server Error (Must be retryable)",
			statusCode:   500,
			body:         `{"error": {"message": "Internal error"}}`,
			nonRetryable: false,
		},
		{
			name:         "HTTP 503 Service Unavailable (Must be retryable)",
			statusCode:   503,
			body:         `Service Unavailable`,
			nonRetryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := fmt.Sprintf("API returned %d: %s", tt.statusCode, tt.body)
			got := isNonRetryableLLMError(errStr)
			if got != tt.nonRetryable {
				t.Errorf("isNonRetryableLLMError(%q) = %v, want %v", errStr, got, tt.nonRetryable)
			}
		})
	}
}
