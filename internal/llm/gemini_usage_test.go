package llm

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// newGeminiTestClient builds a Client wired to a mock server and forces the
// Gemini ("google") code path so the token-usage parsing is exercised.
func newGeminiTestClient(t *testing.T, srvURL string) *Client {
	t.Helper()
	cfg := &config.Config{LLM: "gemini-2.5-flash", APIBase: srvURL, APIKey: "test"}
	c := NewClient(cfg)
	c.provider = "google" // route through the native Gemini endpoint logic
	return c
}

// TestGeminiUsageAccountingNonStreaming proves the non-streaming path (doChat)
// counts tokens reported under Gemini's usageMetadata. Before the fix these
// counters stayed at zero because the code only understood the OpenAI-style
// `usage` object.
func TestGeminiUsageAccountingNonStreaming(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"pong"}]}}],` +
			`"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":40,"totalTokenCount":140}}`))
	}))
	defer srv.Close()

	c := newGeminiTestClient(t, srv.URL)
	out, err := c.Chat([]Message{{Role: "user", Content: "ping"}})
	if err != nil {
		t.Fatalf("Chat returned error: %v", err)
	}
	if out != "pong" {
		t.Fatalf("unexpected content: %q", out)
	}

	in, comp, total := c.GetTokens()
	if in != 100 || comp != 40 || total != 140 {
		t.Fatalf("Gemini usage not counted: in=%d completion=%d total=%d (want 100/40/140)", in, comp, total)
	}
}

// TestGeminiUsageAccountingStreaming proves the streaming path (ChatStream)
// adds the FINAL cumulative usageMetadata exactly once. Gemini repeats a
// growing usageMetadata on every SSE chunk, so a naive per-chunk sum would
// massively over-count; this asserts the totals equal the last chunk's values.
func TestGeminiUsageAccountingStreaming(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		chunks := []string{
			`{"candidates":[{"content":{"parts":[{"text":"po"}]}}],` +
				`"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":10,"totalTokenCount":110}}`,
			`{"candidates":[{"content":{"parts":[{"text":"ng"}]}}],` +
				`"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":40,"totalTokenCount":140}}`,
		}
		for _, ch := range chunks {
			_, _ = w.Write([]byte("data: " + ch + "\n\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer srv.Close()

	c := newGeminiTestClient(t, srv.URL)
	var sb strings.Builder
	for chunk := range c.ChatStream([]Message{{Role: "user", Content: "ping"}}) {
		if chunk.Err != nil {
			t.Fatalf("stream returned error: %v", chunk.Err)
		}
		sb.WriteString(chunk.Content)
	}
	if sb.String() != "pong" {
		t.Fatalf("unexpected streamed content: %q", sb.String())
	}

	in, comp, total := c.GetTokens()
	if in != 100 || comp != 40 || total != 140 {
		t.Fatalf("Gemini streaming usage wrong (must use final cumulative chunk, not a per-chunk sum): "+
			"in=%d completion=%d total=%d (want 100/40/140)", in, comp, total)
	}
}
