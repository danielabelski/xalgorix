package llm

import (
	"net/http"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// TestDoChat_MessageContentAsArrayParts regression-tests the Mistral
// zai-glm-latest response shape, where message.content is an array of
// typed parts (thinking + text) instead of a plain string.
func TestDoChat_MessageContentAsArrayParts(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "mistral/zai-glm-latest",
		APIBase:       "https://api.mistral.ai/v1",
		APIKey:        "mistral-key",
		LLMMaxRetries: 1,
	})
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":[{"type":"thinking","thinking":[{"type":"text","text":"ponder"}],"closed":true},{"type":"text","text":"Hi there, friend!"}]}}],"usage":{"prompt_tokens":18,"completion_tokens":5,"total_tokens":23}}`), nil
	})}

	got, err := c.doChat([]Message{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatalf("doChat returned error: %v", err)
	}
	if got != "Hi there, friend!" {
		t.Fatalf("doChat = %q, want %q", got, "Hi there, friend!")
	}
	in, out, _ := c.GetTokens()
	if in != 18 || out != 5 {
		t.Errorf("tokens in/out = %d/%d, want 18/5", in, out)
	}
}

// TestChatStream_DeltaContentMixedShapes covers the streaming variants
// observed from zai-glm-latest: empty-string deltas, thinking-part
// arrays, mixed arrays, and plain-string text deltas.
func TestChatStream_DeltaContentMixedShapes(t *testing.T) {
	c := NewClient(&config.Config{
		LLM:           "mistral/zai-glm-latest",
		APIBase:       "https://api.mistral.ai/v1",
		APIKey:        "mistral-key",
		LLMMaxRetries: 1,
	})
	sse := strings.Join([]string{
		`data: {"choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`,
		``,
		`data: {"choices":[{"index":0,"delta":{"index":0,"content":[{"type":"thinking","thinking":[{"type":"text","text":"The"}],"closed":true}]},"finish_reason":null}]}`,
		``,
		`data: {"choices":[{"index":0,"delta":{"index":0,"content":[{"type":"thinking","thinking":[{"type":"text","text":" user"}],"closed":true},{"type":"text","text":"Hello"}]},"finish_reason":null}]}`,
		``,
		`data: {"choices":[{"index":0,"delta":{"index":0,"content":" there, friend!"},"finish_reason":null}]}`,
		``,
		`data: {"choices":[{"index":0,"delta":{"index":0,"content":""},"finish_reason":"stop"}],"usage":{"prompt_tokens":18,"completion_tokens":9,"total_tokens":27}}`,
		``,
	}, "\n")
	c.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, sse), nil
	})}

	var sb strings.Builder
	for chunk := range c.ChatStream([]Message{{Role: "user", Content: "hi"}}) {
		if chunk.Err != nil {
			t.Fatalf("ChatStream error: %v", chunk.Err)
		}
		if chunk.Done {
			break
		}
		sb.WriteString(chunk.Content)
	}
	if got := sb.String(); got != "Hello there, friend!" {
		t.Fatalf("streamed content = %q, want %q", got, "Hello there, friend!")
	}
}
