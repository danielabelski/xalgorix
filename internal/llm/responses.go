// Package llm — OpenAI Responses API support (HeaderStyle "openai_responses").
//
// This file implements the request/response shape for OpenAI's Responses
// API as consumed by the Codex CLI and the ChatGPT backend
// (https://chatgpt.com/backend-api/codex/responses). It is intentionally
// self-contained so the existing chat-completions / Anthropic / Gemini
// branches in client.go stay untouched.
//
// Why a separate protocol: the ChatGPT subscription backend does NOT speak
// /v1/chat/completions. It only accepts the Responses contract:
//
//   - body uses `input[]` (typed message items), not `messages[]`
//   - `store=false` + `stream=true` are required
//   - reasoning models need `include: ["reasoning.encrypted_content"]` so
//     reasoning context survives across stateless turns
//   - the response is always Server-Sent Events; the terminal text arrives
//     in `response.output_text.delta` / `response.completed` events
//
// The request shape here is the minimal subset Xalgorix needs (system +
// user/assistant text turns). Tool-calling over the Responses API is not
// modeled — Xalgorix drives tools through its own text protocol, so plain
// text in/out is sufficient.
package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// headerStyleResponses is the HeaderStyle value that routes a request
// through the OpenAI Responses API path (doResponses / streamResponses)
// instead of chat-completions. Resolvers set this on the Endpoint for the
// Codex / ChatGPT-subscription provider.
const headerStyleResponses = "openai_responses"

// responsesRequest is the outbound body for the Responses API.
type responsesRequest struct {
	Model        string              `json:"model"`
	Instructions string              `json:"instructions,omitempty"`
	Input        []responsesInput    `json:"input"`
	Store        bool                `json:"store"`
	Stream       bool                `json:"stream"`
	Reasoning    *responsesReasoning `json:"reasoning,omitempty"`
	Include      []string            `json:"include,omitempty"`
}

// responsesReasoning carries the reasoning-effort knob for GPT-5.x /
// codex models. Summary "auto" mirrors the Codex CLI default.
type responsesReasoning struct {
	Effort  string `json:"effort,omitempty"`
	Summary string `json:"summary,omitempty"`
}

// responsesInput is one typed item in the Responses `input` array. Only
// the "message" item type is produced here.
type responsesInput struct {
	Type    string                  `json:"type"`
	Role    string                  `json:"role"`
	Content []responsesInputContent `json:"content"`
}

// responsesInputContent is a content part inside an input message. The
// Responses API distinguishes input vs output text parts: user/system/
// developer turns use "input_text", assistant turns use "output_text".
type responsesInputContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// buildResponsesBody converts the flat []Message conversation into a
// Responses request body. The leading system message (if present) becomes
// the top-level `instructions` field — the ChatGPT backend expects the
// Codex system prompt there — and the remaining turns become typed input
// items. effort is the reasoning effort ("low"/"medium"/"high"/"xhigh");
// an empty value omits the reasoning block.
func buildResponsesBody(model string, messages []Message, effort string, stream bool) responsesRequest {
	req := responsesRequest{
		Model:  model,
		Store:  false,
		Stream: stream,
		// store=false makes the call stateless; encrypted reasoning content
		// must be echoed back so multi-turn reasoning continuity works.
		Include: []string{"reasoning.encrypted_content"},
	}

	if eff := normalizeResponsesEffort(effort); eff != "" {
		req.Reasoning = &responsesReasoning{Effort: eff, Summary: "auto"}
	}

	input := make([]responsesInput, 0, len(messages))
	for _, m := range messages {
		role := strings.ToLower(strings.TrimSpace(m.Role))
		switch role {
		case "system":
			// First system message → top-level instructions. Additional
			// system messages (rare) fold into a developer input item so
			// nothing is dropped.
			if req.Instructions == "" {
				req.Instructions = m.Content
				continue
			}
			input = append(input, responsesInput{
				Type: "message",
				Role: "developer",
				Content: []responsesInputContent{
					{Type: "input_text", Text: m.Content},
				},
			})
		case "assistant":
			input = append(input, responsesInput{
				Type: "message",
				Role: "assistant",
				Content: []responsesInputContent{
					{Type: "output_text", Text: m.Content},
				},
			})
		default: // user and anything else
			input = append(input, responsesInput{
				Type: "message",
				Role: "user",
				Content: []responsesInputContent{
					{Type: "input_text", Text: m.Content},
				},
			})
		}
	}
	req.Input = input
	return req
}

// normalizeResponsesEffort clamps the configured reasoning effort to the
// set the ChatGPT/Codex backend accepts (none/low/medium/high/xhigh).
// "minimal" maps to "low" (the backend rejects "minimal"); unknown values
// fall back to "medium". An empty input yields "" so the caller omits the
// reasoning block entirely.
func normalizeResponsesEffort(effort string) string {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "":
		return ""
	case "none":
		return "none"
	case "minimal", "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "xhigh":
		return "xhigh"
	default:
		return "medium"
	}
}

// responsesEvent is a single SSE event payload from the Responses API.
// Only the fields Xalgorix consumes are modeled; the rest are ignored by
// the JSON decoder.
type responsesEvent struct {
	Type     string `json:"type"`
	Delta    string `json:"delta"`
	Response struct {
		Output []struct {
			Type    string `json:"type"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
		Usage *struct {
			InputTokens        int `json:"input_tokens"`
			OutputTokens       int `json:"output_tokens"`
			InputTokensDetails *struct {
				CachedTokens int `json:"cached_tokens"`
			} `json:"input_tokens_details"`
		} `json:"usage"`
	} `json:"response"`
	// Error events carry a message under `error` on some backends and at
	// the top level on others; capture both shapes.
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	Message string `json:"message"`
}

// extractResponsesText pulls the assistant text out of a completed
// response.output array (the terminal "response.completed" event). It
// concatenates every output_text part of every "message" output item.
func extractResponsesText(ev *responsesEvent) string {
	var b strings.Builder
	for _, item := range ev.Response.Output {
		if item.Type != "message" {
			continue
		}
		for _, part := range item.Content {
			if part.Type == "output_text" {
				b.WriteString(part.Text)
			}
		}
	}
	return b.String()
}

// doResponses performs a single non-streaming Responses API call. The
// request is sent with stream=true (the backend only streams), and the
// SSE deltas are accumulated into the full text before returning, so the
// agent loop sees the same blocking string contract as doChat.
func (c *Client) doResponses(ctx context.Context, ep Endpoint, messages []Message) (string, error) {
	resp, _, err := c.doResponsesWithUsage(ctx, ep, messages)
	return resp, err
}

func (c *Client) doResponsesWithUsage(ctx context.Context, ep Endpoint, messages []Message) (string, *TokenUsage, error) {
	effort := ""
	if c.cfg != nil {
		effort = c.cfg.ReasoningEffort
	}
	reqBody := buildResponsesBody(ep.Model, messages, effort, true)
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal Responses request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	applyAuthHeaders(req, ep)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var full strings.Builder
	var usage *TokenUsage
	scanErr := scanResponsesSSE(resp.Body, func(ev *responsesEvent) {
		switch ev.Type {
		case "response.output_text.delta":
			full.WriteString(ev.Delta)
		case "response.completed":
			// Final event carries the assembled output and usage. Prefer
			// the assembled text when deltas were missed; track usage.
			if full.Len() == 0 {
				full.WriteString(extractResponsesText(ev))
			}
			if ev.Response.Usage != nil {
				cached := 0
				if ev.Response.Usage.InputTokensDetails != nil {
					cached = ev.Response.Usage.InputTokensDetails.CachedTokens
				}
				c.mu.Lock()
				c.totalIn += ev.Response.Usage.InputTokens
				c.totalOut += ev.Response.Usage.OutputTokens
				c.totalCached += cached
				c.mu.Unlock()
				usage = &TokenUsage{
					PromptTokens:     ev.Response.Usage.InputTokens,
					CompletionTokens: ev.Response.Usage.OutputTokens,
					TotalTokens:      ev.Response.Usage.InputTokens + ev.Response.Usage.OutputTokens,
					CachedTokens:     cached,
					PromptTokensDetails: &PromptTokensDetails{
						CachedTokens: cached,
					},
				}
			}
		}
	})
	if scanErr != nil {
		return "", usage, scanErr
	}
	return full.String(), usage, nil
}

// streamResponses performs a streaming Responses API call, forwarding text
// deltas onto ch as StreamChunks. It mirrors the OpenAI/Anthropic streaming
// branches in ChatStream. The caller owns ch and closes it.
func (c *Client) streamResponses(ctx context.Context, ep Endpoint, messages []Message, ch chan<- StreamChunk) {
	effort := ""
	if c.cfg != nil {
		effort = c.cfg.ReasoningEffort
	}
	reqBody := buildResponsesBody(ep.Model, messages, effort, true)
	body, err := json.Marshal(reqBody)
	if err != nil {
		ch <- StreamChunk{Err: fmt.Errorf("failed to marshal Responses request: %w", err)}
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		ch <- StreamChunk{Err: err}
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	applyAuthHeaders(req, ep)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		ch <- StreamChunk{Err: fmt.Errorf("request failed: %w", err)}
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		ch <- StreamChunk{Err: fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))}
		return
	}

	scanErr := scanResponsesSSE(resp.Body, func(ev *responsesEvent) {
		switch ev.Type {
		case "response.output_text.delta":
			if ev.Delta != "" {
				ch <- StreamChunk{Content: ev.Delta}
			}
		case "response.completed":
			if ev.Response.Usage != nil {
				cached := 0
				if ev.Response.Usage.InputTokensDetails != nil {
					cached = ev.Response.Usage.InputTokensDetails.CachedTokens
				}
				c.mu.Lock()
				c.totalIn += ev.Response.Usage.InputTokens
				c.totalOut += ev.Response.Usage.OutputTokens
				c.totalCached += cached
				c.mu.Unlock()
			}
		}
	})
	if scanErr != nil {
		ch <- StreamChunk{Err: scanErr}
		return
	}
	ch <- StreamChunk{Done: true}
}

// scanResponsesSSE reads an SSE stream of Responses events, invoking onEvent
// for each parsed `data:` payload. It returns an error if an error event is
// observed or the stream terminates abnormally. The "[DONE]" sentinel and
// non-data lines (event:, id:, comments, blank keep-alives) are ignored.
func scanResponsesSSE(r io.Reader, onEvent func(*responsesEvent)) error {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		data = strings.TrimSpace(data)
		if data == "" || data == "[DONE]" {
			continue
		}
		var ev responsesEvent
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			// Skip unparseable frames rather than aborting — the backend
			// interleaves event types Xalgorix doesn't model.
			continue
		}
		if ev.Type == "response.failed" || ev.Type == "error" || ev.Error != nil {
			msg := responsesErrorMessage(&ev)
			// Surface usage/rate-limit exhaustion with a marker the client's
			// isRateLimitError() recognizes, so the agent applies its
			// rate-limit backoff instead of treating it as a hard failure.
			if isResponsesUsageLimit(msg) {
				return fmt.Errorf("rate limited: Responses API usage limit: %s", msg)
			}
			return fmt.Errorf("responses API error: %s", msg)
		}
		onEvent(&ev)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading Responses stream: %w", err)
	}
	return nil
}

// responsesErrorMessage extracts a human-readable error message from an
// error-shaped event, falling back to a generic string.
func responsesErrorMessage(ev *responsesEvent) string {
	if ev.Error != nil && ev.Error.Message != "" {
		return ev.Error.Message
	}
	if ev.Message != "" {
		return ev.Message
	}
	return "unknown error"
}

// isResponsesUsageLimit reports whether an error message indicates the
// ChatGPT subscription quota was exhausted (vs. a genuine failure). These
// map to the client's rate-limit handling so a busy subscription pauses
// rather than aborting the scan.
func isResponsesUsageLimit(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "usage_limit_reached") ||
		strings.Contains(m, "usage limit") ||
		strings.Contains(m, "usage_not_included") ||
		strings.Contains(m, "rate_limit") ||
		strings.Contains(m, "rate limit") ||
		strings.Contains(m, "too many requests")
}
