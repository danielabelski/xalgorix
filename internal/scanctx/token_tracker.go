package scanctx

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// RequestCategory identifies the purpose or phase of an LLM request.
const (
	CategoryNormalReasoning         = "normal"
	CategoryVerifier                = "verifier"
	CategoryRetry                   = "retry"
	CategoryMalformedToolRecovery   = "malformed-tool"
	CategoryNoToolRecovery          = "no-tool"
	CategoryFinishRejectionRecovery = "finish-rejection"
)

// AgentType defines the canonical role of an agent in a scan.
const (
	AgentTypeRoot            = "coordinator/root"
	AgentTypeAuthzLogic      = "authz-logic"
	AgentTypeInjectionServer = "injection-serverside"
	AgentTypeClientSource    = "client-source"
	AgentTypeVerifier        = "verifier"
	AgentTypeOther           = "other"
)

// TokenAttribution records detailed metrics for a single outbound LLM request.
type TokenAttribution struct {
	ScanID                  string    `json:"scan_id"`
	AgentID                 string    `json:"agent_id"`
	AgentType               string    `json:"agent_type"` // e.g., coordinator/root, authz-logic, verifier
	Iteration               int       `json:"iteration"`
	Model                   string    `json:"model"`
	Provider                string    `json:"provider"`
	PromptTokens            int       `json:"prompt_tokens"`
	CompletionTokens        int       `json:"completion_tokens"`
	TotalTokens             int       `json:"total_tokens"`
	CachedInputTokens       int       `json:"cached_input_tokens"`   // provider cache read tokens
	UncachedInputTokens     int       `json:"uncached_input_tokens"` // prompt_tokens - cached_input_tokens
	MessageCount            int       `json:"message_count"`
	SerializedMessageBytes  int       `json:"serialized_message_bytes"`
	SystemMessageBytes      int       `json:"system_message_bytes"`
	UserMessageBytes        int       `json:"user_message_bytes"`
	AssistantMessageBytes   int       `json:"assistant_message_bytes"`
	ToolResultCount         int       `json:"tool_result_count"`
	ToolResultBytes         int       `json:"tool_result_bytes"`
	SkillResultCount        int       `json:"skill_result_count"`
	SkillResultBytes        int       `json:"skill_result_bytes"`
	ConversationBufferBytes int       `json:"conversation_buffer_bytes"`
	RetryAttempt            int       `json:"retry_attempt"`
	RequestCategory         string    `json:"request_category"` // normal, verifier, retry, etc.
	CompactionCount         int       `json:"compaction_count"`
	ScanCumulativePrompt    int       `json:"scan_cumulative_prompt"`
	ScanCumulativeOutput    int       `json:"scan_cumulative_output"`
	Timestamp               time.Time `json:"timestamp"`
}

// TokenSummary provides aggregated post-scan metrics.
type TokenSummary struct {
	TotalTokens         int            `json:"total_tokens"`
	PromptTokens        int            `json:"prompt_tokens"`
	CompletionTokens    int            `json:"completion_tokens"`
	CachedInputTokens   int            `json:"cached_input_tokens"`
	UncachedInputTokens int            `json:"uncached_input_tokens"`
	RootTokens          int            `json:"root_tokens"`
	VerifierTokens      int            `json:"verifier_tokens"`
	SpecialistTokens    map[string]int `json:"specialist_tokens"` // role -> total tokens
	AgentTypeTokens     map[string]int `json:"agent_type_tokens"`
	CategoryTokens      map[string]int `json:"category_tokens"` // request_category -> total tokens
	ToolOutputBytes     int            `json:"tool_output_bytes"`
	SkillResultBytes    int            `json:"skill_result_bytes"`
	ToolResultMessages  int            `json:"tool_result_messages"`
	SkillResultMessages int            `json:"skill_result_messages"`
	RetryLoopTokens     int            `json:"retry_loop_tokens"`
	TotalRequests       int            `json:"total_requests"`
}

// TokenTracker collects and aggregates TokenAttribution records across a scan session.
type TokenTracker struct {
	mu      sync.RWMutex
	records []TokenAttribution
}

// NewTokenTracker initializes a new TokenTracker.
func NewTokenTracker() *TokenTracker {
	return &TokenTracker{
		records: make([]TokenAttribution, 0, 64),
	}
}

// Record appends a new token attribution event under lock.
func (t *TokenTracker) Record(rec TokenAttribution) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now()
	}
	if rec.UncachedInputTokens == 0 && rec.PromptTokens > 0 {
		rec.UncachedInputTokens = rec.PromptTokens - rec.CachedInputTokens
		if rec.UncachedInputTokens < 0 {
			rec.UncachedInputTokens = 0
		}
	}
	t.records = append(t.records, rec)
}

// Records returns a shallow copy of all recorded attributions.
func (t *TokenTracker) Records() []TokenAttribution {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]TokenAttribution, len(t.records))
	copy(out, t.records)
	return out
}

// Summary calculates the aggregated metrics across all recorded requests.
func (t *TokenTracker) Summary() TokenSummary {
	if t == nil {
		return TokenSummary{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	s := TokenSummary{
		SpecialistTokens: make(map[string]int),
		AgentTypeTokens:  make(map[string]int),
		CategoryTokens:   make(map[string]int),
		TotalRequests:    len(t.records),
	}

	for _, r := range t.records {
		s.TotalTokens += r.TotalTokens
		s.PromptTokens += r.PromptTokens
		s.CompletionTokens += r.CompletionTokens
		s.CachedInputTokens += r.CachedInputTokens
		s.UncachedInputTokens += r.UncachedInputTokens

		s.AgentTypeTokens[r.AgentType] += r.TotalTokens
		s.CategoryTokens[r.RequestCategory] += r.TotalTokens

		switch r.AgentType {
		case AgentTypeRoot:
			s.RootTokens += r.TotalTokens
		case AgentTypeVerifier:
			s.VerifierTokens += r.TotalTokens
		default:
			s.SpecialistTokens[r.AgentType] += r.TotalTokens
		}

		if r.RequestCategory == CategoryRetry ||
			r.RequestCategory == CategoryMalformedToolRecovery ||
			r.RequestCategory == CategoryNoToolRecovery ||
			r.RetryAttempt > 0 {
			s.RetryLoopTokens += r.TotalTokens
		}

		s.ToolOutputBytes += r.ToolResultBytes
		s.SkillResultBytes += r.SkillResultBytes
		s.ToolResultMessages += r.ToolResultCount
		s.SkillResultMessages += r.SkillResultCount
	}

	return s
}

// FormatLog returns a clean, human-readable summary for logs and telemetry.
func (t *TokenTracker) FormatLog() string {
	s := t.Summary()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(
		"LLM Token Attribution: total=%d (prompt=%d, completion=%d, cached=%d, uncached=%d) across %d requests | root=%d, verifier=%d | recovery/retries=%d",
		s.TotalTokens, s.PromptTokens, s.CompletionTokens, s.CachedInputTokens, s.UncachedInputTokens, s.TotalRequests, s.RootTokens, s.VerifierTokens, s.RetryLoopTokens,
	))
	if len(s.SpecialistTokens) > 0 {
		sb.WriteString(" | specialists: [")
		first := true
		for role, toks := range s.SpecialistTokens {
			if !first {
				sb.WriteString(", ")
			}
			sb.WriteString(fmt.Sprintf("%s: %d", role, toks))
			first = false
		}
		sb.WriteString("]")
	}
	return sb.String()
}
