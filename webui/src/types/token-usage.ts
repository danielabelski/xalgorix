// Token-attribution diagnostics shapes mirrored from
// internal/scanctx/token_tracker.go (TokenDiagnostics / TokenRequestPoint).

export interface TokenPromptGrowth {
  first_prompt_tokens: number;
  last_prompt_tokens: number;
  median_prompt_tokens: number;
  p95_prompt_tokens: number;
  max_prompt_tokens: number;
  prompt_growth_ratio: number;
  cumulative_prompt_tokens: number;
}

export interface TokenContextHeuristics {
  cumulative_context_bytes_sent: number;
  unique_context_bytes_added: number;
  resend_amplification_ratio: number;
}

export interface TokenAgentBreakdown {
  agent_type: string;
  agent_ids: string[];
  requests: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cached_input_tokens: number;
  uncached_input_tokens: number;
  average_prompt_tokens: number;
  max_prompt_tokens: number;
  tool_result_bytes: number;
  skill_result_bytes: number;
  iterations: number;
  compactions: number;
  first_prompt_tokens: number;
  last_prompt_tokens: number;
}

export interface TokenAgentContextComposition {
  agent_type: string;
  agent_id: string;
  iteration: number;
  message_count: number;
  system_bytes: number;
  assistant_bytes: number;
  user_other_bytes: number;
  tool_result_bytes: number;
  skill_result_bytes: number;
  total_bytes: number;
}

export interface TokenSourceBreakdown {
  aggregate: {
    system_bytes: number;
    assistant_bytes: number;
    user_other_bytes: number;
    tool_result_bytes: number;
    skill_result_bytes: number;
  };
  latest: TokenAgentContextComposition[];
}

export interface TokenRecoveryStats {
  retry_requests: number;
  retry_tokens: number;
  no_tool_requests: number;
  no_tool_tokens: number;
  malformed_tool_requests: number;
  malformed_tool_tokens: number;
  finish_rejection_requests: number;
  finish_rejection_tokens: number;
}

export interface TokenDiagnostics {
  generated_at: string;
  scan_id: string;
  total_tokens: number;
  prompt_tokens: number;
  completion_tokens: number;
  cached_input_tokens: number | null;
  uncached_input_tokens: number | null;
  cache_hit_rate: number | null;
  cache_reported_requests: number;
  total_llm_requests: number;
  root_tokens: number;
  verifier_tokens: number;
  specialist_tokens: Record<string, number>;
  agent_type_tokens: Record<string, number>;
  category_tokens: Record<string, number>;
  tool_result_bytes: number;
  skill_result_bytes: number;
  tool_result_messages: number;
  skill_result_messages: number;
  average_prompt_tokens_per_request: number | null;
  average_completion_tokens_per_request: number | null;
  largest_prompt_tokens: number;
  largest_conversation_bytes: number;
  growth: TokenPromptGrowth;
  context: TokenContextHeuristics;
  agents: TokenAgentBreakdown[];
  sources: TokenSourceBreakdown;
  recovery: TokenRecoveryStats;
}

export interface TokenRequestPoint {
  seq: number;
  ts: string;
  agent_type: string;
  agent_id: string;
  iter: number;
  category: string;
  retry: number;
  prompt: number;
  completion: number;
  cached: number;
  conv_bytes: number;
  tool_bytes: number;
  skill_bytes: number;
  compactions: number;
}

export interface TokenUsageResponse {
  diagnostics: TokenDiagnostics;
  series: TokenRequestPoint[];
}
