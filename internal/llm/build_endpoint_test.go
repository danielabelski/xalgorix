package llm

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// TestBuildCatalogEndpoint_CodexResponses is the regression guard for the
// bug where the per-scan resolver (internal/web/scan_resolve.go) used a
// divergent endpoint builder that lacked the "openai_responses" case: it
// sent Codex traffic to <base>/v1/chat/completions (legacy chat-completions
// → Cloudflare 403) and dropped the required ChatGPT headers. Both the
// composite resolver and the per-scan resolver now call BuildCatalogEndpoint,
// so this test pins the correct URL + header behavior in one place.
func TestBuildCatalogEndpoint_CodexResponses(t *testing.T) {
	entry := providers.Entry{
		ID:          "codex",
		BaseURL:     "https://chatgpt.com/backend-api/codex",
		HeaderStyle: "openai_responses",
		Models:      []string{"gpt-5.5", "gpt-5.5-codex"},
	}
	prof := auth.Profile{
		Provider:    "codex",
		ProfileID:   "default",
		Type:        auth.OAuth,
		AccessToken: "tok_codex",
		AccountID:   "acct_codex_77",
	}

	ep, err := BuildCatalogEndpoint(entry, prof, "", "")
	if err != nil {
		t.Fatalf("BuildCatalogEndpoint: %v", err)
	}

	// Must hit the Responses API path, NOT /v1/chat/completions.
	if ep.URL != "https://chatgpt.com/backend-api/codex/responses" {
		t.Errorf("URL = %q, want .../codex/responses", ep.URL)
	}
	if ep.HeaderStyle != "openai_responses" {
		t.Errorf("HeaderStyle = %q, want openai_responses", ep.HeaderStyle)
	}
	if ep.Auth != AuthOAuthBearer || ep.AccessToken != "tok_codex" {
		t.Errorf("auth = %v token = %q, want OAuth bearer tok_codex", ep.Auth, ep.AccessToken)
	}
	if ep.Model != "gpt-5.5" {
		t.Errorf("model = %q, want gpt-5.5 (first catalog model)", ep.Model)
	}

	// VendorOverride must attach the three Codex/ChatGPT headers.
	if ep.VendorOverride == nil {
		t.Fatal("VendorOverride is nil; codex headers would be dropped")
	}
	req := httptest.NewRequest(http.MethodPost, ep.URL, nil)
	ep.VendorOverride(req)
	if got := req.Header.Get("chatgpt-account-id"); got != "acct_codex_77" {
		t.Errorf("chatgpt-account-id = %q, want acct_codex_77", got)
	}
	if got := req.Header.Get("OpenAI-Beta"); got != "responses=experimental" {
		t.Errorf("OpenAI-Beta = %q, want responses=experimental", got)
	}
	if got := req.Header.Get("originator"); got != "codex_cli_rs" {
		t.Errorf("originator = %q, want codex_cli_rs", got)
	}
}

// TestBuildCatalogEndpoint_PreferModel verifies an explicit preferModel
// overrides the catalog's default first model.
func TestBuildCatalogEndpoint_PreferModel(t *testing.T) {
	entry := providers.Entry{
		ID:          "codex",
		BaseURL:     "https://chatgpt.com/backend-api/codex",
		HeaderStyle: "openai_responses",
		Models:      []string{"gpt-5.5"},
	}
	prof := auth.Profile{Provider: "codex", ProfileID: "default", Type: auth.OAuth, AccessToken: "t"}
	ep, err := BuildCatalogEndpoint(entry, prof, "gpt-5.5-codex", "")
	if err != nil {
		t.Fatalf("BuildCatalogEndpoint: %v", err)
	}
	if ep.Model != "gpt-5.5-codex" {
		t.Errorf("model = %q, want gpt-5.5-codex (preferModel wins)", ep.Model)
	}
}

// TestBuildCatalogEndpoint_OpenAIAndUnknown covers the openai chat path and
// the unsupported-header-style error.
func TestBuildCatalogEndpoint_OpenAIAndUnknown(t *testing.T) {
	openai := providers.Entry{
		ID:          "openai",
		BaseURL:     "https://api.openai.com/v1",
		HeaderStyle: "openai",
		Models:      []string{"gpt-5.5"},
	}
	keyProf := auth.Profile{Provider: "openai", ProfileID: "default", Type: auth.APIKey, APIKey: "sk-x"}
	ep, err := BuildCatalogEndpoint(openai, keyProf, "", "")
	if err != nil {
		t.Fatalf("openai BuildCatalogEndpoint: %v", err)
	}
	if ep.URL != "https://api.openai.com/v1/chat/completions" {
		t.Errorf("openai URL = %q", ep.URL)
	}
	if ep.Auth != AuthAPIKey || ep.APIKey != "sk-x" {
		t.Errorf("openai auth = %v key = %q, want APIKey sk-x", ep.Auth, ep.APIKey)
	}
	if ep.VendorOverride != nil {
		t.Error("openai endpoint should not set a codex VendorOverride")
	}

	bad := providers.Entry{ID: "weird", BaseURL: "https://x", HeaderStyle: "made-up"}
	if _, err := BuildCatalogEndpoint(bad, keyProf, "", ""); err == nil {
		t.Error("expected error for unsupported header style, got nil")
	}
}

// TestBuildCatalogEndpoint_CustomProviderFallbackBase is the regression
// guard for issue #122: a "custom" provider has an empty catalog
// Entry.BaseURL, so when the credential profile is also missing its
// APIBaseOverride the builder must fall back to the operator-configured
// base URL (cfg.APIBase / XALGORIX_API_BASE) instead of emitting a
// relative "/v1/chat/completions" path.
func TestBuildCatalogEndpoint_CustomProviderFallbackBase(t *testing.T) {
	custom := providers.Entry{
		ID:          "custom",
		DisplayName: "Custom Provider",
		BaseURL:     "",
		HeaderStyle: "openai",
	}
	// Profile carries the key but NO APIBaseOverride — the exact
	// shape that previously produced a relative request URL.
	prof := auth.Profile{Provider: "custom", ProfileID: "default", Type: auth.APIKey, APIKey: "sk-x"}

	ep, err := BuildCatalogEndpoint(custom, prof, "router-gpt-5.5-xhigh", "http://10.0.0.201:20128/v1")
	if err != nil {
		t.Fatalf("custom BuildCatalogEndpoint: %v", err)
	}
	if ep.URL != "http://10.0.0.201:20128/v1/chat/completions" {
		t.Errorf("URL = %q, want http://10.0.0.201:20128/v1/chat/completions", ep.URL)
	}
	if ep.Model != "router-gpt-5.5-xhigh" {
		t.Errorf("model = %q, want router-gpt-5.5-xhigh", ep.Model)
	}

	// With no base URL anywhere, the builder must fail fast with a
	// *ConfigError rather than returning a relative path that the
	// HTTP client would reject with `unsupported protocol scheme ""`.
	if _, err := BuildCatalogEndpoint(custom, prof, "router-gpt-5.5-xhigh", ""); err == nil {
		t.Error("expected ConfigError for custom provider with no base URL, got nil")
	} else if _, ok := err.(*ConfigError); !ok {
		t.Errorf("error type = %T, want *ConfigError", err)
	}
}

func TestBuildCatalogEndpoint_ZAICodingPlanPreservesV4(t *testing.T) {
	entry, ok := providers.LookupBuiltin("zai-coding-plan")
	if !ok {
		t.Fatal("Z.AI Coding Plan provider is missing")
	}
	prof := auth.Profile{
		Provider:  "zai-coding-plan",
		ProfileID: "default",
		Type:      auth.APIKey,
		APIKey:    "zai-key",
	}
	ep, err := BuildCatalogEndpoint(entry, prof, "GLM-5.3", "")
	if err != nil {
		t.Fatalf("BuildCatalogEndpoint: %v", err)
	}
	if ep.URL != "https://api.z.ai/api/coding/paas/v4/chat/completions" {
		t.Fatalf("URL = %q, want Z.AI /v4/chat/completions without injected /v1", ep.URL)
	}
	if ep.Model != "glm-5.3" || ep.APIKey != "zai-key" || ep.HeaderStyle != "openai" {
		t.Fatalf("endpoint = %+v", ep)
	}
}

func TestNormalizeEndpointModelRecognizesLegacyCustomZAIConfig(t *testing.T) {
	got := normalizeEndpointModel(
		"custom",
		"https://api.z.ai/api/coding/paas/v4/chat/completions",
		"Glm-5.3-Flash",
	)
	if got != "glm-5.3-flash" {
		t.Fatalf("normalized model = %q, want glm-5.3-flash", got)
	}
}
