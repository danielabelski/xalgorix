package llm

import (
	"net/url"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/providers"
)

// normalizeProviderModel applies provider-specific normalization without
// freezing a remote provider's model catalog into the binary. Z.AI publishes
// lowercase GLM model IDs, while its product pages often render them as
// uppercase names. Accept either form and send the canonical lowercase ID.
func normalizeProviderModel(entry providers.Entry, model string) string {
	model = strings.TrimSpace(model)
	if entry.ID != "zai" && entry.ID != "zai-coding-plan" {
		return model
	}
	if strings.HasPrefix(strings.ToLower(model), "glm-") {
		return strings.ToLower(model)
	}
	return model
}

// normalizeEndpointModel also recognizes an explicitly configured Z.AI URL.
// This matters for existing installations that selected "Custom Provider"
// before native Z.AI support existed: their provider ID remains "custom", but
// the /api/(coding/)paas/v4 URL still identifies the target unambiguously.
func normalizeEndpointModel(providerID, endpointURL, model string) string {
	if inferred := zaiProviderFromURL(endpointURL); inferred != "" {
		providerID = inferred
	}
	entry, ok := providers.LookupBuiltin(providerID)
	if !ok {
		return strings.TrimSpace(model)
	}
	return normalizeProviderModel(entry, model)
}

func zaiProviderFromURL(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || !strings.EqualFold(u.Hostname(), "api.z.ai") {
		return ""
	}
	path := strings.ToLower(u.Path)
	if strings.Contains(path, "/api/coding/paas/v4") {
		return "zai-coding-plan"
	}
	if strings.Contains(path, "/api/paas/v4") {
		return "zai"
	}
	return ""
}
