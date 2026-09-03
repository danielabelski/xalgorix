package providers

import "testing"

func TestOpenAICompatibleURL(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		resource string
		want     string
	}{
		{
			name:     "unversioned base receives v1",
			base:     "https://llm.example/api",
			resource: "chat/completions",
			want:     "https://llm.example/api/v1/chat/completions",
		},
		{
			name:     "openai v1 base is preserved",
			base:     "https://api.openai.com/v1",
			resource: "chat/completions",
			want:     "https://api.openai.com/v1/chat/completions",
		},
		{
			name:     "zai coding v4 base is preserved",
			base:     "https://api.z.ai/api/coding/paas/v4",
			resource: "chat/completions",
			want:     "https://api.z.ai/api/coding/paas/v4/chat/completions",
		},
		{
			name:     "zai models use v4 directly",
			base:     "https://api.z.ai/api/coding/paas/v4/",
			resource: "models",
			want:     "https://api.z.ai/api/coding/paas/v4/models",
		},
		{
			name:     "existing resource is not duplicated",
			base:     "https://api.z.ai/api/paas/v4/chat/completions",
			resource: "chat/completions",
			want:     "https://api.z.ai/api/paas/v4/chat/completions",
		},
		{
			name:     "version segment before provider path is respected",
			base:     "https://llm.example/v2/openai",
			resource: "chat/completions",
			want:     "https://llm.example/v2/openai/chat/completions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OpenAICompatibleURL(tt.base, tt.resource); got != tt.want {
				t.Fatalf("OpenAICompatibleURL(%q, %q) = %q, want %q", tt.base, tt.resource, got, tt.want)
			}
		})
	}
}
