package llm

import (
	"context"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// The legacy (no-resolver) path must swap the configured key for the
// next pooled key on every request.
func TestApplyKeyRotationAlternatesPooledKeys(t *testing.T) {
	cfg := &config.Config{
		LLM:     "minimax/MiniMax-M2.1",
		APIKey:  "k-primary",
		APIKeys: []string{"k-extra"},
	}
	c := NewClient(cfg)
	seen := map[string]bool{}
	for range 2 {
		ep, err := c.resolveRequestEndpoint(context.Background())
		if err != nil {
			t.Fatalf("resolveRequestEndpoint: %v", err)
		}
		seen[ep.APIKey] = true
	}
	if len(seen) != 2 {
		t.Fatalf("expected both pooled keys to be used, got %v", seen)
	}
}

// A key that just hit a provider rate limit must be skipped by the
// next endpoint resolution.
func TestApplyKeyRotationSkipsRateLimitedKey(t *testing.T) {
	cfg := &config.Config{
		LLM:     "minimax/MiniMax-M2.1",
		APIKey:  "k-primary",
		APIKeys: []string{"k-extra"},
	}
	c := NewClient(cfg)
	ep1, err := c.resolveRequestEndpoint(context.Background())
	if err != nil {
		t.Fatalf("resolveRequestEndpoint: %v", err)
	}
	ep2, err := c.resolveRequestEndpoint(context.Background())
	if err != nil {
		t.Fatalf("resolveRequestEndpoint: %v", err)
	}
	if ep1.APIKey == ep2.APIKey {
		t.Fatalf("expected rotation across two picks, both used %q", ep1.APIKey)
	}
	c.noteKeyRateLimited()
	ep3, err := c.resolveRequestEndpoint(context.Background())
	if err != nil {
		t.Fatalf("resolveRequestEndpoint: %v", err)
	}
	if ep3.APIKey == ep2.APIKey {
		t.Fatalf("expected %q to be skipped after rate limit, but it was picked again", ep2.APIKey)
	}
	if ep3.APIKey != ep1.APIKey {
		t.Fatalf("expected fallback to %q, got %q", ep1.APIKey, ep3.APIKey)
	}
}

// A single-key configuration must not build a rotator and must leave
// the resolved key byte-identical to the legacy behavior.
func TestSingleKeyLeavesRotatorOff(t *testing.T) {
	cfg := &config.Config{
		LLM:    "minimax/MiniMax-M2.1",
		APIKey: "only",
	}
	c := NewClient(cfg)
	if c.keyRotator != nil {
		t.Fatal("single-key config must not build a rotator")
	}
	ep, err := c.resolveRequestEndpoint(context.Background())
	if err != nil {
		t.Fatalf("resolveRequestEndpoint: %v", err)
	}
	if ep.APIKey != "only" {
		t.Fatalf("expected key %q, got %q", "only", ep.APIKey)
	}
}
