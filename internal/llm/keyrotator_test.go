package llm

import "testing"

func TestKeyRotatorRoundRobin(t *testing.T) {
	r := NewKeyRotator([]string{"a", "b", "c"})
	seen := map[string]int{}
	for range 6 {
		seen[r.Pick()]++
	}
	for _, k := range []string{"a", "b", "c"} {
		if seen[k] != 2 {
			t.Fatalf("expected 2 picks for %q, got %d", k, seen[k])
		}
	}
}

func TestKeyRotatorDedupAndEmpty(t *testing.T) {
	if got := NewKeyRotator(nil); got != nil {
		t.Fatal("nil input must yield nil rotator")
	}
	r := NewKeyRotator([]string{"a", "", "a", "b"})
	if r.Len() != 2 {
		t.Fatalf("expected dedupe to 2 keys, got %d", r.Len())
	}
}

func TestKeyRotatorCooldownSkip(t *testing.T) {
	r := NewKeyRotator([]string{"a", "b"})
	first := r.Pick()
	r.MarkLastRateLimited()
	next := r.Pick()
	if next == first {
		t.Fatalf("expected cooldown to skip %q", first)
	}
	// While `first` cools, every pick must land on the other key.
	for range 3 {
		if got := r.Pick(); got != next {
			t.Fatalf("expected %q while %q cools, got %q", next, first, got)
		}
	}
}

func TestKeyRotatorAllCoolingFallsBack(t *testing.T) {
	r := NewKeyRotator([]string{"a"})
	k := r.Pick()
	r.MarkLastRateLimited()
	if got := r.Pick(); got != k {
		t.Fatalf("single-key pool must still return its key, got %q", got)
	}
}

func TestKeyRotatorAllCoolingPicksPooled(t *testing.T) {
	r := NewKeyRotator([]string{"a", "b"})
	a := r.Pick()
	r.MarkLastRateLimited()
	b := r.Pick()
	r.MarkLastRateLimited()
	// Both cooling: pick must still return one of the pool keys.
	got := r.Pick()
	if got != a && got != b {
		t.Fatalf("expected a pooled key, got %q", got)
	}
}
