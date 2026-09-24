package config

import "testing"

func TestParseAPIKeyList(t *testing.T) {
	got := ParseAPIKeyList("k1, k2,k3\nk4  k5")
	want := []string{"k1", "k2", "k3", "k4", "k5"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParseAPIKeyListDedupAndEmpty(t *testing.T) {
	if got := ParseAPIKeyList("  "); len(got) != 0 {
		t.Fatalf("whitespace-only must parse to empty, got %v", got)
	}
	got := ParseAPIKeyList("k1,k1,k2")
	if len(got) != 2 || got[0] != "k1" || got[1] != "k2" {
		t.Fatalf("expected dedupe [k1 k2], got %v", got)
	}
}
