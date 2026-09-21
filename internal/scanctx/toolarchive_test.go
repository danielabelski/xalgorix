package scanctx

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestToolArchiveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a := NewToolArchive(filepath.Join(dir, "scan-1"))

	// Below threshold → not archived.
	if id := a.Archive("curl", "short", 1500); id != "" {
		t.Fatalf("small output archived: %q", id)
	}

	content := strings.Repeat("A", 5000)
	id := a.Archive("curl", content, 1500)
	if id == "" {
		t.Fatal("expected archive id")
	}
	if !strings.HasPrefix(id, "to_") {
		t.Fatalf("id format = %q", id)
	}
	// Unique ids.
	id2 := a.Archive("curl", content, 1500)
	if id2 == id {
		t.Fatal("ids must be unique")
	}

	got, ok := a.Get(id)
	if !ok || got != content {
		t.Fatalf("round-trip mismatch: ok=%v len(got)=%d want len=%d", ok, len(got), len(content))
	}

	if _, ok := a.Get("to_999999"); ok {
		t.Fatal("unknown id must miss")
	}
	if _, ok := a.Get("../../etc/passwd"); ok {
		t.Fatal("path traversal must miss")
	}
	if _, ok := a.Get(""); ok {
		t.Fatal("empty id must miss")
	}
	if a.Count() != 2 {
		t.Fatalf("count = %d, want 2", a.Count())
	}
}

func TestToolArchivePersistsToDisk(t *testing.T) {
	dir := t.TempDir()
	a := NewToolArchive(dir)
	content := strings.Repeat("payload\n", 400)
	id := a.Archive("subfinder", content, 100)
	if id == "" {
		t.Fatal("expected archive id")
	}
	data, err := os.ReadFile(filepath.Join(dir, toolArchiveDir, id))
	if err != nil {
		t.Fatalf("archive file: %v", err)
	}
	if !strings.Contains(string(data), content) {
		t.Fatal("archive file must contain the full raw output")
	}
	if !strings.HasPrefix(string(data), "tool: subfinder\n\n") {
		t.Fatalf("archive header missing: %q", data[:30])
	}
}

func TestToolArchiveNilSafe(t *testing.T) {
	a := NewToolArchive("")
	if id := a.Archive("curl", strings.Repeat("x", 9999), 1); id != "" {
		t.Fatal("disabled archive must not store")
	}
	if _, ok := a.Get("to_000001"); ok {
		t.Fatal("disabled archive must not retrieve")
	}
}

func TestToolArchiveConcurrentArchive(t *testing.T) {
	a := NewToolArchive(t.TempDir())
	var wg sync.WaitGroup
	ids := make([]string, 50)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids[i] = a.Archive("curl", strings.Repeat("z", 2000), 100)
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" {
			t.Fatal("concurrent archive lost an id")
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}
