package scanheaders

import (
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   \n  ", nil},
		{"single", "X-Bug-Bounty: ulises2k", []string{"X-Bug-Bounty: ulises2k"}},
		{"trims and normalizes spacing", "  X-Bug-Bounty:ulises2k  ", []string{"X-Bug-Bounty: ulises2k"}},
		{"multiple via newline", "X-Bug-Bounty: u\nX-Scan-ID: 42", []string{"X-Bug-Bounty: u", "X-Scan-ID: 42"}},
		{"multiple via semicolon", "X-Bug-Bounty: u; X-Scan-ID: 42", []string{"X-Bug-Bounty: u", "X-Scan-ID: 42"}},
		{"dedup by name keeps first", "X-A: 1\nX-A: 2", []string{"X-A: 1"}},
		{"dedup case-insensitive", "X-A: 1\nx-a: 2", []string{"X-A: 1"}},
		{"skips entry without colon", "not-a-header\nX-Ok: 1", []string{"X-Ok: 1"}},
		{"skips empty value", "X-Empty:\nX-Ok: 1", []string{"X-Ok: 1"}},
		{"skips invalid header name", "Bad Name: v\nX-Ok: 1", []string{"X-Ok: 1"}},
		{"value may contain colons", "Authorization: Bearer a:b:c", []string{"Authorization: Bearer a:b:c"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.raw)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Parse(%q) = %#v, want %#v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	got := Merge([]string{"X-A: 1", "X-B: 2"}, []string{"x-a: override-ignored", "X-C: 3"})
	want := []string{"X-A: 1", "X-B: 2", "X-C: 3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Merge = %#v, want %#v", got, want)
	}
}

func TestApplyDoesNotClobberCallerHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Existing", "keep")
	Apply(h, []string{"X-Bug-Bounty: u", "X-Existing: should-not-win", "malformed"})
	if got := h.Get("X-Bug-Bounty"); got != "u" {
		t.Fatalf("X-Bug-Bounty = %q, want u", got)
	}
	if got := h.Get("X-Existing"); got != "keep" {
		t.Fatalf("X-Existing = %q, want keep (attribution must not clobber a caller header)", got)
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "headers.txt")
	content := "# comment line\nX-Bug-Bounty: u\n\n  X-Scan-ID: 42  \nno-colon-line\n"
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"X-Bug-Bounty: u", "X-Scan-ID: 42"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseFile = %#v, want %#v", got, want)
	}
	if _, err := ParseFile(filepath.Join(dir, "missing.txt")); err == nil {
		t.Fatal("ParseFile(missing) should return an error")
	}
}
