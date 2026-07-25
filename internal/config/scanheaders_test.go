package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadScanHeaders(t *testing.T) {
	// Env only: ';'-separated pair parses into two ordered headers.
	t.Setenv("XALGORIX_SCAN_HEADERS", "X-Bug-Bounty: ulises2k; X-Scan-ID: 42")
	t.Setenv("XALGORIX_SCAN_HEADERS_FILE", "")
	got := loadScanHeaders()
	want := []string{"X-Bug-Bounty: ulises2k", "X-Scan-ID: 42"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env-only loadScanHeaders() = %#v, want %#v", got, want)
	}

	// Env + file: env entries win on a name clash (X-Scan-ID); the file adds a
	// new header (X-Extra) and its comment/blank lines are ignored.
	dir := t.TempDir()
	fp := filepath.Join(dir, "headers.txt")
	if err := os.WriteFile(fp, []byte("# comment\nX-Scan-ID: from-file-ignored\nX-Extra: e\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XALGORIX_SCAN_HEADERS_FILE", fp)
	got = loadScanHeaders()
	want = []string{"X-Bug-Bounty: ulises2k", "X-Scan-ID: 42", "X-Extra: e"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env+file loadScanHeaders() = %#v, want %#v", got, want)
	}

	// A missing file is non-fatal: the env headers still load.
	t.Setenv("XALGORIX_SCAN_HEADERS_FILE", filepath.Join(dir, "does-not-exist.txt"))
	got = loadScanHeaders()
	want = []string{"X-Bug-Bounty: ulises2k", "X-Scan-ID: 42"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing-file loadScanHeaders() = %#v, want %#v", got, want)
	}

	// Nothing configured -> nil.
	t.Setenv("XALGORIX_SCAN_HEADERS", "")
	t.Setenv("XALGORIX_SCAN_HEADERS_FILE", "")
	if got := loadScanHeaders(); got != nil {
		t.Fatalf("unset loadScanHeaders() = %#v, want nil", got)
	}
}
