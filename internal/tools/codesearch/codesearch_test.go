package codesearch

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func TestSetGetSourceRoot(t *testing.T) {
	const ctx = "ctx-A"
	SetSourceRoot(ctx, "/tmp/src")
	if got := GetSourceRoot(ctx); got != "/tmp/src" {
		t.Fatalf("GetSourceRoot = %q, want /tmp/src", got)
	}
	SetSourceRoot(ctx, "") // clear
	if got := GetSourceRoot(ctx); got != "" {
		t.Fatalf("after clear GetSourceRoot = %q, want empty", got)
	}
}

func TestSinkPatternsAreValidRE2(t *testing.T) {
	// Every curated sink pattern must compile under Go's RE2 engine so the
	// grep fallback (grep -E is looser, but we also surface patterns to the
	// agent) never ships a broken regex.
	for class, pat := range sinkPatterns {
		if _, err := regexp.Compile(pat); err != nil {
			t.Errorf("sink pattern %q does not compile: %v", class, err)
		}
	}
	// Guard the class list the tool advertises stays in sync.
	classes := sinkClasses()
	if len(classes) != len(sinkPatterns) {
		t.Fatalf("sinkClasses()=%d != sinkPatterns=%d", len(classes), len(sinkPatterns))
	}
}

func TestLooksLikeGitURL(t *testing.T) {
	yes := []string{
		"https://github.com/x/y.git",
		"http://host/repo",
		"git@github.com:x/y.git",
		"ssh://git@host/repo",
		"anything.git",
	}
	no := []string{"/local/path", "./rel", "not-a-url", ""}
	for _, s := range yes {
		if !looksLikeGitURL(s) {
			t.Errorf("looksLikeGitURL(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksLikeGitURL(s) {
			t.Errorf("looksLikeGitURL(%q) = true, want false", s)
		}
	}
}

func TestResolveSourceEmpty(t *testing.T) {
	root, err := ResolveSource("  ", t.TempDir())
	if err != nil {
		t.Fatalf("empty repo must be a no-op, got err %v", err)
	}
	if root != "" {
		t.Fatalf("empty repo must resolve to empty root, got %q", root)
	}
}

func TestResolveSourceLocalDir(t *testing.T) {
	dir := t.TempDir()
	root, err := ResolveSource(dir, filepath.Join(t.TempDir(), "dest"))
	if err != nil {
		t.Fatalf("local dir resolve: %v", err)
	}
	absWant, _ := filepath.Abs(dir)
	if root != absWant {
		t.Fatalf("root = %q, want abs local dir %q", root, absWant)
	}
}

func TestResolveSourceInvalidNonGit(t *testing.T) {
	_, err := ResolveSource("/no/such/path/and/not/a/url", filepath.Join(t.TempDir(), "dest"))
	if err == nil {
		t.Fatal("a non-existent, non-git reference must error")
	}
	if !strings.Contains(err.Error(), "neither") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteWithContextNoSource(t *testing.T) {
	// Unknown context → no source root → helpful fallback message, no error.
	res, err := executeWithContext("ctx-no-source", map[string]string{"sinks": "rce"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Output, "Whitebox source not available") {
		t.Fatalf("expected fallback message, got: %s", res.Output)
	}
}

func TestExecuteWithContextUnknownSink(t *testing.T) {
	const ctx = "ctx-unknown-sink"
	SetSourceRoot(ctx, t.TempDir())
	defer SetSourceRoot(ctx, "")
	res, err := executeWithContext(ctx, map[string]string{"sinks": "not-a-real-class"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Output, "Unknown sink class") {
		t.Fatalf("expected unknown-sink message, got: %s", res.Output)
	}
}

func TestExecuteWithContextNoQuery(t *testing.T) {
	const ctx = "ctx-no-query"
	SetSourceRoot(ctx, t.TempDir())
	defer SetSourceRoot(ctx, "")
	res, err := executeWithContext(ctx, map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Output, "Provide either") {
		t.Fatalf("expected 'provide either' message, got: %s", res.Output)
	}
}

func TestExecuteWithContextFindsSink(t *testing.T) {
	const ctx = "ctx-real-search"
	dir := t.TempDir()
	// Plant a dangerous RCE sink the curated 'rce' class should catch.
	src := "import os\n\ndef handler(cmd):\n    os.system(cmd)  # user-controlled\n"
	if err := os.WriteFile(filepath.Join(dir, "vuln.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	SetSourceRoot(ctx, dir)
	defer SetSourceRoot(ctx, "")

	res, err := executeWithContext(ctx, map[string]string{"sinks": "rce"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Output, "os.system") {
		t.Fatalf("expected os.system hit in output, got: %s", res.Output)
	}
	if !strings.Contains(res.Output, "Source matches") {
		t.Fatalf("expected 'Source matches' header, got: %s", res.Output)
	}
}

func TestExecuteWithContextCustomQueryNoMatch(t *testing.T) {
	const ctx = "ctx-no-match"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	SetSourceRoot(ctx, dir)
	defer SetSourceRoot(ctx, "")

	res, err := executeWithContext(ctx, map[string]string{"query": "ZZ_definitely_absent_ZZ"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Output, "No matches") {
		t.Fatalf("expected 'No matches' message, got: %s", res.Output)
	}
}

func TestExecuteWithContextPathTraversalContained(t *testing.T) {
	// A malicious 'path' that tries to escape the source root must be
	// contained: the search must stay within root (no panic, no crash, and
	// it should behave as an in-root search).
	const ctx = "ctx-traversal"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("token=abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	SetSourceRoot(ctx, dir)
	defer SetSourceRoot(ctx, "")

	res, err := executeWithContext(ctx, map[string]string{
		"query": "token",
		"path":  "../../../../etc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Must not leak /etc/passwd style content; output references our root.
	if strings.Contains(res.Output, "root:x:0:0") {
		t.Fatalf("path traversal escaped the source root: %s", res.Output)
	}
}

func TestRegister(t *testing.T) {
	reg := tools.NewRegistry()
	Register(reg)
	tool, ok := reg.Get("code_search")
	if !ok {
		t.Fatal("code_search not registered")
	}
	if tool.Name != "code_search" {
		t.Fatalf("tool name = %q", tool.Name)
	}
	if len(tool.Parameters) == 0 {
		t.Fatal("code_search should declare parameters")
	}
}

func TestSinkScanNoSource(t *testing.T) {
	// No source root configured for this context → SinkScan must error so the
	// caller can fall back to black-box discovery.
	if _, err := SinkScan("ctx-sinkscan-missing", 20); err == nil {
		t.Fatal("SinkScan must error when no source root is configured")
	}
}

func TestSinkScanFindsRCESink(t *testing.T) {
	const ctx = "ctx-sinkscan-rce"
	dir := t.TempDir()
	// A user-controlled command reaching os.system — the canonical RCE sink the
	// curated 'rce' class must catch. grep-ERE-safe (no (?i)) so it passes with
	// the grep fallback when ripgrep is absent (as in CI).
	src := "import os\n\ndef handler(request):\n    cmd = request.args.get('cmd')\n    os.system(cmd)  # RCE sink\n"
	if err := os.WriteFile(filepath.Join(dir, "vuln.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	SetSourceRoot(ctx, dir)
	defer SetSourceRoot(ctx, "")

	res, err := SinkScan(ctx, 20)
	if err != nil {
		t.Fatalf("SinkScan: %v", err)
	}
	rce := res["rce"]
	if len(rce) == 0 {
		t.Fatalf("expected >=1 rce sink match, got none; full result: %+v", res)
	}
	var found bool
	for _, m := range rce {
		// Structured fields must be populated: a source-root-relative file
		// (never absolute), a 1-based line, and bounded text.
		if m.File == "" || filepath.IsAbs(m.File) {
			t.Fatalf("SinkMatch.File must be a source-root-relative path, got %q", m.File)
		}
		if m.Line <= 0 {
			t.Fatalf("SinkMatch.Line must be 1-based, got %d", m.Line)
		}
		if strings.Contains(m.Text, "os.system") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an os.system hit in rce matches, got: %+v", rce)
	}
	if rce[0].File != "vuln.py" {
		t.Fatalf("expected match file 'vuln.py', got %q", rce[0].File)
	}
}

func TestSinkScanBoundsPerClass(t *testing.T) {
	const ctx = "ctx-sinkscan-bound"
	dir := t.TempDir()
	var sb strings.Builder
	sb.WriteString("import os\n")
	for i := 0; i < 5; i++ {
		sb.WriteString("os.system('x')\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "many.py"), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	SetSourceRoot(ctx, dir)
	defer SetSourceRoot(ctx, "")

	res, err := SinkScan(ctx, 2)
	if err != nil {
		t.Fatalf("SinkScan: %v", err)
	}
	if n := len(res["rce"]); n > 2 {
		t.Fatalf("maxPerClass=2 must bound rce matches, got %d", n)
	}
}
