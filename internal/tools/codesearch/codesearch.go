// Package codesearch provides whitebox / source-assisted capability: it
// resolves the target's source (a Git URL or local path) and exposes a
// code_search tool so the agent can hunt dangerous sinks in code, trace them
// to reachable routes, and build exploits against the live target.
//
// This is the whitebox methodology that yields the high-severity classes
// (RCE, command injection, deserialization, secret exposure, SSRF) that
// black-box testing misses — you can SEE the vulnerable sink in the code.
package codesearch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

var (
	rootMu      sync.RWMutex
	sourceRoots = map[string]string{} // contextID -> absolute source root
)

// SetSourceRoot records the resolved source directory for a scan context.
func SetSourceRoot(contextID, path string) {
	rootMu.Lock()
	defer rootMu.Unlock()
	if path == "" {
		delete(sourceRoots, contextID)
		return
	}
	sourceRoots[contextID] = path
}

func getSourceRoot(contextID string) string {
	rootMu.RLock()
	defer rootMu.RUnlock()
	return sourceRoots[contextID]
}

// GetSourceRoot returns the resolved source directory for a scan context, or
// "" when whitebox source is not configured/resolved.
func GetSourceRoot(contextID string) string {
	return getSourceRoot(contextID)
}

// sinkPatterns maps a vulnerability class to a ripgrep regex covering common
// dangerous sinks across popular stacks. These are DISCOVERY aids — the agent
// still has to trace reachability and prove exploitability against the target.
var sinkPatterns = map[string]string{
	"rce":             `\b(exec|execSync|spawn|child_process|system|popen|proc_open|shell_exec|passthru|Runtime\.getRuntime|ProcessBuilder|os\.system|subprocess\.(call|run|Popen)|pty\.spawn|eval|new Function|Function\()`,
	"cmdi":            `\b(exec|execSync|spawn|shell_exec|passthru|popen|proc_open|os\.system|subprocess\.|\bsh -c\b|/bin/(ba)?sh)`,
	"sqli":            `(SELECT|INSERT|UPDATE|DELETE|WHERE).{0,80}(\+|\$\{|%s|f"|f'|\.format|concat|\|\|)|(query|execute|raw|rawQuery)\s*\(`,
	"deserialization": `\b(pickle\.loads|yaml\.load\b|Marshal\.load|ObjectInputStream|readObject|unserialize|Deserialize|JSON\.parse\().{0,40}|node-serialize|fastjson|SnakeYAML`,
	"ssrf":            `\b(requests\.(get|post)|urllib|http\.get|axios|fetch\(|HttpClient|curl_exec|file_get_contents|URL\(|OpenStream|WebClient)\b`,
	"fileio":          `\b(open\(|readFile|writeFile|fopen|File\.(read|write)|os\.(open|remove)|path\.join|sendFile|include|require\(|fs\.(read|write|createReadStream))`,
	"template":        `\b(render_template_string|Template\(|Jinja|Mustache|Handlebars|Freemarker|Velocity|Thymeleaf|ejs\.render|new Function|\{\{.*\}\})`,
	"secrets":         `(?i)(api[_-]?key|secret|password|passwd|token|private[_-]?key|aws_(access|secret)|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY)\s*[:=]`,
	"auth":            `(?i)(isAdmin|is_admin|role\s*==|authorize|authenticate|checkPermission|hasRole|requireAuth|@login_required|verify(Token|Jwt)|jwt\.(verify|decode))`,
	"redirect":        `\b(redirect|sendRedirect|Location:|res\.redirect|window\.location|header\("Location)`,
	"crypto":          `\b(Math\.random|MD5|SHA1|DES|ECB|Random\(\)|mt_rand|rand\(\))`,
}

// Register adds the code_search tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "code_search",
		Description: "Whitebox source-code search over the target's cloned source (fast, ripgrep-backed). Use it to find dangerous SINKS, trace them to reachable HTTP routes, and build exploits. Either pass a custom 'query' regex, or set 'sinks' to a class to search curated dangerous patterns. Classes: rce, cmdi, sqli, deserialization, ssrf, fileio, template, secrets, auth, redirect, crypto. Only available when source is configured for the scan.",
		Parameters: []tools.Parameter{
			{Name: "query", Description: "Custom regex to search (ripgrep syntax). Provide this OR 'sinks'.", Required: false},
			{Name: "sinks", Description: "A vuln class to search curated dangerous sink patterns: rce, cmdi, sqli, deserialization, ssrf, fileio, template, secrets, auth, redirect, crypto.", Required: false},
			{Name: "glob", Description: "Optional file glob to scope the search, e.g. '*.py', '*.js', 'routes/**'.", Required: false},
			{Name: "path", Description: "Optional subdirectory (relative to source root) to scope the search.", Required: false},
			{Name: "max", Description: "Max matches to return (default 60, hard cap 200).", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			return executeWithContext(r.GetScanContextID(), args)
		},
	})
}

func executeWithContext(contextID string, args map[string]string) (tools.Result, error) {
	root := getSourceRoot(contextID)
	if root == "" {
		return tools.Result{Output: "❌ Whitebox source not available for this scan (set XALGORIX_SOURCE_REPO to a git URL or local path). Fall back to black-box testing (fetch and read client-side JS bundles with http_request/browser to discover endpoints)."}, nil
	}

	query := strings.TrimSpace(args["query"])
	if sinks := strings.ToLower(strings.TrimSpace(args["sinks"])); sinks != "" {
		if p, ok := sinkPatterns[sinks]; ok {
			query = p
		} else {
			return tools.Result{Output: fmt.Sprintf("❌ Unknown sink class %q. Valid: %s", sinks, strings.Join(sinkClasses(), ", "))}, nil
		}
	}
	if query == "" {
		return tools.Result{Output: "❌ Provide either 'query' (regex) or 'sinks' (a vuln class)."}, nil
	}

	max := 60
	if s := strings.TrimSpace(args["max"]); s != "" {
		if n, err := parseIntSafe(s); err == nil && n > 0 {
			max = n
		}
	}
	if max > 200 {
		max = 200
	}

	// Scope the search dir, staying strictly within the source root.
	searchDir := root
	if sub := strings.TrimSpace(args["path"]); sub != "" {
		joined := filepath.Join(root, filepath.Clean("/"+sub)) // clean leading .. away
		if strings.HasPrefix(joined, filepath.Clean(root)) {
			searchDir = joined
		}
	}

	out, err := runSearch(searchDir, query, strings.TrimSpace(args["glob"]), max)
	if err != nil {
		return tools.Result{Output: "code_search error: " + err.Error()}, nil
	}
	if strings.TrimSpace(out) == "" {
		return tools.Result{Output: fmt.Sprintf("No matches for /%s/ in source. Try a different pattern or sink class.", query)}, nil
	}
	return tools.Result{Output: fmt.Sprintf("Source matches (root=%s):\n\n%s\n\nNext: for each hit, trace the sink back to a reachable HTTP route/handler and the user-controlled input that reaches it, then build a PoC against the LIVE target.", filepath.Base(root), out)}, nil
}

// runSearch prefers ripgrep; falls back to grep -RnE.
func runSearch(dir, pattern, glob string, max int) (string, error) {
	ctxTimeout := 60 * time.Second
	var cmd *exec.Cmd
	if rg, err := exec.LookPath("rg"); err == nil {
		rgArgs := []string{"--no-heading", "--line-number", "--color", "never", "-S", "--max-count", "5", "-m", fmt.Sprintf("%d", max), "-C", "1"}
		if glob != "" {
			rgArgs = append(rgArgs, "-g", glob)
		}
		rgArgs = append(rgArgs, "-e", pattern, dir)
		cmd = exec.Command(rg, rgArgs...)
	} else {
		grepArgs := []string{"-RnE", "--color=never"}
		if glob != "" {
			grepArgs = append(grepArgs, "--include="+glob)
		}
		grepArgs = append(grepArgs, pattern, dir)
		cmd = exec.Command("grep", grepArgs...)
	}
	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		out, runErr = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(ctxTimeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", fmt.Errorf("search timed out")
	}
	// rg/grep exit 1 == no matches (not an error for us).
	lines := strings.Split(string(out), "\n")
	if len(lines) > max {
		lines = lines[:max]
		lines = append(lines, fmt.Sprintf("... [truncated at %d matches]", max))
	}
	_ = runErr
	return strings.Join(lines, "\n"), nil
}

func sinkClasses() []string {
	cs := make([]string, 0, len(sinkPatterns))
	for k := range sinkPatterns {
		cs = append(cs, k)
	}
	sort.Strings(cs)
	return cs
}

// SinkMatch is one dangerous-sink hit located in the target's source: a
// source-root-relative file, a 1-based line number, and the (bounded) matched
// source text. It is the structured unit the agent seeds into the ledger as a
// source->sink hypothesis to trace back to a reachable HTTP route.
type SinkMatch struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// SinkScan runs every curated sink-class pattern over the scan's resolved
// source root and returns the structured matches grouped by class (only classes
// with at least one hit appear in the map). maxPerClass bounds matches returned
// per class (defaults to 20, hard cap 100). It errors only when no whitebox
// source is configured for the scan — the signal callers use to fall back to
// black-box discovery.
//
// This is the programmatic, seed-the-ledger sibling of the code_search tool:
// code_search renders a human-readable blob for one class on demand, whereas
// SinkScan sweeps all classes at once and yields typed matches so the agent can
// deterministically populate source->sink hypotheses. A single class whose
// search times out is skipped rather than failing the whole sweep.
func SinkScan(contextID string, maxPerClass int) (map[string][]SinkMatch, error) {
	root := getSourceRoot(contextID)
	if root == "" {
		return nil, fmt.Errorf("whitebox source not configured for scan %q", contextID)
	}
	if maxPerClass <= 0 {
		maxPerClass = 20
	}
	if maxPerClass > 100 {
		maxPerClass = 100
	}
	results := make(map[string][]SinkMatch)
	for _, class := range sinkClasses() {
		pattern := sinkPatterns[class]
		if pattern == "" {
			continue
		}
		matches, err := searchSinkMatches(root, pattern, maxPerClass)
		if err != nil {
			continue // e.g. this class's search timed out; keep sweeping.
		}
		if len(matches) > 0 {
			results[class] = matches
		}
	}
	return results, nil
}

// searchSinkMatches runs one sink-class regex over dir and returns structured
// matches (file:line:text), preferring ripgrep and falling back to grep -RnE.
// It is the structured sibling of runSearch: instead of a display blob it
// yields []SinkMatch for programmatic seeding, with source-root-relative paths
// and bounded text. rg/grep exit 1 (no matches) is not treated as an error;
// only a timeout is.
func searchSinkMatches(dir, pattern string, max int) ([]SinkMatch, error) {
	if max <= 0 {
		max = 20
	}
	var cmd *exec.Cmd
	if rg, err := exec.LookPath("rg"); err == nil {
		cmd = exec.Command(rg, "--no-heading", "--line-number", "--color", "never", "-S",
			"--max-count", strconv.Itoa(max), "-e", pattern, dir)
	} else {
		cmd = exec.Command("grep", "-RnE", "--color=never", pattern, dir)
	}

	done := make(chan struct{})
	var out []byte
	go func() {
		out, _ = cmd.CombinedOutput() // exit 1 == no matches; tolerated
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return nil, fmt.Errorf("sink search timed out")
	}

	matches := make([]SinkMatch, 0, max)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		m, ok := parseGrepLine(dir, line)
		if !ok {
			continue
		}
		matches = append(matches, m)
		if len(matches) >= max {
			break
		}
	}
	return matches, nil
}

// parseGrepLine parses a single rg/grep "file:line:text" record into a
// SinkMatch with a source-root-relative path and bounded text. It returns
// ok=false for lines that don't carry a parseable line number (e.g. binary
// notices or blank separators).
func parseGrepLine(root, line string) (SinkMatch, bool) {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) < 3 {
		return SinkMatch{}, false
	}
	ln, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return SinkMatch{}, false
	}
	file := parts[0]
	if rel, err := filepath.Rel(root, file); err == nil && !strings.HasPrefix(rel, "..") {
		file = rel
	}
	return SinkMatch{File: file, Line: ln, Text: boundText(parts[2], 200)}, true
}

// boundText trims and length-bounds a matched source line for compact display.
func boundText(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func parseIntSafe(s string) (int, error) {
	n := 0
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// ResolveSource turns an operator-supplied repo reference into a local source
// directory. A pre-existing local path is used in place; a Git URL is
// shallow-cloned into destDir. Returns the resolved absolute path.
func ResolveSource(repo, destDir string) (string, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return "", nil
	}
	// Local directory already on disk → use directly (read-only intent).
	if info, err := os.Stat(repo); err == nil && info.IsDir() {
		abs, _ := filepath.Abs(repo)
		return abs, nil
	}
	// Otherwise treat as a Git URL and shallow-clone.
	if !looksLikeGitURL(repo) {
		return "", fmt.Errorf("source %q is neither an existing directory nor a git URL", repo)
	}
	if err := os.MkdirAll(filepath.Dir(destDir), 0o750); err != nil {
		return "", fmt.Errorf("prepare source dir: %w", err)
	}
	_ = os.RemoveAll(destDir)
	cmd := exec.Command("git", "clone", "--depth", "1", "--single-branch", repo, destDir)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Minute):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return "", fmt.Errorf("git clone timed out after 3m")
	}
	if err != nil {
		return "", fmt.Errorf("git clone failed: %w: %s", err, truncate(string(out), 300))
	}
	abs, _ := filepath.Abs(destDir)
	return abs, nil
}

func looksLikeGitURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "git@") || strings.HasPrefix(s, "ssh://") ||
		strings.HasSuffix(s, ".git")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
