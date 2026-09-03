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

func TestRoutePatternsAreValidRE2(t *testing.T) {
	// Every framework route pattern must compile under Go's RE2 engine (it is
	// recompiled in searchRouteMatches to extract method/path groups) and stay
	// grep-ERE-safe so the grep fallback works when ripgrep is absent.
	for _, rp := range routePatterns {
		if _, err := regexp.Compile(rp.re); err != nil {
			t.Errorf("route pattern %q does not compile: %v", rp.framework, err)
		}
	}
}

func TestRouteScanNoSource(t *testing.T) {
	if _, err := RouteScan("ctx-routescan-missing", 60); err == nil {
		t.Fatal("RouteScan must error when no source root is configured")
	}
}

func TestRouteScanFindsRoutes(t *testing.T) {
	const ctx = "ctx-routescan"
	dir := t.TempDir()
	// Flask: a generic @app.route (method ANY) and a @app.get method decorator.
	flask := "from flask import Flask\napp = Flask(__name__)\n\n" +
		"@app.route('/admin')\ndef admin():\n    return 'ok'\n\n" +
		"@app.get('/users')\ndef users():\n    return 'ok'\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(flask), 0o644); err != nil {
		t.Fatal(err)
	}
	// Express: app.post method call (no decorator).
	express := "const app = require('express')()\n" +
		"app.post('/login', (req, res) => res.send('ok'))\n"
	if err := os.WriteFile(filepath.Join(dir, "server.js"), []byte(express), 0o644); err != nil {
		t.Fatal(err)
	}
	SetSourceRoot(ctx, dir)
	defer SetSourceRoot(ctx, "")

	routes, err := RouteScan(ctx, 60)
	if err != nil {
		t.Fatalf("RouteScan: %v", err)
	}
	byPath := map[string]RouteMatch{}
	for _, r := range routes {
		byPath[r.Path] = r
		if r.File == "" || filepath.IsAbs(r.File) {
			t.Fatalf("RouteMatch.File must be source-root-relative, got %q", r.File)
		}
		if r.Line <= 0 {
			t.Fatalf("RouteMatch.Line must be 1-based, got %d for %s", r.Line, r.Path)
		}
	}
	admin, ok := byPath["/admin"]
	if !ok {
		t.Fatalf("expected /admin route, got %+v", routes)
	}
	if admin.File != "app.py" {
		t.Fatalf("/admin should be in app.py, got %q", admin.File)
	}
	if users, ok := byPath["/users"]; !ok || users.Method != "GET" {
		t.Fatalf("expected GET /users, got %+v (all: %+v)", users, routes)
	}
	login, ok := byPath["/login"]
	if !ok || login.Method != "POST" {
		t.Fatalf("expected POST /login, got %+v (all: %+v)", login, routes)
	}
	if login.File != "server.js" {
		t.Fatalf("/login should be in server.js, got %q", login.File)
	}
}

func TestRouteScanBounded(t *testing.T) {
	const ctx = "ctx-routescan-bound"
	dir := t.TempDir()
	src := "from flask import Flask\napp = Flask(__name__)\n" +
		"@app.get('/a')\ndef a():\n    return 1\n" +
		"@app.get('/b')\ndef b():\n    return 1\n" +
		"@app.get('/c')\ndef c():\n    return 1\n" +
		"@app.get('/d')\ndef d():\n    return 1\n" +
		"@app.get('/e')\ndef e():\n    return 1\n"
	if err := os.WriteFile(filepath.Join(dir, "many.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	SetSourceRoot(ctx, dir)
	defer SetSourceRoot(ctx, "")

	routes, err := RouteScan(ctx, 2)
	if err != nil {
		t.Fatalf("RouteScan: %v", err)
	}
	if len(routes) > 2 {
		t.Fatalf("max=2 must bound routes, got %d", len(routes))
	}
}

func TestRouteScanIgnoresNonRouterGetCalls(t *testing.T) {
	// Regression: the express pattern must not treat arbitrary .get()/.post()
	// calls (request.args.get, dict.get, session.get) as HTTP routes — only
	// router-like receivers (app, router, …) declare routes.
	const ctx = "ctx-routescan-fp"
	dir := t.TempDir()
	src := "from flask import request\n" +
		"def handler():\n" +
		"    host = request.args.get('host', '')\n" +
		"    k = data.get('secret_key')\n" +
		"    v = session.get('token')\n" +
		"    app.get('/users')\n" +
		"    router.post('/login')\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	SetSourceRoot(ctx, dir)
	defer SetSourceRoot(ctx, "")

	routes, err := RouteScan(ctx, 60)
	if err != nil {
		t.Fatalf("RouteScan: %v", err)
	}
	paths := map[string]bool{}
	for _, r := range routes {
		paths[r.Path] = true
	}
	// Real router route declarations are still found.
	if !paths["/users"] || !paths["/login"] {
		t.Fatalf("expected /users and /login routes, got %+v", routes)
	}
	// Non-router .get() argument strings must NOT be seeded as routes.
	for _, bogus := range []string{"host", "secret_key", "token"} {
		if paths[bogus] {
			t.Fatalf("non-router .get() call must not yield a route %q; got %+v", bogus, routes)
		}
	}
}

// TestRouteScanCrossLanguage verifies route extraction works across the
// frameworks the bridge claims to support beyond Flask/Express: Go routers
// (gin/net-http), Java Spring annotations, Django urls, and Rails routes.
func TestRouteScanCrossLanguage(t *testing.T) {
	const ctx = "ctx-routescan-xlang"
	dir := t.TempDir()
	files := map[string]string{
		"routes.go": "package main\n\nfunc register(r *gin.Engine, mux *http.ServeMux) {\n" +
			"\tr.GET(\"/go/items\", listItems)\n" +
			"\tmux.HandleFunc(\"/go/health\", health)\n}\n",
		"Controller.java": "@RestController\npublic class C {\n" +
			"  @GetMapping(\"/spring/users\")\n  public String users() { return \"ok\"; }\n\n" +
			"  @PostMapping(value = \"/spring/login\")\n  public String login() { return \"ok\"; }\n}\n",
		"urls.py": "from django.urls import path, re_path\n\nurlpatterns = [\n" +
			"    path('django/admin/', admin_view),\n" +
			"    re_path(r'^django/legacy$', legacy_view),\n]\n",
		"routes.rb": "Rails.application.routes.draw do\n" +
			"  get 'rails/profile'\n  post 'rails/session'\nend\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	SetSourceRoot(ctx, dir)
	defer SetSourceRoot(ctx, "")

	routes, err := RouteScan(ctx, 100)
	if err != nil {
		t.Fatalf("RouteScan: %v", err)
	}
	byPath := map[string]RouteMatch{}
	for _, r := range routes {
		byPath[r.Path] = r
	}

	// Go + Spring routes are asserted precisely (path + method + file).
	for _, want := range []struct{ path, method, file string }{
		{"/go/items", "GET", "routes.go"},
		{"/spring/users", "GET", "Controller.java"},
		{"/spring/login", "POST", "Controller.java"},
	} {
		r, ok := byPath[want.path]
		if !ok {
			t.Errorf("expected route %q (all: %+v)", want.path, routes)
			continue
		}
		if r.Method != want.method {
			t.Errorf("route %q: method=%q want %q", want.path, r.Method, want.method)
		}
		if r.File != want.file {
			t.Errorf("route %q: file=%q want %q", want.path, r.File, want.file)
		}
	}
	// Go mux.HandleFunc, Django, and Rails routes: assert the distinctive path
	// segment is present (leading-slash / trailing-slash normalization tolerant).
	hasSeg := func(seg string) bool {
		for p := range byPath {
			if strings.Contains(p, seg) {
				return true
			}
		}
		return false
	}
	for _, seg := range []string{"go/health", "django/admin", "django/legacy", "rails/profile", "rails/session"} {
		if !hasSeg(seg) {
			t.Errorf("expected a route containing %q (all: %+v)", seg, routes)
		}
	}
}

// TestSinkScanCrossLanguage verifies command-exec sink detection works across
// languages: Java (Runtime.getRuntime/ProcessBuilder), Go (os/exec), PHP
// (shell_exec) — each must surface as an rce sink.
func TestSinkScanCrossLanguage(t *testing.T) {
	const ctx = "ctx-sinkscan-xlang"
	dir := t.TempDir()
	files := map[string]string{
		"Exec.java": "public class Exec {\n  void run(String h) throws Exception {\n" +
			"    Runtime.getRuntime().exec(\"ping \" + h);\n" +
			"    new ProcessBuilder(\"sh\", \"-c\", h).start();\n  }\n}\n",
		"run.go": "package main\n\nimport \"os/exec\"\n\nfunc run(h string) {\n" +
			"\texec.Command(\"sh\", \"-c\", h).Run()\n}\n",
		"shell.php": "<?php\nfunction run($h) {\n  return shell_exec('ping ' . $h);\n}\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	SetSourceRoot(ctx, dir)
	defer SetSourceRoot(ctx, "")

	found, err := SinkScan(ctx, 50)
	if err != nil {
		t.Fatalf("SinkScan: %v", err)
	}
	rce := found["rce"]
	if len(rce) == 0 {
		t.Fatalf("expected rce sinks across languages, got none (found classes: %v)", classKeys(found))
	}
	filesWithRCE := map[string]bool{}
	for _, m := range rce {
		filesWithRCE[m.File] = true
	}
	for _, f := range []string{"Exec.java", "run.go", "shell.php"} {
		if !filesWithRCE[f] {
			t.Errorf("expected an rce sink in %s (rce matches: %+v)", f, rce)
		}
	}
}

func classKeys(m map[string][]SinkMatch) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
