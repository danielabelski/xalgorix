package sandbox

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// TestCheckRead_AllowsOutsideAllowList confirms the new read policy:
// reads outside the write Allow_List succeed by default. This is the
// whole point of the change — wordlists in /usr/share, payload dirs
// in /opt, and other read-mostly assets must be reachable without
// being copied into the workspace.
func TestCheckRead_AllowsOutsideAllowList(t *testing.T) {
	// Allow_List intentionally narrow. /etc/hostname is outside it but
	// is a real read-only file present on every Linux box, so it
	// exercises the canonicalization path too.
	p := New("/tmp/xalgorix-write-only")

	canonical, err := p.CheckRead(nil, "test", "/etc/hostname")
	if err != nil {
		t.Fatalf("read of /etc/hostname rejected: %v", err)
	}
	if !filepath.IsAbs(canonical) {
		t.Fatalf("canonical path = %q, want absolute", canonical)
	}
}

// TestCheckRead_AllowsInsideAllowList confirms reads inside the
// Allow_List still succeed (the old behavior is preserved).
func TestCheckRead_AllowsInsideAllowList(t *testing.T) {
	root := t.TempDir()
	p := New(root)

	canonical, err := p.CheckRead(nil, "test", filepath.Join(root, "any-file"))
	if err != nil {
		t.Fatalf("read inside allow-list rejected: %v", err)
	}
	if !strings.HasPrefix(canonical, root) {
		t.Fatalf("canonical = %q, want prefix %q", canonical, root)
	}
}

// TestCheckRead_DenyListBlocks confirms the deny-list portion: reads
// of paths under a deny-list root are rejected with PathRejectError.
// errors.Is(err, ErrPathReject) must match for callers that want the
// generic check.
func TestCheckRead_DenyListBlocks(t *testing.T) {
	denyRoot := t.TempDir()
	p := NewWithReadDeny(
		[]string{"/tmp/xalgorix-write-only"},
		[]string{denyRoot},
	)

	target := filepath.Join(denyRoot, "secret-key")
	_, err := p.CheckRead(nil, "test", target)
	if err == nil {
		t.Fatalf("read of %s should have been rejected", target)
	}
	if !errors.Is(err, ErrPathReject) {
		t.Fatalf("err = %T %v, want errors.Is(ErrPathReject)", err, err)
	}
	var rej *PathRejectError
	if !errors.As(err, &rej) {
		t.Fatalf("err = %T, want *PathRejectError", err)
	}
	if rej.Tool != "test" {
		t.Fatalf("rej.Tool = %q, want %q", rej.Tool, "test")
	}
}

// TestCheckRead_DenyListExactMatch confirms an exact match against a
// deny-list root (not just a descendant) is rejected. Without this
// guard, a deny-list entry like "/etc/shadow" would only fire on
// reads of /etc/shadow/something — which never happens because
// /etc/shadow is a file.
func TestCheckRead_DenyListExactMatch(t *testing.T) {
	denyFile := filepath.Join(t.TempDir(), "shadow")
	p := NewWithReadDeny(nil, []string{denyFile})

	_, err := p.CheckRead(nil, "test", denyFile)
	if err == nil {
		t.Fatalf("read of exact deny-list path %s should have been rejected", denyFile)
	}
	if !errors.Is(err, ErrPathReject) {
		t.Fatalf("err = %T %v, want errors.Is(ErrPathReject)", err, err)
	}
}

// TestCheckRead_DenyListSiblingNotBlocked confirms the deny-list
// boundary uses prefix-with-separator semantics — a sibling path like
// "/etc/shadow.bak" must NOT be rejected by a "/etc/shadow" deny-list
// entry. (Naive strings.HasPrefix without the separator check would
// produce a false positive here.)
func TestCheckRead_DenyListSiblingNotBlocked(t *testing.T) {
	dir := t.TempDir()
	denyFile := filepath.Join(dir, "shadow")
	siblingFile := filepath.Join(dir, "shadow.bak")
	p := NewWithReadDeny(nil, []string{denyFile})

	if _, err := p.CheckRead(nil, "test", siblingFile); err != nil {
		t.Fatalf("sibling path %s should not be denied by entry %s: %v",
			siblingFile, denyFile, err)
	}
}

// TestCheckRead_EmptyDenyListAllowsEverything confirms a Policy
// constructed with no deny-list (the legacy New behavior) admits every
// read. This is the behavior tests written before the deny-list
// addition relied on.
func TestCheckRead_EmptyDenyListAllowsEverything(t *testing.T) {
	p := New("/tmp/xalgorix-write-only")
	if got := len(p.ReadDenyRoots()); got != 0 {
		t.Fatalf("ReadDenyRoots() len = %d, want 0", got)
	}

	for _, target := range []string{
		"/etc/hostname",
		"/usr/share/wordlists/rockyou.txt",
		"/opt/some/payload",
	} {
		if _, err := p.CheckRead(nil, "test", target); err != nil {
			t.Fatalf("read of %s rejected with empty deny-list: %v", target, err)
		}
	}
}

// TestCheckResolve_Unchanged confirms the WRITE entry point is
// untouched by the read-policy work: writes outside the Allow_List
// remain rejected.
func TestCheckResolve_Unchanged(t *testing.T) {
	root := t.TempDir()
	p := NewWithReadDeny([]string{root}, []string{filepath.Join(root, "secret")})

	// Write inside Allow_List → ok.
	if _, err := p.CheckResolve(nil, "test", filepath.Join(root, "ok.txt")); err != nil {
		t.Fatalf("write inside allow-list rejected: %v", err)
	}
	// Write outside Allow_List → reject.
	outside := filepath.Join(t.TempDir(), "elsewhere.txt")
	if _, err := p.CheckResolve(nil, "test", outside); err == nil {
		t.Fatalf("write outside allow-list (%s) should have been rejected", outside)
	}
}

func TestCheckResolve_AllowsActiveScanDirOutsideGlobalRoots(t *testing.T) {
	globalRoot := t.TempDir()
	scanRoot := t.TempDir()
	p := New(globalRoot)
	sc := scanctx.New("sandbox-dynamic-scan-root", scanRoot)
	defer sc.Close()

	target := filepath.Join(scanRoot, "tmp", "proof.py")
	resolved, err := p.CheckResolve(sc, "fileedit.create", target)
	if err != nil {
		t.Fatalf("write inside active ScanDir rejected: %v", err)
	}
	if resolved != target {
		t.Fatalf("resolved path = %q, want %q", resolved, target)
	}

	outside := filepath.Join(t.TempDir(), "outside.txt")
	if _, err := p.CheckResolve(sc, "fileedit.create", outside); err == nil {
		t.Fatalf("write outside global roots and ScanDir (%s) should be rejected", outside)
	}
}

// TestReadDenyRoots_DefensiveCopy confirms callers cannot mutate
// the Policy's internal state via the returned slice.
func TestReadDenyRoots_DefensiveCopy(t *testing.T) {
	p := NewWithReadDeny(nil, []string{"/secret/one"})
	got := p.ReadDenyRoots()
	if len(got) != 1 {
		t.Fatalf("ReadDenyRoots() len = %d, want 1", len(got))
	}
	got[0] = "/mutated"
	if p.ReadDenyRoots()[0] == "/mutated" {
		t.Fatal("ReadDenyRoots returned a slice aliased to internal state")
	}
}
