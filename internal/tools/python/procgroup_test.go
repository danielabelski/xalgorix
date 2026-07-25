//go:build unix

package python

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestConfigureProcessGroupKill reproduces the orphaned-child hang: a shell
// stays alive (via `wait`) while a background child inherits the command's
// stdout pipe. When the context deadline fires, exec.CommandContext's default
// cancel would SIGKILL only the shell PID, leaving the child holding the pipe
// so cmd.Wait() blocks until the child's own 60s sleep ends. With
// configureProcessGroupKill the whole process group is SIGKILLed, so both die
// and Wait() returns promptly.
func TestConfigureProcessGroupKill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// `sleep 60 & wait` keeps the shell alive until the deadline (so Cancel
	// actually fires) with a backgrounded child holding the inherited stdout
	// pipe — the classic orphan-holds-the-pipe case.
	cmd := exec.CommandContext(ctx, "sh", "-c", "sleep 60 & wait")
	configureProcessGroupKill(cmd)

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
		// Returned promptly after the 300ms deadline — process group was killed.
	case <-time.After(10 * time.Second):
		t.Fatal("cmd.Wait() did not return within 10s of the 300ms timeout: " +
			"orphaned child still holds the pipe (process group not killed)")
	}
}
