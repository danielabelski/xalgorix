package agent

import (
	"context"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

func TestAgent_IterationDelay_DefaultAndGetters(t *testing.T) {
	cfg := &config.Config{
		IterationDelaySec: 0,
	}
	sctx := scanctx.New("test-getters", t.TempDir())
	scanctx.Activate(sctx)
	defer sctx.Close()

	agnt := NewAgent(cfg, "test", make(chan Event, 10), scopeguard.Config{}, sctx)
	if delay := agnt.getIterationDelay(); delay != 0 {
		t.Fatalf("expected 0 delay, got %v", delay)
	}

	cfg.IterationDelaySec = 2.5
	agnt2 := NewAgent(cfg, "test2", make(chan Event, 10), scopeguard.Config{}, sctx)
	if delay := agnt2.getIterationDelay(); delay != 2500*time.Millisecond {
		t.Fatalf("expected 2500ms delay, got %v", delay)
	}
}

func TestAgent_SetIterationDelay_PropagatesToChildren(t *testing.T) {
	cfg := &config.Config{
		IterationDelaySec: 0,
	}
	sctx := scanctx.New("test-propagate", t.TempDir())
	scanctx.Activate(sctx)
	defer sctx.Close()

	root := NewAgent(cfg, "root", make(chan Event, 10), scopeguard.Config{}, sctx)
	child := NewAgent(cfg, "child", make(chan Event, 10), scopeguard.Config{}, sctx)

	root.registerChildAgent(child)
	defer root.unregisterChildAgent(child)

	root.SetIterationDelay(1.5)

	if delay := root.getIterationDelay(); delay != 1500*time.Millisecond {
		t.Fatalf("expected root delay 1500ms, got %v", delay)
	}
	if root.cfg.IterationDelaySec != 1.5 {
		t.Fatalf("expected root cfg.IterationDelaySec 1.5, got %v", root.cfg.IterationDelaySec)
	}
	if delay := child.getIterationDelay(); delay != 1500*time.Millisecond {
		t.Fatalf("expected child delay 1500ms, got %v", delay)
	}

	// Negative values clamp to 0
	root.SetIterationDelay(-5)
	if delay := root.getIterationDelay(); delay != 0 {
		t.Fatalf("expected root delay 0 after negative value, got %v", delay)
	}
	if delay := child.getIterationDelay(); delay != 0 {
		t.Fatalf("expected child delay 0 after negative value, got %v", delay)
	}
}

func TestAgent_IterationDelay_CanceledImmediateUnblock(t *testing.T) {
	cfg := &config.Config{
		IterationDelaySec: 10, // 10 seconds delay
	}
	sctx := scanctx.New("test-delay-cancel", t.TempDir())
	scanctx.Activate(sctx)
	defer sctx.Close()

	agnt := NewAgent(cfg, "test-cancel", make(chan Event, 10), scopeguard.Config{}, sctx)
	agnt.ctx, agnt.cancel = context.WithCancel(context.Background())

	start := time.Now()
	doneCh := make(chan struct{})

	go func() {
		delay := agnt.getIterationDelay()
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-agnt.ctx.Done():
			timer.Stop()
		}
		close(doneCh)
	}()

	// Stop after 20ms
	time.Sleep(20 * time.Millisecond)
	agnt.Stop()

	select {
	case <-doneCh:
		elapsed := time.Since(start)
		if elapsed >= 2*time.Second {
			t.Fatalf("expected fast cancel unblock, but took %v", elapsed)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for cancel unblock")
	}
}
