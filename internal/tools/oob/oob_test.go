package oob

import (
	"strings"
	"testing"
)

func TestEmptyPollGuidanceThresholds(t *testing.T) {
	// Below the nudge threshold: no extra guidance (a first empty poll right
	// after planting a payload is normal).
	for n := 0; n < emptyPollNudgeAt; n++ {
		if g := emptyPollGuidance(n); g != "" {
			t.Fatalf("expected no guidance at %d empty polls, got %q", n, g)
		}
	}
	// Nudge band: gentle "egress may be filtered" hint, not a hard stop.
	nudge := emptyPollGuidance(emptyPollNudgeAt)
	if !strings.Contains(nudge, "Egress may be filtered") || strings.Contains(nudge, "STOP polling") {
		t.Fatalf("expected a gentle nudge at %d, got %q", emptyPollNudgeAt, nudge)
	}
	// Stop band: hard directive to stop and pivot in-band.
	stop := emptyPollGuidance(emptyPollStopAt)
	if !strings.Contains(stop, "STOP polling") || !strings.Contains(stop, "IN-BAND") {
		t.Fatalf("expected a hard stop directive at %d, got %q", emptyPollStopAt, stop)
	}
	if !strings.Contains(emptyPollGuidance(emptyPollStopAt+7), "STOP polling") {
		t.Fatal("expected the hard stop directive to persist above the stop threshold")
	}
}

func TestRecordAndResetEmptyPoll(t *testing.T) {
	pollMu.Lock()
	emptyPollCount = map[string]int{}
	pollMu.Unlock()

	tok := "tok-A"
	if n := recordEmptyPoll(tok); n != 1 {
		t.Fatalf("first empty poll should be 1, got %d", n)
	}
	if n := recordEmptyPoll(tok); n != 2 {
		t.Fatalf("second empty poll should be 2, got %d", n)
	}
	// A different token counts independently.
	if n := recordEmptyPoll("tok-B"); n != 1 {
		t.Fatalf("independent token should start at 1, got %d", n)
	}
	// A landed callback resets that token's dry-spell counter.
	resetEmptyPoll(tok)
	if n := recordEmptyPoll(tok); n != 1 {
		t.Fatalf("after reset the counter should restart at 1, got %d", n)
	}
}

func TestEmptyPollMapIsBounded(t *testing.T) {
	pollMu.Lock()
	emptyPollCount = map[string]int{}
	pollMu.Unlock()

	// Exceed the cap; the map must not grow without bound.
	for i := 0; i < emptyPollTokenCap+50; i++ {
		recordEmptyPoll("t-" + string(rune(i)) + "-" + strings.Repeat("x", i%3))
	}
	pollMu.Lock()
	size := len(emptyPollCount)
	pollMu.Unlock()
	if size > emptyPollTokenCap+1 {
		t.Fatalf("expected map bounded near %d, got %d", emptyPollTokenCap, size)
	}
}
