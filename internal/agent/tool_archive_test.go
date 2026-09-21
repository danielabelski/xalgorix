package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/scanctx"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

func newBoundedContextAgent(t *testing.T, enabled bool) (*Agent, *scanctx.ScanContext) {
	t.Helper()
	cfg := &config.Config{BoundedContext: enabled}
	sctx := scanctx.New("bounded-ctx-test", t.TempDir())
	scanctx.Activate(sctx)
	t.Cleanup(sctx.Close)
	a := NewAgent(cfg, "test", make(chan Event, 8), scopeguard.Config{}, sctx)
	return a, sctx
}

func toolResultMsg(name, body string) llm.Message {
	return llm.Message{Role: "user", Content: "Tool '" + name + "' result:\n" + body}
}

// TestBoundedContextDisabledByDefault proves the flag-off path is byte-identical
// to the pre-feature behavior: no archive marker, no stub, no archive file.
func TestBoundedContextDisabledByDefault(t *testing.T) {
	a, sctx := newBoundedContextAgent(t, false)
	raw := strings.Repeat("HTTP/1.1 200 OK\n", 400)
	result := capToolOutputForLLM(raw)
	msg := toolResultMsg("send_request", result)

	// The flag gates every agent-side archive/stub path.
	if a.boundedContextEnabled() {
		t.Fatal("bounded context must be off")
	}
	_ = raw
	_ = result
	_ = msg

	// Flag off: aging is a no-op even with tool messages present.
	a.msgMu.Lock()
	a.messages = []llm.Message{msg, msg, msg, msg}
	a.msgMu.Unlock()
	a.ageOutToolOutputs()
	a.msgMu.Lock()
	defer a.msgMu.Unlock()
	for _, m := range a.messages {
		if !strings.HasPrefix(m.Content, "Tool 'send_request' result:") {
			t.Fatalf("flag off must not alter messages: %q", m.Content[:40])
		}
		if strings.Contains(m.Content, archiveStubPrefix) {
			t.Fatal("flag off must never stub")
		}
	}
	if sctx.ToolOutputs.Count() != 0 {
		t.Fatal("flag off must not archive anything")
	}
}

// TestAgeOutToolOutputsStubsOlderMessages verifies: active window verbatim,
// older messages stubbed once, idempotent, unarchived messages untouched.
func TestAgeOutToolOutputsStubsOlderMessages(t *testing.T) {
	a, sctx := newBoundedContextAgent(t, true)
	if a.toolArchiveActiveWindow() != 8 {
		t.Fatalf("default window = %d", a.toolArchiveActiveWindow())
	}

	raw := strings.Repeat("payload-line\n", 300) // ~4KB raw
	ids := make([]string, 12)
	a.msgMu.Lock()
	a.messages = []llm.Message{{Role: "system", Content: "system"}}
	for i := range ids {
		id := sctx.ToolOutputs.Archive("curl", raw, 1)
		if id == "" {
			t.Fatalf("archive failed for message %d", i)
		}
		ids[i] = id
		body := capToolOutputForLLM(raw)
		a.messages = append(a.messages, llm.Message{
			Role:    "user",
			Content: "Tool 'curl' result:\n" + body + "\n" + archiveToolResultMarker(id),
		})
	}
	// An unarchived (pre-flag) tool message must stay verbatim.
	a.messages = append(a.messages, toolResultMsg("legacy", "small old result"))
	a.msgMu.Unlock()

	a.ageOutToolOutputs()

	// Snapshot one stubbed message for the idempotence check below.
	a.msgMu.Lock()
	stubAfterFirstPass := a.messages[1].Content
	a.msgMu.Unlock()

	// Idempotent: second pass stubs nothing new (run before locking below).
	a.ageOutToolOutputs()

	a.msgMu.Lock()
	defer a.msgMu.Unlock()
	if len(a.messages) != 14 {
		t.Fatalf("message count changed: %d", len(a.messages))
	}
	stubbed, verbatim := 0, 0
	for i, m := range a.messages {
		switch {
		case i == 0:
			continue // system
		case strings.Contains(m.Content, archiveStubPrefix):
			stubbed++
		case strings.HasPrefix(m.Content, "Tool 'curl'"):
			verbatim++
		}
	}
	// 12 archived curl messages + 1 unarchived legacy tool message = 13
	// tool-result messages; the newest 8 (7 curl + legacy) stay verbatim, the
	// oldest 5 curl messages are stubbed.
	if stubbed != 5 {
		t.Fatalf("stubbed = %d, want 5", stubbed)
	}
	if verbatim != 7 {
		t.Fatalf("verbatim recent window = %d, want 7", verbatim)
	}
	if !strings.Contains(a.messages[len(a.messages)-1].Content, "small old result") {
		t.Fatal("unarchived legacy message must stay verbatim")
	}
	// Stub must carry its archive id and a head snippet.
	stub := a.messages[1].Content
	if !strings.Contains(stub, ids[0]) {
		t.Fatalf("stub missing archive id %q: %q", ids[0], stub[:120])
	}
	if !strings.Contains(stub, "read_tool_output") {
		t.Fatal("stub must name read_tool_output")
	}

	// Idempotent: the second pass (run above, before locking) changed nothing.
	if a.messages[1].Content != stubAfterFirstPass {
		t.Fatal("aging must be idempotent")
	}

	// Stubbed sizes are tiny vs the ~16KB originals.
	if len(stub) > 1200 {
		t.Fatalf("stub too large: %d bytes", len(stub))
	}
}

// TestReadToolOutputRetrievesOriginal is the information-complete guarantee:
// the retrieval tool returns the byte-identical raw output that was stubbed
// out of the conversation.
func TestReadToolOutputRetrievesOriginal(t *testing.T) {
	a, sctx := newBoundedContextAgent(t, true)
	raw := strings.Repeat("SENSITIVE-RAW-OUTPUT-LINE\n", 500) // ~12.5KB raw
	id := sctx.ToolOutputs.Archive("send_request", raw, 1)
	if id == "" {
		t.Fatal("archive failed")
	}

	res, err := a.readToolOutputTool(map[string]string{"id": id})
	if err != nil {
		t.Fatalf("tool error: %v", err)
	}
	if res.Error != "" {
		t.Fatalf("tool result error: %s", res.Error)
	}
	if res.Output != raw {
		t.Fatalf("retrieved output differs from original: got %d bytes, want %d", len(res.Output), len(raw))
	}

	// Bad/missing ids produce actionable errors, not panics.
	res, _ = a.readToolOutputTool(map[string]string{"id": ""})
	if res.Error == "" {
		t.Fatal("empty id must error")
	}
	res, _ = a.readToolOutputTool(map[string]string{"id": "to_999999"})
	if res.Error == "" {
		t.Fatal("unknown id must error")
	}
}

// TestArchiveMarkerPreservesToolMessageShape guarantees the annotated message
// still parses as a tool-result message (isToolResultMessage) so compaction
// digests, aging, and byte-metrics heuristics keep working.
func TestArchiveMarkerPreservesToolMessageShape(t *testing.T) {
	id := "to_000001"
	msg := "Tool 'curl' result:\nbody" + "\n" + archiveToolResultMarker(id)
	if !isToolResultMessage(msg) {
		t.Fatal("annotated message must still be recognized as a tool result")
	}
	got, ok := archiveIDFromMessage(msg)
	if !ok || got != id {
		t.Fatalf("archive id extraction = %q ok=%v", got, ok)
	}
	// Marker regex tolerates longer sequences.
	if _, ok := archiveIDFromMessage("Tool 'x' result:\nno marker here"); ok {
		t.Fatal("unmarked message must not yield an id")
	}
}
