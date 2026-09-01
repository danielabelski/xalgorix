package browser

import (
	"strings"
	"sync"
	"time"
)

// ExecSignal is a captured client-side JavaScript execution signal. Today that
// is a JavaScript dialog (alert/confirm/prompt) opened during navigation —
// the strongest, simplest proof that an injected payload actually EXECUTED in
// the browser, as opposed to merely being reflected in the HTTP response. This
// is what turns an XSS candidate into a confirmed finding and is exactly the
// gap that keeps reflection-only scanners' XSS precision low.
type ExecSignal struct {
	Kind    string    // "dialog:alert" | "dialog:confirm" | "dialog:prompt" | "dialog:beforeunload"
	Message string    // the dialog text (carries the payload's nonce)
	URL     string    // page URL that raised it
	At      time.Time // capture time
}

const maxExecSignalsPerCtx = 50

var (
	execSignalsMu sync.Mutex
	execSignals   = map[string][]ExecSignal{}
)

// recordExecSignal appends a signal for a scan context, bounded so a page that
// loops alert() cannot grow memory without limit.
func recordExecSignal(ctxID string, s ExecSignal) {
	if ctxID == "" {
		return
	}
	execSignalsMu.Lock()
	defer execSignalsMu.Unlock()
	sigs := append(execSignals[ctxID], s)
	if len(sigs) > maxExecSignalsPerCtx {
		sigs = sigs[len(sigs)-maxExecSignalsPerCtx:]
	}
	execSignals[ctxID] = sigs
}

// clearExecSignals drops all recorded signals for a context. Callers verifying
// a payload clear first so a stale dialog from an earlier navigation cannot
// produce a false positive.
func clearExecSignals(ctxID string) {
	execSignalsMu.Lock()
	defer execSignalsMu.Unlock()
	delete(execSignals, ctxID)
}

// execSignalsFor returns a copy of the recorded signals for a context.
func execSignalsFor(ctxID string) []ExecSignal {
	execSignalsMu.Lock()
	defer execSignalsMu.Unlock()
	src := execSignals[ctxID]
	if len(src) == 0 {
		return nil
	}
	out := make([]ExecSignal, len(src))
	copy(out, src)
	return out
}

// matchExecNonce returns the first signal whose message contains the nonce
// (case-insensitive substring), which proves that the specific injected
// payload — not some unrelated dialog — executed.
func matchExecNonce(signals []ExecSignal, nonce string) (ExecSignal, bool) {
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return ExecSignal{}, false
	}
	ln := strings.ToLower(nonce)
	for _, s := range signals {
		if strings.Contains(strings.ToLower(s.Message), ln) {
			return s, true
		}
	}
	return ExecSignal{}, false
}
