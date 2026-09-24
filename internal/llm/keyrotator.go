// API-key pool rotation for provider rate limits.
//
// KeyRotator spreads outbound API-key-authenticated requests across a
// pool of operator-configured keys (XALGORIX_API_KEYS plus
// XALGORIX_API_KEY). Picks advance round-robin, so a pool of N keys
// raises the effective provider rate ceiling roughly N times. When a
// request fails with a provider rate limit (429 / usage-window), the
// key it used enters a short cooldown and subsequent picks skip it
// until the cooldown expires, concentrating traffic on the remaining
// keys.
//
// Thread-safe: concurrent chatWithRetry / ChatStream goroutines from
// parallel scans share one rotator per llm.Client.

package llm

import (
	"sync"
	"time"
)

// keyPoolCooldown is how long a rate-limited key is skipped before it
// becomes eligible again. It exceeds chatWithRetry's 30s rate-limit
// backoff so the retry immediately following a 429 lands on a
// different key; the cooled key returns once the provider's window
// has very likely reset.
const keyPoolCooldown = 90 * time.Second

// KeyRotator hands out keys from a fixed pool in round-robin order,
// skipping keys that are cooling down after a rate limit.
type KeyRotator struct {
	mu       sync.Mutex
	keys     []string
	idx      int
	cooldown map[string]time.Time
	last     string
}

// NewKeyRotator builds a rotator from the given candidate keys. Empty
// entries and duplicates are dropped; order is preserved. Returns nil
// when no usable key remains so callers can leave the feature off.
func NewKeyRotator(keys []string) *KeyRotator {
	deduped := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		if k == "" {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		deduped = append(deduped, k)
	}
	if len(deduped) == 0 {
		return nil
	}
	return &KeyRotator{
		keys:     deduped,
		cooldown: make(map[string]time.Time),
	}
}

// Pick returns the next eligible key, advancing round-robin and
// skipping keys still in cooldown. When every key is cooling down it
// returns the key whose cooldown expires soonest instead of failing:
// the caller still needs a key to attempt, and its own bounded
// backoff prevents hammering.
func (r *KeyRotator) Pick() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for range r.keys {
		k := r.keys[r.idx%len(r.keys)]
		r.idx++
		until, cooling := r.cooldown[k]
		if !cooling || now.After(until) {
			delete(r.cooldown, k)
			r.last = k
			return k
		}
	}
	best := ""
	var bestUntil time.Time
	for _, k := range r.keys {
		until := r.cooldown[k]
		if best == "" || until.Before(bestUntil) {
			best, bestUntil = k, until
		}
	}
	r.last = best
	return best
}

// MarkLastRateLimited puts the key most recently returned by Pick into
// cooldown so subsequent picks concentrate on the remaining keys.
func (r *KeyRotator) MarkLastRateLimited() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == "" {
		return
	}
	r.cooldown[r.last] = time.Now().Add(keyPoolCooldown)
}

// Len reports how many distinct keys the pool holds.
func (r *KeyRotator) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.keys)
}
