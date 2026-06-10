package service

import (
	"encoding/json"
	"sync"
	"time"
)

// defaultRegisterPerMinute is the default per-owner budget for
// identity register/rotate calls. Each call can trigger an outbound
// fetch (did:web advisory resolution) before any proof exists, so
// the budget exists to stop an authenticated owner from turning the
// RA into a fetch proxy (design §3.7 "bounded fetch").
const defaultRegisterPerMinute = 10

// ownerLimiter is a fixed-window per-owner rate limiter. In-process
// and intentionally simple: the window is a minute, the state is one
// counter per owner, and stale owners are pruned opportunistically.
// Deployments needing distributed rate limiting put it in front of
// the RA; this is the in-depth backstop.
type ownerLimiter struct {
	mu        sync.Mutex
	perMinute int
	windows   map[string]*ownerWindow
}

type ownerWindow struct {
	start time.Time
	count int
}

// newOwnerLimiter constructs a limiter allowing perMinute calls per
// owner per fixed one-minute window.
func newOwnerLimiter(perMinute int) *ownerLimiter {
	return &ownerLimiter{
		perMinute: perMinute,
		windows:   make(map[string]*ownerWindow),
	}
}

// Allow reports whether the owner may proceed at the given instant,
// consuming one slot when it does.
func (l *ownerLimiter) Allow(owner string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	w, ok := l.windows[owner]
	if !ok || now.Sub(w.start) >= time.Minute {
		l.prune(now)
		l.windows[owner] = &ownerWindow{start: now, count: 1}
		return true
	}
	if w.count >= l.perMinute {
		return false
	}
	w.count++
	return true
}

// prune drops windows older than two minutes so the map stays
// bounded by the set of recently-active owners. Called with the lock
// held, only on the window-rollover path (amortized — not per call).
func (l *ownerLimiter) prune(now time.Time) {
	for owner, w := range l.windows {
		if now.Sub(w.start) >= 2*time.Minute {
			delete(l.windows, owner)
		}
	}
}

// marshalOutboxPayload renders the {innerEventCanonical,
// producerSignature} outbox payload — the bytes the worker replays
// verbatim. Shared by every event family; the inner canonical bytes
// are family-specific, the payload wrapper is not.
func marshalOutboxPayload(innerCanonical []byte, producerSig string) ([]byte, error) {
	return json.Marshal(OutboxPayload{
		InnerEventCanonical: json.RawMessage(innerCanonical),
		ProducerSignature:   producerSig,
	})
}
