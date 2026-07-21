package handler

import (
	"sync"
	"time"
)

// RateLimiter is a simple global token bucket guarding the
// unauthenticated discovery surface. ARD discovery is anonymous, so abuse
// control — not authentication — is the access mechanism (ARDS §3.5); a
// global bucket bounds total request rate regardless of source.
//
// The bucket holds up to burst tokens and refills at rate tokens per
// second. Each Allow call removes one token if available. The
// implementation is deliberately small and lock-guarded rather than
// per-IP — a single Finder instance serves a bounded, public, read-only
// surface, and a global cap is the simplest control that prevents one
// client (or the aggregate) from overwhelming the index.
type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	burst    float64
	rate     float64 // tokens per second
	last     time.Time
	now      func() time.Time
	disabled bool
}

// newRateLimiter builds a limiter allowing rate requests/second with a
// burst ceiling. A non-positive rate or burst disables limiting entirely
// (Allow always returns true) — useful for tests and for operators who
// front the Finder with their own gateway. now is injected for
// deterministic tests; nil means time.Now.
func newRateLimiter(rate, burst float64, now func() time.Time) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	rl := &RateLimiter{
		tokens: burst,
		burst:  burst,
		rate:   rate,
		last:   now(),
		now:    now,
	}
	if rate <= 0 || burst <= 0 {
		rl.disabled = true
	}
	return rl
}

// Allow reports whether a request may proceed, consuming one token if so.
// It refills the bucket based on elapsed time since the last call, caps
// at burst, then takes a token when one is available. A nil receiver (no
// limiter wired) allows everything — fail-open, since a missing limiter
// must not wedge the discovery surface.
func (rl *RateLimiter) Allow() bool {
	if rl == nil || rl.disabled {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	elapsed := now.Sub(rl.last).Seconds()
	if elapsed > 0 {
		rl.tokens += elapsed * rl.rate
		if rl.tokens > rl.burst {
			rl.tokens = rl.burst
		}
		rl.last = now
	}
	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}
	return false
}
