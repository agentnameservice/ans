package handler

import (
	"testing"
	"time"
)

func TestRateLimiter_BurstThenDeny(t *testing.T) {
	t.Parallel()
	clock := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := newRateLimiter(1, 3, func() time.Time { return clock })
	// Burst of 3 allowed, 4th denied (no time has advanced to refill).
	for i := range 3 {
		if !rl.Allow() {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	if rl.Allow() {
		t.Error("4th request should be denied (burst exhausted)")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := newRateLimiter(2 /* per sec */, 1, func() time.Time { return now })
	if !rl.Allow() {
		t.Fatal("first token should be allowed")
	}
	if rl.Allow() {
		t.Fatal("second immediate token should be denied")
	}
	// Advance 600ms → at 2 tokens/sec that is 1.2 tokens, enough for one.
	now = now.Add(600 * time.Millisecond)
	if !rl.Allow() {
		t.Error("token should have refilled after 600ms")
	}
}

func TestRateLimiter_CapsAtBurst(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := newRateLimiter(100, 2, func() time.Time { return now })
	// Drain.
	rl.Allow()
	rl.Allow()
	// Idle a long time — refill must cap at burst (2), not accumulate.
	now = now.Add(time.Hour)
	if !rl.Allow() {
		t.Fatal("first token should be available after refill")
	}
	if !rl.Allow() {
		t.Fatal("second token should be available after refill")
	}
	if rl.Allow() {
		t.Error("third token should be denied — refill caps at burst")
	}
}

func TestRateLimiter_DisabledAlwaysAllows(t *testing.T) {
	t.Parallel()
	for _, rl := range []*RateLimiter{
		newRateLimiter(0, 5, nil), // zero rate
		newRateLimiter(5, 0, nil), // zero burst
		newRateLimiter(-1, -1, nil),
	} {
		for range 100 {
			if !rl.Allow() {
				t.Fatal("disabled limiter must always allow")
			}
		}
	}
}

func TestRateLimiter_NilClockDefaults(t *testing.T) {
	t.Parallel()
	rl := newRateLimiter(1000, 1, nil) // nil clock → time.Now
	if !rl.Allow() {
		t.Error("first token with default clock should be allowed")
	}
}
