package service

// White-box tests for the badge-status decision tree. Pre-coverage
// statusFromRecord sat at 33.3% — only AGENT_REGISTERED → ACTIVE was
// exercised through the public testbed. Hitting REVOKED, DEPRECATED,
// EXPIRED, WARNING, and ACTIVE-with-far-future expiry directly here
// is cheaper than spinning up the full TL pipeline per case.

import (
	"testing"
	"time"

	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
)

func TestStatusFromRecord_TerminalEventTypes(t *testing.T) {
	// Both AGENT_REVOKED and AGENT_DEPRECATED short-circuit the
	// expiry check — even with a far-future expiry the terminal
	// label wins.
	farFuture := time.Now().Add(365 * 24 * time.Hour)
	svc := &BadgeService{warningWindow: 30 * 24 * time.Hour}

	if got := svc.statusFromRecord(&sqlitetl.EventRecord{EventType: "AGENT_REVOKED"}, farFuture); got != BadgeRevoked {
		t.Errorf("AGENT_REVOKED: got %q want %q", got, BadgeRevoked)
	}
	if got := svc.statusFromRecord(&sqlitetl.EventRecord{EventType: "AGENT_DEPRECATED"}, farFuture); got != BadgeDeprecated {
		t.Errorf("AGENT_DEPRECATED: got %q want %q", got, BadgeDeprecated)
	}
}

func TestStatusFromRecord_ExpiryDrivesActive(t *testing.T) {
	// AGENT_REGISTERED with no expiry → ACTIVE.
	svc := &BadgeService{warningWindow: 30 * 24 * time.Hour}
	got := svc.statusFromRecord(&sqlitetl.EventRecord{EventType: "AGENT_REGISTERED"}, time.Time{})
	if got != BadgeActive {
		t.Errorf("no-expiry path: got %q want ACTIVE", got)
	}
}

func TestStatusFromRecord_PastExpiryYieldsExpired(t *testing.T) {
	svc := &BadgeService{warningWindow: 30 * 24 * time.Hour}
	expired := time.Now().Add(-time.Hour) // already past
	got := svc.statusFromRecord(&sqlitetl.EventRecord{EventType: "AGENT_REGISTERED"}, expired)
	if got != BadgeExpired {
		t.Errorf("expired path: got %q want EXPIRED", got)
	}
}

func TestStatusFromRecord_ImminentExpiryYieldsWarning(t *testing.T) {
	// 1-day window, expiry is 12h away → inside warning window.
	svc := &BadgeService{warningWindow: 24 * time.Hour}
	soon := time.Now().Add(12 * time.Hour)
	got := svc.statusFromRecord(&sqlitetl.EventRecord{EventType: "AGENT_REGISTERED"}, soon)
	if got != BadgeWarning {
		t.Errorf("warning path: got %q want WARNING", got)
	}
}

func TestStatusFromRecord_FarFutureExpiryYieldsActive(t *testing.T) {
	svc := &BadgeService{warningWindow: 30 * 24 * time.Hour}
	farFuture := time.Now().Add(180 * 24 * time.Hour)
	got := svc.statusFromRecord(&sqlitetl.EventRecord{EventType: "AGENT_REGISTERED"}, farFuture)
	if got != BadgeActive {
		t.Errorf("far-future path: got %q want ACTIVE", got)
	}
}
