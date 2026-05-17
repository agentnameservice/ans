//go:build live

package opentimestamps

import (
	"context"
	"testing"
	"time"
)

// TestWitness_Attest_LivePublicCalendar makes a real network call to the
// public OpenTimestamps calendar. Skipped by default; run with:
//
//	go test -tags=live ./internal/adapter/witness/opentimestamps/...
func TestWitness_Attest_LivePublicCalendar(t *testing.T) {
	w := New()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	att, err := w.Attest(ctx, []byte("ans-live-test-checkpoint"))
	if err != nil {
		t.Fatalf("Attest against public calendar: %v", err)
	}
	if att.Profile != ProfileID {
		t.Errorf("Profile: got %q, want %q", att.Profile, ProfileID)
	}
	if len(att.ExternalProof) == 0 {
		t.Error("ExternalProof is empty")
	}
	if len(att.CheckpointDigest) != 32 {
		t.Errorf("CheckpointDigest: got %d bytes, want 32", len(att.CheckpointDigest))
	}
	t.Logf("OTS proof: %d bytes, attestedAt=%s", len(att.ExternalProof), att.AttestedAt)
}
