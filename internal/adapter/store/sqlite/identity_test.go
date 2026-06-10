package sqlite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

var identityNow = time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)

func newIdentityFixture(t *testing.T, id, owner, value string) *domain.VerifiedIdentity {
	t.Helper()
	v, err := domain.NewVerifiedIdentity(id, owner, value, identityNow)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return v
}

func TestIdentityStore_SaveAndFind(t *testing.T) {
	db := newTestDB(t)
	store := NewIdentityStore(db)
	ctx := context.Background()

	v := newIdentityFixture(t, "id-1", "owner-1", "did:web:identity.acme-corp.com")
	if err := v.IssueChallenge("nonce-1", time.Hour, identityNow); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, v); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := store.FindByID(ctx, "id-1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.ProviderID != "owner-1" || got.Kind != domain.KindDIDWeb ||
		got.Status != domain.IdentityPendingControl {
		t.Fatalf("loaded identity wrong: %+v", got)
	}
	if got.Challenge == nil || got.Challenge.Nonce != "nonce-1" || got.Challenge.ConsumedAt != nil {
		t.Fatalf("challenge wrong: %+v", got.Challenge)
	}
	if !got.Challenge.ExpiresAt.Equal(identityNow.Add(time.Hour)) {
		t.Fatalf("expiry wrong: %v", got.Challenge.ExpiresAt)
	}

	if _, err := store.FindByID(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing should be not-found, got %v", err)
	}
}

func TestIdentityStore_SaveUpsertsLifecycle(t *testing.T) {
	db := newTestDB(t)
	store := NewIdentityStore(db)
	ctx := context.Background()

	v := newIdentityFixture(t, "id-1", "owner-1", "did:web:a.com")
	if err := store.Save(ctx, v); err != nil {
		t.Fatal(err)
	}
	if _, err := v.CompleteVerification(identityNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, v); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := store.FindByID(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != domain.IdentityVerified || got.ProofMethod != "did-web-sig" || got.VerifiedAt.IsZero() {
		t.Fatalf("verified state lost: %+v", got)
	}
}

func TestIdentityStore_FindLiveAndRevokedFallout(t *testing.T) {
	db := newTestDB(t)
	store := NewIdentityStore(db)
	ctx := context.Background()

	v := newIdentityFixture(t, "id-1", "owner-1", "did:web:a.com")
	if err := store.Save(ctx, v); err != nil {
		t.Fatal(err)
	}

	live, err := store.FindLive(ctx, "owner-1", domain.KindDIDWeb, "did:web:a.com")
	if err != nil || live.IdentityID != "id-1" {
		t.Fatalf("find live: %+v %v", live, err)
	}
	// Wrong owner / kind / value → not found.
	if _, err := store.FindLive(ctx, "owner-2", domain.KindDIDWeb, "did:web:a.com"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner FindLive: %v", err)
	}

	// Revoke → falls out of the live index; re-registering the value
	// succeeds with a fresh row.
	if _, err := v.CompleteVerification(identityNow); err != nil {
		t.Fatal(err)
	}
	if err := v.Revoke(identityNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, v); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindLive(ctx, "owner-1", domain.KindDIDWeb, "did:web:a.com"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoked row should not be live: %v", err)
	}
	fresh := newIdentityFixture(t, "id-2", "owner-1", "did:web:a.com")
	if err := store.Save(ctx, fresh); err != nil {
		t.Fatalf("re-register after revoke: %v", err)
	}
}

func TestIdentityStore_LiveUniquePerOwner(t *testing.T) {
	db := newTestDB(t)
	store := NewIdentityStore(db)
	ctx := context.Background()

	if err := store.Save(ctx, newIdentityFixture(t, "id-1", "owner-1", "did:web:a.com")); err != nil {
		t.Fatal(err)
	}
	err := store.Save(ctx, newIdentityFixture(t, "id-2", "owner-1", "did:web:a.com"))
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate live row should conflict, got %v", err)
	}
	// A different owner may hold a competing pending claim.
	if err := store.Save(ctx, newIdentityFixture(t, "id-3", "owner-2", "did:web:a.com")); err != nil {
		t.Fatalf("competing pending claim should be allowed: %v", err)
	}
}

func TestIdentityStore_ProvenUniqueAcrossOwners(t *testing.T) {
	db := newTestDB(t)
	store := NewIdentityStore(db)
	ctx := context.Background()

	a := newIdentityFixture(t, "id-1", "owner-1", "did:web:a.com")
	b := newIdentityFixture(t, "id-2", "owner-2", "did:web:a.com")
	if err := store.Save(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, b); err != nil {
		t.Fatal(err)
	}

	// First to prove wins…
	if _, err := a.CompleteVerification(identityNow); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, a); err != nil {
		t.Fatalf("first proof: %v", err)
	}
	taken, err := store.ExistsVerified(ctx, domain.KindDIDWeb, "did:web:a.com")
	if err != nil || !taken {
		t.Fatalf("ExistsVerified after proof: %v %v", taken, err)
	}

	// …the loser's verify-time flip violates the proven index.
	if _, err := b.CompleteVerification(identityNow); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, b); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second proof should conflict, got %v", err)
	}

	none, err := store.ExistsVerified(ctx, domain.KindDIDWeb, "did:web:other.com")
	if err != nil || none {
		t.Fatalf("ExistsVerified for unproven value: %v %v", none, err)
	}
}

func TestIdentityStore_ListByOwner(t *testing.T) {
	db := newTestDB(t)
	store := NewIdentityStore(db)
	ctx := context.Background()

	first := newIdentityFixture(t, "id-1", "owner-1", "did:web:a.com")
	second := newIdentityFixture(t, "id-2", "owner-1", "did:web:b.com")
	second.CreatedAt = identityNow.Add(time.Minute)
	second.UpdatedAt = second.CreatedAt
	other := newIdentityFixture(t, "id-3", "owner-2", "did:web:c.com")
	for _, v := range []*domain.VerifiedIdentity{first, second, other} {
		if err := store.Save(ctx, v); err != nil {
			t.Fatal(err)
		}
	}

	got, err := store.ListByOwner(ctx, "owner-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].IdentityID != "id-2" || got[1].IdentityID != "id-1" {
		t.Fatalf("list wrong: %+v", got)
	}
}

func TestIdentityStore_ConsumeChallenge(t *testing.T) {
	db := newTestDB(t)
	store := NewIdentityStore(db)
	ctx := context.Background()

	v := newIdentityFixture(t, "id-1", "owner-1", "did:web:a.com")
	if err := v.IssueChallenge("nonce-1", time.Hour, identityNow); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, v); err != nil {
		t.Fatal(err)
	}

	// Wrong nonce → rejected, nothing consumed.
	if err := store.ConsumeChallenge(ctx, "id-1", "wrong", identityNow.Add(time.Minute)); err == nil {
		t.Fatal("wrong nonce must not consume")
	}
	// Expired → rejected.
	if err := store.ConsumeChallenge(ctx, "id-1", "nonce-1", identityNow.Add(2*time.Hour)); err == nil {
		t.Fatal("expired nonce must not consume")
	}
	// Fresh → consumed exactly once.
	if err := store.ConsumeChallenge(ctx, "id-1", "nonce-1", identityNow.Add(time.Minute)); err != nil {
		t.Fatalf("consume: %v", err)
	}
	err := store.ConsumeChallenge(ctx, "id-1", "nonce-1", identityNow.Add(2*time.Minute))
	if err == nil || !strings.Contains(err.Error(), "PRICC_TOKEN_ALREADY_USED") {
		t.Fatalf("double consume: %v", err)
	}

	got, err := store.FindByID(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Challenge == nil || got.Challenge.ConsumedAt == nil {
		t.Fatalf("consumption not persisted: %+v", got.Challenge)
	}
}

func TestIdentityLinkStore_Lifecycle(t *testing.T) {
	db := newTestDB(t)
	agents := NewAgentStore(db)
	identities := NewIdentityStore(db)
	links := NewIdentityLinkStore(db)
	ctx := context.Background()

	// FK targets must exist.
	if err := agents.Save(ctx, newAgentFixture(t, "agent-1", "a.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := agents.Save(ctx, newAgentFixture(t, "agent-2", "b.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := identities.Save(ctx, newIdentityFixture(t, "id-1", "owner-1", "did:web:a.com")); err != nil {
		t.Fatal(err)
	}

	created, err := links.Link(ctx, "id-1", "agent-1", identityNow)
	if err != nil || !created {
		t.Fatalf("link: created=%v err=%v", created, err)
	}
	// Idempotent re-link.
	created, err = links.Link(ctx, "id-1", "agent-1", identityNow.Add(time.Minute))
	if err != nil || created {
		t.Fatalf("re-link should be a no-op: created=%v err=%v", created, err)
	}
	if _, err := links.Link(ctx, "id-1", "agent-2", identityNow); err != nil {
		t.Fatal(err)
	}

	byIdentity, err := links.ListLiveByIdentity(ctx, "id-1")
	if err != nil || len(byIdentity) != 2 {
		t.Fatalf("live by identity: %d %v", len(byIdentity), err)
	}
	byAgent, err := links.ListLiveByAgent(ctx, "agent-1")
	if err != nil || len(byAgent) != 1 || byAgent[0].Status != domain.LinkLinked {
		t.Fatalf("live by agent: %+v %v", byAgent, err)
	}

	// Unlink → drops out of live views; history row remains.
	if err := links.Unlink(ctx, "id-1", "agent-1", identityNow.Add(time.Hour)); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if err := links.Unlink(ctx, "id-1", "agent-1", identityNow); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("double unlink: %v", err)
	}
	byAgent, err = links.ListLiveByAgent(ctx, "agent-1")
	if err != nil || len(byAgent) != 0 {
		t.Fatalf("live by agent after unlink: %+v %v", byAgent, err)
	}

	// Re-link after unlink — UNLINKED history never blocks.
	created, err = links.Link(ctx, "id-1", "agent-1", identityNow.Add(2*time.Hour))
	if err != nil || !created {
		t.Fatalf("re-link after unlink: created=%v err=%v", created, err)
	}
}
