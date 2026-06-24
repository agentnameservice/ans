package sqlitetl

// Tests for the identity read index over tl_events: identity_id
// column population (via the identityIndexed capability), the
// tl_identity_event_agents fan-out, and the join queries the
// badge/audit/reverse views run on.

import (
	"context"
	"encoding/json"
	"testing"

	identityevent "github.com/godaddy/ans/internal/tl/event/identity"
)

// buildIdentityEnvelope assembles a signed-shaped identity envelope.
func buildIdentityEnvelope(t *testing.T, typ identityevent.Type, identityID string, ansIDs []string) *identityevent.Envelope {
	t.Helper()
	ev := &identityevent.Event{
		EventType:  typ,
		IdentityID: identityID,
		Kind:       "did:web",
		Value:      "did:web:identity.acme-corp.com",
		Timestamp:  "2026-06-10T15:04:05Z",
	}
	switch typ {
	case identityevent.TypeIdentityVerified, identityevent.TypeIdentityUpdated:
		ev.ProviderID = "PID-1"
		ev.VerifiedAt = "2026-06-10T15:04:05Z"
		ev.Keys = []identityevent.ProvenKey{{
			VerificationMethod: json.RawMessage(`{"id":"did:web:identity.acme-corp.com#key-1","type":"JsonWebKey2020","controller":"did:web:identity.acme-corp.com","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"abc"}}`),
			SignedProof:        "jws",
		}}
	case identityevent.TypeIdentityRevoked:
		ev.RevokedAt = "2026-06-10T16:00:00Z"
	case identityevent.TypeIdentityLinked, identityevent.TypeIdentityUnlinked:
		ev.AnsIDs = ansIDs
	}
	env := identityevent.BuildEnvelope("log-"+identityID, ev, "key-1", "psig")
	env.Signature = "tl-attestation"
	return env
}

// storeIdentityEvent appends one identity envelope at the given leaf.
func storeIdentityEvent(t *testing.T, store *EventStore, leaf uint64, env *identityevent.Envelope) {
	t.Helper()
	canonical, err := env.LeafBytes()
	if err != nil {
		t.Fatalf("leaf bytes: %v", err)
	}
	leafHash, err := env.LeafHash()
	if err != nil {
		t.Fatalf("leaf hash: %v", err)
	}
	if _, err := store.StoreEvent(
		context.Background(), leaf, leafHash,
		"event-hash-"+itoa(int(leaf)), env, canonical,
	); err != nil {
		t.Fatalf("store event: %v", err)
	}
}

func TestStoreEvent_IdentityEnvelope_IndexesIdentityID(t *testing.T) {
	db := newDB(t)
	store := NewEventStore(db)

	env := buildIdentityEnvelope(t, identityevent.TypeIdentityVerified, "id-A", nil)
	storeIdentityEvent(t, store, 0, env)

	rec, err := store.GetLatestByIdentityID(context.Background(), "id-A")
	if err != nil {
		t.Fatalf("GetLatestByIdentityID: %v", err)
	}
	if rec.IdentityID != "id-A" {
		t.Errorf("IdentityID = %q", rec.IdentityID)
	}
	if rec.AgentID != "" {
		t.Errorf("AgentID should be empty for identity events, got %q", rec.AgentID)
	}
	if rec.EventType != "IDENTITY_VERIFIED" {
		t.Errorf("EventType = %q", rec.EventType)
	}
}

func TestStoreEvent_AgentRowsHaveEmptyIdentityID(t *testing.T) {
	db := newDB(t)
	store := NewEventStore(db)

	insertRawEvent(t, db, 0, "agent-1")
	rec, err := store.GetEventByLeafIndex(context.Background(), 0)
	if err != nil {
		t.Fatalf("GetEventByLeafIndex: %v", err)
	}
	if rec.IdentityID != "" {
		t.Errorf("agent row IdentityID = %q, want empty", rec.IdentityID)
	}
}

func TestStoreEvent_LinkFanOut(t *testing.T) {
	db := newDB(t)
	store := NewEventStore(db)
	ctx := context.Background()

	// Verify, then link two agents in ONE event.
	storeIdentityEvent(t, store, 0,
		buildIdentityEnvelope(t, identityevent.TypeIdentityVerified, "id-A", nil))
	storeIdentityEvent(t, store, 1,
		buildIdentityEnvelope(t, identityevent.TypeIdentityLinked, "id-A", []string{"agent-1", "agent-2"}))

	// Both agents see the link.
	for _, agent := range []string{"agent-1", "agent-2"} {
		states, err := store.LinkStatesByAgent(ctx, agent)
		if err != nil {
			t.Fatalf("LinkStatesByAgent(%s): %v", agent, err)
		}
		if len(states) != 1 || !states[0].Linked() || states[0].IdentityID != "id-A" {
			t.Fatalf("LinkStatesByAgent(%s) = %+v", agent, states)
		}
	}

	// Reverse join sees both agents.
	states, err := store.LinkStatesByIdentity(ctx, "id-A")
	if err != nil {
		t.Fatalf("LinkStatesByIdentity: %v", err)
	}
	if len(states) != 2 {
		t.Fatalf("expected 2 link states, got %d", len(states))
	}
}

func TestLinkStates_LatestWins(t *testing.T) {
	db := newDB(t)
	store := NewEventStore(db)
	ctx := context.Background()

	storeIdentityEvent(t, store, 0,
		buildIdentityEnvelope(t, identityevent.TypeIdentityLinked, "id-A", []string{"agent-1"}))
	storeIdentityEvent(t, store, 1,
		buildIdentityEnvelope(t, identityevent.TypeIdentityUnlinked, "id-A", []string{"agent-1"}))

	states, err := store.LinkStatesByAgent(ctx, "agent-1")
	if err != nil {
		t.Fatalf("LinkStatesByAgent: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("expected 1 state, got %d", len(states))
	}
	if states[0].Linked() {
		t.Fatal("latest event is UNLINKED — Linked() must be false")
	}

	// Re-link → live again (UNLINKED rows never block re-linking).
	storeIdentityEvent(t, store, 2,
		buildIdentityEnvelope(t, identityevent.TypeIdentityLinked, "id-A", []string{"agent-1"}))
	states, err = store.LinkStatesByAgent(ctx, "agent-1")
	if err != nil {
		t.Fatalf("LinkStatesByAgent: %v", err)
	}
	if len(states) != 1 || !states[0].Linked() {
		t.Fatalf("expected live link after re-link, got %+v", states)
	}
}

func TestLinkEventsByAgent_History(t *testing.T) {
	db := newDB(t)
	store := NewEventStore(db)
	ctx := context.Background()

	storeIdentityEvent(t, store, 0,
		buildIdentityEnvelope(t, identityevent.TypeIdentityLinked, "id-A", []string{"agent-1"}))
	storeIdentityEvent(t, store, 1,
		buildIdentityEnvelope(t, identityevent.TypeIdentityUnlinked, "id-A", []string{"agent-1"}))
	// A link event for a DIFFERENT agent must not appear.
	storeIdentityEvent(t, store, 2,
		buildIdentityEnvelope(t, identityevent.TypeIdentityLinked, "id-A", []string{"agent-2"}))

	recs, err := store.LinkEventsByAgent(ctx, "agent-1", 50, 0)
	if err != nil {
		t.Fatalf("LinkEventsByAgent: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 history records, got %d", len(recs))
	}
	// Newest first.
	if recs[0].EventType != "IDENTITY_UNLINKED" || recs[1].EventType != "IDENTITY_LINKED" {
		t.Fatalf("history order wrong: %s, %s", recs[0].EventType, recs[1].EventType)
	}
}

func TestGetLatestProofByIdentityID_SkipsLinkEvents(t *testing.T) {
	db := newDB(t)
	store := NewEventStore(db)
	ctx := context.Background()

	storeIdentityEvent(t, store, 0,
		buildIdentityEnvelope(t, identityevent.TypeIdentityVerified, "id-A", nil))
	storeIdentityEvent(t, store, 1,
		buildIdentityEnvelope(t, identityevent.TypeIdentityLinked, "id-A", []string{"agent-1"}))

	proof, err := store.GetLatestProofByIdentityID(ctx, "id-A")
	if err != nil {
		t.Fatalf("GetLatestProofByIdentityID: %v", err)
	}
	if proof.EventType != "IDENTITY_VERIFIED" {
		t.Fatalf("latest proof = %s, want IDENTITY_VERIFIED", proof.EventType)
	}

	// A rotation supersedes the original proof.
	upd := buildIdentityEnvelope(t, identityevent.TypeIdentityUpdated, "id-A", nil)
	upd.Payload.Producer.Event.Keys[0].VerificationMethod = json.RawMessage(
		`{"id":"did:web:identity.acme-corp.com#key-2","type":"JsonWebKey2020","controller":"did:web:identity.acme-corp.com","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"def"}}`)
	storeIdentityEvent(t, store, 2, upd)

	proof, err = store.GetLatestProofByIdentityID(ctx, "id-A")
	if err != nil {
		t.Fatalf("GetLatestProofByIdentityID after rotation: %v", err)
	}
	if proof.EventType != "IDENTITY_UPDATED" {
		t.Fatalf("latest proof = %s, want IDENTITY_UPDATED", proof.EventType)
	}
}

func TestGetByIdentityID_Pagination(t *testing.T) {
	db := newDB(t)
	store := NewEventStore(db)
	ctx := context.Background()

	storeIdentityEvent(t, store, 0,
		buildIdentityEnvelope(t, identityevent.TypeIdentityVerified, "id-A", nil))
	storeIdentityEvent(t, store, 1,
		buildIdentityEnvelope(t, identityevent.TypeIdentityLinked, "id-A", []string{"agent-1"}))
	storeIdentityEvent(t, store, 2,
		buildIdentityEnvelope(t, identityevent.TypeIdentityRevoked, "id-A", nil))

	all, err := store.GetByIdentityID(ctx, "id-A", 50, 0)
	if err != nil {
		t.Fatalf("GetByIdentityID: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 events, got %d", len(all))
	}
	if all[0].EventType != "IDENTITY_REVOKED" {
		t.Fatalf("newest first expected, got %s", all[0].EventType)
	}

	page, err := store.GetByIdentityID(ctx, "id-A", 1, 1)
	if err != nil {
		t.Fatalf("GetByIdentityID paged: %v", err)
	}
	if len(page) != 1 || page[0].EventType != "IDENTITY_LINKED" {
		t.Fatalf("page = %+v", page)
	}

	// Unknown identity → empty, no error.
	none, err := store.GetByIdentityID(ctx, "id-unknown", 50, 0)
	if err != nil {
		t.Fatalf("GetByIdentityID unknown: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected no events, got %d", len(none))
	}
}

func TestGetLatestByIdentityID_NotFound(t *testing.T) {
	db := newDB(t)
	store := NewEventStore(db)
	if _, err := store.GetLatestByIdentityID(context.Background(), "missing"); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestStoreEvent_IdentityDedupAcrossFamilies(t *testing.T) {
	db := newDB(t)
	store := NewEventStore(db)
	ctx := context.Background()

	env := buildIdentityEnvelope(t, identityevent.TypeIdentityVerified, "id-A", nil)
	storeIdentityEvent(t, store, 0, env)

	dup, leaf, err := store.ExistsByEventHash(ctx, "event-hash-0")
	if err != nil {
		t.Fatalf("ExistsByEventHash: %v", err)
	}
	if !dup || leaf != 0 {
		t.Fatalf("dedup miss: dup=%v leaf=%d", dup, leaf)
	}
}

func TestReceiptStore_FindByLeafIndex(t *testing.T) {
	db := newDB(t)
	receipts := NewReceiptStore(db)
	ctx := context.Background()

	if err := receipts.Store(ctx, 7, "id-A", 10, []byte{0xd2, 0x84}); err != nil {
		t.Fatalf("store receipt: %v", err)
	}

	rec, err := receipts.FindByLeafIndex(ctx, 7, 10)
	if err != nil {
		t.Fatalf("FindByLeafIndex: %v", err)
	}
	if rec == nil || rec.AgentID != "id-A" || len(rec.ReceiptBlob) != 2 {
		t.Fatalf("unexpected record: %+v", rec)
	}

	// Different tree size → miss (nil, nil).
	miss, err := receipts.FindByLeafIndex(ctx, 7, 11)
	if err != nil {
		t.Fatalf("FindByLeafIndex miss: %v", err)
	}
	if miss != nil {
		t.Fatalf("expected cache miss, got %+v", miss)
	}
}
