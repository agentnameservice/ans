package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// newTestDB opens an in-memory sqlite DB and applies migrations.
func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newAgentFixture builds a PENDING_VALIDATION registration for
// persistence tests. AgentHost is derived from AnsName.FQDN().
func newAgentFixture(t *testing.T, agentID, host string) *domain.AgentRegistration {
	t.Helper()
	ansName, err := domain.NewAnsName(mustSemVer(t, 1, 0, 0), host)
	if err != nil {
		t.Fatal(err)
	}
	return &domain.AgentRegistration{
		AgentID: agentID,
		OwnerID: "owner-1",
		AnsName: ansName,
		Status:  domain.StatusPendingValidation,
		Details: domain.RegistrationDetails{
			RegistrationTimestamp: time.Now().UTC().Truncate(time.Millisecond),
			DisplayName:           "Test Agent " + agentID,
			Description:           "test",
		},
	}
}

func mustSemVer(t *testing.T, major, minor, patch int) domain.SimplifiedSemVer {
	t.Helper()
	v, err := domain.NewSemVer(major, minor, patch)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// ----- Save (insert + update) -----

func TestAgentStore_Save_InsertAndUpdate(t *testing.T) {
	db := newTestDB(t)
	store := NewAgentStore(db)
	ctx := context.Background()

	agent := newAgentFixture(t, "agent-uuid-1", "a.example.com")
	if err := store.Save(ctx, agent); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if agent.ID == 0 {
		t.Fatal("Save must populate ID after insert")
	}

	// Update: advance status, re-save (UPDATE branch).
	agent.Status = domain.StatusActive
	agent.Details.Description = "updated"
	if err := store.Save(ctx, agent); err != nil {
		t.Fatalf("update: %v", err)
	}

	found, err := store.FindByID(ctx, agent.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if found.Status != domain.StatusActive {
		t.Errorf("status: got %q, want ACTIVE", found.Status)
	}
	if found.Details.Description != "updated" {
		t.Errorf("description: got %q", found.Details.Description)
	}
}

func TestAgentStore_Save_NilAgent(t *testing.T) {
	store := NewAgentStore(newTestDB(t))
	if err := store.Save(context.Background(), nil); err == nil {
		t.Error("want error for nil agent")
	}
}

func TestAgentStore_Save_UniqueAnsNameViolation(t *testing.T) {
	store := NewAgentStore(newTestDB(t))
	ctx := context.Background()

	a1 := newAgentFixture(t, "id-1", "dup.example.com")
	if err := store.Save(ctx, a1); err != nil {
		t.Fatal(err)
	}
	a2 := newAgentFixture(t, "id-2", "dup.example.com") // same host+version → same ans_name
	err := store.Save(ctx, a2)
	if err == nil {
		t.Fatal("expected unique-constraint violation")
	}
	if !errors.Is(err, domain.ErrConflict) {
		t.Errorf("want ErrConflict, got %v", err)
	}
}

// ----- Lookup variants -----

func TestAgentStore_Lookups(t *testing.T) {
	store := NewAgentStore(newTestDB(t))
	ctx := context.Background()

	a := newAgentFixture(t, "uuid-a", "a.example.com")
	if err := store.Save(ctx, a); err != nil {
		t.Fatal(err)
	}

	t.Run("FindByID", func(t *testing.T) {
		got, err := store.FindByID(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.AgentID != a.AgentID {
			t.Errorf("mismatch")
		}
	})

	t.Run("FindByID not found", func(t *testing.T) {
		_, err := store.FindByID(ctx, 999999)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("FindByAgentID", func(t *testing.T) {
		got, err := store.FindByAgentID(ctx, "uuid-a")
		if err != nil || got.AgentID != "uuid-a" {
			t.Errorf("got=%v err=%v", got, err)
		}
	})

	t.Run("FindByAgentID not found", func(t *testing.T) {
		_, err := store.FindByAgentID(ctx, "missing")
		if !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("FindByAnsName", func(t *testing.T) {
		got, err := store.FindByAnsName(ctx, a.AnsName)
		if err != nil || got.AgentID != a.AgentID {
			t.Errorf("got=%v err=%v", got, err)
		}
	})

	t.Run("FindByAnsName not found", func(t *testing.T) {
		other, _ := domain.NewAnsName(mustSemVer(t, 9, 9, 9), "nope.example.com")
		_, err := store.FindByAnsName(ctx, other)
		if !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("ExistsByAnsName true/false", func(t *testing.T) {
		ok, err := store.ExistsByAnsName(ctx, a.AnsName)
		if err != nil || !ok {
			t.Errorf("expected true, got ok=%v err=%v", ok, err)
		}
		other, _ := domain.NewAnsName(mustSemVer(t, 9, 9, 9), "nope.example.com")
		ok, err = store.ExistsByAnsName(ctx, other)
		if err != nil || ok {
			t.Errorf("expected false, got ok=%v err=%v", ok, err)
		}
	})
}

// ----- Queries that return multiple rows -----

func TestAgentStore_FindAllByAgentHost(t *testing.T) {
	store := NewAgentStore(newTestDB(t))
	ctx := context.Background()

	// Two versions under the same host.
	for _, v := range []struct{ maj, min, patch int }{{1, 0, 0}, {1, 1, 0}, {2, 0, 0}} {
		ansName, _ := domain.NewAnsName(mustSemVer(t, v.maj, v.min, v.patch), "multi.example.com")
		reg := &domain.AgentRegistration{
			AgentID: "id-" + ansName.String(),
			OwnerID: "o",
			AnsName: ansName,
			Status:  domain.StatusActive,
			Details: domain.RegistrationDetails{RegistrationTimestamp: time.Now()},
		}
		if err := store.Save(ctx, reg); err != nil {
			t.Fatal(err)
		}
	}
	// Also one unrelated host.
	other := newAgentFixture(t, "unrelated", "other.example.com")
	_ = store.Save(ctx, other)

	rows, err := store.FindAllByAgentHost(ctx, "multi.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Errorf("FindAllByAgentHost: got %d rows, want 3", len(rows))
	}
	// Newest first → 2.0.0 then 1.1.0 then 1.0.0 (by insertion order).
	if rows[0].AnsName.Version().String() != "2.0.0" {
		t.Errorf("expected newest-first ordering, got %v", rows[0].AnsName)
	}
}

func TestAgentStore_FindExistingByFQDN_FiltersTerminal(t *testing.T) {
	store := NewAgentStore(newTestDB(t))
	ctx := context.Background()

	// ACTIVE + REVOKED on same FQDN.
	active, _ := domain.NewAnsName(mustSemVer(t, 1, 0, 0), "host.example.com")
	revoked, _ := domain.NewAnsName(mustSemVer(t, 2, 0, 0), "host.example.com")
	_ = store.Save(ctx, &domain.AgentRegistration{
		AgentID: "a", OwnerID: "o", AnsName: active, Status: domain.StatusActive,
		Details: domain.RegistrationDetails{RegistrationTimestamp: time.Now()},
	})
	_ = store.Save(ctx, &domain.AgentRegistration{
		AgentID: "r", OwnerID: "o", AnsName: revoked, Status: domain.StatusRevoked,
		Details: domain.RegistrationDetails{RegistrationTimestamp: time.Now()},
	})

	rows, err := store.FindExistingByFQDN(ctx, "host.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("want 1 (active only), got %d", len(rows))
	}
	if rows[0].Status != domain.StatusActive {
		t.Errorf("filter leaked terminal status: %s", rows[0].Status)
	}
}

// ----- ListByOwner pagination -----

func TestAgentStore_ListByOwner_Pagination(t *testing.T) {
	store := NewAgentStore(newTestDB(t))
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		ansName, _ := domain.NewAnsName(mustSemVer(t, 1, 0, i), "p.example.com")
		reg := &domain.AgentRegistration{
			AgentID: "paged-" + ansName.String(), OwnerID: "alice",
			AnsName: ansName, Status: domain.StatusActive,
			Details: domain.RegistrationDetails{RegistrationTimestamp: time.Now()},
		}
		_ = store.Save(ctx, reg)
	}
	// One row for a different owner — filter must exclude it.
	bobAnsName, _ := domain.NewAnsName(mustSemVer(t, 5, 0, 0), "bob.example.com")
	_ = store.Save(ctx, &domain.AgentRegistration{
		AgentID: "bob", OwnerID: "bob", AnsName: bobAnsName,
		Status:  domain.StatusActive,
		Details: domain.RegistrationDetails{RegistrationTimestamp: time.Now()},
	})

	page1, err := store.ListByOwner(ctx, "alice", port.ListFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page1.Items) != 2 {
		t.Errorf("page1: got %d, want 2", len(page1.Items))
	}
	if !page1.HasMore || page1.NextCursor == "" {
		t.Error("HasMore + NextCursor expected")
	}

	// Follow the cursor.
	page2, err := store.ListByOwner(ctx, "alice", port.ListFilter{Limit: 2, Cursor: page1.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2.Items) != 2 {
		t.Errorf("page2: got %d, want 2", len(page2.Items))
	}
	// Page 1 last ID should be greater than page 2 first ID.
	if page1.Items[len(page1.Items)-1].ID <= page2.Items[0].ID {
		t.Errorf("cursor did not advance: page1 last=%d page2 first=%d",
			page1.Items[len(page1.Items)-1].ID, page2.Items[0].ID)
	}
}

func TestAgentStore_ListByOwner_FiltersByHostAndStatus(t *testing.T) {
	store := NewAgentStore(newTestDB(t))
	ctx := context.Background()

	for _, spec := range []struct {
		host   string
		status domain.RegistrationStatus
	}{
		{"a.example.com", domain.StatusActive},
		{"a.example.com", domain.StatusRevoked},
		{"b.example.com", domain.StatusActive},
	} {
		ansName, _ := domain.NewAnsName(mustSemVer(t, 1, 0, 0), spec.host)
		_ = store.Save(ctx, &domain.AgentRegistration{
			AgentID: spec.host + "-" + string(spec.status), OwnerID: "alice",
			AnsName: ansName, Status: spec.status,
			Details: domain.RegistrationDetails{RegistrationTimestamp: time.Now()},
		})
	}

	page, err := store.ListByOwner(ctx, "alice", port.ListFilter{
		AgentHost: "a.example.com",
		Statuses:  []domain.RegistrationStatus{domain.StatusActive},
		Limit:     10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Errorf("filter: got %d rows, want 1", len(page.Items))
	}
	if page.Items[0].Status != domain.StatusActive {
		t.Errorf("status leaked")
	}
}

func TestAgentStore_ListByOwner_InvalidCursor(t *testing.T) {
	store := NewAgentStore(newTestDB(t))
	_, err := store.ListByOwner(context.Background(), "o", port.ListFilter{Cursor: "!!!"})
	if err == nil {
		t.Fatal("expected cursor decode error")
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "INVALID_CURSOR" {
		t.Errorf("want INVALID_CURSOR domain error, got %v", err)
	}
}

// ----- Delete -----

func TestAgentStore_Delete(t *testing.T) {
	store := NewAgentStore(newTestDB(t))
	ctx := context.Background()

	a := newAgentFixture(t, "to-delete", "del.example.com")
	_ = store.Save(ctx, a)

	if err := store.Delete(ctx, a.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err := store.FindByID(ctx, a.ID)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

// ----- cursor helpers -----

func TestEncodeDecodeCursor(t *testing.T) {
	for _, id := range []int64{1, 42, 1_000_000, 9_999_999_999} {
		c := encodeCursor(id)
		got, err := decodeCursor(c)
		if err != nil {
			t.Errorf("decode %q: %v", c, err)
		}
		if got != id {
			t.Errorf("round-trip: got %d, want %d", got, id)
		}
	}
}

func TestDecodeCursor_Garbage(t *testing.T) {
	if _, err := decodeCursor("!!!"); err == nil {
		t.Error("expected error on bad base64")
	}
	// Valid base64 but not numeric.
	if _, err := decodeCursor("Zm9v"); err == nil { // base64("foo")
		t.Error("expected error on non-numeric cursor content")
	}
}

// ----- DBX accessor + misc helpers -----

func TestDB_DBX_ReturnsUnderlyingHandle(t *testing.T) {
	db := newTestDB(t)
	x := db.DBX()
	if x == nil {
		t.Fatal("DBX must be non-nil")
	}
	// Ping to prove it's live.
	if err := x.PingContext(context.Background()); err != nil {
		t.Errorf("ping: %v", err)
	}
}

func TestMsToTime_RoundTripUTC(t *testing.T) {
	now := time.Now().UnixMilli()
	ts := msToTime(now)
	if ts.Location() != time.UTC {
		t.Errorf("msToTime should return UTC, got %s", ts.Location())
	}
	if ts.UnixMilli() != now {
		t.Errorf("round-trip: got %d, want %d", ts.UnixMilli(), now)
	}
}

func TestNullableMsAndInt64(t *testing.T) {
	if nullableMs(time.Time{}) != nil {
		t.Error("zero time should map to nil")
	}
	if nullableMs(time.UnixMilli(1)) == nil {
		t.Error("non-zero time should map to non-nil")
	}
	if nullableInt64(0) != nil {
		t.Error("0 should map to nil")
	}
	if nullableInt64(42) == nil {
		t.Error("non-zero should map to non-nil")
	}
}

// newBaseOnlyFixture builds a §3.2.0 base-only registration: zero
// AnsName, AgentHost set explicitly. Status starts PENDING_VALIDATION
// so ExistsActiveBaseOnlyByAgentHost returns it as "claimed."
func newBaseOnlyFixture(t *testing.T, agentID, host string) *domain.AgentRegistration {
	t.Helper()
	return &domain.AgentRegistration{
		AgentID:   agentID,
		OwnerID:   "owner-1",
		AgentHost: host,
		Status:    domain.StatusPendingValidation,
		Details: domain.RegistrationDetails{
			RegistrationTimestamp: time.Now().UTC().Truncate(time.Millisecond),
			DisplayName:           "Base-only " + agentID,
		},
	}
}

func TestAgentStore_ExistsActiveBaseOnlyByAgentHost(t *testing.T) {
	db := newTestDB(t)
	store := NewAgentStore(db)
	ctx := context.Background()

	// Empty store → false.
	exists, err := store.ExistsActiveBaseOnlyByAgentHost(ctx, "skill-a.example.com")
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if exists {
		t.Error("empty store should return false")
	}

	// Persist a base-only registration in PENDING_VALIDATION.
	pending := newBaseOnlyFixture(t, "agent-base-1", "skill-a.example.com")
	if err := store.Save(ctx, pending); err != nil {
		t.Fatalf("save pending: %v", err)
	}

	exists, err = store.ExistsActiveBaseOnlyByAgentHost(ctx, "skill-a.example.com")
	if err != nil {
		t.Fatalf("after pending: %v", err)
	}
	if !exists {
		t.Error("PENDING_VALIDATION base-only should count as claimed")
	}

	// Different FQDN → still false.
	exists, _ = store.ExistsActiveBaseOnlyByAgentHost(ctx, "skill-b.example.com")
	if exists {
		t.Error("unrelated FQDN should not match")
	}

	// Versioned registration on the same FQDN should NOT trigger the
	// base-only conflict — the two paths track distinct namespaces.
	versioned := newAgentFixture(t, "agent-versioned", "skill-c.example.com")
	if err := store.Save(ctx, versioned); err != nil {
		t.Fatalf("save versioned: %v", err)
	}
	exists, _ = store.ExistsActiveBaseOnlyByAgentHost(ctx, "skill-c.example.com")
	if exists {
		t.Error("versioned row must not count as a base-only claim")
	}

	// Revoke the base-only row → conflict releases.
	pending.Status = domain.StatusRevoked
	if err := store.Save(ctx, pending); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	exists, _ = store.ExistsActiveBaseOnlyByAgentHost(ctx, "skill-a.example.com")
	if exists {
		t.Error("revoked base-only row should release the FQDN")
	}
}

func TestAgentStore_AnchorClaim_RoundTrip(t *testing.T) {
	db := newTestDB(t)
	store := NewAgentStore(db)
	ctx := context.Background()

	cases := []struct {
		name  string
		claim *domain.IdentityClaim
	}{
		{
			name: "FQDN claim",
			claim: &domain.IdentityClaim{
				AnchorType: domain.AnchorTypeFQDN,
				ResolvedID: "agent.example.com",
			},
		},
		{
			name: "DID claim",
			claim: &domain.IdentityClaim{
				AnchorType: domain.AnchorTypeDID,
				ResolvedID: "did:web:agent.example.com",
			},
		},
		{
			name: "LEI claim",
			claim: &domain.IdentityClaim{
				AnchorType: domain.AnchorTypeLEI,
				ResolvedID: "529900T8BM49AURSDO55",
			},
		},
		{
			name:  "no claim (legacy path)",
			claim: nil,
		},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Distinct host + agent ID per case so the per-FQDN
			// base-only uniqueness check does not interfere.
			agentID := "agent-anchor-" + strconvI(i)
			host := "agent" + strconvI(i) + ".example.com"
			fixture := newBaseOnlyFixture(t, agentID, host)
			fixture.AnchorClaim = c.claim

			if err := store.Save(ctx, fixture); err != nil {
				t.Fatalf("Save: %v", err)
			}
			loaded, err := store.FindByID(ctx, fixture.ID)
			if err != nil {
				t.Fatalf("FindByID: %v", err)
			}
			if c.claim == nil {
				if loaded.AnchorClaim != nil {
					t.Errorf("expected nil AnchorClaim, got %+v", loaded.AnchorClaim)
				}
				return
			}
			if loaded.AnchorClaim == nil {
				t.Fatal("expected AnchorClaim, got nil")
			}
			if loaded.AnchorClaim.AnchorType != c.claim.AnchorType {
				t.Errorf("AnchorType: got %q, want %q",
					loaded.AnchorClaim.AnchorType, c.claim.AnchorType)
			}
			if loaded.AnchorClaim.ResolvedID != c.claim.ResolvedID {
				t.Errorf("ResolvedID: got %q, want %q",
					loaded.AnchorClaim.ResolvedID, c.claim.ResolvedID)
			}
			// PublicKeyJWK is intentionally not persisted; verifiers
			// re-resolve through the AnchorResolver to honor the
			// per-profile freshness budget.
			if len(loaded.AnchorClaim.PublicKeyJWK) != 0 {
				t.Errorf("PublicKeyJWK should not be persisted, got %d bytes",
					len(loaded.AnchorClaim.PublicKeyJWK))
			}
		})
	}
}

// strconvI keeps the test imports minimal.
func strconvI(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestAgentStore_ExistsByAnsName_ZeroIsFalse pins the contract
// guarding base-only registrations: looking up the zero-value AnsName
// must short-circuit to false rather than match every empty ans_name
// row in the table (the pre-Plan-F shape would have collided every
// base-only registration).
func TestAgentStore_ExistsByAnsName_ZeroIsFalse(t *testing.T) {
	db := newTestDB(t)
	store := NewAgentStore(db)
	ctx := context.Background()

	pending := newBaseOnlyFixture(t, "agent-base-1", "skill-a.example.com")
	if err := store.Save(ctx, pending); err != nil {
		t.Fatalf("save: %v", err)
	}

	exists, err := store.ExistsByAnsName(ctx, domain.AnsName{})
	if err != nil {
		t.Fatalf("ExistsByAnsName(zero): %v", err)
	}
	if exists {
		t.Error("ExistsByAnsName must return false for the zero value")
	}
}
