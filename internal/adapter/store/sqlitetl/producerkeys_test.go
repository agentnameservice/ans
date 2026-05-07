package sqlitetl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
	"github.com/godaddy/ans/internal/tl/producerkey"
)

// freezeAt returns a Clock pinned to the given time — makes validity
// window assertions deterministic.
func freezeAt(t time.Time) func() time.Time { return func() time.Time { return t } }

// testPubPEM generates a P-256 key and returns its PKIX public PEM.
// Each call is a fresh key pair; tests that need a stable key should
// call once and reuse.
func testPubPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// newTestStore opens a :memory: DB and returns a store clocked at t0.
func newTestStore(t *testing.T, t0 time.Time) *sqlitetl.ProducerKeyStore {
	t.Helper()
	db, err := sqlitetl.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return sqlitetl.NewProducerKeyStore(db).WithClock(freezeAt(t0))
}

// baseEntry returns a registration payload with sensible defaults.
// Callers can override any field before passing to Register.
func baseEntry(t *testing.T, t0 time.Time) producerkey.Entry {
	return producerkey.Entry{
		RaID:         "ra-test",
		KeyID:        "key-001",
		Algorithm:    "ES256",
		PublicKeyPEM: testPubPEM(t),
		ValidFrom:    t0,
		ExpiresAt:    t0.Add(365 * 24 * time.Hour),
	}
}

func TestProducerKeyStore_RegisterThenGet(t *testing.T) {
	t0 := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	s := newTestStore(t, t0)

	rec, err := s.Register(context.Background(), baseEntry(t, t0))
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Record fields we expect the store to populate.
	if rec.Status != "active" {
		t.Errorf("status: got %q, want active", rec.Status)
	}
	if !strings.HasPrefix(rec.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint: got %q, want SHA256: prefix", rec.Fingerprint)
	}
	if len(rec.Fingerprint) != len("SHA256:")+64 {
		t.Errorf("fingerprint: hex length %d, want 64", len(rec.Fingerprint)-len("SHA256:"))
	}
	if !rec.CreatedAt.Equal(t0) {
		t.Errorf("createdAt: got %v, want %v", rec.CreatedAt, t0)
	}

	// Hot path: Get returns the PEM.
	pem, err := s.Get(context.Background(), "ra-test", "key-001")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if pem != rec.PublicKeyPEM {
		t.Errorf("pem mismatch on get")
	}
}

func TestProducerKeyStore_DuplicateKeyID(t *testing.T) {
	t0 := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	s := newTestStore(t, t0)

	entry := baseEntry(t, t0)
	if _, err := s.Register(context.Background(), entry); err != nil {
		t.Fatalf("first register: %v", err)
	}
	// Same keyID — even from a different raID — must collide because
	// key_id is the globally-unique PK in our schema (matches
	// reference; cross-RA keyId reuse would break the admin DELETE
	// route which is by keyId only).
	entry.RaID = "ra-different"
	entry.PublicKeyPEM = testPubPEM(t)
	_, err := s.Register(context.Background(), entry)
	if !errors.Is(err, producerkey.ErrDuplicateKey) {
		t.Fatalf("second register: got %v, want ErrDuplicateKey", err)
	}
}

func TestProducerKeyStore_InvalidInputs(t *testing.T) {
	t0 := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	s := newTestStore(t, t0)

	cases := []struct {
		name string
		mod  func(*producerkey.Entry)
	}{
		{"missing raId", func(e *producerkey.Entry) { e.RaID = "" }},
		{"missing keyId", func(e *producerkey.Entry) { e.KeyID = "" }},
		{"missing algorithm", func(e *producerkey.Entry) { e.Algorithm = "" }},
		{"missing pem", func(e *producerkey.Entry) { e.PublicKeyPEM = "" }},
		{"zero validFrom", func(e *producerkey.Entry) { e.ValidFrom = time.Time{} }},
		{"zero expiresAt", func(e *producerkey.Entry) { e.ExpiresAt = time.Time{} }},
		{"validFrom after expiresAt", func(e *producerkey.Entry) {
			e.ValidFrom, e.ExpiresAt = e.ExpiresAt, e.ValidFrom
		}},
		{"validFrom == expiresAt", func(e *producerkey.Entry) {
			e.ExpiresAt = e.ValidFrom
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := baseEntry(t, t0)
			tc.mod(&entry)
			_, err := s.Register(context.Background(), entry)
			if !errors.Is(err, producerkey.ErrInvalidRange) {
				t.Fatalf("got %v, want ErrInvalidRange", err)
			}
		})
	}
}

func TestProducerKeyStore_BadPEM(t *testing.T) {
	t0 := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	s := newTestStore(t, t0)

	t.Run("not a PEM block", func(t *testing.T) {
		e := baseEntry(t, t0)
		e.PublicKeyPEM = "definitely not a pem"
		_, err := s.Register(context.Background(), e)
		if err == nil || !strings.Contains(err.Error(), "PEM") {
			t.Fatalf("expected PEM error, got %v", err)
		}
	})

	t.Run("private key pasted into trust store", func(t *testing.T) {
		// A common paste-mistake: operator accidentally pastes the
		// RA's private key. fingerprintFromPEM's x509.ParsePKIXPublicKey
		// call rejects this because PKCS#8 private-key DER doesn't
		// parse as SPKI public-key DER.
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		privDER, _ := x509.MarshalPKCS8PrivateKey(k)
		privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
		e := baseEntry(t, t0)
		e.PublicKeyPEM = string(privPEM)
		_, err := s.Register(context.Background(), e)
		if err == nil {
			t.Fatal("expected rejection of private key; got nil error")
		}
	})
}

func TestProducerKeyStore_ValidityWindow(t *testing.T) {
	t0 := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	s := newTestStore(t, t0)

	entry := baseEntry(t, t0)
	entry.ValidFrom = t0.Add(1 * time.Hour)
	entry.ExpiresAt = t0.Add(2 * time.Hour)
	if _, err := s.Register(context.Background(), entry); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Before validFrom → not active.
	if _, err := s.Get(context.Background(), "ra-test", "key-001"); !errors.Is(err, producerkey.ErrNotFound) {
		t.Errorf("pre-window: got %v, want ErrNotFound", err)
	}

	// Inside window → found.
	s2 := newTestStore(t, t0)
	// Reuse the same DB? No — newTestStore creates a new :memory: DB.
	// Instead just re-register on the same store but with a fresh clock.
	// Pattern: use a pointer to the clock value so it's mutable.
	s3 := s.WithClock(freezeAt(t0.Add(90 * time.Minute)))
	if _, err := s3.Get(context.Background(), "ra-test", "key-001"); err != nil {
		t.Errorf("inside window: %v", err)
	}

	// After expiresAt → not active.
	s4 := s.WithClock(freezeAt(t0.Add(3 * time.Hour)))
	if _, err := s4.Get(context.Background(), "ra-test", "key-001"); !errors.Is(err, producerkey.ErrNotFound) {
		t.Errorf("post-window: got %v, want ErrNotFound", err)
	}
	_ = s2 // silence unused
}

func TestProducerKeyStore_Revoke(t *testing.T) {
	t0 := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	s := newTestStore(t, t0)

	if _, err := s.Register(context.Background(), baseEntry(t, t0)); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Revoke at t0 + 1h — status flips, revoked_at populated.
	s2 := s.WithClock(freezeAt(t0.Add(1 * time.Hour)))
	if err := s2.Revoke(context.Background(), "key-001"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Second revoke: already revoked → ErrNotFound.
	if err := s2.Revoke(context.Background(), "key-001"); !errors.Is(err, producerkey.ErrNotFound) {
		t.Errorf("double revoke: got %v, want ErrNotFound", err)
	}

	// Revoke of never-registered key → ErrNotFound.
	if err := s.Revoke(context.Background(), "nonexistent"); !errors.Is(err, producerkey.ErrNotFound) {
		t.Errorf("nonexistent revoke: got %v, want ErrNotFound", err)
	}

	// Get still returns ErrNotFound (key is revoked).
	if _, err := s2.Get(context.Background(), "ra-test", "key-001"); !errors.Is(err, producerkey.ErrNotFound) {
		t.Errorf("post-revoke get: got %v, want ErrNotFound", err)
	}

	// GetByKeyID returns the record with status=revoked for audit.
	rec, err := s2.GetByKeyID(context.Background(), "key-001")
	if err != nil {
		t.Fatalf("getByKeyID: %v", err)
	}
	if rec.Status != "revoked" {
		t.Errorf("status: got %q, want revoked", rec.Status)
	}
	if rec.RevokedAt.IsZero() {
		t.Error("revokedAt not populated")
	}
}

func TestProducerKeyStore_ListByRAID(t *testing.T) {
	t0 := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	s := newTestStore(t, t0)

	// Three keys for ra-one, one for ra-two.
	for i, ra := range []string{"ra-one", "ra-one", "ra-one", "ra-two"} {
		entry := baseEntry(t, t0)
		entry.RaID = ra
		entry.KeyID = map[int]string{
			0: "k1", 1: "k2", 2: "k3", 3: "k4",
		}[i]
		// Spread validFrom so ordering is deterministic.
		entry.ValidFrom = t0.Add(time.Duration(i) * time.Hour)
		entry.ExpiresAt = entry.ValidFrom.Add(24 * time.Hour)
		if _, err := s.Register(context.Background(), entry); err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
	}

	got, err := s.ListByRAID(context.Background(), "ra-one")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("list len: got %d, want 3", len(got))
	}
	// Newest validFrom first.
	if got[0].KeyID != "k3" || got[2].KeyID != "k1" {
		t.Errorf("ordering: got %s, %s, %s; want k3,k2,k1",
			got[0].KeyID, got[1].KeyID, got[2].KeyID)
	}

	// Revoked keys are still listed (audit).
	if err := s.Revoke(context.Background(), "k2"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, err = s.ListByRAID(context.Background(), "ra-one")
	if err != nil {
		t.Fatalf("list after revoke: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("list len after revoke: got %d, want 3 (audit keeps revoked rows)", len(got))
	}

	// Unknown raID → empty slice, not error.
	got, err = s.ListByRAID(context.Background(), "ra-nonexistent")
	if err != nil {
		t.Fatalf("list unknown: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("unknown raID: got %d keys, want 0", len(got))
	}
}

func TestProducerKeyStore_GetByKeyID_NotFound(t *testing.T) {
	t0 := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	s := newTestStore(t, t0)

	_, err := s.GetByKeyID(context.Background(), "nope")
	if !errors.Is(err, producerkey.ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestProducerKeyStore_Metadata(t *testing.T) {
	t0 := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	s := newTestStore(t, t0)

	entry := baseEntry(t, t0)
	entry.Metadata = []byte(`{"environment":"local","region":"na"}`)
	rec, err := s.Register(context.Background(), entry)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if string(rec.Metadata) == "" {
		t.Fatal("metadata missing")
	}
	if !strings.Contains(string(rec.Metadata), "local") {
		t.Errorf("metadata roundtrip: got %q", rec.Metadata)
	}
}

func TestProducerKeyStore_Metadata_InvalidJSON(t *testing.T) {
	t0 := time.Date(2026, 4, 19, 0, 0, 0, 0, time.UTC)
	s := newTestStore(t, t0)

	entry := baseEntry(t, t0)
	// SQLite's CHECK (json_valid(metadata)) rejects non-JSON text.
	// Admin handlers should refuse this upstream too, but the
	// constraint is the belt-and-braces defense.
	entry.Metadata = []byte("this is not json")
	_, err := s.Register(context.Background(), entry)
	if err == nil {
		t.Fatal("expected CHECK constraint failure, got nil")
	}
}
