package producerkey_test

import (
	"context"
	"errors"
	"testing"

	"github.com/agentnameservice/ans/internal/tl/producerkey"
)

func TestMemoryStore_AddGet(t *testing.T) {
	t.Parallel()
	s := producerkey.NewMemoryStore()
	if err := s.Add(producerkey.Entry{
		RaID: "ra1", KeyID: "k1", Algorithm: "ES256",
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	pem, err := s.Get(context.Background(), "ra1", "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if pem == "" {
		t.Fatal("empty PEM returned")
	}
}

func TestMemoryStore_GetNotFound(t *testing.T) {
	t.Parallel()
	s := producerkey.NewMemoryStore()
	if _, err := s.Get(context.Background(), "ra1", "k1"); !errors.Is(err, producerkey.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_AddRejectsEmpty(t *testing.T) {
	t.Parallel()
	s := producerkey.NewMemoryStore()
	cases := []producerkey.Entry{
		{KeyID: "k", PublicKeyPEM: "pem"}, // missing raID
		{RaID: "ra", PublicKeyPEM: "pem"}, // missing keyID
		{RaID: "ra", KeyID: "k"},          // missing PEM
	}
	for i, e := range cases {
		if err := s.Add(e); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestMemoryStore_AddDuplicate(t *testing.T) {
	t.Parallel()
	s := producerkey.NewMemoryStore()
	e := producerkey.Entry{RaID: "ra", KeyID: "k", PublicKeyPEM: "pem"}
	if err := s.Add(e); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(e); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestMemoryStore_Revoke(t *testing.T) {
	t.Parallel()
	s := producerkey.NewMemoryStore()
	_ = s.Add(producerkey.Entry{RaID: "ra", KeyID: "k", PublicKeyPEM: "pem"})

	if err := s.Revoke("ra", "k"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := s.Get(context.Background(), "ra", "k"); !errors.Is(err, producerkey.ErrNotFound) {
		t.Fatal("expected ErrNotFound after revoke")
	}
	// Double-revoke returns ErrNotFound.
	if err := s.Revoke("ra", "k"); !errors.Is(err, producerkey.ErrNotFound) {
		t.Fatalf("double revoke: want ErrNotFound, got %v", err)
	}
}

func TestNewMemoryStoreFromEntries(t *testing.T) {
	t.Parallel()
	entries := []producerkey.Entry{
		{RaID: "ra1", KeyID: "k1", PublicKeyPEM: "pem1"},
		{RaID: "ra2", KeyID: "k2", PublicKeyPEM: "pem2"},
	}
	s, err := producerkey.NewMemoryStoreFromEntries(entries)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := s.Get(context.Background(), "ra1", "k1"); err != nil || p != "pem1" {
		t.Fatalf("ra1/k1: err=%v p=%q", err, p)
	}
	if p, err := s.Get(context.Background(), "ra2", "k2"); err != nil || p != "pem2" {
		t.Fatalf("ra2/k2: err=%v p=%q", err, p)
	}
}

func TestNewMemoryStoreFromEntries_RejectsDup(t *testing.T) {
	t.Parallel()
	entries := []producerkey.Entry{
		{RaID: "ra", KeyID: "k", PublicKeyPEM: "pem"},
		{RaID: "ra", KeyID: "k", PublicKeyPEM: "pem"},
	}
	if _, err := producerkey.NewMemoryStoreFromEntries(entries); err == nil {
		t.Fatal("expected duplicate error")
	}
}
