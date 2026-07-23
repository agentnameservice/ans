package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
)

func TestSPKIKeyHash4_Length(t *testing.T) {
	t.Parallel()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	out, err := anscrypto.SPKIKeyHash4(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 {
		t.Fatalf("want 4 bytes, got %d", len(out))
	}
}

func TestSPKIKeyHash4_DeterministicAcrossCalls(t *testing.T) {
	t.Parallel()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a, _ := anscrypto.SPKIKeyHash4(&k.PublicKey)
	b, _ := anscrypto.SPKIKeyHash4(&k.PublicKey)
	if string(a) != string(b) {
		t.Fatalf("same key should hash identically; a=%x b=%x", a, b)
	}
}

func TestSPKIKeyHash4_DifferentKeysDiffer(t *testing.T) {
	t.Parallel()
	// Two random P-256 keys should collide on the 4-byte prefix with
	// probability 2^-32; a single sampled pair is overwhelmingly
	// different.
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h1, _ := anscrypto.SPKIKeyHash4(&k1.PublicKey)
	h2, _ := anscrypto.SPKIKeyHash4(&k2.PublicKey)
	if string(h1) == string(h2) {
		t.Fatalf("keys collided on 4-byte hash (astronomically unlikely): %x", h1)
	}
}

func TestSPKIKeyIDHex4_Matches4ByteHash(t *testing.T) {
	t.Parallel()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, err := anscrypto.SPKIKeyHash4(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	h, err := anscrypto.SPKIKeyIDHex4(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if h != hex.EncodeToString(b) {
		t.Fatalf("hex form mismatch: hex=%q bytes=%x", h, b)
	}
	if len(h) != 8 {
		t.Fatalf("hex form should be 8 chars, got %d", len(h))
	}
}

func TestSPKIKeyHash4_RejectsNonMarshalable(t *testing.T) {
	t.Parallel()
	// An arbitrary interface{} that isn't an acceptable PKIX key.
	_, err := anscrypto.SPKIKeyHash4("not a key")
	if err == nil {
		t.Fatal("expected error on unsupported key type")
	}
}

func TestSPKIKeyIDHex4_RejectsNonMarshalable(t *testing.T) {
	t.Parallel()
	// Same failure mode as SPKIKeyHash4 — propagates MarshalPKIXPublicKey
	// errors rather than silently returning an empty string.
	_, err := anscrypto.SPKIKeyIDHex4("not a key")
	if err == nil {
		t.Fatal("expected error on unsupported key type")
	}
}
