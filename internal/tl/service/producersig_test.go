package service_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/tl/producerkey"
	"github.com/godaddy/ans/internal/tl/service"
)

func TestProducerSigVerifier_HappyPath(t *testing.T) {
	t.Parallel()
	km, pubPEM := newTestKM(t, "prod-k")
	store, _ := producerkey.NewMemoryStoreFromEntries([]producerkey.Entry{
		{RaID: "ra-1", KeyID: "prod-k", Algorithm: "ES256", PublicKeyPEM: pubPEM},
	})

	payload := []byte(`{"ansId":"agent-1","eventType":"AGENT_REGISTRATION"}`)
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "prod-k",
		anscrypto.JWSProtectedHeader{Typ: "JWT", Timestamp: 1700000000, RAID: "ra-1"},
		payload,
	)
	if err != nil {
		t.Fatal(err)
	}

	v := service.NewProducerSigVerifier(store)
	raID, keyID, err := v.Verify(context.Background(), jws, payload)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if raID != "ra-1" || keyID != "prod-k" {
		t.Fatalf("ids: got %q/%q", raID, keyID)
	}
}

// TestProducerSigVerifier_RawBodyInvariant pins the contract that the
// producer passes raw (non-canonicalized) bytes all the way through
// to the verifier, which canonicalizes exactly once. If someone ever
// "helpfully" pre-canonicalizes before calling Verify, the signature
// mismatches because JCS outputs idempotent *canonical* bytes but the
// caller signed over *canonical bytes of the original*, which differ
// in whitespace/key-order. This test demonstrates the invariant by
// signing a payload whose canonical form reorders the keys.
func TestProducerSigVerifier_RawBodyInvariant(t *testing.T) {
	t.Parallel()
	km, pubPEM := newTestKM(t, "prod-k")
	store, _ := producerkey.NewMemoryStoreFromEntries([]producerkey.Entry{
		{RaID: "ra", KeyID: "prod-k", Algorithm: "ES256", PublicKeyPEM: pubPEM},
	})

	// Non-canonical JSON: keys in reverse order, extra whitespace.
	// JCS will sort keys and strip whitespace — but SignDetachedJWS
	// does the JCS itself, so signing over this string and verifying
	// against it must both round-trip through the same canonicalization.
	nonCanonical := []byte(`{  "z":"last", "a":"first", "m":42 }`)
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "prod-k",
		anscrypto.JWSProtectedHeader{Typ: "JWT", Timestamp: 1700000000, RAID: "ra"},
		nonCanonical,
	)
	if err != nil {
		t.Fatal(err)
	}

	v := service.NewProducerSigVerifier(store)
	// Pass the SAME non-canonical bytes. The verifier must canonicalize
	// internally and produce bytes identical to what the signer
	// canonicalized. This is the contract.
	if _, _, err := v.Verify(context.Background(), jws, nonCanonical); err != nil {
		t.Fatalf("verify raw non-canonical body: %v", err)
	}
}

func TestProducerSigVerifier_NoSignature(t *testing.T) {
	t.Parallel()
	v := service.NewProducerSigVerifier(producerkey.NewMemoryStore())
	_, _, err := v.Verify(context.Background(), "", []byte(`{}`))
	assertDomainCode(t, err, service.CodeNoSignature)
}

func TestProducerSigVerifier_MalformedJWS(t *testing.T) {
	t.Parallel()
	v := service.NewProducerSigVerifier(producerkey.NewMemoryStore())
	_, _, err := v.Verify(context.Background(), "not-a-jws", []byte(`{}`))
	assertDomainCode(t, err, service.CodeInvalidSignatureHeader)
}

func TestProducerSigVerifier_MissingHeaderFields(t *testing.T) {
	t.Parallel()
	km, pubPEM := newTestKM(t, "k")
	// Sign with RAID="" so header is missing raid.
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{Typ: "JWT"}, // no RAID
		[]byte(`{}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = pubPEM // not registered

	v := service.NewProducerSigVerifier(producerkey.NewMemoryStore())
	_, _, err = v.Verify(context.Background(), jws, []byte(`{}`))
	assertDomainCode(t, err, service.CodeInvalidSignatureHeader)
}

func TestProducerSigVerifier_NotFoundProducerKey(t *testing.T) {
	t.Parallel()
	km, _ := newTestKM(t, "k")
	jws, _ := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{RAID: "ra-1"},
		[]byte(`{}`),
	)
	v := service.NewProducerSigVerifier(producerkey.NewMemoryStore()) // empty
	_, _, err := v.Verify(context.Background(), jws, []byte(`{}`))
	assertDomainCode(t, err, service.CodeNotFoundProducerKey)
}

func TestProducerSigVerifier_MismatchSignature(t *testing.T) {
	t.Parallel()
	km, pubPEM := newTestKM(t, "k")
	store, _ := producerkey.NewMemoryStoreFromEntries([]producerkey.Entry{
		{RaID: "ra", KeyID: "k", Algorithm: "ES256", PublicKeyPEM: pubPEM},
	})
	jws, _ := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{RAID: "ra"},
		[]byte(`{"a":1}`),
	)
	v := service.NewProducerSigVerifier(store)
	// Tamper with the body: canonicalized shape differs → sig mismatch.
	_, _, err := v.Verify(context.Background(), jws, []byte(`{"a":2}`))
	assertDomainCode(t, err, service.CodeMismatchSignature)
}

func TestProducerSigVerifier_InvalidPEM(t *testing.T) {
	t.Parallel()
	km, _ := newTestKM(t, "k")
	store, _ := producerkey.NewMemoryStoreFromEntries([]producerkey.Entry{
		{RaID: "ra", KeyID: "k", Algorithm: "ES256", PublicKeyPEM: "garbage"},
	})
	jws, _ := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{RAID: "ra"},
		[]byte(`{}`),
	)
	v := service.NewProducerSigVerifier(store)
	// Invalid PEM → VerifyDetachedWithPEM fails → we map to
	// MISMATCH_SIGNATURE (a bad key is indistinguishable from a bad
	// signature to the caller).
	_, _, err := v.Verify(context.Background(), jws, []byte(`{}`))
	assertDomainCode(t, err, service.CodeMismatchSignature)
}

func TestProducerSigVerifier_InternalStoreError(t *testing.T) {
	t.Parallel()
	km, _ := newTestKM(t, "k")
	jws, _ := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{RAID: "ra"},
		[]byte(`{}`),
	)
	v := service.NewProducerSigVerifier(&erroringStore{})
	_, _, err := v.Verify(context.Background(), jws, []byte(`{}`))
	assertDomainCode(t, err, service.CodeInvalidProducerKey)
}

// ----- helpers -----

func assertDomainCode(t *testing.T, err error, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error with code %s, got nil", wantCode)
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("want *domain.Error with code %s, got %T: %v", wantCode, err, err)
	}
	if de.Code != wantCode {
		t.Fatalf("code: want %s, got %s (%s)", wantCode, de.Code, de.Message)
	}
}

type testKM struct {
	key crypto.Signer
	id  string
}

func (k *testKM) Sign(_ context.Context, id string, data []byte) ([]byte, error) {
	if id != k.id {
		return nil, errors.New("no key")
	}
	return k.key.Sign(rand.Reader, data, crypto.SHA256)
}
func (k *testKM) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) { return false, nil }
func (k *testKM) GetPublicKey(_ context.Context, id string) (crypto.PublicKey, error) {
	if id != k.id {
		return nil, errors.New("no key")
	}
	return k.key.Public(), nil
}
func (k *testKM) CreateKey(_ context.Context, _ string) (string, error) { return "", nil }
func (k *testKM) ListKeys(_ context.Context) ([]string, error)          { return []string{k.id}, nil }

func newTestKM(t *testing.T, id string) (*testKM, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(k.Public())
	return &testKM{key: k, id: id}, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

type erroringStore struct{}

func (e *erroringStore) Get(_ context.Context, _, _ string) (string, error) {
	return "", errors.New("db is down")
}
