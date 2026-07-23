package crypto_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
)

// TestSignVerifyRoundTrip_ES256 proves sign-then-verify works with our
// own KeyManager path. This is the baseline.
func TestSignVerifyRoundTrip_ES256(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k1")

	payload := []byte(`{"foo":"bar","num":42}`)
	header := anscrypto.JWSProtectedHeader{
		Typ:       "JWT",
		Timestamp: 1700000000,
		RAID:      "ans-ra-local",
	}
	jws, err := anscrypto.SignDetachedJWS(context.Background(), km, "k1", header, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.Contains(jws, "..") {
		t.Fatalf("expected detached JWS, got %q", jws)
	}

	decoded, err := anscrypto.VerifyDetachedJWS(context.Background(), km, jws, payload)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if decoded.Alg != "ES256" {
		t.Errorf("alg: got %q, want ES256", decoded.Alg)
	}
	if decoded.Kid != "k1" {
		t.Errorf("kid: got %q, want k1", decoded.Kid)
	}
	if decoded.RAID != "ans-ra-local" {
		t.Errorf("raid: got %q, want ans-ra-local", decoded.RAID)
	}
	if decoded.Timestamp != 1700000000 {
		t.Errorf("timestamp: got %d, want 1700000000", decoded.Timestamp)
	}
}

// TestInteropWithGoJose is the most important test in this file. It
// proves our detached-JWS output is parseable by a standards-compliant
// library. If this breaks, every external verifier breaks.
func TestInteropWithGoJose(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "interop-key")

	payload := []byte(`{"hello":"world"}`)
	jwsCompact, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "interop-key",
		anscrypto.JWSProtectedHeader{Typ: "JWT", Timestamp: 1700000000, RAID: "ra"},
		payload,
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Re-canonicalize because that's what VerifyDetachedWithPEM does.
	canonical, err := anscrypto.Canonicalize(payload)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	sig, err := jose.ParseDetached(jwsCompact, canonical, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("jose ParseDetached: %v", err)
	}
	pubPEM := km.publicPEM(t, "interop-key")
	pub, err := parsePEM(pubPEM)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	if _, err := sig.Verify(pub); err != nil {
		t.Fatalf("jose verify: %v — our output is not standards-compliant", err)
	}
}

// TestVerifyDetachedWithPEM uses the jose-based PEM path (producer sig).
func TestVerifyDetachedWithPEM(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "producer-1")

	payload := []byte(`{"eventType":"AGENT_REGISTRATION"}`)
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "producer-1",
		anscrypto.JWSProtectedHeader{Typ: "JWT", Timestamp: 1700000000, RAID: "ra"},
		payload,
	)
	if err != nil {
		t.Fatal(err)
	}

	h, err := anscrypto.VerifyDetachedWithPEM(jws, payload, km.publicPEM(t, "producer-1"))
	if err != nil {
		t.Fatalf("verify PEM: %v", err)
	}
	if h.Alg != "ES256" || h.RAID != "ra" {
		t.Fatalf("header preserved wrong: %+v", h)
	}
}

// TestTamperedPayloadFails ensures any mutation to the payload breaks
// verification (on every path).
func TestTamperedPayloadFails(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	orig := []byte(`{"x":1}`)
	mutated := []byte(`{"x":2}`)
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{Timestamp: 1700000000, RAID: "ra"},
		orig,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := anscrypto.VerifyDetachedJWS(context.Background(), km, jws, mutated); !errors.Is(err, anscrypto.ErrJWSVerify) {
		t.Fatalf("km path: expected ErrJWSVerify, got %v", err)
	}
	if _, err := anscrypto.VerifyDetachedWithPEM(jws, mutated, km.publicPEM(t, "k")); !errors.Is(err, anscrypto.ErrJWSVerify) {
		t.Fatalf("pem path: expected ErrJWSVerify, got %v", err)
	}
}

func TestTamperedSignatureFails(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	payload := []byte(`{"x":1}`)
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{Timestamp: 1700000000, RAID: "ra"},
		payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a character in the middle of the signature segment.
	// The last base64url char has padding bits that can decode to the
	// same bytes regardless of some bit flips — so pick something
	// squarely in the middle of the sig where a flip guarantees the
	// decoded bytes differ.
	lastDot := strings.LastIndex(jws, ".")
	if lastDot == -1 || lastDot >= len(jws)-4 {
		t.Fatalf("sig segment too short: %q", jws)
	}
	sigMid := (lastDot + len(jws)) / 2
	orig := jws[sigMid]
	replacement := byte('A')
	if orig == replacement {
		replacement = 'B'
	}
	tampered := jws[:sigMid] + string(replacement) + jws[sigMid+1:]
	if tampered == jws {
		t.Fatal("failed to tamper")
	}
	if _, err := anscrypto.VerifyDetachedJWS(context.Background(), km, tampered, payload); err == nil {
		t.Fatal("expected verify failure on tampered sig")
	}
}

func TestSignDetachedJWS_RSA256(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "")
	km.addRSA(t, "rsa-1")

	payload := []byte(`{"a":1}`)
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "rsa-1",
		anscrypto.JWSProtectedHeader{Typ: "JWT", Timestamp: 1700000000},
		payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	h, err := anscrypto.VerifyDetachedJWS(context.Background(), km, jws, payload)
	if err != nil {
		t.Fatal(err)
	}
	if h.Alg != "RS256" {
		t.Fatalf("alg: got %q, want RS256", h.Alg)
	}
}

func TestDecodeHeader(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{RAID: "ra-42"},
		[]byte(`{"x":1}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	h, err := anscrypto.DecodeHeader(jws)
	if err != nil {
		t.Fatal(err)
	}
	if h.RAID != "ra-42" {
		t.Fatalf("raid: got %q, want ra-42", h.RAID)
	}
}

func TestSplitDetached_Errors(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"no dots":           "abcdef",
		"one dot":           "abc.def",
		"too many dots":     "a.b.c.d",
		"non-empty payload": "a.b.c",
		"empty header":      ".abc",
		"empty signature":   "abc..",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := anscrypto.DecodeHeader(in); err == nil {
				t.Fatalf("expected error for %q", in)
			}
		})
	}
}

func TestUnsupportedAlg(t *testing.T) {
	t.Parallel()
	// Build a JWS by hand with a bogus alg.
	h := map[string]any{"alg": "HS256", "kid": "k"}
	hj, _ := json.Marshal(h)
	encHeader := base64.RawURLEncoding.EncodeToString(hj)
	jws := encHeader + "..AAAA"
	if _, err := anscrypto.VerifyWithPublicKey(&ecdsa.PublicKey{}, jws, []byte("{}")); err == nil {
		t.Fatal("expected unsupported-alg error")
	}
}

func TestAlgKeyMismatch(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "") // ECDSA key will be "ec"; no rsa key here
	km.addECDSA(t, "ec")
	_, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "ec",
		anscrypto.JWSProtectedHeader{Alg: "RS256"},
		[]byte(`{}`),
	)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestVerifyDetachedWithPEM_InvalidPEM(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	jws, _ := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, []byte(`{"x":1}`),
	)
	if _, err := anscrypto.VerifyDetachedWithPEM(jws, []byte(`{"x":1}`), "not a pem"); err == nil {
		t.Fatal("expected invalid PEM error")
	}
}

func TestVerifyWithPublicKey_UnsupportedKey(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	jws, _ := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, []byte(`{"x":1}`),
	)
	if _, err := anscrypto.VerifyWithPublicKey("not a key", jws, []byte(`{"x":1}`)); err == nil {
		t.Fatal("expected unsupported-key error")
	}
}

// ----- in-memory KeyManager used only by the crypto tests -----

type memKM struct {
	keys map[string]crypto.Signer
}

func newMemKM(t *testing.T, initialKeyID string) *memKM {
	t.Helper()
	km := &memKM{keys: map[string]crypto.Signer{}}
	if initialKeyID != "" {
		km.addECDSA(t, initialKeyID)
	}
	return km
}

func (m *memKM) addECDSA(t *testing.T, id string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m.keys[id] = k
}

func (m *memKM) addRSA(t *testing.T, id string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m.keys[id] = k
}

func (m *memKM) Sign(_ context.Context, id string, data []byte) ([]byte, error) {
	s, ok := m.keys[id]
	if !ok {
		return nil, errors.New("no key")
	}
	return s.Sign(rand.Reader, data, crypto.SHA256)
}

func (m *memKM) Verify(_ context.Context, id string, data, sig []byte) (bool, error) {
	s, ok := m.keys[id]
	if !ok {
		return false, errors.New("no key")
	}
	switch pub := s.Public().(type) {
	case *ecdsa.PublicKey:
		r, ss, err := anscrypto.P1363ToScalars(sig)
		if err != nil {
			// Fall back to DER for KM-internal use; tests exercise both.
			return ecdsa.VerifyASN1(pub, data, sig), nil //nolint:nilerr // bad P1363 → try DER, not a verifier error
		}
		return ecdsa.Verify(pub, data, r, ss), nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, data, sig); err != nil {
			return false, nil //nolint:nilerr // bad sig is "verified=false", not a verifier error
		}
		return true, nil
	default:
		return false, errors.New("unsupported key")
	}
}

func (m *memKM) GetPublicKey(_ context.Context, id string) (crypto.PublicKey, error) {
	s, ok := m.keys[id]
	if !ok {
		return nil, errors.New("no key")
	}
	return s.Public(), nil
}

func (m *memKM) CreateKey(_ context.Context, _ string) (string, error) {
	return "", errors.New("not implemented in test KM")
}

func (m *memKM) ListKeys(_ context.Context) ([]string, error) {
	ids := make([]string, 0, len(m.keys))
	for id := range m.keys {
		ids = append(ids, id)
	}
	return ids, nil
}

func (m *memKM) publicPEM(t *testing.T, id string) string {
	t.Helper()
	s, ok := m.keys[id]
	if !ok {
		t.Fatalf("no key %q", id)
	}
	der, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func parsePEM(s string) (any, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no pem")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// ----- additional coverage for error paths -----

func TestSignDetachedJWS_KeyNotFound(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "") // empty
	_, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "missing",
		anscrypto.JWSProtectedHeader{}, []byte(`{}`),
	)
	if err == nil {
		t.Fatal("expected error when key missing")
	}
}

func TestSignDetachedJWS_UnsupportedKeyType(t *testing.T) {
	t.Parallel()
	km := &dummyKM{pub: "not a key"}
	_, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, []byte(`{}`),
	)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestSignDetachedJWS_BadExplicitAlg(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	_, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{Alg: "HS256"},
		[]byte(`{}`),
	)
	if err == nil {
		t.Fatal("expected error for bogus alg")
	}
}

func TestSignDetachedJWS_BadCanonicalJSON(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	_, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, []byte(`{not-json`),
	)
	if err == nil {
		t.Fatal("expected canonicalize error on malformed JSON")
	}
}

func TestSignDetachedJWS_SignerError(t *testing.T) {
	t.Parallel()
	km := &erroringKM{}
	_, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, []byte(`{}`),
	)
	if err == nil {
		t.Fatal("expected signer error")
	}
}

func TestVerifyDetachedJWS_KeyNotFound(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, []byte(`{}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	empty := newMemKM(t, "") // no keys
	if _, err := anscrypto.VerifyDetachedJWS(context.Background(), empty, jws, []byte(`{}`)); err == nil {
		t.Fatal("expected key-not-found error")
	}
}

func TestVerifyDetachedJWS_MalformedJWS(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	if _, err := anscrypto.VerifyDetachedJWS(context.Background(), km, "garbage", []byte(`{}`)); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestVerifyDetachedJWS_BadHeader(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	// Header that isn't base64 — triggers decodeHeader error.
	jws := "not.base64..AAAA"
	if _, err := anscrypto.VerifyDetachedJWS(context.Background(), km, jws, []byte(`{}`)); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestVerifyWithPublicKey_BadSigB64(t *testing.T) {
	t.Parallel()
	h, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": "k"})
	encHeader := base64.RawURLEncoding.EncodeToString(h)
	jws := encHeader + "..!@#$"
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := anscrypto.VerifyWithPublicKey(&pk.PublicKey, jws, []byte(`{}`)); err == nil {
		t.Fatal("expected sig decode error")
	}
}

func TestVerifyWithPublicKey_BadP1363(t *testing.T) {
	t.Parallel()
	// Sig that decodes from base64 but is not a valid P1363 (odd length).
	h, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": "k"})
	encHeader := base64.RawURLEncoding.EncodeToString(h)
	bad := base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x01, 0x02}) // 3 bytes, not P1363
	jws := encHeader + "..ABCD" + bad
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := anscrypto.VerifyWithPublicKey(&pk.PublicKey, jws, []byte(`{}`)); err == nil {
		t.Fatal("expected P1363 parse error")
	}
}

func TestVerifyDetachedWithPEM_UnsupportedAlg(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	jws, _ := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, []byte(`{}`),
	)
	// Replace the encoded header with one whose alg is HS256.
	h, _ := json.Marshal(map[string]any{"alg": "HS256", "kid": "k"})
	badHeader := base64.RawURLEncoding.EncodeToString(h)
	parts := strings.SplitN(jws, ".", 2)
	tampered := badHeader + "." + parts[1]
	if _, err := anscrypto.VerifyDetachedWithPEM(tampered, []byte(`{}`), km.publicPEM(t, "k")); err == nil {
		t.Fatal("expected unsupported-alg error")
	}
}

func TestVerifyDetachedWithPEM_RSAPublicKeyPEM(t *testing.T) {
	t.Parallel()
	// RSA PKCS#1 public key PEM (RSA PUBLIC KEY block type).
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1 := x509.MarshalPKCS1PublicKey(&k.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pkcs1})

	// Sign with a KM holding the same key.
	km := &fixedRSAKM{key: k}
	payload := []byte(`{"x":1}`)
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anscrypto.VerifyDetachedWithPEM(jws, payload, string(pemBytes)); err != nil {
		t.Fatalf("RSA PUBLIC KEY PEM verify: %v", err)
	}
}

func TestVerifyDetachedWithPEM_WrongPEMBlockType(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	jws, _ := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, []byte(`{}`),
	)
	weird := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x00}}))
	if _, err := anscrypto.VerifyDetachedWithPEM(jws, []byte(`{}`), weird); err == nil {
		t.Fatal("expected PEM-type error")
	}
}

// ----- test doubles for the edge cases above -----

type dummyKM struct{ pub any }

func (d *dummyKM) Sign(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, errors.New("should not reach sign")
}
func (d *dummyKM) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, nil
}
func (d *dummyKM) GetPublicKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	return d.pub, nil
}
func (d *dummyKM) CreateKey(_ context.Context, _ string) (string, error) { return "", nil }
func (d *dummyKM) ListKeys(_ context.Context) ([]string, error)          { return nil, nil }

type erroringKM struct{}

func (e *erroringKM) Sign(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, errors.New("sign failed")
}
func (e *erroringKM) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return false, nil
}
func (e *erroringKM) GetPublicKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return k.Public(), nil
}
func (e *erroringKM) CreateKey(_ context.Context, _ string) (string, error) { return "", nil }
func (e *erroringKM) ListKeys(_ context.Context) ([]string, error)          { return nil, nil }

type fixedRSAKM struct{ key *rsa.PrivateKey }

func (f *fixedRSAKM) Sign(_ context.Context, _ string, data []byte) ([]byte, error) {
	return f.key.Sign(rand.Reader, data, crypto.SHA256)
}
func (f *fixedRSAKM) Verify(_ context.Context, _ string, _, _ []byte) (bool, error) {
	return true, nil
}
func (f *fixedRSAKM) GetPublicKey(_ context.Context, _ string) (crypto.PublicKey, error) {
	return &f.key.PublicKey, nil
}
func (f *fixedRSAKM) CreateKey(_ context.Context, _ string) (string, error) { return "", nil }
func (f *fixedRSAKM) ListKeys(_ context.Context) ([]string, error)          { return nil, nil }

// silence unused (sha256 is used via the file-level import check).
var _ = sha256.Size

// ----- SignStandardJWS (embedded-payload form used by TL checkpoints) -----

// TestSignStandardJWS_RoundTrip covers the happy path for the
// embedded-payload variant. The checkpoint signer uses this form so
// verifiers don't need an out-of-band payload channel.
func TestSignStandardJWS_RoundTrip(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "tl-ckpt")
	payload := map[string]any{"origin": "ans-demo", "size": 42}

	jws, err := anscrypto.SignStandardJWS(
		context.Background(), km, "tl-ckpt",
		anscrypto.JWSProtectedHeader{Typ: "JOSE+JSON"},
		payload,
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Standard form has three non-empty segments.
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("want 3 segments, got %d (%q)", len(parts), jws)
	}
	for i, p := range parts {
		if p == "" {
			t.Errorf("segment %d is empty", i)
		}
	}
}

// TestSignStandardJWS_PreservesExplicitKid covers the branch where the
// caller sets header.Kid directly (the TL checkpoint signer uses the
// opaque keyhash hex rather than the KeyManager's keyID).
func TestSignStandardJWS_PreservesExplicitKid(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	jws, err := anscrypto.SignStandardJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{Kid: "deadbeef"},
		map[string]any{"foo": "bar"},
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Decode the header segment to assert kid survived unchanged.
	parts := strings.Split(jws, ".")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if !strings.Contains(string(headerJSON), `"kid":"deadbeef"`) {
		t.Errorf("header missing explicit kid: %s", headerJSON)
	}
}

// TestSignStandardJWS_KeyNotFound covers the KM lookup failure branch.
func TestSignStandardJWS_KeyNotFound(t *testing.T) {
	t.Parallel()
	empty := newMemKM(t, "")
	_, err := anscrypto.SignStandardJWS(
		context.Background(), empty, "missing",
		anscrypto.JWSProtectedHeader{}, map[string]any{},
	)
	if !errors.Is(err, anscrypto.ErrJWSEncode) {
		t.Errorf("want ErrJWSEncode, got %v", err)
	}
}

// TestSignStandardJWS_PayloadNotJSONMarshalable covers the json.Marshal
// failure path (channels can't be marshaled).
func TestSignStandardJWS_PayloadNotJSONMarshalable(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	_, err := anscrypto.SignStandardJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{},
		make(chan int),
	)
	if !errors.Is(err, anscrypto.ErrJWSEncode) {
		t.Errorf("want ErrJWSEncode, got %v", err)
	}
}

// TestSignStandardJWS_SignFailure covers the km.Sign error path.
func TestSignStandardJWS_SignFailure(t *testing.T) {
	t.Parallel()
	_, err := anscrypto.SignStandardJWS(
		context.Background(), &erroringKM{}, "k",
		anscrypto.JWSProtectedHeader{}, map[string]any{"a": 1},
	)
	if !errors.Is(err, anscrypto.ErrJWSEncode) {
		t.Errorf("want ErrJWSEncode, got %v", err)
	}
}

// ----- OpaqueKeyIDFromHash -----

func TestOpaqueKeyIDFromHash(t *testing.T) {
	t.Parallel()
	cases := map[uint32]string{
		0x00000000: "00000000",
		0x01020304: "01020304",
		0xdeadbeef: "deadbeef",
		0xffffffff: "ffffffff",
	}
	for in, want := range cases {
		if got := anscrypto.OpaqueKeyIDFromHash(in); got != want {
			t.Errorf("OpaqueKeyIDFromHash(%#x) = %q; want %q", in, got, want)
		}
	}
}

// TestVerifyStandardJWS_RoundTrip proves sign-then-verify works for the
// non-detached variant. Used by the checkpoint-read path to set
// `valid: true` on the additional-signer JWS signature.
func TestVerifyStandardJWS_RoundTrip(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "tl-attest")
	payload := map[string]any{
		"origin":    "ans-test",
		"treesize":  42,
		"rootHash":  "VN9ZqUqdHEvETuCuBIT/aLf3ZeFqPyI8UJGoIoxCTI0=",
		"timestamp": int64(1_700_000_000),
	}
	jws, err := anscrypto.SignStandardJWS(context.Background(), km, "tl-attest",
		anscrypto.JWSProtectedHeader{Typ: "JWT", Timestamp: 1_700_000_000}, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub, _ := km.GetPublicKey(context.Background(), "tl-attest")
	hdr, err := anscrypto.VerifyStandardJWSWithPublicKey(pub, jws)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if hdr.Alg != "ES256" {
		t.Errorf("header alg: got %q want ES256", hdr.Alg)
	}
}

// TestVerifyStandardJWS_TamperedPayloadFails mutates the middle
// segment and confirms the verifier rejects it — prevents regressing
// into a verifier that merely re-decodes without actually verifying.
func TestVerifyStandardJWS_TamperedPayloadFails(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	jws, _ := anscrypto.SignStandardJWS(context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, map[string]any{"a": 1})
	parts := strings.Split(jws, ".")
	// Replace the payload segment with a valid but different base64 body.
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"a":2}`))
	tampered := strings.Join(parts, ".")
	pub, _ := km.GetPublicKey(context.Background(), "k")
	if _, err := anscrypto.VerifyStandardJWSWithPublicKey(pub, tampered); err == nil {
		t.Fatal("want verification failure on tampered payload")
	}
}

// TestVerifyStandardJWS_MalformedInputs exercises splitStandardJWS's
// reject paths and the empty-segment guards.
func TestVerifyStandardJWS_MalformedInputs(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	pub, _ := km.GetPublicKey(context.Background(), "k")

	cases := map[string]string{
		"too-many-dots":        "a.b.c.d",
		"not-enough-dots":      "a.b",
		"detached-empty-mid":   "hdr..sig",
		"empty-header":         ".pay.sig",
		"empty-sig":            "hdr.pay.",
		"bad-header-base64":    "not-base64!.cGF5.c2ln",
		"bad-signature-base64": "cGF5.cGF5.not-base64!",
	}
	for name, in := range cases {
		if _, err := anscrypto.VerifyStandardJWSWithPublicKey(pub, in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// TestVerifyStandardJWS_RSA covers the RSA verification path — the
// helper accepts either ECDSA or RSA public keys, matching the two
// algorithms the rest of the crypto package supports.
func TestVerifyStandardJWS_RSA(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	km := &memKM{keys: map[string]crypto.Signer{"k": priv}}
	jws, err := anscrypto.SignStandardJWS(context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{Alg: "RS256"}, map[string]any{"x": 1})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := anscrypto.VerifyStandardJWSWithPublicKey(&priv.PublicKey, jws); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestVerifyStandardJWS_WrongAlgForKey asserts that a header alg
// claiming RSA while the key is ECDSA (or vice versa) is rejected.
func TestVerifyStandardJWS_WrongAlgForKey(t *testing.T) {
	t.Parallel()
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	km := &memKM{keys: map[string]crypto.Signer{"k": ecPriv}}
	jws, _ := anscrypto.SignStandardJWS(context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, map[string]any{"x": 1})
	// Verify against the RSA pubkey — alg/key mismatch path.
	if _, err := anscrypto.VerifyStandardJWSWithPublicKey(&rsaPriv.PublicKey, jws); err == nil {
		t.Fatal("want error on alg/key mismatch")
	}
}

// TestVerifyStandardJWS_UnsupportedKeyType covers the default branch
// in the key-type switch.
func TestVerifyStandardJWS_UnsupportedKeyType(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	jws, _ := anscrypto.SignStandardJWS(context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{}, map[string]any{"x": 1})
	// ed25519 is supported by the sumdb code but not by our JWS helper.
	if _, err := anscrypto.VerifyStandardJWSWithPublicKey("not-a-key", jws); err == nil {
		t.Fatal("want error on unsupported key type")
	}
}
