package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// fakeDirResolver is a controllable port.WebBotAuthDirectoryResolver: it
// returns a fixed key set (or error) and records the URL + hints it was
// asked for, so a test can assert the fetch target and the hint pass-through.
type fakeDirResolver struct {
	keys     []port.DirectoryKey
	err      error
	gotURL   string
	gotHints []port.KeyHint
	calls    int
}

func (f *fakeDirResolver) Resolve(_ context.Context, url string, hints []port.KeyHint) ([]port.DirectoryKey, error) {
	f.calls++
	f.gotURL = url
	f.gotHints = hints
	if f.err != nil {
		return nil, f.err
	}
	return f.keys, nil
}

const wbaSigningInput = "eyJ0ZXN0Ijoid2ViLWJvdC1hdXRoIn0"

func wbaNow() time.Time { return time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC) }

// newWBAIdentity builds a PENDING_CONTROL web-bot-auth identity whose
// EffectiveValue is the canonical well-known directory URL.
func newWBAIdentity(t *testing.T) *domain.VerifiedIdentity {
	t.Helper()
	id, err := domain.NewVerifiedIdentity("id-1", "owner-1", "https://signer.example.com", wbaNow())
	if err != nil {
		t.Fatalf("build identity: %v", err)
	}
	if id.Kind != domain.KindWebBotAuth {
		t.Fatalf("kind = %q, want web-bot-auth", id.Kind)
	}
	return id
}

func newWBAVerifier(f *fakeDirResolver) *webBotAuthVerifier {
	return &webBotAuthVerifier{resolver: f, clock: wbaNow, logger: zerolog.Nop()}
}

// genEd25519JWK returns a fresh Ed25519 keypair, its minimal JWK, and its
// RFC 7638 thumbprint.
func genEd25519JWK(t *testing.T) (ed25519.PrivateKey, json.RawMessage, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := anscrypto.PublicKeyToJWK(pub)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := anscrypto.JWKThumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	return priv, jwk, tp
}

// signEd25519Proof builds a compact EdDSA JWS whose payload segment IS
// the served signingInput verbatim (RFC 8037: EdDSA signs the raw signing
// input, no prehash). alg overrides the header algorithm for alg-pinning
// tests; jwk, when non-nil, is embedded as the header hint.
func signEd25519Proof(t *testing.T, priv ed25519.PrivateKey, alg, kid, signingInput string, jwk json.RawMessage) string {
	t.Helper()
	header := map[string]any{"alg": alg, "kid": kid}
	if jwk != nil {
		header["jwk"] = jwk
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	toSign := encodedHeader + "." + signingInput
	sig := ed25519.Sign(priv, []byte(toSign))
	return toSign + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestWBAVerify_HappyPath: one proven key sealed as a VM object with a
// non-empty id, the directory JWK verbatim, self-verifying (V2, V4, V7,
// V17). The resolver is asked for the canonical well-known URL (V8).
func TestWBAVerify_HappyPath(t *testing.T) {
	t.Parallel()
	priv, jwk, tp := genEd25519JWK(t)
	f := &fakeDirResolver{keys: []port.DirectoryKey{{JWK: jwk}}}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	jws := signEd25519Proof(t, priv, anscrypto.AlgEdDSA, tp, wbaSigningInput, jwk)

	proven, err := v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jws}}, wbaSigningInput)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(proven) != 1 {
		t.Fatalf("proven keys = %d, want 1", len(proven))
	}
	if f.gotURL != id.Value {
		t.Fatalf("fetch target = %q, want canonical value %q", f.gotURL, id.Value)
	}

	var vm struct {
		ID           string          `json:"id"`
		Type         string          `json:"type"`
		PublicKeyJwk json.RawMessage `json:"publicKeyJwk"`
	}
	if err := json.Unmarshal(proven[0].VerificationMethod, &vm); err != nil {
		t.Fatalf("VM not an object: %v", err)
	}
	if want := id.Value + "#" + tp; vm.ID != want {
		t.Fatalf("VM id = %q, want %q", vm.ID, want)
	}
	if vm.Type != "JsonWebKey2020" {
		t.Fatalf("VM type = %q", vm.Type)
	}
	if !bytes.Equal(vm.PublicKeyJwk, jwk) {
		t.Fatalf("sealed jwk not the directory jwk verbatim")
	}
	// Self-verifying: the sealed proof verifies against the sealed key.
	pub, err := anscrypto.ParseJWK(vm.PublicKeyJwk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anscrypto.VerifyStandardJWSWithPublicKey(pub, proven[0].SignedProof); err != nil {
		t.Fatalf("sealed proof does not verify against sealed key: %v", err)
	}
}

// TestWBAVerify_AuthoritativeIsDirectory: the sealed key is the DIRECTORY
// JWK verbatim, NOT the (thumbprint-equal but byte-different) header hint
// (V3). The directory entry carries an extra `use` member the minimal
// header jwk omits; both share the same thumbprint.
func TestWBAVerify_AuthoritativeIsDirectory(t *testing.T) {
	t.Parallel()
	priv, minimalJWK, tp := genEd25519JWK(t)
	// Directory serves the same key with an extra member — byte-different,
	// thumbprint-identical (the thumbprint is over crv/kty/x only).
	var m map[string]json.RawMessage
	if err := json.Unmarshal(minimalJWK, &m); err != nil {
		t.Fatal(err)
	}
	m["use"] = json.RawMessage(`"sig"`)
	dirJWK, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dirJWK, minimalJWK) {
		t.Fatal("directory jwk should differ in bytes from the header hint")
	}

	f := &fakeDirResolver{keys: []port.DirectoryKey{{JWK: dirJWK}}}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	jws := signEd25519Proof(t, priv, anscrypto.AlgEdDSA, tp, wbaSigningInput, minimalJWK)

	proven, err := v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jws}}, wbaSigningInput)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var vm struct {
		PublicKeyJwk json.RawMessage `json:"publicKeyJwk"`
	}
	_ = json.Unmarshal(proven[0].VerificationMethod, &vm)
	if !bytes.Equal(vm.PublicKeyJwk, dirJWK) {
		t.Fatalf("sealed jwk = %s, want the directory bytes %s", vm.PublicKeyJwk, dirJWK)
	}
}

// TestWBAVerify_MultiKey: two directory-endorsed keys, two proofs, both
// sealed (V6, V16).
func TestWBAVerify_MultiKey(t *testing.T) {
	t.Parallel()
	privA, jwkA, tpA := genEd25519JWK(t)
	privB, jwkB, tpB := genEd25519JWK(t)
	f := &fakeDirResolver{keys: []port.DirectoryKey{{JWK: jwkA}, {JWK: jwkB}}}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	jwsA := signEd25519Proof(t, privA, anscrypto.AlgEdDSA, tpA, wbaSigningInput, jwkA)
	jwsB := signEd25519Proof(t, privB, anscrypto.AlgEdDSA, tpB, wbaSigningInput, jwkB)

	proven, err := v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jwsA, jwsB}}, wbaSigningInput)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(proven) != 2 {
		t.Fatalf("proven = %d, want 2", len(proven))
	}
}

// TestWBAVerify_DropsUnmatchedProof: a proof for a key the directory does
// not endorse is DROPPED, not fatal, as long as another proof matches
// (V16 intersection, mid-rotation tolerance).
func TestWBAVerify_DropsUnmatchedProof(t *testing.T) {
	t.Parallel()
	privA, jwkA, tpA := genEd25519JWK(t)
	privB, jwkB, tpB := genEd25519JWK(t)
	// Directory endorses A only.
	f := &fakeDirResolver{keys: []port.DirectoryKey{{JWK: jwkA}}}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	jwsA := signEd25519Proof(t, privA, anscrypto.AlgEdDSA, tpA, wbaSigningInput, jwkA)
	jwsB := signEd25519Proof(t, privB, anscrypto.AlgEdDSA, tpB, wbaSigningInput, jwkB)

	proven, err := v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jwsA, jwsB}}, wbaSigningInput)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(proven) != 1 {
		t.Fatalf("proven = %d, want 1 (B dropped)", len(proven))
	}
}

// TestWBAVerify_NoneMatchedRejected: every proof names a key absent from
// the directory → reject (V16: ≥1 matched required).
func TestWBAVerify_NoneMatchedRejected(t *testing.T) {
	t.Parallel()
	priv, jwk, tp := genEd25519JWK(t)
	f := &fakeDirResolver{keys: nil} // empty directory
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	jws := signEd25519Proof(t, priv, anscrypto.AlgEdDSA, tp, wbaSigningInput, jwk)

	_, err := v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jws}}, wbaSigningInput)
	assertValidationCode(t, err, "IDENTIFIER_PROOF_INVALID")
}

// TestWBAVerify_WindowSkipped: a directory key outside its nbf/exp window
// is skipped, so a proof for it does not match (V16).
func TestWBAVerify_WindowSkipped(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		key  port.DirectoryKey
	}{
		{"not-yet-valid", port.DirectoryKey{NotBefore: wbaNow().Add(time.Hour)}},
		{"expired", port.DirectoryKey{NotAfter: wbaNow().Add(-time.Hour)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, jwk, tp := genEd25519JWK(t)
			key := tc.key
			key.JWK = jwk
			f := &fakeDirResolver{keys: []port.DirectoryKey{key}}
			v := newWBAVerifier(f)
			id := newWBAIdentity(t)
			jws := signEd25519Proof(t, priv, anscrypto.AlgEdDSA, tp, wbaSigningInput, jwk)
			_, err := v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jws}}, wbaSigningInput)
			assertValidationCode(t, err, "IDENTIFIER_PROOF_INVALID")
		})
	}
}

// TestWBAVerify_RejectsNonEdDSAAlg: a matched proof naming any algorithm
// other than EdDSA is rejected (V5 alg-confusion defense).
func TestWBAVerify_RejectsNonEdDSAAlg(t *testing.T) {
	t.Parallel()
	priv, jwk, tp := genEd25519JWK(t)
	f := &fakeDirResolver{keys: []port.DirectoryKey{{JWK: jwk}}}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	// kid matches the directory key, but the header claims ES256.
	jws := signEd25519Proof(t, priv, "ES256", tp, wbaSigningInput, jwk)
	_, err := v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jws}}, wbaSigningInput)
	assertValidationCode(t, err, "IDENTIFIER_PROOF_INVALID")
}

// TestWBAVerify_RejectsNonEd25519DirectoryKey: an EC directory key has no
// RFC 7638 (OKP) thumbprint, so it is never indexed; a proof for it does
// not match and the call rejects (V12).
func TestWBAVerify_RejectsNonEd25519DirectoryKey(t *testing.T) {
	t.Parallel()
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecJWK, err := anscrypto.PublicKeyToJWK(&ecPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDirResolver{keys: []port.DirectoryKey{{JWK: ecJWK}}}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	// The proof itself is a valid Ed25519 JWS, but its kid can never match
	// the un-thumbprintable EC directory entry.
	priv, jwk, tp := genEd25519JWK(t)
	jws := signEd25519Proof(t, priv, anscrypto.AlgEdDSA, tp, wbaSigningInput, jwk)
	_, err = v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jws}}, wbaSigningInput)
	assertValidationCode(t, err, "IDENTIFIER_PROOF_INVALID")
}

// TestWBAVerify_RejectsEmbeddedJWKMismatch: a header jwk hint whose
// thumbprint differs from the kid is rejected (V4/V17 — the hint must be
// the located key).
func TestWBAVerify_RejectsEmbeddedJWKMismatch(t *testing.T) {
	t.Parallel()
	privA, jwkA, tpA := genEd25519JWK(t)
	_, jwkB, _ := genEd25519JWK(t)
	f := &fakeDirResolver{keys: []port.DirectoryKey{{JWK: jwkA}}}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	// kid = A's thumbprint (matches the directory), but the embedded jwk
	// is B — inconsistent.
	jws := signEd25519Proof(t, privA, anscrypto.AlgEdDSA, tpA, wbaSigningInput, jwkB)
	_, err := v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jws}}, wbaSigningInput)
	assertValidationCode(t, err, "IDENTIFIER_PROOF_INVALID")
}

// TestWBAVerify_PayloadMismatchRejected: a proof whose payload segment is
// not the served signingInput is rejected before any signature work (V2).
func TestWBAVerify_PayloadMismatchRejected(t *testing.T) {
	t.Parallel()
	priv, jwk, tp := genEd25519JWK(t)
	f := &fakeDirResolver{keys: []port.DirectoryKey{{JWK: jwk}}}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	jws := signEd25519Proof(t, priv, anscrypto.AlgEdDSA, tp, "a-different-payload", jwk)
	_, err := v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jws}}, wbaSigningInput)
	assertValidationCode(t, err, "PRICC_SIGNATURE_INVALID")
	// The directory is never consulted when the envelope check fails.
	if f.calls != 0 {
		t.Fatalf("directory fetched %d times before payload check", f.calls)
	}
}

// TestWBAVerify_ForgedSignatureRejected: a matched key with a valid
// envelope but a signature made by a different private key fails the
// verify against the directory key (V17).
func TestWBAVerify_ForgedSignatureRejected(t *testing.T) {
	t.Parallel()
	_, jwk, tp := genEd25519JWK(t)
	otherPriv, _, _ := genEd25519JWK(t) // signs with the wrong key
	f := &fakeDirResolver{keys: []port.DirectoryKey{{JWK: jwk}}}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	// kid + embedded jwk name the directory key, but the signature is the
	// other key's — it cannot verify against the directory key.
	jws := signEd25519Proof(t, otherPriv, anscrypto.AlgEdDSA, tp, wbaSigningInput, jwk)
	_, err := v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jws}}, wbaSigningInput)
	assertValidationCode(t, err, "PRICC_SIGNATURE_INVALID")
}

// TestWBAVerify_FetchFailureIsRetryable: a resolver failure propagates as
// a retryable (503-class) error, never a 500 (V8, V15).
func TestWBAVerify_FetchFailureIsRetryable(t *testing.T) {
	t.Parallel()
	priv, jwk, tp := genEd25519JWK(t)
	f := &fakeDirResolver{err: domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE", "down")}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	jws := signEd25519Proof(t, priv, anscrypto.AlgEdDSA, tp, wbaSigningInput, jwk)
	_, err := v.VerifyProofs(context.Background(), id, ProofSubmission{SignedProofs: []string{jws}}, wbaSigningInput)
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("err = %v, want retryable ErrUnavailable", err)
	}
}

// TestWBAChallenges_EnumeratesThumbprints: the advisory fetch enumerates
// the thumbprintable directory keys as offered kids, skipping non-OKP
// entries.
func TestWBAChallenges_EnumeratesThumbprints(t *testing.T) {
	t.Parallel()
	_, jwkA, tpA := genEd25519JWK(t)
	_, jwkB, tpB := genEd25519JWK(t)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecJWK, _ := anscrypto.PublicKeyToJWK(&ecPriv.PublicKey)
	f := &fakeDirResolver{keys: []port.DirectoryKey{{JWK: jwkA}, {JWK: ecJWK}, {JWK: jwkB}}}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)

	ch, err := v.Challenges(context.Background(), id, wbaSigningInput)
	if err != nil {
		t.Fatalf("challenges: %v", err)
	}
	if len(ch) != 2 {
		t.Fatalf("challenges = %d, want 2 (EC skipped)", len(ch))
	}
	got := map[string]bool{ch[0].Kid: true, ch[1].Kid: true}
	if !got[tpA] || !got[tpB] {
		t.Fatalf("challenge kids = %+v, want %s and %s", ch, tpA, tpB)
	}
	for _, c := range ch {
		if c.SigningInput != wbaSigningInput {
			t.Fatalf("challenge signingInput = %q", c.SigningInput)
		}
	}
}

// TestWBAChallenges_ToleratesFetchFailure: an advisory-fetch failure is
// tolerated with a single unkeyed challenge — the register round never
// fails on the directory (V8).
func TestWBAChallenges_ToleratesFetchFailure(t *testing.T) {
	t.Parallel()
	f := &fakeDirResolver{err: domain.NewUnavailableError("WBA_DIRECTORY_UNAVAILABLE", "down")}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	ch, err := v.Challenges(context.Background(), id, wbaSigningInput)
	if err != nil {
		t.Fatalf("challenges should tolerate fetch failure, got %v", err)
	}
	if len(ch) != 1 || ch[0].Kid != "" || ch[0].SigningInput != wbaSigningInput {
		t.Fatalf("want a single unkeyed challenge, got %+v", ch)
	}
}

// TestWBAChallenges_NoKeysUnkeyed: a reachable-but-empty directory yields
// a single unkeyed challenge.
func TestWBAChallenges_NoKeysUnkeyed(t *testing.T) {
	t.Parallel()
	f := &fakeDirResolver{keys: nil}
	v := newWBAVerifier(f)
	id := newWBAIdentity(t)
	ch, err := v.Challenges(context.Background(), id, wbaSigningInput)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch) != 1 || ch[0].Kid != "" {
		t.Fatalf("want a single unkeyed challenge, got %+v", ch)
	}
}

// assertValidationCode asserts err is a domain validation error carrying
// the given code.
func assertValidationCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", code)
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error %v is not a *domain.Error", err)
	}
	if de.Code != code {
		t.Fatalf("error code = %q, want %q", de.Code, code)
	}
}
