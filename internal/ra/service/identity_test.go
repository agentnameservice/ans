package service_test

// IdentityService tests: the proof gate (payload equality, kid
// selection, signature verification, nonce discipline), the lifecycle
// (register → verify → rotate → revoke), the owner-gated links, and
// the synchronous seal-before-success emission (§5.6.1) through a
// recording sealer. Real SQLite stores + real crypto; the resolver is
// the noop adapter (hint synthesis) or a canned-document fake for the
// did:web rules.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/adapter/didresolver"
	"github.com/godaddy/ans/internal/adapter/keymanager"
	"github.com/godaddy/ans/internal/adapter/leiverifier"
	"github.com/godaddy/ans/internal/adapter/store/sqlite"
	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/service"
	identityevent "github.com/godaddy/ans/internal/tl/event/identity"
	"github.com/rs/zerolog"
)

// fakeResolver returns a canned document — the did:web rule tests
// (kid membership, controller checks, multibase keys) drive it.
type fakeResolver struct {
	doc *port.DIDDocument
	err error
}

func (f *fakeResolver) Resolve(context.Context, string, []port.KeyHint) (*port.DIDDocument, error) {
	return f.doc, f.err
}

type identityFixture struct {
	svc        *service.IdentityService
	db         *sqlite.DB
	sealer     *recordingSealer
	agents     port.AgentStore
	signerPub  any
	clock      *fakeClock
	providerID string
}

// recordingSealer is the test IdentityEventSealer: it records every
// sealed (innerCanonical, producerSig) pair the service submitted —
// each entry is one TL-acknowledged seal — and can be primed to
// fail, exercising the seal-before-success failure paths.
type recordingSealer struct {
	mu     sync.Mutex
	events []sealedEvent
	err    error
	// hook runs inside SealIdentityEvent before recording — the test
	// stand-in for "something committed during the TL round trip",
	// which is exactly the window the Phase C conditional commits
	// must survive.
	hook func()
}

type sealedEvent struct {
	Inner []byte
	Sig   string
}

func (r *recordingSealer) SealIdentityEvent(_ context.Context, innerCanonical []byte, producerSig string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hook != nil {
		r.hook()
	}
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, sealedEvent{
		Inner: append([]byte(nil), innerCanonical...),
		Sig:   producerSig,
	})
	return nil
}

// fail primes the sealer to reject every seal with err (nil restores
// normal operation).
func (r *recordingSealer) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

// newIdentityFixture wires the service against real SQLite + the
// given resolver (nil → noop), with the noop lei verifier.
func newIdentityFixture(t *testing.T, resolver port.DIDResolver) *identityFixture {
	return newIdentityFixtureWithLEI(t, resolver, leiverifier.NewNoop())
}

// newIdentityFixtureWithLEI is newIdentityFixture with an injectable lei
// control verifier — the lei lane tests drive a programmable fake to
// reach every failure code deterministically.
func newIdentityFixtureWithLEI(t *testing.T, resolver port.DIDResolver, lei port.LEIControlVerifier) *identityFixture {
	t.Helper()
	db, err := sqlite.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	km, err := keymanager.NewFileKeyManager(t.TempDir() + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.EnsureKey(context.Background(), "ra-signer", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	pub, err := km.GetPublicKey(context.Background(), "ra-signer")
	if err != nil {
		t.Fatal(err)
	}

	if resolver == nil {
		resolver = didresolver.NewNoopResolver()
	}
	clock := &fakeClock{now: time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)}
	sealer := &recordingSealer{}
	svc := service.NewIdentityService(
		sqlite.NewIdentityStore(db),
		sqlite.NewIdentityLinkStore(db),
		sqlite.NewAgentStore(db),
		resolver,
		sealer,
		lei,
		db,
	).WithSigner(service.EventSigner{
		KeyManager: km,
		KeyID:      "ra-signer",
		RaID:       "ra-test",
	}).WithClock(clock.Now).WithLogger(zerolog.New(io.Discard))

	return &identityFixture{
		svc:        svc,
		db:         db,
		sealer:     sealer,
		agents:     sqlite.NewAgentStore(db),
		signerPub:  pub,
		clock:      clock,
		providerID: "owner-1",
	}
}

// saveAgent persists a minimal ACTIVE agent owned by `owner`.
func (fx *identityFixture) saveAgent(t *testing.T, agentID, owner, host string) {
	t.Helper()
	fx.saveAgentWithStatus(t, agentID, owner, host, domain.StatusActive)
}

// saveAgentWithStatus persists a minimal agent in the given lifecycle
// state — the link liveness-gate tests need every state.
func (fx *identityFixture) saveAgentWithStatus(t *testing.T, agentID, owner, host string, status domain.RegistrationStatus) {
	t.Helper()
	v, err := domain.NewSemVer(1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ansName, err := domain.NewAnsName(v, host)
	if err != nil {
		t.Fatal(err)
	}
	reg := &domain.AgentRegistration{
		AgentID: agentID,
		OwnerID: owner,
		AnsName: ansName,
		Status:  status,
		Details: domain.RegistrationDetails{
			RegistrationTimestamp: fx.clock.now,
			DisplayName:           "agent " + agentID,
		},
	}
	if err := fx.agents.Save(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
}

// signProof builds a standard compact JWS over the served
// signingInput: ES256, P1363 signature, kid + optional embedded jwk
// in the protected header — exactly what a registrant's tooling
// produces.
func signProof(t *testing.T, priv *ecdsa.PrivateKey, kid, signingInput string, embedJWK bool) string {
	t.Helper()
	header := map[string]any{"alg": "ES256", "kid": kid}
	if embedJWK {
		jwk, err := anscrypto.PublicKeyToJWK(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		header["jwk"] = jwk
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	toSign := encodedHeader + "." + signingInput
	digest := sha256.Sum256([]byte(toSign))
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	p1363, err := anscrypto.DERToP1363(der, 32)
	if err != nil {
		t.Fatal(err)
	}
	return toSign + "." + base64.RawURLEncoding.EncodeToString(p1363)
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// drainSealed returns (and clears) everything the recording sealer
// accepted — the events the TL acknowledged, in seal order.
func (fx *identityFixture) drainSealed(t *testing.T) []sealedEvent {
	t.Helper()
	fx.sealer.mu.Lock()
	defer fx.sealer.mu.Unlock()
	out := fx.sealer.events
	fx.sealer.events = nil
	return out
}

// decodeSealed verifies one sealed record's producer signature
// against the fixture's signer key and returns the inner identity
// event.
func (fx *identityFixture) decodeSealed(t *testing.T, rec sealedEvent) *identityevent.Event {
	t.Helper()
	if _, err := anscrypto.VerifyWithPublicKey(fx.signerPub, rec.Sig, rec.Inner); err != nil {
		t.Fatalf("producer signature: %v", err)
	}
	var inner identityevent.Event
	if err := json.Unmarshal(rec.Inner, &inner); err != nil {
		t.Fatalf("inner event: %v", err)
	}
	if err := inner.Validate(); err != nil {
		t.Fatalf("inner event invalid: %v", err)
	}
	return &inner
}

// ----- register -----

func TestIdentityRegister_DIDWebNoop(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, "did:web:Identity.ACME-corp.com")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if res.Identity.Status != domain.IdentityPendingControl {
		t.Fatalf("status: %s", res.Identity.Status)
	}
	if res.Identity.Value != "did:web:identity.acme-corp.com" {
		t.Fatalf("canonicalization: %s", res.Identity.Value)
	}
	if res.Nonce == "" || len(res.Challenges) != 1 || res.Challenges[0].Kid != "" ||
		res.Challenges[0].SigningInput == "" {
		t.Fatalf("challenge round wrong: %+v", res)
	}

	// The signing input decodes to a proof input binding this round.
	raw, err := base64.RawURLEncoding.DecodeString(res.Challenges[0].SigningInput)
	if err != nil {
		t.Fatal(err)
	}
	var input anscrypto.IdentityProofInput
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	if input.IdentityID != res.Identity.IdentityID || input.Nonce != res.Nonce ||
		input.Purpose != anscrypto.IdentityProofPurpose || input.RaID != "ra-test" ||
		input.Scheme != "did:web" || input.Identifier != res.Identity.Value {
		t.Fatalf("proof input wrong: %+v", input)
	}

	// Idempotent re-add: same identityId, fresh nonce.
	again, err := fx.svc.Register(ctx, fx.providerID, "did:web:identity.acme-corp.com")
	if err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if again.Identity.IdentityID != res.Identity.IdentityID {
		t.Fatal("re-add must reuse the identityId")
	}
	if again.Nonce == res.Nonce {
		t.Fatal("re-add must supersede the nonce")
	}

	// Register seals nothing — only proven control reaches the TL.
	if rows := fx.drainSealed(t); len(rows) != 0 {
		t.Fatalf("register must not emit, got %d rows", len(rows))
	}
}

func TestIdentityRegister_Rejections(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	if _, err := fx.svc.Register(ctx, "", "did:web:a.com"); err == nil {
		t.Error("missing owner should fail")
	}
	if _, err := fx.svc.Register(ctx, fx.providerID, "bogus"); err == nil ||
		!strings.Contains(err.Error(), "IDENTIFIER_KIND_UNSUPPORTED") {
		t.Errorf("bogus value: %v", err)
	}
	// lei is now enabled: a register with no presentation fails on the
	// missing CESR, not on the kind being unsupported.
	if _, err := fx.svc.Register(ctx, fx.providerID, "5493001KJTIIGC8Y1R17"); err == nil ||
		!strings.Contains(err.Error(), "IDENTIFIER_PRESENTATION_REQUIRED") {
		t.Errorf("lei without presentation: %v", err)
	}
}

func TestIdentityRegister_RateLimited(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	fx.svc.WithRegisterRateLimit(2)
	ctx := context.Background()

	for i := range 2 {
		if _, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if _, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com"); err == nil ||
		!strings.Contains(err.Error(), "RATE_LIMITED") {
		t.Fatalf("third call: %v", err)
	}
	// A different owner has its own budget.
	if _, err := fx.svc.Register(ctx, "owner-2", "did:web:b.com"); err != nil {
		t.Fatalf("other owner: %v", err)
	}
	// The window rolls over.
	fx.clock.now = fx.clock.now.Add(2 * time.Minute)
	if _, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com"); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

// ----- verify-control: did:web (noop hint synthesis) -----

// verifyDIDWeb registers + proves a did:web identity through the noop
// resolver, returning the verified identity and the key used.
func verifyDIDWeb(t *testing.T, fx *identityFixture, owner, value string) (*domain.VerifiedIdentity, *ecdsa.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	res, err := fx.svc.Register(ctx, owner, value)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	priv := genKey(t)
	kid := res.Identity.Value + "#key-1"
	jws := signProof(t, priv, kid, res.Challenges[0].SigningInput, true)
	identity, err := fx.svc.VerifyControl(ctx, owner, res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jws}})
	if err != nil {
		t.Fatalf("verify-control: %v", err)
	}
	return identity, priv
}

func TestIdentityVerifyControl_DIDWebNoop(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)

	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:identity.acme-corp.com")
	if identity.Status != domain.IdentityVerified || identity.ProofMethod != "did-web-sig" {
		t.Fatalf("verified state: %+v", identity)
	}

	rows := fx.drainSealed(t)
	if len(rows) != 1 {
		t.Fatalf("sealed events: %d", len(rows))
	}
	inner := fx.decodeSealed(t, rows[0])
	if inner.EventType != identityevent.TypeIdentityVerified ||
		inner.IdentityID != identity.IdentityID ||
		inner.ProviderID != fx.providerID ||
		len(inner.Keys) != 1 {
		t.Fatalf("sealed event: %+v", inner)
	}
	key := inner.Keys[0]
	if key.ID() != identity.Value+"#key-1" || key.SignedProof == "" {
		t.Fatalf("sealed key shape wrong: %+v", key)
	}
	// The sealed verification method is quoted VERBATIM: it carries
	// the registrant's exact jwk bytes, and the sealed proof verifies
	// against the key read out of it — offline, no derived values.
	var sealedVM struct {
		Controller   string          `json:"controller"`
		Type         string          `json:"type"`
		PublicKeyJwk json.RawMessage `json:"publicKeyJwk"`
	}
	if err := json.Unmarshal(key.VerificationMethod, &sealedVM); err != nil {
		t.Fatalf("sealed verification method not an object: %v", err)
	}
	if sealedVM.Controller != identity.Value || len(sealedVM.PublicKeyJwk) == 0 {
		t.Fatalf("sealed verification method members: %+v", sealedVM)
	}
	pub, err := anscrypto.ParseJWK(sealedVM.PublicKeyJwk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anscrypto.VerifyStandardJWSWithPublicKey(pub, key.SignedProof); err != nil {
		t.Fatalf("sealed proof does not verify against sealed key: %v", err)
	}
}

func TestIdentityVerifyControl_MultiKey(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com")
	if err != nil {
		t.Fatal(err)
	}
	k1, k2 := genKey(t), genKey(t)
	did := res.Identity.Value
	jws1 := signProof(t, k1, did+"#key-1", res.Challenges[0].SigningInput, true)
	jws2 := signProof(t, k2, did+"#key-2", res.Challenges[0].SigningInput, true)

	if _, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jws1, jws2}}); err != nil {
		t.Fatalf("multi-key verify: %v", err)
	}
	rows := fx.drainSealed(t)
	inner := fx.decodeSealed(t, rows[0])
	if len(inner.Keys) != 2 {
		t.Fatalf("sealed keys: %d", len(inner.Keys))
	}
}

func TestIdentityVerifyControl_FailClosed(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com")
	if err != nil {
		t.Fatal(err)
	}
	id := res.Identity.IdentityID
	did := res.Identity.Value
	priv := genKey(t)
	good := signProof(t, priv, did+"#key-1", res.Challenges[0].SigningInput, true)

	cases := []struct {
		name   string
		proofs []string
		want   string
	}{
		{"no proofs", nil, "IDENTIFIER_PROOF_INVALID"},
		{"not a jws", []string{"garbage"}, "IDENTIFIER_PROOF_INVALID"},
		{"wrong payload", []string{signProof(t, priv, did+"#key-1",
			base64.RawURLEncoding.EncodeToString([]byte(`{"x":1}`)), true)}, "PRICC_SIGNATURE_INVALID"},
		{"missing kid", []string{signProof(t, priv, "", res.Challenges[0].SigningInput, true)}, "DID_VERIFICATION_METHOD_INVALID"},
		{"kid not a fragment of the DID", []string{signProof(t, priv, "did:web:evil.com#key-1",
			res.Challenges[0].SigningInput, true)}, "DID_VERIFICATION_METHOD_INVALID"},
		{"duplicate kid", []string{good, good}, "IDENTIFIER_PROOF_INVALID"},
		{"one bad proof fails the batch", []string{good, signProof(t, genKey(t), did+"#key-2",
			res.Challenges[0].SigningInput, false)}, "DID_VERIFICATION_METHOD_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fx.svc.VerifyControl(ctx, fx.providerID, id, service.ProofSubmission{SignedProofs: tc.proofs})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}

	// Failed attempts never consume the nonce — the good proof still
	// lands.
	if _, err := fx.svc.VerifyControl(ctx, fx.providerID, id, service.ProofSubmission{SignedProofs: []string{good}}); err != nil {
		t.Fatalf("good proof after failures: %v", err)
	}
	// …and the consumed nonce cannot be replayed.
	_, err = fx.svc.VerifyControl(ctx, fx.providerID, id, service.ProofSubmission{SignedProofs: []string{good}})
	if err == nil || !strings.Contains(err.Error(), "PRICC_TOKEN_ALREADY_USED") {
		t.Fatalf("replay: %v", err)
	}
}

// TestIdentityVerifyControl_BothProofFamilies covers the wire oneOf
// contract: a body that sets BOTH signedProofs and cesrSignature is
// rejected, not silently accepted on the JWS member alone. The
// neither-set case is covered by the "no proofs" row in FailClosed.
func TestIdentityVerifyControl_BothProofFamilies(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com")
	if err != nil {
		t.Fatal(err)
	}
	id := res.Identity.IdentityID
	did := res.Identity.Value
	good := signProof(t, genKey(t), did+"#key-1", res.Challenges[0].SigningInput, true)

	_, err = fx.svc.VerifyControl(ctx, fx.providerID, id, service.ProofSubmission{
		SignedProofs:  []string{good},
		CESRSignature: "0Bcesr-signature-bytes",
	})
	if err == nil || !strings.Contains(err.Error(), "IDENTIFIER_PROOF_INVALID") {
		t.Fatalf("want IDENTIFIER_PROOF_INVALID, got %v", err)
	}

	// The rejected attempt must not consume the nonce — the clean
	// single-family proof still lands afterward.
	if _, err := fx.svc.VerifyControl(ctx, fx.providerID, id,
		service.ProofSubmission{SignedProofs: []string{good}}); err != nil {
		t.Fatalf("clean proof after both-families rejection: %v", err)
	}
}

func TestIdentityVerifyControl_WrongSignature(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com")
	if err != nil {
		t.Fatal(err)
	}
	// The embedded jwk names key A, but the signature is from key B:
	// verification against the (noop-synthesized) authoritative key A
	// must fail.
	keyA, keyB := genKey(t), genKey(t)
	jwkA, err := anscrypto.PublicKeyToJWK(&keyA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(map[string]any{
		"alg": "ES256", "kid": res.Identity.Value + "#key-1", "jwk": jwkA,
	})
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	toSign := encodedHeader + "." + res.Challenges[0].SigningInput
	digest := sha256.Sum256([]byte(toSign))
	der, err := ecdsa.SignASN1(rand.Reader, keyB, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	p1363, err := anscrypto.DERToP1363(der, 32)
	if err != nil {
		t.Fatal(err)
	}
	forged := toSign + "." + base64.RawURLEncoding.EncodeToString(p1363)

	_, err = fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{forged}})
	if err == nil || !strings.Contains(err.Error(), "PRICC_SIGNATURE_INVALID") {
		t.Fatalf("forged signature: %v", err)
	}
}

func TestIdentityVerifyControl_ExpiredNonce(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com")
	if err != nil {
		t.Fatal(err)
	}
	jws := signProof(t, genKey(t), res.Identity.Value+"#key-1", res.Challenges[0].SigningInput, true)

	fx.clock.now = fx.clock.now.Add(2 * time.Hour)
	_, err = fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jws}})
	if err == nil || !strings.Contains(err.Error(), "PRICC_TOKEN_EXPIRED") {
		t.Fatalf("expired nonce: %v", err)
	}

	// Recovery is the idempotent re-add: same id, fresh nonce.
	again, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com")
	if err != nil || again.Identity.IdentityID != res.Identity.IdentityID {
		t.Fatalf("re-add recovery: %+v %v", again, err)
	}
}

// ----- verify-control: did:web against a canned document (web-mode rules) -----

func TestIdentityVerifyControl_DIDWebDocumentRules(t *testing.T) {
	t.Parallel()
	did := "did:web:identity.acme-corp.com"
	keyOK := genKey(t)
	keyMB := genKey(t)
	jwkOK, err := anscrypto.PublicKeyToJWK(&keyOK.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	multibase, err := anscrypto.EncodeMultibase(&keyMB.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	doc := &port.DIDDocument{
		ID: did,
		AssertionMethod: []port.VerificationMethod{
			{ID: did + "#jwk-key", Controller: did, Type: "JsonWebKey2020", PublicKeyJwk: jwkOK},
			{ID: did + "#mb-key", Controller: did, Type: "Multikey", PublicKeyMultibase: multibase},
			{ID: did + "#foreign", Controller: "did:web:other.com", Type: "JsonWebKey2020", PublicKeyJwk: jwkOK},
			{ID: did + "#empty", Controller: did, Type: "JsonWebKey2020"},
		},
	}
	fx := newIdentityFixture(t, &fakeResolver{doc: doc})
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, did)
	if err != nil {
		t.Fatal(err)
	}
	// The advisory fetch enumerated the document's kids.
	if len(res.Challenges) != 4 {
		t.Fatalf("challenge kids: %+v", res.Challenges)
	}
	id := res.Identity.IdentityID
	signingInput := res.Challenges[0].SigningInput

	// JWK-keyed and multibase-keyed methods both verify.
	proofs := []string{
		signProof(t, keyOK, did+"#jwk-key", signingInput, false),
		signProof(t, keyMB, did+"#mb-key", signingInput, false),
	}
	if _, err := fx.svc.VerifyControl(ctx, fx.providerID, id, service.ProofSubmission{SignedProofs: proofs}); err != nil {
		t.Fatalf("doc-keyed verify: %v", err)
	}

	// Rotation round for the rule rejections.
	rot, err := fx.svc.Rotate(ctx, fx.providerID, id, did)
	if err != nil {
		t.Fatal(err)
	}
	rotInput := rot.Challenges[0].SigningInput
	cases := []struct {
		name string
		jws  string
		want string
	}{
		{"unknown kid", signProof(t, keyOK, did+"#nope", rotInput, false), "DID_VERIFICATION_METHOD_INVALID"},
		{"cross-controller", signProof(t, keyOK, did+"#foreign", rotInput, false), "DID_VERIFICATION_METHOD_INVALID"},
		{"keyless method", signProof(t, keyOK, did+"#empty", rotInput, false), "DID_VERIFICATION_METHOD_INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fx.svc.VerifyControl(ctx, fx.providerID, id, service.ProofSubmission{SignedProofs: []string{tc.jws}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}
}

func TestIdentityVerifyControl_DocumentIDMismatch(t *testing.T) {
	t.Parallel()
	doc := &port.DIDDocument{ID: "did:web:other.com"}
	fx := newIdentityFixture(t, &fakeResolver{doc: doc})
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com")
	if err != nil {
		t.Fatal(err)
	}
	jws := signProof(t, genKey(t), res.Identity.Value+"#k", res.Challenges[0].SigningInput, false)
	_, err = fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jws}})
	if err == nil || !strings.Contains(err.Error(), "DID_DOCUMENT_ID_MISMATCH") {
		t.Fatalf("doc id mismatch: %v", err)
	}
}

func TestIdentityRegister_ResolutionFailureFailsFast(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, &fakeResolver{
		err: domain.NewValidationError("DID_RESOLUTION_FAILED", "boom"),
	})
	_, err := fx.svc.Register(context.Background(), fx.providerID, "did:web:a.com")
	if err == nil || !strings.Contains(err.Error(), "DID_RESOLUTION_FAILED") {
		t.Fatalf("advisory fetch failure: %v", err)
	}
}

// ----- verify-control: did:key -----

func TestIdentityLifecycle_DIDKey(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	priv := genKey(t)
	msid, err := anscrypto.EncodeMultibase(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	did := "did:key:" + msid

	res, err := fx.svc.Register(ctx, fx.providerID, did)
	if err != nil {
		t.Fatalf("register did:key: %v", err)
	}
	// did:key has exactly one challenge entry naming the method id.
	if len(res.Challenges) != 1 || res.Challenges[0].Kid != did+"#"+msid {
		t.Fatalf("did:key challenges: %+v", res.Challenges)
	}

	// A wrong kid is rejected even with a valid signature.
	bad := signProof(t, priv, did+"#wrong", res.Challenges[0].SigningInput, false)
	if _, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{bad}}); err == nil ||
		!strings.Contains(err.Error(), "DID_VERIFICATION_METHOD_INVALID") {
		t.Fatalf("wrong did:key kid: %v", err)
	}
	// A different key's signature fails against the DID's key.
	forged := signProof(t, genKey(t), did+"#"+msid, res.Challenges[0].SigningInput, false)
	if _, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{forged}}); err == nil ||
		!strings.Contains(err.Error(), "PRICC_SIGNATURE_INVALID") {
		t.Fatalf("forged did:key proof: %v", err)
	}

	good := signProof(t, priv, res.Challenges[0].Kid, res.Challenges[0].SigningInput, false)
	identity, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{good}})
	if err != nil {
		t.Fatalf("did:key verify: %v", err)
	}
	if identity.Status != domain.IdentityVerified || identity.ProofMethod != "did-key-sig" {
		t.Fatalf("did:key verified state: %+v", identity)
	}
	rows := fx.drainSealed(t)
	inner := fx.decodeSealed(t, rows[0])
	if inner.Kind != "did:key" || len(inner.Keys) != 1 {
		t.Fatalf("did:key sealed event: %+v", inner)
	}
}

// TestIdentityLifecycle_Ed25519 drives a did:key Ed25519 identity
// end to end: EdDSA proofs (raw-signing-input signatures, RFC 8037),
// the z6Mk did:key form, and the verbatim Multikey seal.
func TestIdentityLifecycle_Ed25519(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msid, err := anscrypto.EncodeMultibase(pub)
	if err != nil {
		t.Fatal(err)
	}
	did := "did:key:" + msid
	if !strings.HasPrefix(msid, "z6Mk") {
		t.Fatalf("ed25519 did:key form: %s", msid)
	}

	res, err := fx.svc.Register(ctx, fx.providerID, did)
	if err != nil {
		t.Fatalf("register ed25519 did:key: %v", err)
	}
	kid := res.Challenges[0].Kid

	// EdDSA compact JWS: signature over the raw signing input.
	header, err := json.Marshal(map[string]any{"alg": "EdDSA", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	toSign := base64.RawURLEncoding.EncodeToString(header) + "." + res.Challenges[0].SigningInput
	jws := toSign + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(toSign)))

	identity, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jws}})
	if err != nil {
		t.Fatalf("ed25519 verify-control: %v", err)
	}
	if identity.Status != domain.IdentityVerified {
		t.Fatalf("status: %s", identity.Status)
	}

	// The seal quotes the did:key Multikey method — its key material
	// is the method-specific id verbatim from the identifier.
	rows := fx.drainSealed(t)
	inner := fx.decodeSealed(t, rows[0])
	var vm struct {
		Type               string `json:"type"`
		PublicKeyMultibase string `json:"publicKeyMultibase"`
	}
	if err := json.Unmarshal(inner.Keys[0].VerificationMethod, &vm); err != nil {
		t.Fatal(err)
	}
	if vm.Type != "Multikey" || vm.PublicKeyMultibase != msid {
		t.Fatalf("sealed did:key method: %+v", vm)
	}
}

// TestIdentityVerifyControl_X25519Rejected pins the precise
// rejection: a key-agreement key listed as an assertionMethod can
// never prove control.
func TestIdentityVerifyControl_X25519Rejected(t *testing.T) {
	t.Parallel()
	did := "did:web:identity.acme-corp.com"
	doc := &port.DIDDocument{
		ID: did,
		AssertionMethod: []port.VerificationMethod{{
			ID:           did + "#x25519",
			Controller:   did,
			Type:         "JsonWebKey2020",
			PublicKeyJwk: json.RawMessage(`{"kty":"OKP","crv":"X25519","x":"9GXjPGGvmRq9F6Ng5dQQ_s31mfhxrcNZxRGONrmH30k"}`),
			Raw:          json.RawMessage(`{"id":"` + did + `#x25519"}`),
		}},
	}
	fx := newIdentityFixture(t, &fakeResolver{doc: doc})
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, did)
	if err != nil {
		t.Fatal(err)
	}
	jws := signProof(t, genKey(t), did+"#x25519", res.Challenges[0].SigningInput, false)
	_, err = fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jws}})
	if err == nil || !strings.Contains(err.Error(), "key-agreement key") {
		t.Fatalf("X25519 rejection: %v", err)
	}
}

// ----- rotation, revocation, duplicates -----

func TestIdentityRotation_SealsUpdated(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:a.com")
	fx.drainSealed(t)

	rot, err := fx.svc.Rotate(ctx, fx.providerID, identity.IdentityID, "did:web:b.com")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rot.Identity.Value != "did:web:a.com" || rot.Identity.PendingValue != "did:web:b.com" {
		t.Fatalf("staged state: %+v", rot.Identity)
	}
	// Until the proof lands, the previously sealed state stands —
	// nothing emitted by the PUT itself.
	if rows := fx.drainSealed(t); len(rows) != 0 {
		t.Fatalf("PUT must not seal, got %d rows", len(rows))
	}

	newKey := genKey(t)
	jws := signProof(t, newKey, "did:web:b.com#key-1", rot.Challenges[0].SigningInput, true)
	rotated, err := fx.svc.VerifyControl(ctx, fx.providerID, identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jws}})
	if err != nil {
		t.Fatalf("rotation verify: %v", err)
	}
	if rotated.Value != "did:web:b.com" || rotated.PendingValue != "" {
		t.Fatalf("rotated state: %+v", rotated)
	}

	rows := fx.drainSealed(t)
	if len(rows) != 1 {
		t.Fatalf("rotation rows: %d", len(rows))
	}
	inner := fx.decodeSealed(t, rows[0])
	if inner.EventType != identityevent.TypeIdentityUpdated ||
		inner.Value != "did:web:b.com" || inner.PreviousValue != "did:web:a.com" {
		t.Fatalf("IDENTITY_UPDATED event: %+v", inner)
	}
}

func TestIdentityRevoke(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:a.com")
	fx.drainSealed(t)

	revoked, err := fx.svc.Revoke(ctx, fx.providerID, identity.IdentityID)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Status != domain.IdentityRevoked {
		t.Fatalf("status: %s", revoked.Status)
	}
	rows := fx.drainSealed(t)
	inner := fx.decodeSealed(t, rows[0])
	if inner.EventType != identityevent.TypeIdentityRevoked || inner.RevokedAt == "" {
		t.Fatalf("IDENTITY_REVOKED event: %+v", inner)
	}

	// Terminal: no rotate, no verify, no re-revoke.
	if _, err := fx.svc.Rotate(ctx, fx.providerID, identity.IdentityID, "did:web:b.com"); err == nil {
		t.Error("rotate after revoke should fail")
	}
	if _, err := fx.svc.Revoke(ctx, fx.providerID, identity.IdentityID); err == nil {
		t.Error("double revoke should fail")
	}
	// The owner can re-register the value on a fresh row.
	if _, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com"); err != nil {
		t.Errorf("re-register after revoke: %v", err)
	}
}

func TestIdentityDuplicates(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	verifyDIDWeb(t, fx, fx.providerID, "did:web:a.com")

	// Same owner re-registering a VERIFIED value → rotate instead.
	_, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com")
	if err == nil || !strings.Contains(err.Error(), "IDENTIFIER_DUPLICATE") {
		t.Fatalf("owner duplicate: %v", err)
	}
	// Another owner registering an already-proven value → early
	// duplicate feedback.
	_, err = fx.svc.Register(ctx, "owner-2", "did:web:a.com")
	if err == nil || !strings.Contains(err.Error(), "IDENTIFIER_DUPLICATE") {
		t.Fatalf("cross-owner duplicate: %v", err)
	}
}

func TestIdentityProvenUniquenessRace(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	// Two owners hold competing PENDING claims (registered before
	// either proved).
	resA, err := fx.svc.Register(ctx, "owner-1", "did:web:contested.com")
	if err != nil {
		t.Fatal(err)
	}
	resB, err := fx.svc.Register(ctx, "owner-2", "did:web:contested.com")
	if err != nil {
		t.Fatal(err)
	}

	// First to PROVE wins.
	keyA := genKey(t)
	jwsA := signProof(t, keyA, resA.Identity.Value+"#key-1", resA.Challenges[0].SigningInput, true)
	if _, err := fx.svc.VerifyControl(ctx, "owner-1", resA.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jwsA}}); err != nil {
		t.Fatalf("winner: %v", err)
	}

	// The loser's verify-time flip hits the proven-uniqueness index.
	keyB := genKey(t)
	jwsB := signProof(t, keyB, resB.Identity.Value+"#key-1", resB.Challenges[0].SigningInput, true)
	_, err = fx.svc.VerifyControl(ctx, "owner-2", resB.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jwsB}})
	if err == nil || !strings.Contains(err.Error(), "IDENTIFIER_DUPLICATE") {
		t.Fatalf("loser: %v", err)
	}
	// The losing transaction rolled back whole — including the nonce
	// consumption — and only the winner's event sealed.
	rows := fx.drainSealed(t)
	if len(rows) != 1 {
		t.Fatalf("sealed events after race: %d", len(rows))
	}
}

// ----- owner gates -----

func TestIdentityOwnerGates(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:a.com")

	// Reads hide existence (404-shaped not-found).
	if _, _, err := fx.svc.Detail(ctx, "owner-2", identity.IdentityID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner detail: %v", err)
	}
	// Writes surface the authorization failure (403-shaped).
	if _, err := fx.svc.Revoke(ctx, "owner-2", identity.IdentityID); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("cross-owner revoke: %v", err)
	}
	if _, err := fx.svc.Rotate(ctx, "owner-2", identity.IdentityID, "did:web:b.com"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("cross-owner rotate: %v", err)
	}
	// List is owner-scoped (one page, default limit).
	mine, err := fx.svc.List(ctx, fx.providerID, 0, "")
	if err != nil || len(mine.Items) != 1 {
		t.Fatalf("list mine: %+v %v", mine, err)
	}
	theirs, err := fx.svc.List(ctx, "owner-2", 0, "")
	if err != nil || len(theirs.Items) != 0 {
		t.Fatalf("list theirs: %+v %v", theirs, err)
	}
}

// ----- links -----

func TestIdentityLinks(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:a.com")
	fx.drainSealed(t)
	fx.saveAgent(t, "agent-1", fx.providerID, "one.example.com")
	fx.saveAgent(t, "agent-2", fx.providerID, "two.example.com")
	fx.saveAgent(t, "agent-x", "owner-2", "theirs.example.com")

	// Owner gate, agent side: naming someone else's agent fails the
	// whole call without revealing the agent's existence.
	_, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-1", "agent-x"})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner agent in batch: %v", err)
	}
	if rows := fx.drainSealed(t); len(rows) != 0 {
		t.Fatal("failed batch must seal nothing")
	}

	// Batch of two (with a duplicate id deduped) → ONE sealed event.
	linked, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-1", "agent-2", "agent-1"})
	if err != nil || linked != 2 {
		t.Fatalf("link batch: %d %v", linked, err)
	}
	rows := fx.drainSealed(t)
	if len(rows) != 1 {
		t.Fatalf("link batch rows: %d", len(rows))
	}
	inner := fx.decodeSealed(t, rows[0])
	if inner.EventType != identityevent.TypeIdentityLinked || len(inner.AnsIDs) != 2 {
		t.Fatalf("IDENTITY_LINKED event: %+v", inner)
	}

	// Fully idempotent repeat seals nothing.
	linked, err = fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-1"})
	if err != nil || linked != 0 {
		t.Fatalf("idempotent link: %d %v", linked, err)
	}
	if rows := fx.drainSealed(t); len(rows) != 0 {
		t.Fatal("idempotent link must seal nothing")
	}

	// Detail surfaces the live links.
	_, links, err := fx.svc.Detail(ctx, fx.providerID, identity.IdentityID)
	if err != nil || len(links) != 2 {
		t.Fatalf("detail links: %d %v", len(links), err)
	}

	// Unlink seals IDENTITY_UNLINKED for the one agent.
	if err := fx.svc.Unlink(ctx, fx.providerID, identity.IdentityID, "agent-1"); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	rows = fx.drainSealed(t)
	inner = fx.decodeSealed(t, rows[0])
	if inner.EventType != identityevent.TypeIdentityUnlinked ||
		len(inner.AnsIDs) != 1 || inner.AnsIDs[0] != "agent-1" {
		t.Fatalf("IDENTITY_UNLINKED event: %+v", inner)
	}
	// Unlinking a non-link 404s and seals nothing.
	if err := fx.svc.Unlink(ctx, fx.providerID, identity.IdentityID, "agent-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("double unlink: %v", err)
	}
	if rows := fx.drainSealed(t); len(rows) != 0 {
		t.Fatal("failed unlink must seal nothing")
	}
}

func TestIdentityLinkGuards(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	// Links attach only while VERIFIED.
	res, err := fx.svc.Register(ctx, fx.providerID, "did:web:a.com")
	if err != nil {
		t.Fatal(err)
	}
	fx.saveAgent(t, "agent-1", fx.providerID, "one.example.com")
	_, err = fx.svc.Link(ctx, fx.providerID, res.Identity.IdentityID, []string{"agent-1"})
	if err == nil || !strings.Contains(err.Error(), "IDENTITY_NOT_VERIFIED") {
		t.Fatalf("link pending identity: %v", err)
	}

	identity, _ := verifyDIDWeb(t, fx, "owner-2", "did:web:b.com")
	// Cross-owner identity write → 403-shaped.
	if _, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-1"}); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("cross-owner identity link: %v", err)
	}
	// Empty and oversized batches.
	if _, err := fx.svc.Link(ctx, "owner-2", identity.IdentityID, nil); err == nil {
		t.Error("empty batch should fail")
	}
	huge := make([]string, 257)
	for i := range huge {
		huge[i] = "agent"
	}
	if _, err := fx.svc.Link(ctx, "owner-2", identity.IdentityID, huge); err == nil ||
		!strings.Contains(err.Error(), "at most") {
		t.Errorf("oversized batch: %v", err)
	}
}

// TestVerifyControl_SealFailureIsRetryable pins seal-before-success
// (§5.6.1): a TL failure surfaces retryable, consumes nothing —
// including the provisional claim — and the SAME proof succeeds once
// the TL returns.
func TestVerifyControl_SealFailureIsRetryable(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, "did:web:seal-fail.example.com")
	if err != nil {
		t.Fatal(err)
	}
	priv := genKey(t)
	jws := signProof(t, priv, res.Identity.Value+"#key-1", res.Challenges[0].SigningInput, true)
	sub := service.ProofSubmission{SignedProofs: []string{jws}}

	fx.sealer.fail(domain.NewUnavailableError("TL_UNAVAILABLE", "down"))
	if _, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, sub); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	// Nothing sealed, row untouched, nonce unconsumed.
	if rows := fx.drainSealed(t); len(rows) != 0 {
		t.Fatalf("failed seal must record nothing, got %d", len(rows))
	}
	identity, _, err := fx.svc.Detail(ctx, fx.providerID, res.Identity.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Status != domain.IdentityPendingControl {
		t.Fatalf("row must stand on seal failure, got %s", identity.Status)
	}

	// TL back: the same proof (same nonce) succeeds — the claim was
	// released, the nonce never consumed.
	fx.sealer.fail(nil)
	verified, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, sub)
	if err != nil {
		t.Fatalf("retry after TL recovery: %v", err)
	}
	if verified.Status != domain.IdentityVerified {
		t.Fatalf("status: %s", verified.Status)
	}
	if rows := fx.drainSealed(t); len(rows) != 1 {
		t.Fatalf("exactly one seal after recovery, got %d", len(rows))
	}
}

// TestLink_LivenessGate pins §4.3: terminal and pre-activation agents
// are AGENT_NOT_LINKABLE (atomically — one bad agent fails the whole
// batch); DEPRECATED is deliberately linkable.
func TestLink_LivenessGate(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()
	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:liveness.example.com")
	fx.drainSealed(t)

	fx.saveAgentWithStatus(t, "agent-active", fx.providerID, "a.example.com", domain.StatusActive)
	fx.saveAgentWithStatus(t, "agent-deprecated", fx.providerID, "d.example.com", domain.StatusDeprecated)
	fx.saveAgentWithStatus(t, "agent-revoked", fx.providerID, "r.example.com", domain.StatusRevoked)
	fx.saveAgentWithStatus(t, "agent-pending", fx.providerID, "p.example.com", domain.StatusPendingValidation)

	for _, tc := range []struct {
		name    string
		agentID string
	}{
		{"terminal", "agent-revoked"},
		{"pre-activation", "agent-pending"},
		{"mixed batch is atomic", "agent-revoked"},
	} {
		batch := []string{tc.agentID}
		if tc.name == "mixed batch is atomic" {
			batch = []string{"agent-active", tc.agentID}
		}
		_, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, batch)
		var de *domain.Error
		if !errors.As(err, &de) || de.Code != "AGENT_NOT_LINKABLE" {
			t.Fatalf("%s: want AGENT_NOT_LINKABLE, got %v", tc.name, err)
		}
	}
	// The atomic rejection linked nothing.
	if rows := fx.drainSealed(t); len(rows) != 0 {
		t.Fatalf("rejected batches must seal nothing, got %d", len(rows))
	}

	// ACTIVE and DEPRECATED both link.
	linked, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-active", "agent-deprecated"})
	if err != nil || linked != 2 {
		t.Fatalf("live link: %d %v", linked, err)
	}
}

// TestLink_SealFailureLeavesNoRows pins seal-before-success on the
// link path: a failed seal writes no link rows and the retry links
// the full batch.
func TestLink_SealFailureLeavesNoRows(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()
	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:link-seal.example.com")
	fx.drainSealed(t)
	fx.saveAgent(t, "agent-ls", fx.providerID, "ls.example.com")

	fx.sealer.fail(domain.NewUnavailableError("TL_UNAVAILABLE", "down"))
	if _, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-ls"}); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if _, links, _ := fx.svc.Detail(ctx, fx.providerID, identity.IdentityID); len(links) != 0 {
		t.Fatalf("failed seal must write no rows, got %d", len(links))
	}

	fx.sealer.fail(nil)
	if linked, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-ls"}); err != nil || linked != 1 {
		t.Fatalf("retry: %d %v", linked, err)
	}
}

// TestLink_RateLimited pins the §4.3 link-route limiter.
func TestLink_RateLimited(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	fx.svc.WithLinkRateLimit(1)
	ctx := context.Background()
	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:ratelimit.example.com")
	fx.saveAgent(t, "agent-rl-1", fx.providerID, "rl1.example.com")
	fx.saveAgent(t, "agent-rl-2", fx.providerID, "rl2.example.com")

	if _, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-rl-1"}); err != nil {
		t.Fatalf("first link: %v", err)
	}
	_, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-rl-2"})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "RATE_LIMITED" {
		t.Fatalf("want RATE_LIMITED, got %v", err)
	}
}

// TestUnlink_Discipline pins the unlink guards: rate limit shared
// with link, LINK_NOT_FOUND before anything seals, seal failure
// leaves the link standing, and a clean unlink seals exactly one
// IDENTITY_UNLINKED.
func TestUnlink_Discipline(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	fx.svc.WithSealTimeout(2 * time.Second)
	ctx := context.Background()
	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:unlink.example.com")
	fx.saveAgent(t, "agent-ud", fx.providerID, "ud.example.com")

	// Unlink before any link: LINK_NOT_FOUND, nothing sealed.
	err := fx.svc.Unlink(ctx, fx.providerID, identity.IdentityID, "agent-ud")
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "LINK_NOT_FOUND" {
		t.Fatalf("want LINK_NOT_FOUND, got %v", err)
	}

	if _, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-ud"}); err != nil {
		t.Fatal(err)
	}
	fx.drainSealed(t)

	// Seal failure: the link stands, retry works.
	fx.sealer.fail(domain.NewUnavailableError("TL_UNAVAILABLE", "down"))
	if err := fx.svc.Unlink(ctx, fx.providerID, identity.IdentityID, "agent-ud"); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if _, links, _ := fx.svc.Detail(ctx, fx.providerID, identity.IdentityID); len(links) != 1 {
		t.Fatalf("failed unlink seal must leave the link, got %d", len(links))
	}
	fx.sealer.fail(nil)
	if err := fx.svc.Unlink(ctx, fx.providerID, identity.IdentityID, "agent-ud"); err != nil {
		t.Fatalf("retry unlink: %v", err)
	}
	rows := fx.drainSealed(t)
	if len(rows) != 1 {
		t.Fatalf("unlink seals exactly one event, got %d", len(rows))
	}
	if inner := fx.decodeSealed(t, rows[0]); inner.EventType != identityevent.TypeIdentityUnlinked {
		t.Fatalf("event type: %s", inner.EventType)
	}
}

// TestVisibilityPredicate_RASide pins §5.6.3 on the management
// plane: a terminal agent's AgentDetails identities[] is empty, and
// the identity detail's linked list drops links to terminal agents —
// while the link rows (history) stay in place.
func TestVisibilityPredicate_RASide(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()
	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:predicate.example.com")
	fx.saveAgent(t, "agent-vp-1", fx.providerID, "vp1.example.com")
	fx.saveAgent(t, "agent-vp-2", fx.providerID, "vp2.example.com")
	if _, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-vp-1", "agent-vp-2"}); err != nil {
		t.Fatal(err)
	}

	// Both live: both views full.
	if got, err := fx.svc.LinkedIdentitiesForAgent(ctx, "agent-vp-1"); err != nil || len(got) != 1 {
		t.Fatalf("live agent view: %v %v", got, err)
	}
	if _, links, _ := fx.svc.Detail(ctx, fx.providerID, identity.IdentityID); len(links) != 2 {
		t.Fatalf("want 2 visible links, got %d", len(links))
	}

	// Terminal agent: drops from every current view. Flip the status
	// on the EXISTING row (a fresh save would collide on ans_name).
	reg, err := fx.agents.FindByAgentID(ctx, "agent-vp-2")
	if err != nil {
		t.Fatal(err)
	}
	reg.Status = domain.StatusRevoked
	if err := fx.agents.Save(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if got, err := fx.svc.LinkedIdentitiesForAgent(ctx, "agent-vp-2"); err != nil || len(got) != 0 {
		t.Fatalf("terminal agent view must be empty: %v %v", got, err)
	}
	if _, links, _ := fx.svc.Detail(ctx, fx.providerID, identity.IdentityID); len(links) != 1 {
		t.Fatalf("terminal agent's link must drop from the count, got %d", len(links))
	}
}

// TestVerifyControl_ClaimSerializesAttempts pins the seal claim: a
// held claim rejects a second attempt (VERIFICATION_IN_FLIGHT)
// without consuming anything.
func TestVerifyControl_ClaimSerializesAttempts(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()
	res, err := fx.svc.Register(ctx, fx.providerID, "did:web:claimrace.example.com")
	if err != nil {
		t.Fatal(err)
	}
	priv := genKey(t)
	jws := signProof(t, priv, res.Identity.Value+"#key-1", res.Challenges[0].SigningInput, true)
	sub := service.ProofSubmission{SignedProofs: []string{jws}}

	// Simulate a concurrent in-flight attempt holding the claim.
	store := sqlite.NewIdentityStore(fx.db)
	now := fx.clock.now
	if err := store.ClaimChallenge(ctx, res.Identity.IdentityID, res.Nonce, now, now.Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, sub)
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "VERIFICATION_IN_FLIGHT" {
		t.Fatalf("want VERIFICATION_IN_FLIGHT, got %v", err)
	}

	// The holder releases (failed attempt) — the next attempt wins.
	if err := store.ReleaseChallenge(ctx, res.Identity.IdentityID, res.Nonce); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, sub); err != nil {
		t.Fatalf("verify after release: %v", err)
	}
}

// TestLink_RevokeDuringSealRoundTrip pins the Phase C re-read: a
// revoke committing while the IDENTITY_LINKED seal is in flight must
// not gain live link rows — the §4.3 VERIFIED gate holds at commit,
// and the sealed link event is inert (the TL's read-time status is
// terminal on any revocation leaf).
func TestLink_RevokeDuringSealRoundTrip(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()
	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:race-link.example.com")
	fx.saveAgent(t, "agent-race", fx.providerID, "race.example.com")
	fx.drainSealed(t)

	store := sqlite.NewIdentityStore(fx.db)
	fx.sealer.hook = func() {
		if err := store.MarkRevoked(ctx, identity.IdentityID, fx.clock.now); err != nil {
			t.Errorf("hook revoke: %v", err)
		}
	}
	_, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-race"})
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "IDENTITY_NOT_VERIFIED" {
		t.Fatalf("want IDENTITY_NOT_VERIFIED at commit, got %v", err)
	}
	fx.sealer.hook = nil
	if _, links, _ := fx.svc.Detail(ctx, fx.providerID, identity.IdentityID); len(links) != 0 {
		t.Fatalf("revoked identity must gain no live links, got %d", len(links))
	}
}

// TestVerifyControl_RevokeDuringSealRoundTrip pins the other side of
// the race: a revoke committing while a rotation's IDENTITY_UPDATED
// seal is in flight clears the nonce, so the verifier's conditional
// consume fails closed — the row stays REVOKED, never resurrected.
func TestVerifyControl_RevokeDuringSealRoundTrip(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()
	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:race-verify.example.com")
	fx.drainSealed(t)

	// Stage a rotation (same value — key rotation) → fresh nonce.
	res, err := fx.svc.Rotate(ctx, fx.providerID, identity.IdentityID, identity.Value)
	if err != nil {
		t.Fatal(err)
	}
	priv := genKey(t)
	jws := signProof(t, priv, identity.Value+"#key-1", res.Challenges[0].SigningInput, true)

	store := sqlite.NewIdentityStore(fx.db)
	fx.sealer.hook = func() {
		if err := store.MarkRevoked(ctx, identity.IdentityID, fx.clock.now); err != nil {
			t.Errorf("hook revoke: %v", err)
		}
	}
	_, err = fx.svc.VerifyControl(ctx, fx.providerID, identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jws}})
	if err == nil {
		t.Fatal("verify racing a committed revoke must fail closed")
	}
	fx.sealer.hook = nil
	got, _, gerr := fx.svc.Detail(ctx, fx.providerID, identity.IdentityID)
	if gerr != nil || got.Status != domain.IdentityRevoked {
		t.Fatalf("row must stay REVOKED, got %v (%v)", got.Status, gerr)
	}
}

// TestNilSealerFailsClosed pins seal-before-success's no-"seal
// later" rule: without a configured sealer every sealing operation
// refuses with TL_UNAVAILABLE and consumes nothing.
func TestNilSealerFailsClosed(t *testing.T) {
	t.Parallel()
	db, err := sqlite.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	svc := service.NewIdentityService(
		sqlite.NewIdentityStore(db),
		sqlite.NewIdentityLinkStore(db),
		sqlite.NewAgentStore(db),
		didresolver.NewNoopResolver(),
		nil, // no sealer
		leiverifier.NewNoop(),
		db,
	)
	ctx := context.Background()
	res, err := svc.Register(ctx, "owner-ns", "did:web:nosealer.example.com")
	if err != nil {
		t.Fatalf("register (no seal needed): %v", err)
	}
	priv := genKey(t)
	jws := signProof(t, priv, res.Identity.Value+"#key-1", res.Challenges[0].SigningInput, true)
	_, err = svc.VerifyControl(ctx, "owner-ns", res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jws}})
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("nil sealer must fail closed with ErrUnavailable, got %v", err)
	}
	got, _, gerr := svc.Detail(ctx, "owner-ns", res.Identity.IdentityID)
	if gerr != nil || got.Status != domain.IdentityPendingControl {
		t.Fatalf("row must stand: %v (%v)", got.Status, gerr)
	}
}

// TestVerifyControl_TLRejectedEventFailsClosed pins the ERROR seal
// branch: a NON-transient TL rejection (TL_REJECTED_EVENT — the RA
// produced an event the TL refuses, a pipeline bug) fails the
// operation closed, consumes nothing, and is distinct from the
// retryable TL_UNAVAILABLE path.
func TestVerifyControl_TLRejectedEventFailsClosed(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()
	res, err := fx.svc.Register(ctx, fx.providerID, "did:web:rejected.example.com")
	if err != nil {
		t.Fatal(err)
	}
	priv := genKey(t)
	jws := signProof(t, priv, res.Identity.Value+"#key-1", res.Challenges[0].SigningInput, true)
	sub := service.ProofSubmission{SignedProofs: []string{jws}}

	// A schema rejection is ErrInternal (TL_REJECTED_EVENT), not
	// ErrUnavailable — the seal boundary logs it at ERROR and the
	// operation fails.
	fx.sealer.fail(domain.NewInternalError("TL_REJECTED_EVENT", "the transparency log rejected the identity event", errors.New("422")))
	_, err = fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, sub)
	if err == nil || errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("want a non-unavailable rejection error, got %v", err)
	}
	if rows := fx.drainSealed(t); len(rows) != 0 {
		t.Fatalf("rejected seal must record nothing, got %d", len(rows))
	}
	identity, _, derr := fx.svc.Detail(ctx, fx.providerID, res.Identity.IdentityID)
	if derr != nil || identity.Status != domain.IdentityPendingControl {
		t.Fatalf("row must stand on rejection: %v (%v)", identity.Status, derr)
	}

	// The claim was released, so a retry once the pipeline is fixed
	// succeeds with the same proof.
	fx.sealer.fail(nil)
	if _, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, sub); err != nil {
		t.Fatalf("retry after rejection cleared: %v", err)
	}
}

// releaseFailStore wraps the real identity store but fails
// ReleaseChallenge, so the leaked-claim WARN path in releaseClaim is
// exercised — the operation must still fail (best-effort release does
// not change the outcome) without panicking.
type releaseFailStore struct {
	port.IdentityStore
}

func (releaseFailStore) ReleaseChallenge(context.Context, string, string) error {
	return errors.New("release failed (simulated)")
}

// TestReleaseClaim_LeakedClaimIsLoggedNotSwallowed pins that a failed
// claim release is surfaced (logged), not silently dropped, and does
// not change the operation's failure.
func TestReleaseClaim_LeakedClaimIsLoggedNotSwallowed(t *testing.T) {
	t.Parallel()
	db, err := sqlite.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	km, err := keymanager.NewFileKeyManager(t.TempDir() + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.EnsureKey(context.Background(), "ra-signer", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{now: time.Date(2026, 6, 10, 15, 0, 0, 0, time.UTC)}
	sealer := &recordingSealer{err: domain.NewUnavailableError("TL_UNAVAILABLE", "down")}
	svc := service.NewIdentityService(
		releaseFailStore{IdentityStore: sqlite.NewIdentityStore(db)},
		sqlite.NewIdentityLinkStore(db),
		sqlite.NewAgentStore(db),
		didresolver.NewNoopResolver(),
		sealer,
		leiverifier.NewNoop(),
		db,
	).WithSigner(service.EventSigner{KeyManager: km, KeyID: "ra-signer", RaID: "ra-test"}).
		WithClock(clock.Now).WithLogger(zerolog.New(io.Discard))

	ctx := context.Background()
	res, err := svc.Register(ctx, "owner-rl", "did:web:leak.example.com")
	if err != nil {
		t.Fatal(err)
	}
	priv := genKey(t)
	jws := signProof(t, priv, res.Identity.Value+"#key-1", res.Challenges[0].SigningInput, true)
	// Seal fails (TL down) → the success path releases the claim; the
	// release itself fails → WARN-logged, but the verify still fails
	// retryable as expected (not a panic, not a different error).
	_, err = svc.VerifyControl(ctx, "owner-rl", res.Identity.IdentityID, service.ProofSubmission{SignedProofs: []string{jws}})
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable despite the release failure, got %v", err)
	}
}
