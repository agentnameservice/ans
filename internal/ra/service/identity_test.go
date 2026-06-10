package service_test

// IdentityService tests: the proof gate (payload equality, kid
// selection, signature verification, nonce discipline), the lifecycle
// (register → verify → rotate → revoke), the owner-gated links, and
// the sealed-event emission on the outbox IDENTITY lane. Real SQLite
// stores + real crypto; the resolver is the noop adapter (hint
// synthesis) or a canned-document fake for the did:web rules.

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
	"strings"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/adapter/didresolver"
	"github.com/godaddy/ans/internal/adapter/keymanager"
	"github.com/godaddy/ans/internal/adapter/store/sqlite"
	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/service"
	identityevent "github.com/godaddy/ans/internal/tl/event/identity"
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
	outbox     *sqlite.OutboxStore
	agents     port.AgentStore
	signerPub  any
	clock      *fakeClock
	providerID string
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

// newIdentityFixture wires the service against real SQLite + the
// given resolver (nil → noop).
func newIdentityFixture(t *testing.T, resolver port.DIDResolver) *identityFixture {
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
	svc := service.NewIdentityService(
		sqlite.NewIdentityStore(db),
		sqlite.NewIdentityLinkStore(db),
		sqlite.NewAgentStore(db),
		resolver,
		sqlite.NewOutboxStore(db),
		db,
	).WithSigner(service.EventSigner{
		KeyManager: km,
		KeyID:      "ra-signer",
		RaID:       "ra-test",
	}).WithClock(clock.Now)

	return &identityFixture{
		svc:        svc,
		db:         db,
		outbox:     sqlite.NewOutboxStore(db),
		agents:     sqlite.NewAgentStore(db),
		signerPub:  pub,
		clock:      clock,
		providerID: "owner-1",
	}
}

// saveAgent persists a minimal ACTIVE agent owned by `owner`.
func (fx *identityFixture) saveAgent(t *testing.T, agentID, owner, host string) {
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
		Status:  domain.StatusActive,
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

// drainOutbox claims and returns all pending outbox rows.
func (fx *identityFixture) drainOutbox(t *testing.T) []sqlite.OutboxEvent {
	t.Helper()
	rows, err := fx.outbox.Claim(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if err := fx.outbox.MarkSent(context.Background(), row.ID); err != nil {
			t.Fatal(err)
		}
	}
	return rows
}

// decodeOutboxEvent parses one outbox row's payload, verifies the
// producer signature against the fixture's signer key, and returns
// the inner identity event.
func (fx *identityFixture) decodeOutboxEvent(t *testing.T, row sqlite.OutboxEvent) *identityevent.Event {
	t.Helper()
	var payload struct {
		InnerEventCanonical json.RawMessage `json:"innerEventCanonical"`
		ProducerSignature   string          `json:"producerSignature"`
	}
	if err := json.Unmarshal(row.PayloadJSON, &payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if _, err := anscrypto.VerifyWithPublicKey(fx.signerPub, payload.ProducerSignature, payload.InnerEventCanonical); err != nil {
		t.Fatalf("producer signature: %v", err)
	}
	var inner identityevent.Event
	if err := json.Unmarshal(payload.InnerEventCanonical, &inner); err != nil {
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
	if rows := fx.drainOutbox(t); len(rows) != 0 {
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
	// lei is recognized but postponed.
	if _, err := fx.svc.Register(ctx, fx.providerID, "5493001KJTIIGC8Y1R17"); err == nil ||
		!strings.Contains(err.Error(), "IDENTIFIER_KIND_UNSUPPORTED") {
		t.Errorf("lei: %v", err)
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

	rows := fx.drainOutbox(t)
	if len(rows) != 1 || rows[0].SchemaVersion != "IDENTITY" {
		t.Fatalf("outbox rows: %+v", rows)
	}
	inner := fx.decodeOutboxEvent(t, rows[0])
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
	rows := fx.drainOutbox(t)
	inner := fx.decodeOutboxEvent(t, rows[0])
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
	rows := fx.drainOutbox(t)
	inner := fx.decodeOutboxEvent(t, rows[0])
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
	rows := fx.drainOutbox(t)
	inner := fx.decodeOutboxEvent(t, rows[0])
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
	fx.drainOutbox(t)

	rot, err := fx.svc.Rotate(ctx, fx.providerID, identity.IdentityID, "did:web:b.com")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rot.Identity.Value != "did:web:a.com" || rot.Identity.PendingValue != "did:web:b.com" {
		t.Fatalf("staged state: %+v", rot.Identity)
	}
	// Until the proof lands, the previously sealed state stands —
	// nothing emitted by the PUT itself.
	if rows := fx.drainOutbox(t); len(rows) != 0 {
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

	rows := fx.drainOutbox(t)
	if len(rows) != 1 {
		t.Fatalf("rotation rows: %d", len(rows))
	}
	inner := fx.decodeOutboxEvent(t, rows[0])
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
	fx.drainOutbox(t)

	revoked, err := fx.svc.Revoke(ctx, fx.providerID, identity.IdentityID)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Status != domain.IdentityRevoked {
		t.Fatalf("status: %s", revoked.Status)
	}
	rows := fx.drainOutbox(t)
	inner := fx.decodeOutboxEvent(t, rows[0])
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
	rows := fx.drainOutbox(t)
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
	// List is owner-scoped.
	mine, err := fx.svc.List(ctx, fx.providerID)
	if err != nil || len(mine) != 1 {
		t.Fatalf("list mine: %d %v", len(mine), err)
	}
	theirs, err := fx.svc.List(ctx, "owner-2")
	if err != nil || len(theirs) != 0 {
		t.Fatalf("list theirs: %d %v", len(theirs), err)
	}
}

// ----- links -----

func TestIdentityLinks(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	identity, _ := verifyDIDWeb(t, fx, fx.providerID, "did:web:a.com")
	fx.drainOutbox(t)
	fx.saveAgent(t, "agent-1", fx.providerID, "one.example.com")
	fx.saveAgent(t, "agent-2", fx.providerID, "two.example.com")
	fx.saveAgent(t, "agent-x", "owner-2", "theirs.example.com")

	// Owner gate, agent side: naming someone else's agent fails the
	// whole call without revealing the agent's existence.
	_, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-1", "agent-x"})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-owner agent in batch: %v", err)
	}
	if rows := fx.drainOutbox(t); len(rows) != 0 {
		t.Fatal("failed batch must seal nothing")
	}

	// Batch of two (with a duplicate id deduped) → ONE sealed event.
	linked, err := fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-1", "agent-2", "agent-1"})
	if err != nil || linked != 2 {
		t.Fatalf("link batch: %d %v", linked, err)
	}
	rows := fx.drainOutbox(t)
	if len(rows) != 1 {
		t.Fatalf("link batch rows: %d", len(rows))
	}
	inner := fx.decodeOutboxEvent(t, rows[0])
	if inner.EventType != identityevent.TypeIdentityLinked || len(inner.AnsIDs) != 2 {
		t.Fatalf("IDENTITY_LINKED event: %+v", inner)
	}

	// Fully idempotent repeat seals nothing.
	linked, err = fx.svc.Link(ctx, fx.providerID, identity.IdentityID, []string{"agent-1"})
	if err != nil || linked != 0 {
		t.Fatalf("idempotent link: %d %v", linked, err)
	}
	if rows := fx.drainOutbox(t); len(rows) != 0 {
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
	rows = fx.drainOutbox(t)
	inner = fx.decodeOutboxEvent(t, rows[0])
	if inner.EventType != identityevent.TypeIdentityUnlinked ||
		len(inner.AnsIDs) != 1 || inner.AnsIDs[0] != "agent-1" {
		t.Fatalf("IDENTITY_UNLINKED event: %+v", inner)
	}
	// Unlinking a non-link 404s and seals nothing.
	if err := fx.svc.Unlink(ctx, fx.providerID, identity.IdentityID, "agent-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("double unlink: %v", err)
	}
	if rows := fx.drainOutbox(t); len(rows) != 0 {
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
