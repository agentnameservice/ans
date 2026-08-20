package service_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/ra/service"
	identityevent "github.com/agentnameservice/ans/internal/tl/event/identity"
)

// signEd25519Flow builds a compact EdDSA JWS over the served signingInput
// with the key's thumbprint as kid and its JWK embedded as the hint — the
// shape a web-bot-auth registrant's tooling produces. The noop directory
// resolver synthesizes the endorsed key set from that hint, so the full
// verify-control flow runs end to end without any outbound fetch.
func signEd25519Flow(t *testing.T, priv ed25519.PrivateKey, jwk json.RawMessage, kid, signingInput string) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "EdDSA", "kid": kid, "jwk": jwk})
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	toSign := encodedHeader + "." + signingInput
	sig := ed25519.Sign(priv, []byte(toSign))
	return toSign + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestIdentityVerifyControl_WebBotAuthNoop drives the full web-bot-auth
// verify-control flow on the quickstart (noop) directory resolver: the
// canonical well-known value is sealed as IDENTITY_VERIFIED with the
// web-bot-auth-sig proof method, and the sealed key is self-verifying.
func TestIdentityVerifyControl_WebBotAuthNoop(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, "https://Signer.Example.com")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	wantValue := "https://signer.example.com/.well-known/http-message-signatures-directory"
	if res.Identity.Value != wantValue {
		t.Fatalf("canonical value = %q, want %q", res.Identity.Value, wantValue)
	}
	if res.Identity.Kind != domain.KindWebBotAuth {
		t.Fatalf("kind = %q", res.Identity.Kind)
	}
	// No advisory keys on the noop path → a single unkeyed challenge.
	if len(res.Challenges) != 1 || res.Challenges[0].Kid != "" {
		t.Fatalf("challenge round = %+v", res.Challenges)
	}

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
	jws := signEd25519Flow(t, priv, jwk, tp, res.Challenges[0].SigningInput)

	identity, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID,
		service.ProofSubmission{SignedProofs: []string{jws}})
	if err != nil {
		t.Fatalf("verify-control: %v", err)
	}
	if identity.Status != domain.IdentityVerified || identity.ProofMethod != "web-bot-auth-sig" {
		t.Fatalf("verified state: status=%s proofMethod=%s", identity.Status, identity.ProofMethod)
	}

	rows := fx.drainSealed(t)
	if len(rows) != 1 {
		t.Fatalf("sealed events: %d", len(rows))
	}
	inner := fx.decodeSealed(t, rows[0])
	if inner.EventType != identityevent.TypeIdentityVerified || len(inner.Keys) != 1 {
		t.Fatalf("sealed event: %+v", inner)
	}
	key := inner.Keys[0]
	if key.ID() != wantValue+"#"+tp {
		t.Fatalf("sealed key id = %q, want %q", key.ID(), wantValue+"#"+tp)
	}
	var vm struct {
		Type         string          `json:"type"`
		PublicKeyJwk json.RawMessage `json:"publicKeyJwk"`
	}
	if err := json.Unmarshal(key.VerificationMethod, &vm); err != nil {
		t.Fatalf("sealed VM not an object: %v", err)
	}
	if vm.Type != "JsonWebKey2020" {
		t.Fatalf("sealed VM type = %q", vm.Type)
	}
	sealedPub, err := anscrypto.ParseJWK(vm.PublicKeyJwk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anscrypto.VerifyStandardJWSWithPublicKey(sealedPub, key.SignedProof); err != nil {
		t.Fatalf("sealed proof does not verify against sealed key: %v", err)
	}
}

// TestIdentityRotate_WebBotAuth covers a same-kind URL replacement: a
// verified web-bot-auth identity rotated to a new Signature-Agent URL
// re-proves control and seals IDENTITY_UPDATED.
func TestIdentityRotate_WebBotAuth(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixture(t, nil)
	ctx := context.Background()

	res, err := fx.svc.Register(ctx, fx.providerID, "https://signer-one.example.com")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	verifyWBA(t, fx, res)

	// Rotate to a new same-kind URL.
	rot, err := fx.svc.Rotate(ctx, fx.providerID, res.Identity.IdentityID, "https://signer-two.example.com")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rot.Identity.PendingValue == "" {
		t.Fatalf("rotate should stage a pending value: %+v", rot.Identity)
	}
	verifyWBA(t, fx, rot)

	// The second seal is an update, not a fresh verify.
	rows := fx.drainSealed(t)
	last := fx.decodeSealed(t, rows[len(rows)-1])
	if last.EventType != identityevent.TypeIdentityUpdated {
		t.Fatalf("rotation sealed %s, want IDENTITY_UPDATED", last.EventType)
	}
}

// verifyWBA proves control for a pending web-bot-auth challenge round on
// the noop path.
func verifyWBA(t *testing.T, fx *identityFixture, res *service.IdentityChallengeResponse) {
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
	jws := signEd25519Flow(t, priv, jwk, tp, res.Challenges[0].SigningInput)
	if _, err := fx.svc.VerifyControl(context.Background(), fx.providerID, res.Identity.IdentityID,
		service.ProofSubmission{SignedProofs: []string{jws}}); err != nil {
		t.Fatalf("verify-control: %v", err)
	}
}
