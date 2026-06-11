package service_test

// lei (vLEI) lane tests for IdentityService: the register-time
// presentation (subject-AID pinning + LEI reconciliation), the single
// CESR-signature control proof, the live re-authorization at
// verify-control, and the AID+thumbprint seal. A programmable fake
// LEIControlVerifier stands in for the noop/real adapters so every
// failure code is reachable deterministically.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/service"
	identityevent "github.com/godaddy/ans/internal/tl/event/identity"
)

// the LEI the lei tests register; a valid 20-char LEI so the kind infers.
const testLEI = "5493001KJTIIGC8Y1R17"

// fakeLEI is a programmable port.LEIControlVerifier.
type fakeLEI struct {
	present    port.PresentationResult
	presentErr error
	auth       port.AuthorizationResult
	authErr    error
	verifyOK   bool
	verifyErr  error
}

func (f *fakeLEI) Present(context.Context, string) (port.PresentationResult, error) {
	return f.present, f.presentErr
}

func (f *fakeLEI) Authorization(context.Context, string) (port.AuthorizationResult, error) {
	return f.auth, f.authErr
}

func (f *fakeLEI) VerifySignature(context.Context, string, string, string) (bool, error) {
	return f.verifyOK, f.verifyErr
}

// authorizedFakeLEI is the all-clear fake: presents the testLEI for AID
// "EHolderAID", authorizes it, and verifies any signature.
func authorizedFakeLEI() *fakeLEI {
	return &fakeLEI{
		present:  port.PresentationResult{SubjectAID: "EHolderAID", LEI: testLEI, Status: "AUTHORIZED"},
		auth:     port.AuthorizationResult{Authorized: true, LEI: testLEI},
		verifyOK: true,
	}
}

func leiCode(t *testing.T, err error, want string) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}

func TestIdentityLifecycle_LEIHappy(t *testing.T) {
	t.Parallel()
	fx := newIdentityFixtureWithLEI(t, nil, authorizedFakeLEI())
	ctx := context.Background()

	// Register with the presentation → 202 with the advisory status and
	// the single AID-kid challenge.
	res, err := fx.svc.Register(ctx, fx.providerID, testLEI,
		service.RegisterOptions{VLEIPresentation: "full-chain-cesr-blob"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if res.Identity.Kind != domain.KindLEI {
		t.Fatalf("kind = %s, want lei", res.Identity.Kind)
	}
	if res.PresentationStatus != "AUTHORIZED" {
		t.Fatalf("presentation status = %q", res.PresentationStatus)
	}
	if len(res.Challenges) != 1 || res.Challenges[0].Kid != "EHolderAID" || res.Challenges[0].SigningInput == "" {
		t.Fatalf("challenge shape: %+v", res.Challenges)
	}

	// verify-control with the CESR signature → VERIFIED, seal emitted.
	identity, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID,
		service.ProofSubmission{CESRSignature: "0Bcesr-signature-bytes"})
	if err != nil {
		t.Fatalf("verify-control: %v", err)
	}
	if identity.Status != domain.IdentityVerified || identity.ProofMethod != "lei-vlei-acdc" {
		t.Fatalf("verified state: %+v", identity)
	}

	rows := fx.drainOutbox(t)
	if len(rows) != 1 {
		t.Fatalf("outbox rows: %d", len(rows))
	}
	inner := fx.decodeOutboxEvent(t, rows[0])
	if inner.EventType != identityevent.TypeIdentityVerified || len(inner.Keys) != 1 {
		t.Fatalf("sealed event: %+v", inner)
	}
	key := inner.Keys[0]
	// The lei seal commits the subject AID as the id, a vLEI-KERI-AID
	// type, and a base64url(SHA-256(AID)) thumbprint — no JWK, no doc.
	if key.ID() != "EHolderAID" || key.SignedProof != "0Bcesr-signature-bytes" {
		t.Fatalf("sealed key: id=%q proof=%q", key.ID(), key.SignedProof)
	}
	var vm struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Thumbprint string `json:"thumbprint"`
	}
	if err := json.Unmarshal(key.VerificationMethod, &vm); err != nil {
		t.Fatalf("verification method not an object: %v", err)
	}
	wantThumb := base64.RawURLEncoding.EncodeToString(sha256Sum("EHolderAID"))
	if vm.ID != "EHolderAID" || vm.Type != "vLEI-KERI-AID" || vm.Thumbprint != wantThumb {
		t.Fatalf("sealed verification method: %+v", vm)
	}
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func TestIdentityRegister_LEIFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("presentation required", func(t *testing.T) {
		fx := newIdentityFixtureWithLEI(t, nil, authorizedFakeLEI())
		_, err := fx.svc.Register(ctx, fx.providerID, testLEI)
		leiCode(t, err, "IDENTIFIER_PRESENTATION_REQUIRED")
	})

	t.Run("present error propagates", func(t *testing.T) {
		fake := &fakeLEI{presentErr: domain.NewInternalError("LEI_VERIFIER_UNAVAILABLE", "down", nil)}
		fx := newIdentityFixtureWithLEI(t, nil, fake)
		_, err := fx.svc.Register(ctx, fx.providerID, testLEI, service.RegisterOptions{VLEIPresentation: "x"})
		leiCode(t, err, "LEI_VERIFIER_UNAVAILABLE")
	})

	t.Run("no subject AID", func(t *testing.T) {
		fake := &fakeLEI{present: port.PresentationResult{LEI: testLEI, Status: "AUTHORIZED"}}
		fx := newIdentityFixtureWithLEI(t, nil, fake)
		_, err := fx.svc.Register(ctx, fx.providerID, testLEI, service.RegisterOptions{VLEIPresentation: "x"})
		leiCode(t, err, "LEI_PRESENTATION_INVALID")
	})

	t.Run("lei mismatch at presentation", func(t *testing.T) {
		fake := &fakeLEI{present: port.PresentationResult{SubjectAID: "EAID", LEI: "OTHERLEI000000000000", Status: "AUTHORIZED"}}
		fx := newIdentityFixtureWithLEI(t, nil, fake)
		_, err := fx.svc.Register(ctx, fx.providerID, testLEI, service.RegisterOptions{VLEIPresentation: "x"})
		leiCode(t, err, "LEI_MISMATCH")
	})
}

// registerLEI drives a lei identity to PENDING_CONTROL and returns the
// challenge response, for the verify-control failure cases.
func registerLEI(t *testing.T, fx *identityFixture) *service.IdentityChallengeResponse {
	t.Helper()
	res, err := fx.svc.Register(context.Background(), fx.providerID, testLEI,
		service.RegisterOptions{VLEIPresentation: "x"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return res
}

func TestIdentityVerifyControl_LEIFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("missing cesr signature", func(t *testing.T) {
		fx := newIdentityFixtureWithLEI(t, nil, authorizedFakeLEI())
		res := registerLEI(t, fx)
		_, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID, service.ProofSubmission{})
		leiCode(t, err, "IDENTIFIER_PROOF_INVALID")
	})

	t.Run("not authorized", func(t *testing.T) {
		fake := authorizedFakeLEI()
		fake.auth = port.AuthorizationResult{Authorized: false}
		fx := newIdentityFixtureWithLEI(t, nil, fake)
		res := registerLEI(t, fx)
		_, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID,
			service.ProofSubmission{CESRSignature: "0Bsig"})
		leiCode(t, err, "LEI_NOT_AUTHORIZED")
	})

	t.Run("authorization lei mismatch", func(t *testing.T) {
		fake := authorizedFakeLEI()
		fake.auth = port.AuthorizationResult{Authorized: true, LEI: "OTHERLEI000000000000"}
		fx := newIdentityFixtureWithLEI(t, nil, fake)
		res := registerLEI(t, fx)
		_, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID,
			service.ProofSubmission{CESRSignature: "0Bsig"})
		leiCode(t, err, "LEI_MISMATCH")
	})

	t.Run("signature does not verify", func(t *testing.T) {
		fake := authorizedFakeLEI()
		fake.verifyOK = false
		fx := newIdentityFixtureWithLEI(t, nil, fake)
		res := registerLEI(t, fx)
		_, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID,
			service.ProofSubmission{CESRSignature: "0Bsig"})
		leiCode(t, err, "PRICC_SIGNATURE_INVALID")
	})

	t.Run("verify error propagates", func(t *testing.T) {
		fake := authorizedFakeLEI()
		fake.verifyErr = domain.NewInternalError("LEI_VERIFIER_UNAVAILABLE", "down", nil)
		fx := newIdentityFixtureWithLEI(t, nil, fake)
		res := registerLEI(t, fx)
		_, err := fx.svc.VerifyControl(ctx, fx.providerID, res.Identity.IdentityID,
			service.ProofSubmission{CESRSignature: "0Bsig"})
		leiCode(t, err, "LEI_VERIFIER_UNAVAILABLE")
	})
}
