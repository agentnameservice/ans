package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	identityevent "github.com/godaddy/ans/internal/tl/event/identity"
)

// leiVerifier is the lei (vLEI) controlVerifier — the per-kind gate
// behind the lei identifier kind. It owns no key state itself: every
// CESR/KERI question routes to the injected port.LEIControlVerifier
// (the noop quickstart adapter, or the real vlei-verifier HTTP client).
//
// lei differs from the JWS kinds in two structural ways, both absorbed
// behind the seam:
//
//   - The credential presentation arrives at REGISTER time, so lei
//     also implements presentationRegistrar: the shared challenge path
//     submits the CESR and gets back the verifier-derived subject AID
//     and advisory presentation status. A re-add (or rotation)
//     re-presents and refreshes the verifier's authorization window
//     for free.
//   - The proof is a single CESR signature over the served
//     signingInput (not a JWS array), and the seal commits the subject
//     AID + a thumbprint only — no JWK, no document. The KEL is the
//     authoritative key history; the ACDC is PII. (event.go §lei seal
//     exception.)
type leiVerifier struct {
	v port.LEIControlVerifier
}

// RegisterPresentation submits the register-time CESR to the verifier
// and reconciles the credential's LEI against effectiveValue. Returns
// the derived subject AID and the advisory presentation status for the
// 202; the caller stages the AID.
func (lv *leiVerifier) RegisterPresentation(
	ctx context.Context,
	effectiveValue string,
	opts RegisterOptions,
) (string, port.PresentationStatus, error) {
	if opts.VLEIPresentation == "" {
		return "", "", domain.NewValidationError("IDENTIFIER_PRESENTATION_REQUIRED",
			"lei registration requires vleiPresentation.cesr")
	}
	res, err := lv.v.Present(ctx, opts.VLEIPresentation)
	if err != nil {
		return "", "", err
	}
	if res.SubjectAID == "" {
		return "", "", domain.NewValidationError("LEI_PRESENTATION_INVALID",
			"the vlei verifier returned no subject AID for the presentation")
	}
	// Reconcile the presented LEI against the registered value. The
	// noop adapter waives the AID↔LEI binding and returns an empty LEI
	// (the documented quickstart waiver, mirroring noop-DNS); skip the
	// equality check in that case.
	if res.LEI != "" && !strings.EqualFold(res.LEI, effectiveValue) {
		return "", "", domain.NewValidationError("LEI_MISMATCH",
			fmt.Sprintf("presented credential authorizes LEI %q, not %q", res.LEI, effectiveValue))
	}
	return res.SubjectAID, res.Status, nil
}

// Challenges returns the single lei challenge entry: the pinned
// subject AID as the kid, the served signingInput as the payload to
// sign. RegisterPresentation has already run (same challenge path), so
// the subject AID is pinned on the aggregate.
func (lv *leiVerifier) Challenges(
	_ context.Context,
	identity *domain.VerifiedIdentity,
	signingInput string,
) ([]ProofChallenge, error) {
	aid := identity.EffectiveSubjectAID()
	if aid == "" {
		return nil, domain.NewInternalError("LEI_SUBJECT_AID_MISSING",
			"subject AID was not pinned before challenge", nil)
	}
	return []ProofChallenge{{Kid: aid, SigningInput: signingInput}}, nil
}

// VerifyProofs runs the lei control proof: a LIVE authorization
// re-check against the verifier (the register-time status is
// advisory), then a CESR signature verification over the served
// signingInput by the pinned subject AID's current key. Seals one
// ProvenKey = subject AID + thumbprint (no JWK, no document).
func (lv *leiVerifier) VerifyProofs(
	ctx context.Context,
	identity *domain.VerifiedIdentity,
	sub ProofSubmission,
	signingInput string,
) ([]identityevent.ProvenKey, error) {
	if sub.CESRSignature == "" {
		return nil, domain.NewValidationError("IDENTIFIER_PROOF_INVALID", "cesrSignature is required")
	}
	aid := identity.EffectiveSubjectAID()
	if aid == "" {
		return nil, domain.NewInvalidStateError("LEI_SUBJECT_AID_MISSING",
			"no subject AID is pinned; re-register the identifier with its presentation")
	}

	auth, err := lv.v.Authorization(ctx, aid)
	if err != nil {
		return nil, err
	}
	if !auth.Authorized {
		return nil, domain.NewValidationError("LEI_NOT_AUTHORIZED",
			"the vlei verifier does not currently authorize this AID")
	}
	if auth.LEI != "" && !strings.EqualFold(auth.LEI, identity.EffectiveValue()) {
		return nil, domain.NewValidationError("LEI_MISMATCH",
			fmt.Sprintf("the AID is authorized for LEI %q, not %q", auth.LEI, identity.EffectiveValue()))
	}

	ok, err := lv.v.VerifySignature(ctx, aid, signingInput, sub.CESRSignature)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, domain.NewValidationError("PRICC_SIGNATURE_INVALID",
			"the CESR signature does not verify against the subject AID's current key")
	}

	vm, err := json.Marshal(map[string]string{
		"id":         aid,
		"type":       "vLEI-KERI-AID",
		"thumbprint": aidThumbprint(aid),
	})
	if err != nil {
		return nil, domain.NewInternalError("PROOF_SEAL", "could not build lei verification method", err)
	}
	return []identityevent.ProvenKey{{
		VerificationMethod: vm,
		SignedProof:        sub.CESRSignature,
	}}, nil
}

// aidThumbprint is the sealed key fingerprint for a lei proof:
// base64url(SHA-256(subjectAID)). The subject AID is itself a KERI
// self-addressing identifier (a digest of the holder's inception key
// state), so a hash over it is a stable, content-bound fingerprint —
// the AID+thumbprint pair is what the seal commits in lieu of a JWK
// (the KEL is the authoritative key history; see event.go §lei seal).
func aidThumbprint(aid string) string {
	sum := sha256.Sum256([]byte(aid))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// compile-time conformance: lei implements both the control gate and
// the register-time presentation capability.
var (
	_ controlVerifier       = (*leiVerifier)(nil)
	_ presentationRegistrar = (*leiVerifier)(nil)
)
