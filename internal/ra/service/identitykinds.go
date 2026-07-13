package service

// This file is THE extension seam for identifier kinds. Each kind —
// did:web, did:key today; did:plc, did:ion, did:ethr, lei (vLEI)
// next — implements controlVerifier and registers itself in
// newControlVerifiers. Everything else in the identity service is
// kind-agnostic: the aggregate lifecycle, the nonce discipline, the
// owner gates, the links, and the sealing pipeline never branch on
// kind.
//
// How to add a kind, end to end:
//
//  1. Teach domain.InferIdentifierKind the kind's lexical form and
//     canonicalization (the kind set is spec-frozen — a new kind is
//     an ANS-spec amendment, so a new dispatch arm there is correct,
//     not a smell). Add its proofMethod token.
//  2. Implement controlVerifier. Inject whatever I/O the kind needs
//     through ports (did:plc → a PLC-directory fetcher; did:ion → an
//     ION-node fetcher; lei → port-wrapped GLEIF L1 + vlei-verifier
//     clients), each with a noop adapter for the quickstart and a
//     real adapter selected by config — the DNS-verifier pattern.
//  3. Register it in newControlVerifiers. Unregistered kinds fail
//     with IDENTIFIER_KIND_UNSUPPORTED — the 404-is-the-signal rule:
//     no stubs, a kind exists only when its proof is real.
//
// Per-kind WIRE shapes are additive, never branching:
//
//   - Request side: ProofSubmission carries every kind's proof
//     material as optional members. JWS kinds read SignedProofs;
//     lei will add CESRSignature, did:ethr will add EthSignature.
//     Exactly one family of members is set per kind (the design's
//     "exactly one proof field is set per kind" rule); each verifier
//     validates its own members and ignores the rest.
//   - Response side: the 202 challenge offer is the shared
//     {nonce, expiresAt, challenges[]} envelope. A kind needing
//     extra offer fields (lei's presentationStatus) adds an optional
//     capability interface here — the same discover-by-type-assertion
//     pattern the TL store uses for identity indexing — so existing
//     kinds never grow dead fields.
//   - Seal side: identityevent.ProvenKey quotes the kind's
//     authoritative verification material verbatim. Kinds with no
//     document to quote commit minimally (lei: subject AID +
//     thumbprint — the KEL is the authoritative key history).

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	identityevent "github.com/godaddy/ans/internal/tl/event/identity"
)

// ProofSubmission carries the kind-specific proof material from the
// verify-control request body. Members are additive per kind; each
// controlVerifier validates exactly the members its kind defines.
type ProofSubmission struct {
	// SignedProofs is the JWS-scheme proof set (did:web, did:key,
	// and the future did:plc / did:ion): one compact JWS per proven
	// key, every payload equal to the served signingInput verbatim.
	SignedProofs []string
	// CESRSignature is the lei (vLEI) proof: one CESR signature over
	// the served signingInput, produced by the subject AID's current
	// signing key. Set only for lei; the JWS kinds ignore it.
	CESRSignature string
}

// validateExactlyOneFamily enforces the wire oneOf contract declared
// by VerifyControlRequest in spec/api-spec-v2.yaml: EXACTLY ONE proof
// family is set per request (JWS kinds → signedProofs; lei →
// cesrSignature).
//
// Checks value-presence, not the spec oneOf's literal key-presence:
// the plain []string/string types collapse absent, null, and empty to
// the same zero value, so key-presence is not recoverable here. Value-
// presence is stricter — it rejects a body with no usable proof rather
// than deferring to a per-kind verifier — diverging only on a body with
// both keys present but one empty, which routes by the non-empty family.
func (s ProofSubmission) validateExactlyOneFamily() error {
	hasJWS := len(s.SignedProofs) > 0
	hasCESR := s.CESRSignature != ""
	if hasJWS == hasCESR {
		return domain.NewValidationError("IDENTIFIER_PROOF_INVALID",
			"exactly one of signedProofs or cesrSignature must be set")
	}
	return nil
}

// RegisterOptions carries the additive, per-kind material a register
// (or rotate) call may need beyond the identifier value. It is empty
// for kinds with no register-time presentation (did:web, did:key);
// lei populates VLEIPresentation. Additive by design — a new kind adds
// a member here, existing callers pass the zero value.
type RegisterOptions struct {
	// VLEIPresentation is the lei full-chain CESR export submitted to
	// the vlei-verifier at register time (the credential + KELs). The
	// verifier derives the subject AID from it; the caller never
	// asserts the AID.
	VLEIPresentation string
}

// presentationRegistrar is the optional capability a kind implements
// when it carries credential material at REGISTER time (lei's vLEI
// presentation), discovered by type-assertion on the controlVerifier so
// kinds without one (did:web, did:key) grow no dead method.
//
// It returns derived facts and never receives the aggregate, so it
// cannot touch the conditional-persist guard columns (Status,
// Challenge.Nonce): challenge() stages the returned identifier itself.
// The presentation fetch is thus race-safe by construction — see the
// StageChallenge doc block in internal/adapter/store/sqlite/identity.go
// for the conditional-persist guard the snapshot rides.
type presentationRegistrar interface {
	// RegisterPresentation submits the register-time credential to the
	// verifier, reconciles it against effectiveValue, and returns the
	// verifier-derived subject identifier and advisory presentation
	// status ("AUTHORIZED" | "PENDING") for the 202.
	RegisterPresentation(ctx context.Context, effectiveValue string, opts RegisterOptions) (subjectAID string, status port.PresentationStatus, err error)
}

// controlVerifier is the per-kind control-proof gate — the design's
// §3 centerpiece, one implementation per identifier kind.
type controlVerifier interface {
	// Challenges runs the kind's advisory resolution and returns the
	// 202 challenge entries, all sharing the served signingInput
	// (the input is key-independent; entries enumerate the keys the
	// kind could see in advance). Advisory only — verify-time
	// resolution is the authoritative key source.
	Challenges(ctx context.Context, identity *domain.VerifiedIdentity, signingInput string) ([]ProofChallenge, error)

	// VerifyProofs runs the kind's control proof over the submission
	// and returns the proven keys to seal. Every proof must pass —
	// one bad proof fails the call closed. Implementations never
	// consume the nonce; the service owns nonce/transaction
	// discipline so it stays uniform across kinds.
	VerifyProofs(ctx context.Context, identity *domain.VerifiedIdentity, sub ProofSubmission, signingInput string) ([]identityevent.ProvenKey, error)
}

// newControlVerifiers builds the kind registry. lei (vLEI), did:plc,
// did:ion, and did:ethr slot in here when their verifiers are real;
// until then domain.InferIdentifierKind may recognize a value's form
// but the missing registry entry yields IDENTIFIER_KIND_UNSUPPORTED.
func newControlVerifiers(resolver port.DIDResolver, leiCtl port.LEIControlVerifier) map[domain.IdentifierKind]controlVerifier {
	// NOTE: deliberately NOT exhaustive over IdentifierKind — a
	// recognized-but-absent kind (did:plc, did:ion, did:ethr, until
	// their verifiers ship) MUST fail with IDENTIFIER_KIND_UNSUPPORTED
	// rather than register a stub. The 404-is-the-signal rule. LEI
	// only registered when configured.
	m := map[domain.IdentifierKind]controlVerifier{
		domain.KindDIDWeb: &didWebVerifier{resolver: resolver},
		domain.KindDIDKey: &didKeyVerifier{},
	}
	if leiCtl != nil {
		m[domain.KindLEI] = &leiVerifier{v: leiCtl} // absent → IDENTIFIER_KIND_UNSUPPORTED
	}
	return m
}

// ----- shared JWS proof machinery -----
//
// Every JWS-scheme kind (did:web, did:key, did:plc, did:ion) shares
// the same proof envelope: standard compact JWSes whose payload
// segment equals the served signingInput verbatim, each naming its
// claimed key by `kid`. What differs per kind is only the
// authoritative key source, expressed as the selectKey callback.

// jwsProof is one parsed submission entry.
type jwsProof struct {
	jws    string
	header *anscrypto.JWSProtectedHeader
}

// parseJWSProofs validates the submission envelope: presence, batch
// bound, compact-JWS form, payload equality (BEFORE any signature
// work — clients never canonicalize), kid presence, kid uniqueness.
// Returns the parsed proofs plus the kid → embedded-jwk hints the
// noop resolver synthesizes documents from.
func parseJWSProofs(sub ProofSubmission, signingInput string) ([]jwsProof, []port.KeyHint, error) {
	proofs := sub.SignedProofs
	if len(proofs) == 0 {
		return nil, nil, domain.NewValidationError("IDENTIFIER_PROOF_INVALID", "signedProofs is required")
	}
	if len(proofs) > maxProofsPerVerify {
		return nil, nil, domain.NewValidationError("IDENTIFIER_PROOF_INVALID",
			fmt.Sprintf("at most %d proofs per call", maxProofsPerVerify))
	}

	parsed := make([]jwsProof, 0, len(proofs))
	hints := make([]port.KeyHint, 0, len(proofs))
	seenKids := make(map[string]bool, len(proofs))
	for i, jws := range proofs {
		header, payloadSeg, err := anscrypto.DecodeStandardJWS(jws)
		if err != nil {
			return nil, nil, domain.NewValidationError("IDENTIFIER_PROOF_INVALID",
				fmt.Sprintf("signedProofs[%d] is not a compact JWS", i))
		}
		if payloadSeg != signingInput {
			return nil, nil, domain.NewValidationError("PRICC_SIGNATURE_INVALID",
				fmt.Sprintf("signedProofs[%d] payload does not equal the served signingInput", i))
		}
		if header.Kid == "" {
			return nil, nil, domain.NewValidationError("DID_VERIFICATION_METHOD_INVALID",
				fmt.Sprintf("signedProofs[%d] names no kid", i))
		}
		if seenKids[header.Kid] {
			return nil, nil, domain.NewValidationError("IDENTIFIER_PROOF_INVALID",
				fmt.Sprintf("signedProofs[%d] duplicates kid %q", i, header.Kid))
		}
		seenKids[header.Kid] = true
		parsed = append(parsed, jwsProof{jws: jws, header: header})
		hints = append(hints, port.KeyHint{Kid: header.Kid, PublicKeyJWK: header.Jwk})
	}
	return parsed, hints, nil
}

// sealJWSProofs verifies each parsed proof against the key the
// kind's selectKey callback resolves for its kid, and returns the
// proven set: the kind's authoritative verification-method material
// quoted VERBATIM (never a derived, re-encoded, or normalized value)
// plus the registrant's proof. The alg is pinned to the key type
// inside the verifier (alg-confusion defense): ES256 ↔ P-256,
// EdDSA ↔ Ed25519, RS256 ↔ RSA.
func sealJWSProofs(
	parsed []jwsProof,
	did string,
	selectKey func(kid string) (any, json.RawMessage, error),
) ([]identityevent.ProvenKey, error) {
	proven := make([]identityevent.ProvenKey, 0, len(parsed))
	for i, p := range parsed {
		pub, sealVM, err := selectKey(p.header.Kid)
		if err != nil {
			return nil, err
		}
		if _, err := anscrypto.VerifyStandardJWSWithPublicKey(pub, p.jws); err != nil {
			return nil, domain.NewValidationError("PRICC_SIGNATURE_INVALID",
				fmt.Sprintf("signedProofs[%d] does not verify against %s's key %q", i, did, p.header.Kid))
		}
		proven = append(proven, identityevent.ProvenKey{
			VerificationMethod: sealVM,
			SignedProof:        p.jws,
		})
	}
	return proven, nil
}

// ----- did:web -----

// didWebVerifier proves control of a did:web identifier: possession
// of one or more keys the DID document lists under assertionMethod,
// any host (design §3.3/§3.6). The document fetch is the kind's only
// I/O and rides the injected resolver port (noop or hardened web).
type didWebVerifier struct {
	resolver port.DIDResolver
}

// Challenges runs the advisory fetch and enumerates the document's
// assertionMethod kids. With an unenumerable key set (the noop
// resolver before any proofs exist, or a document listing none), a
// single unkeyed entry tells the registrant to name keys via the
// JWS `kid` header at verify time.
func (v *didWebVerifier) Challenges(ctx context.Context, identity *domain.VerifiedIdentity, signingInput string) ([]ProofChallenge, error) {
	doc, err := v.resolver.Resolve(ctx, identity.EffectiveValue(), nil)
	if err != nil {
		return nil, err
	}
	if len(doc.AssertionMethod) == 0 {
		return []ProofChallenge{{SigningInput: signingInput}}, nil
	}
	challenges := make([]ProofChallenge, 0, len(doc.AssertionMethod))
	for _, vm := range doc.AssertionMethod {
		challenges = append(challenges, ProofChallenge{Kid: vm.ID, SigningInput: signingInput})
	}
	return challenges, nil
}

// VerifyProofs re-fetches the document authoritatively (the
// verify-time document is the key source — §3.6) and checks each
// proof against its named assertionMethod: the kid must be a
// fragment of THIS DID, the method must carry no cross-controller
// indirection, and the key must parse under the supported types.
// Seals the document's verification-method objects verbatim.
func (v *didWebVerifier) VerifyProofs(ctx context.Context, identity *domain.VerifiedIdentity, sub ProofSubmission, signingInput string) ([]identityevent.ProvenKey, error) {
	parsed, hints, err := parseJWSProofs(sub, signingInput)
	if err != nil {
		return nil, err
	}
	did := identity.EffectiveValue()
	doc, err := v.resolver.Resolve(ctx, did, hints)
	if err != nil {
		return nil, err
	}
	if doc.ID != did {
		return nil, domain.NewValidationError("DID_DOCUMENT_ID_MISMATCH",
			fmt.Sprintf("resolved document id %q does not match %q", doc.ID, did))
	}
	return sealJWSProofs(parsed, did, func(kid string) (any, json.RawMessage, error) {
		if !strings.HasPrefix(kid, did+"#") {
			return nil, nil, domain.NewValidationError("DID_VERIFICATION_METHOD_INVALID",
				fmt.Sprintf("kid %q is not a fragment of %q", kid, did))
		}
		vm := doc.FindAssertionMethod(kid)
		if vm == nil {
			return nil, nil, domain.NewValidationError("DID_VERIFICATION_METHOD_INVALID",
				fmt.Sprintf("kid %q is not an assertionMethod of %q", kid, did))
		}
		if vm.Controller != "" && vm.Controller != did {
			return nil, nil, domain.NewValidationError("DID_VERIFICATION_METHOD_INVALID",
				fmt.Sprintf("verification method %q is controlled by %q, not %q", kid, vm.Controller, did))
		}
		var pub any
		switch {
		case len(vm.PublicKeyJwk) > 0:
			pub, err = anscrypto.ParseJWK(vm.PublicKeyJwk)
		case vm.PublicKeyMultibase != "":
			pub, err = anscrypto.DecodeMultibase(vm.PublicKeyMultibase)
		default:
			return nil, nil, domain.NewValidationError("DID_VERIFICATION_METHOD_INVALID",
				fmt.Sprintf("verification method %q carries no key material", kid))
		}
		if err != nil {
			return nil, nil, domain.NewValidationError("DID_VERIFICATION_METHOD_INVALID", err.Error())
		}
		return pub, vm.Raw, nil
	})
}

// ----- did:key -----

// didKeyVerifier proves control of a did:key identifier — the key
// IS the identifier, decoded from the DID string with zero I/O.
// The keyless-future test track (§2.2): any kind whose key material
// is self-contained follows this shape.
type didKeyVerifier struct{}

// Challenges decodes the DID and returns its single legal kid,
// {did}#{method-specific-id}.
func (v *didKeyVerifier) Challenges(_ context.Context, identity *domain.VerifiedIdentity, signingInput string) ([]ProofChallenge, error) {
	_, kid, err := anscrypto.DecodeDIDKey(identity.EffectiveValue())
	if err != nil {
		return nil, domain.NewValidationError("DID_BAD_FORMAT", err.Error())
	}
	return []ProofChallenge{{Kid: kid, SigningInput: signingInput}}, nil
}

// VerifyProofs decodes the key from the identifier and verifies the
// (single-key) proof set against it. The sealed verification method
// is the did:key method's derived Multikey entry; its key material
// (publicKeyMultibase) is the method-specific id quoted verbatim
// from the identifier itself.
func (v *didKeyVerifier) VerifyProofs(_ context.Context, identity *domain.VerifiedIdentity, sub ProofSubmission, signingInput string) ([]identityevent.ProvenKey, error) {
	parsed, _, err := parseJWSProofs(sub, signingInput)
	if err != nil {
		return nil, err
	}
	did := identity.EffectiveValue()
	pub, expectedKid, err := anscrypto.DecodeDIDKey(did)
	if err != nil {
		return nil, domain.NewValidationError("DID_BAD_FORMAT", err.Error())
	}
	sealVM, err := json.Marshal(map[string]string{
		"id":                 expectedKid,
		"type":               "Multikey",
		"controller":         did,
		"publicKeyMultibase": strings.TrimPrefix(did, "did:key:"),
	})
	if err != nil {
		return nil, domain.NewInternalError("PROOF_SEAL", "could not build did:key verification method", err)
	}
	return sealJWSProofs(parsed, did, func(kid string) (any, json.RawMessage, error) {
		if kid != expectedKid {
			return nil, nil, domain.NewValidationError("DID_VERIFICATION_METHOD_INVALID",
				fmt.Sprintf("kid %q is not the did:key verification method %q", kid, expectedKid))
		}
		return pub, sealVM, nil
	})
}
