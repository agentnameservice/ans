package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
	identityevent "github.com/agentnameservice/ans/internal/tl/event/identity"
)

// webBotAuthVerifier is the web-bot-auth controlVerifier — the per-kind
// gate behind the web-bot-auth identifier kind. It proves that the
// Signature-Agent URL genuinely endorses the key the registrant signs
// with, by making TWO gates pass together:
//
//   - possession — a compact JWS over the served signingInput verifies
//     against a key (the JWS proof, the did:key/did:web analog), and
//   - endorsement — that key is a member of the JWKS the URL's HTTP
//     Message Signatures directory serves (the directory fetch, the
//     did:web document-resolution analog).
//
// The directory is authoritative: the key sealed and verified against is
// the entry located in the RESOLVED directory (by RFC 7638 thumbprint),
// never the self-asserted `jwk` in the proof header — that header key is
// a resolution hint only (the noop resolver synthesizes the endorsed set
// from it for the quickstart). This mirrors didWebVerifier, where the
// resolved document — not the proof — is the key source.
//
// The fetch target is the identifier's canonical value: the well-known
// directory URL (domain.canonicalizeWebBotAuthURL), so any verifier
// reproduces the same fetch. web-bot-auth is Ed25519-only; a proof
// naming any other algorithm or a directory key of any other type is
// rejected (alg-confusion defense).
type webBotAuthVerifier struct {
	resolver port.WebBotAuthDirectoryResolver
	// clock sources the wall-clock used to test each directory key's
	// nbf/exp window. Injected so the service's WithClock override drives
	// window decisions deterministically in tests.
	clock  func() time.Time
	logger zerolog.Logger
}

// now returns the current time through the injected clock, defaulting to
// the wall clock when unset (a zero-value verifier is still usable).
func (v *webBotAuthVerifier) now() time.Time {
	if v.clock != nil {
		return v.clock().UTC()
	}
	return time.Now().UTC()
}

// Challenges runs the advisory directory fetch and enumerates the
// endorsed keys' thumbprints as the offered `kid`s. The fetch is
// advisory only — the verify-time fetch is authoritative — so a failure
// is tolerated: the registrant then receives a single unkeyed entry and
// names keys via the JWS `kid`/`jwk` headers at verify time (the noop
// DID resolver analog). A directory key whose type has no RFC 7638
// thumbprint here (non-Ed25519) is skipped: it can never be a
// web-bot-auth kid.
func (v *webBotAuthVerifier) Challenges(ctx context.Context, identity *domain.VerifiedIdentity, signingInput string) ([]ProofChallenge, error) {
	value := identity.EffectiveValue()
	keys, err := v.resolver.Resolve(ctx, value, nil)
	if err != nil {
		v.logger.Debug().
			Err(err).
			Str("identityId", identity.IdentityID).
			Msg("web-bot-auth advisory directory fetch failed; offering a single unkeyed challenge")
		return []ProofChallenge{{SigningInput: signingInput}}, nil
	}
	challenges := make([]ProofChallenge, 0, len(keys))
	for _, k := range keys {
		tp, terr := anscrypto.JWKThumbprint(k.JWK)
		if terr != nil {
			continue
		}
		challenges = append(challenges, ProofChallenge{Kid: tp, SigningInput: signingInput})
	}
	if len(challenges) == 0 {
		return []ProofChallenge{{SigningInput: signingInput}}, nil
	}
	return challenges, nil
}

// VerifyProofs runs the web-bot-auth control proof. It parses the JWS
// envelope (payload equality checked BEFORE any signature work),
// authoritatively fetches the directory at the canonical value, and
// seals the INTERSECTION of possession-proven and directory-endorsed
// keys: a proof whose key the directory does not currently endorse is
// DROPPED (mid-rotation tolerance), not fatal, but at least one proof
// must match. Each sealed key is the directory JWK verbatim; the JWS is
// verified against it, so the seal is self-verifying.
func (v *webBotAuthVerifier) VerifyProofs(ctx context.Context, identity *domain.VerifiedIdentity, sub ProofSubmission, signingInput string) ([]identityevent.ProvenKey, error) {
	parsed, hints, err := parseJWSProofs(sub, signingInput)
	if err != nil {
		return nil, err
	}
	value := identity.EffectiveValue()
	keys, err := v.resolver.Resolve(ctx, value, hints)
	if err != nil {
		// Retryable 503-class from the resolver — propagated as-is so the
		// handler renders a retryable Problem, never a 500.
		return nil, err
	}

	// Index the endorsed keys by RECOMPUTED thumbprint (never the kid
	// string a directory entry might carry), skipping keys outside their
	// validity window and keys whose type has no thumbprint (non-Ed25519,
	// which can never be a web-bot-auth kid). First-wins on a degenerate
	// duplicate thumbprint.
	now := v.now()
	byThumbprint := make(map[string]port.DirectoryKey, len(keys))
	for _, k := range keys {
		if !withinKeyWindow(k, now) {
			continue
		}
		tp, terr := anscrypto.JWKThumbprint(k.JWK)
		if terr != nil {
			continue
		}
		if _, dup := byThumbprint[tp]; dup {
			continue
		}
		byThumbprint[tp] = k
	}

	// Keep only the proofs whose kid names a currently-endorsed key. A
	// dropped proof is a benign mid-rotation artifact (the registrant
	// still holds a key the directory has since retired), logged at DEBUG
	// but never fatal.
	matched := make([]jwsProof, 0, len(parsed))
	for _, p := range parsed {
		if _, ok := byThumbprint[p.header.Kid]; !ok {
			v.logger.Debug().
				Str("identityId", identity.IdentityID).
				Str("kid", p.header.Kid).
				Msg("web-bot-auth proof names a key the directory does not endorse; dropping")
			continue
		}
		// web-bot-auth is Ed25519-only: reject any other JWS algorithm
		// outright (alg-confusion defense) rather than relying on the
		// key-type check inside the verify step alone.
		if p.header.Alg != anscrypto.AlgEdDSA {
			return nil, domain.NewValidationError("IDENTIFIER_PROOF_INVALID",
				fmt.Sprintf("web-bot-auth requires alg %q, got %q", anscrypto.AlgEdDSA, p.header.Alg))
		}
		// The embedded `jwk` header is a hint only, but when present it
		// MUST be the key we located: its RFC 7638 thumbprint must equal
		// the kid (the encoding-independent form of "the hint is the
		// endorsed key"; byte-equality holds by construction on the noop
		// path, where the directory key IS the hint's bytes). This also
		// enforces the web-bot-auth `kid == thumbprint(jwk)` rule.
		if len(p.header.Jwk) > 0 {
			tp, terr := anscrypto.JWKThumbprint(p.header.Jwk)
			if terr != nil || tp != p.header.Kid {
				return nil, domain.NewValidationError("IDENTIFIER_PROOF_INVALID",
					fmt.Sprintf("embedded jwk for kid %q is not that key", p.header.Kid))
			}
		}
		matched = append(matched, p)
	}
	if len(matched) == 0 {
		return nil, domain.NewValidationError("IDENTIFIER_PROOF_INVALID",
			"no submitted proof matched a key the directory currently endorses")
	}

	// Verify and seal the matched proofs against the DIRECTORY keys
	// (never the header jwk) through the shared machinery. The sealed
	// verification method is an object carrying the directory JWK
	// verbatim, so the event stays self-verifying.
	proven, err := sealJWSProofs(matched, value, func(kid string) (any, json.RawMessage, error) {
		dk := byThumbprint[kid]
		pub, perr := anscrypto.ParseJWK(dk.JWK)
		if perr != nil {
			return nil, nil, domain.NewValidationError("IDENTIFIER_PROOF_INVALID",
				fmt.Sprintf("directory key for kid %q did not parse: %v", kid, perr))
		}
		vm, verr := buildWebBotAuthVM(value, kid, dk.JWK)
		if verr != nil {
			return nil, nil, domain.NewInternalError("PROOF_SEAL",
				"could not build web-bot-auth verification method", verr)
		}
		return pub, vm, nil
	})
	if err != nil {
		return nil, err
	}
	v.logger.Info().
		Str("identityId", identity.IdentityID).
		Int("provenKeys", len(proven)).
		Msg("web-bot-auth control proofs verified against the directory")
	return proven, nil
}

// withinKeyWindow reports whether now falls inside a directory key's
// optional nbf/exp validity window. A zero bound is unbounded on that
// side.
func withinKeyWindow(k port.DirectoryKey, now time.Time) bool {
	if !k.NotBefore.IsZero() && now.Before(k.NotBefore) {
		return false
	}
	if !k.NotAfter.IsZero() && now.After(k.NotAfter) {
		return false
	}
	return true
}

// buildWebBotAuthVM renders the sealed verification method for a
// web-bot-auth proven key: an object whose `id` is "<value>#<thumbprint>"
// (a non-empty id the TL codec requires — event.go validateProofFields)
// and whose `publicKeyJwk` is the directory JWK VERBATIM (nothing
// derived or re-encoded enters a seal).
func buildWebBotAuthVM(value, thumbprint string, jwk json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(struct {
		ID           string          `json:"id"`
		Type         string          `json:"type"`
		PublicKeyJwk json.RawMessage `json:"publicKeyJwk"`
	}{
		ID:           value + "#" + thumbprint,
		Type:         "JsonWebKey2020",
		PublicKeyJwk: jwk,
	})
}

// compile-time conformance.
var _ controlVerifier = (*webBotAuthVerifier)(nil)
