package domain

import (
	"fmt"
	"strings"
	"time"
)

// IdentifierKind classifies a verified identity's identifier scheme.
// The set is spec-frozen: adding a kind is an ANS-spec amendment plus
// a per-kind control-proof implementation, never just a new string.
type IdentifierKind string

// Identifier kinds. A kind being *recognized* here is independent of
// it being *enabled* — the service layer dispatches per kind and
// returns IDENTIFIER_KIND_UNSUPPORTED for kinds this deployment has
// no control verifier for (lei is recognized but postponed).
const (
	// KindDIDWeb — did:web. The authoritative keys live in the DID
	// document fetched from the operator's web host; control is
	// possession of the document's assertionMethod keys.
	KindDIDWeb IdentifierKind = "did:web"

	// KindDIDKey — did:key. The key IS the identifier (decoded from
	// the DID string); zero I/O, pure key possession.
	KindDIDKey IdentifierKind = "did:key"

	// KindLEI — an ISO 17442 Legal Entity Identifier, proven through
	// a vLEI credential presentation. Postponed: recognized so the
	// error is precise, but no control verifier ships yet.
	KindLEI IdentifierKind = "lei"
)

// IdentityStatus is the verified-identity lifecycle state.
type IdentityStatus string

// Identity lifecycle states. The machine is deliberately tiny:
//
//	PENDING_CONTROL → VERIFIED → REVOKED
//
// with VERIFIED → VERIFIED on rotation (a staged replacement proves
// control again before anything changes — the previously sealed
// state stands until the new proof lands).
const (
	IdentityPendingControl IdentityStatus = "PENDING_CONTROL"
	IdentityVerified       IdentityStatus = "VERIFIED"
	IdentityRevoked        IdentityStatus = "REVOKED"
)

// IdentityChallenge is the single-use anti-replay nonce issued at
// register / rotate time. The registrant signs the served
// IdentityProofInput (which embeds this nonce); the nonce is consumed
// exactly once, inside the success transaction of verify-control —
// a failed verification attempt does NOT consume it, so a registrant
// may retry a bad proof until expiry.
type IdentityChallenge struct {
	// Nonce is the base64url-encoded 32-byte random value.
	Nonce string
	// ExpiresAt bounds the challenge's validity.
	ExpiresAt time.Time
	// ConsumedAt is set when a verify-control succeeded against this
	// nonce. A consumed nonce can never verify again.
	ConsumedAt *time.Time
}

// VerifiedIdentity is the "who" aggregate — an identity owned by a
// providerId, proven through a per-kind control proof, sealed onto
// its own Transparency Log stream, and linked to any number of that
// owner's agents. It is NOT part of AgentRegistration: the agent (the
// "what") carries no identity fields, and the two lifecycles never
// cascade into each other.
//
// No public-key field lives on this aggregate (ANS-0 §6.2 key
// transience): proven keys are sealed in the identity's TL events,
// not persisted as live state.
type VerifiedIdentity struct {
	// IdentityID is the RA-assigned UUIDv7 — the TL stream key.
	IdentityID string
	// ProviderID is the owning authentication principal — the same
	// principal that owns the agents this identity may link to.
	ProviderID string
	Kind       IdentifierKind
	// Value is the canonical identifier (e.g.
	// "did:web:identity.acme-corp.com").
	Value  string
	Status IdentityStatus
	// ProofMethod names the control proof that verified this
	// identity ("did-web-sig" | "did-key-sig"). Empty until the
	// first successful verify-control.
	ProofMethod string
	// PendingValue stages a same-kind replacement during rotation
	// (§4.2): set by StageRotation, applied by CompleteVerification.
	// While staged, the previously sealed state stands.
	PendingValue string
	// SubjectAID is the lei (vLEI) holder AID the verifier extracted
	// from the presentation at register time and the RA pinned on the
	// aggregate — the signer the verify-control proof is checked
	// against (§3.6 pinning rule; the caller never re-supplies it).
	// Empty for kinds with no register-time presentation (did:web,
	// did:key).
	SubjectAID string
	// Challenge is the live anti-replay nonce, if any.
	Challenge  *IdentityChallenge
	VerifiedAt time.Time // zero until first proof
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// proofMethodForKind maps a kind to its sealed proofMethod token.
func proofMethodForKind(kind IdentifierKind) string {
	switch kind {
	case KindDIDWeb:
		return "did-web-sig"
	case KindDIDKey:
		return "did-key-sig"
	case KindLEI:
		return "lei-vlei-acdc"
	default:
		return ""
	}
}

// ProofMethodForKind exposes the kind → proofMethod mapping for the
// service layer's event builder.
func ProofMethodForKind(kind IdentifierKind) string { return proofMethodForKind(kind) }

// InferIdentifierKind lexically classifies a raw identifier value and
// returns its canonical form. Kind inference is pure dispatch — it
// proves nothing; the per-kind control proof is the gate.
func InferIdentifierKind(raw string) (IdentifierKind, string, error) {
	value := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(value, "did:web:"):
		canonical, err := canonicalizeDIDWeb(value)
		if err != nil {
			return "", "", err
		}
		return KindDIDWeb, canonical, nil
	case strings.HasPrefix(value, "did:key:"):
		if len(value) <= len("did:key:") {
			return "", "", NewValidationError("DID_BAD_FORMAT", "did:key value is empty")
		}
		return KindDIDKey, value, nil
	case isLEI(value):
		return KindLEI, strings.ToUpper(value), nil
	case strings.HasPrefix(value, "did:"):
		// A well-formed DID of a method we don't dispatch yet
		// (did:plc, did:ion, did:ethr, …) — name the method so the
		// caller learns exactly what's missing, not just "no kind".
		// Adding a method = a dispatch arm here (canonicalization
		// rules are per-method) + a controlVerifier registration in
		// the service's identitykinds registry.
		method := value[len("did:"):]
		if i := strings.IndexByte(method, ':'); i > 0 {
			method = method[:i]
		}
		return "", "", NewValidationError("IDENTIFIER_KIND_UNSUPPORTED",
			fmt.Sprintf("did method %q is not supported (supported: did:web, did:key)", method))
	default:
		return "", "", NewValidationError("IDENTIFIER_KIND_UNSUPPORTED",
			fmt.Sprintf("identifier %q matches no supported kind (did:web, did:key, lei)", value))
	}
}

// isLEI reports whether the value is shaped like an ISO 17442 LEI:
// exactly 20 alphanumeric characters. (The mod-97 check digit and the
// GLEIF status precondition belong to the lei control verifier, which
// is postponed — this is lexical dispatch only.)
func isLEI(value string) bool {
	if len(value) != 20 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		default:
			return false
		}
	}
	return true
}

// canonicalizeDIDWeb validates a did:web identifier and returns its
// canonical form (host lowercased; path segments preserved).
//
// v1 restrictions (each rejected with DID_BAD_FORMAT):
//   - no port (the did:web encoding of a port is %3A — fetches are
//     pinned to 443),
//   - no userinfo,
//   - no percent-encoded characters at all (did:web allows them in
//     path segments; v1 keeps the grammar strict so the resolution
//     URL is byte-derivable from the DID),
//   - host must be a plausible DNS name (letters, digits, hyphens,
//     dots; no leading/trailing hyphen or dot in a label).
func canonicalizeDIDWeb(value string) (string, error) {
	rest := strings.TrimPrefix(value, "did:web:")
	if rest == "" {
		return "", NewValidationError("DID_BAD_FORMAT", "did:web value is empty")
	}
	if strings.Contains(rest, "%") {
		return "", NewValidationError("DID_BAD_FORMAT",
			"did:web with percent-encoded characters (including ports, %3A) is not supported")
	}
	if strings.Contains(rest, "@") {
		return "", NewValidationError("DID_BAD_FORMAT", "did:web must not carry userinfo")
	}
	if strings.Contains(rest, "/") {
		return "", NewValidationError("DID_BAD_FORMAT",
			"did:web path segments are separated by ':' in the DID, not '/'")
	}
	segments := strings.Split(rest, ":")
	host := strings.ToLower(segments[0])
	if err := validateDNSHost(host); err != nil {
		return "", err
	}
	for _, seg := range segments[1:] {
		if seg == "" {
			return "", NewValidationError("DID_BAD_FORMAT", "did:web has an empty path segment")
		}
		// Dot segments would re-path the resolution URL; control
		// bytes (NUL first among them) have no legitimate use in a
		// path segment. The same parsed segments feed both the
		// resolution URL and the SSRF dialer check (§3.6/§3.7), so
		// the rejection happens exactly once, here.
		if seg == "." || seg == ".." {
			return "", NewValidationError("DID_BAD_FORMAT",
				"did:web path segments must not be '.' or '..'")
		}
		for _, r := range seg {
			if r < 0x20 || r == 0x7f {
				return "", NewValidationError("DID_BAD_FORMAT",
					"did:web path segment contains a control character")
			}
		}
	}
	canonical := "did:web:" + host
	if len(segments) > 1 {
		canonical += ":" + strings.Join(segments[1:], ":")
	}
	return canonical, nil
}

// validateDNSHost applies conservative DNS-name validation to the
// did:web host portion.
func validateDNSHost(host string) error {
	if host == "" || len(host) > 253 {
		return NewValidationError("DID_BAD_FORMAT", "did:web host is empty or too long")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return NewValidationError("DID_BAD_FORMAT",
				fmt.Sprintf("did:web host %q has an invalid label", host))
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return NewValidationError("DID_BAD_FORMAT",
				fmt.Sprintf("did:web host label %q must not start or end with '-'", label))
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			default:
				return NewValidationError("DID_BAD_FORMAT",
					fmt.Sprintf("did:web host %q contains invalid character %q", host, r))
			}
		}
	}
	return nil
}

// DIDWebResolutionURL maps a canonical did:web identifier to the URL
// its DID document resolves at, per the did:web method spec:
//
//	did:web:example.com           → https://example.com/.well-known/did.json
//	did:web:example.com:user:al   → https://example.com/user/al/did.json
//
// Pure function — the hardened fetcher in the adapter layer owns the
// actual I/O and its SSRF posture.
func DIDWebResolutionURL(canonicalValue string) (string, error) {
	if !strings.HasPrefix(canonicalValue, "did:web:") {
		return "", NewValidationError("DID_BAD_FORMAT", "not a did:web identifier")
	}
	segments := strings.Split(strings.TrimPrefix(canonicalValue, "did:web:"), ":")
	host := segments[0]
	if host == "" {
		return "", NewValidationError("DID_BAD_FORMAT", "did:web host is empty")
	}
	if len(segments) == 1 {
		return "https://" + host + "/.well-known/did.json", nil
	}
	return "https://" + host + "/" + strings.Join(segments[1:], "/") + "/did.json", nil
}

// NewVerifiedIdentity constructs a fresh identity in PENDING_CONTROL.
// The caller supplies the RA-assigned identityID (UUIDv7) and the
// authenticated owner; the raw value is kind-inferred and
// canonicalized here so every code path shares one grammar.
func NewVerifiedIdentity(identityID, providerID, rawValue string, now time.Time) (*VerifiedIdentity, error) {
	if identityID == "" {
		return nil, NewValidationError("INVALID_IDENTITY_ID", "identityId is required")
	}
	if providerID == "" {
		return nil, NewValidationError("INVALID_PROVIDER_ID", "providerId is required")
	}
	kind, canonical, err := InferIdentifierKind(rawValue)
	if err != nil {
		return nil, err
	}
	return &VerifiedIdentity{
		IdentityID: identityID,
		ProviderID: providerID,
		Kind:       kind,
		Value:      canonical,
		Status:     IdentityPendingControl,
		CreatedAt:  now.UTC(),
		UpdatedAt:  now.UTC(),
	}, nil
}

// IssueChallenge mints a fresh anti-replay nonce, superseding any
// prior one (idempotent re-add, §4.2: a re-POST while PENDING_CONTROL
// returns the same identity with a fresh challenge). Valid while the
// identity is PENDING_CONTROL (initial proof) or VERIFIED (rotation
// re-proof); a revoked identity can never be challenged again.
func (v *VerifiedIdentity) IssueChallenge(nonce string, ttl time.Duration, now time.Time) error {
	if v.Status == IdentityRevoked {
		return NewInvalidStateError("IDENTITY_REVOKED",
			"a revoked identity cannot be re-challenged")
	}
	if nonce == "" {
		return NewValidationError("INVALID_CHALLENGE", "challenge nonce is required")
	}
	if ttl <= 0 {
		return NewValidationError("INVALID_CHALLENGE", "challenge ttl must be positive")
	}
	v.Challenge = &IdentityChallenge{
		Nonce:     nonce,
		ExpiresAt: now.UTC().Add(ttl),
	}
	v.UpdatedAt = now.UTC()
	return nil
}

// CheckChallenge reports whether the live challenge can still be
// proven against: present, unconsumed, unexpired. It does NOT consume
// — consumption is a storage-level conditional update inside the
// verify-control success transaction (the TOCTOU guard).
func (v *VerifiedIdentity) CheckChallenge(now time.Time) error {
	switch {
	case v.Challenge == nil:
		return NewInvalidStateError("IDENTIFIER_CHALLENGE_EXPIRED",
			"no active challenge; re-register the identifier to receive a fresh one")
	case v.Challenge.ConsumedAt != nil:
		return NewInvalidStateError("PRICC_TOKEN_ALREADY_USED",
			"challenge nonce already consumed")
	case !now.Before(v.Challenge.ExpiresAt):
		return NewInvalidStateError("PRICC_TOKEN_EXPIRED",
			"challenge nonce expired; re-register the identifier to receive a fresh one")
	default:
		return nil
	}
}

// EffectiveValue is the identifier the current proof round is over:
// the staged replacement during a rotation, otherwise the proven
// value.
func (v *VerifiedIdentity) EffectiveValue() string {
	if v.PendingValue != "" {
		return v.PendingValue
	}
	return v.Value
}

// StageRotation stages a same-kind replacement value (§4.2 PUT). The
// row stays VERIFIED with the old value — nothing changes until the
// replacement proves control. Cross-kind replacement is rejected
// (remove + add, not a rotation).
func (v *VerifiedIdentity) StageRotation(rawValue string, now time.Time) error {
	if v.Status != IdentityVerified {
		return NewInvalidStateError("IDENTITY_NOT_VERIFIED",
			fmt.Sprintf("rotation requires a VERIFIED identity, status is %s", v.Status))
	}
	kind, canonical, err := InferIdentifierKind(rawValue)
	if err != nil {
		return err
	}
	if kind != v.Kind {
		return NewValidationError("IDENTIFIER_KIND_MISMATCH",
			fmt.Sprintf("cannot rotate a %s identity to %s; revoke and register a new identity", v.Kind, kind))
	}
	v.PendingValue = canonical
	v.UpdatedAt = now.UTC()
	return nil
}

// SetSubjectAID pins the lei holder AID the verifier derived from the
// presentation (§3.6). Rejects an empty AID — pinning a blank signer
// would let any key satisfy verify-control.
func (v *VerifiedIdentity) SetSubjectAID(aid string, now time.Time) error {
	if aid == "" {
		return NewValidationError("LEI_PRESENTATION_INVALID", "subject AID is required")
	}
	v.SubjectAID = aid
	v.UpdatedAt = now.UTC()
	return nil
}

// CompleteVerification applies a successful control proof:
//
//   - PENDING_CONTROL → VERIFIED (first proof; seals IDENTITY_VERIFIED)
//   - VERIFIED with a staged rotation → swap the value (seals
//     IDENTITY_UPDATED)
//   - VERIFIED without a staged rotation → re-proof of the current
//     value (also seals IDENTITY_UPDATED — the proven key set may
//     have changed even when the value did not)
//
// Returns the previous value when the proof completes a rotation that
// changed the identifier (for the sealed event's previousValue).
func (v *VerifiedIdentity) CompleteVerification(now time.Time) (string, error) {
	previousValue := ""
	switch v.Status {
	case IdentityPendingControl:
		v.Status = IdentityVerified
	case IdentityVerified:
		if v.PendingValue != "" && v.PendingValue != v.Value {
			previousValue = v.Value
			v.Value = v.PendingValue
		}
	case IdentityRevoked:
		return "", NewInvalidStateError("IDENTITY_REVOKED",
			"a revoked identity cannot be verified")
	default:
		return "", NewInvalidStateError("IDENTITY_INVALID_STATE",
			fmt.Sprintf("unexpected identity status %s", v.Status))
	}
	v.PendingValue = ""
	v.ProofMethod = proofMethodForKind(v.Kind)
	v.VerifiedAt = now.UTC()
	v.UpdatedAt = now.UTC()
	return previousValue, nil
}

// Revoke transitions a VERIFIED identity to REVOKED — a state change,
// never a delete: the identity's history is append-only in the TL.
// Revoking an unproven (PENDING_CONTROL) identity is rejected — it
// never sealed anything, so there is nothing to revoke; its challenge
// simply expires.
func (v *VerifiedIdentity) Revoke(now time.Time) error {
	if v.Status != IdentityVerified {
		return NewInvalidStateError("IDENTITY_NOT_VERIFIED",
			fmt.Sprintf("revocation requires a VERIFIED identity, status is %s", v.Status))
	}
	v.Status = IdentityRevoked
	v.PendingValue = ""
	v.Challenge = nil
	v.UpdatedAt = now.UTC()
	return nil
}

// LinkStatus is the lifecycle state of one identity↔agent
// association.
type LinkStatus string

// Link states. UNLINKED rows are history caches — the sealed
// IDENTITY_UNLINKED event is the authoritative record — and never
// block re-linking.
const (
	LinkLinked   LinkStatus = "LINKED"
	LinkUnlinked LinkStatus = "UNLINKED"
)

// IdentityLink associates a verified identity with one agent of the
// same owner. It is the only thing that touches an agent — a row plus
// a sealed event on the IDENTITY stream, never a field on the
// registration aggregate. Links carry no proof: within one owner a
// link asserts a fact the owner gate already establishes (§4.3).
type IdentityLink struct {
	IdentityID string
	AgentID    string
	Status     LinkStatus
	LinkedAt   time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
