package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	identityevent "github.com/godaddy/ans/internal/tl/event/identity"
)

// maxProofsPerVerify bounds the multi-key proof set on one
// verify-control call. did:web legitimately proves several
// assertionMethod keys; sixteen is far beyond any real document while
// keeping the request body and the sealed event bounded.
const maxProofsPerVerify = 16

// maxLinkBatch bounds one link call. The design allows the RA to
// chunk very large fleets to bound leaf size; rather than silently
// chunking, v1 rejects oversized batches and lets the caller chunk —
// every accepted call still seals exactly one event.
const maxLinkBatch = 256

// sealClaimTTL bounds the provisional verify-control claim taken
// across the seal-before-success TL round trip: a claim older than
// this (a crashed claimer) is reclaimable. Comfortably above the
// seal timeout, comfortably below the nonce TTL.
const sealClaimTTL = 30 * time.Second

// defaultSealTimeout bounds the inline TL seal call (§5.6.1) —
// parity with the outbound-fetch budget (§3.7).
const defaultSealTimeout = 5 * time.Second

// IdentityEventSealer submits one producer-signed identity event to
// the TL's IDENTITY ingest lane and returns only after the TL
// acknowledges the seal — the dependency seal-before-success (design
// §5.6.1) hangs on. Identity events never ride the outbox: delivery
// precedes success, a failed delivery IS a failed operation, and
// there is nothing for a background worker to retry (retrying would
// seal an event whose row transition never happened). Implementations
// map failures to domain error kinds (ErrUnavailable for transient).
type IdentityEventSealer interface {
	SealIdentityEvent(ctx context.Context, innerCanonical []byte, producerSig string) error
}

// ProofChallenge is one entry of the 202 challenge list: a key the
// registrant may prove, plus the exact base64url signing input a
// compact JWS over it must carry as its payload segment. Every entry
// of one round shares the same nonce and the same signing input —
// the input is key-independent.
//
// Kid is empty when the resolver could not enumerate keys (the noop
// resolver before any proofs exist): the registrant then names keys
// via the JWS `kid` header at verify time.
type ProofChallenge struct {
	Kid          string
	SigningInput string
}

// IdentityChallengeResponse is returned by Register and Rotate — the
// service half of the 202 body.
type IdentityChallengeResponse struct {
	Identity   *domain.VerifiedIdentity
	Nonce      string
	ExpiresAt  time.Time
	Challenges []ProofChallenge
	// PresentationStatus is the advisory register-time status a kind
	// with a register-time presentation reports ("AUTHORIZED" |
	// "PENDING"); empty for kinds without one (did:web, did:key). The
	// handler emits it on the 202 only when set.
	PresentationStatus port.PresentationStatus
}

// IdentityService owns the Verified Identity lifecycle: register →
// verify-control → (rotate | revoke), plus the owner-gated link
// surface. One service, one aggregate; the only per-kind branching is
// the control-proof dispatch in verify-control (and the advisory
// resolution at register), per the design's minimal-abstraction rule.
type IdentityService struct {
	identities port.IdentityStore
	links      port.IdentityLinkStore
	agents     port.AgentStore
	sealer     IdentityEventSealer
	uow        port.UnitOfWork
	signer     *EventSigner

	// verifiers is the per-kind control-proof registry — THE
	// extension seam (see identitykinds.go). A kind is enabled iff
	// it has an entry here.
	verifiers map[domain.IdentifierKind]controlVerifier

	challengeTTL time.Duration
	sealTimeout  time.Duration
	limiter      *ownerLimiter
	linkLimiter  *ownerLimiter
	logger       zerolog.Logger
	clock        func() time.Time
	newID        func() (string, error)
	newNonce     func() (string, error)
}

// NewIdentityService constructs an IdentityService. A nil sealer
// fails every sealing operation closed with TL_UNAVAILABLE — the
// seal-before-success rule (§5.6.1) admits no "seal later" mode.
func NewIdentityService(
	identities port.IdentityStore,
	links port.IdentityLinkStore,
	agents port.AgentStore,
	resolver port.DIDResolver,
	sealer IdentityEventSealer,
	leiCtl port.LEIControlVerifier,
	uow port.UnitOfWork,
) *IdentityService {
	return &IdentityService{
		identities:   identities,
		links:        links,
		agents:       agents,
		verifiers:    newControlVerifiers(resolver, leiCtl),
		sealer:       sealer,
		uow:          uow,
		challengeTTL: time.Hour,
		sealTimeout:  defaultSealTimeout,
		limiter:      newOwnerLimiter(defaultRegisterPerMinute),
		linkLimiter:  newOwnerLimiter(defaultLinkPerMinute),
		logger:       zerolog.Nop(),
		clock:        time.Now,
		newID: func() (string, error) {
			id, err := uuid.NewV7()
			if err != nil {
				return "", err
			}
			return id.String(), nil
		},
		newNonce: func() (string, error) {
			var b [32]byte
			if _, err := rand.Read(b[:]); err != nil {
				return "", err
			}
			return base64.RawURLEncoding.EncodeToString(b[:]), nil
		},
	}
}

// WithLogger attaches the structured logger used at the seal
// boundary (default: a no-op logger). The identity lane seals
// synchronously, so — unlike the agent lane's outbox worker — there
// is no background component to log TL failures; this is where the
// operator's signal for TL_REJECTED_EVENT / TL_UNAVAILABLE comes
// from.
func (s *IdentityService) WithLogger(logger zerolog.Logger) *IdentityService {
	s.logger = logger.With().Str("component", "identity-service").Logger()
	return s
}

// WithSigner attaches the producer event signer (same KeyManager +
// keyID + raID tuple the registration service signs with — one RA,
// one producer identity).
func (s *IdentityService) WithSigner(sig EventSigner) *IdentityService {
	s.signer = &sig
	return s
}

// WithChallengeTTL overrides the nonce TTL (default 1h; the design
// floor for high-assurance deployments is 5m).
func (s *IdentityService) WithChallengeTTL(ttl time.Duration) *IdentityService {
	if ttl > 0 {
		s.challengeTTL = ttl
	}
	return s
}

// WithRegisterRateLimit overrides the per-owner register/rotate rate
// limit (default 10/min). Register and rotate trigger an outbound
// fetch for did:web before any proof exists, so they are rate-limited
// per authenticated owner (design §3.7).
func (s *IdentityService) WithRegisterRateLimit(perMinute int) *IdentityService {
	if perMinute > 0 {
		s.limiter = newOwnerLimiter(perMinute)
	}
	return s
}

// WithLinkRateLimit overrides the per-owner link/unlink rate limit
// (default 60/min — design §4.3 operational hardening: the bounds
// limit blast radius and TL noise, not the named risk).
func (s *IdentityService) WithLinkRateLimit(perMinute int) *IdentityService {
	if perMinute > 0 {
		s.linkLimiter = newOwnerLimiter(perMinute)
	}
	return s
}

// WithSealTimeout overrides the inline TL seal budget (default 5s).
func (s *IdentityService) WithSealTimeout(timeout time.Duration) *IdentityService {
	if timeout > 0 {
		s.sealTimeout = timeout
	}
	return s
}

// WithClock overrides the time source (tests only).
func (s *IdentityService) WithClock(fn func() time.Time) *IdentityService {
	s.clock = fn
	return s
}

// raID returns the configured RA identifier stamped into proof inputs
// and sealed events. Empty without a signer (tests).
func (s *IdentityService) raID() string {
	if s.signer != nil {
		return s.signer.RaID
	}
	return ""
}

// verifierFor returns the kind's control verifier, or the precise
// IDENTIFIER_KIND_UNSUPPORTED error when this deployment has none.
// Kinds are recognized lexically but only enabled once their verifier
// registers (identitykinds.go).
func (s *IdentityService) verifierFor(kind domain.IdentifierKind) (controlVerifier, error) {
	v, ok := s.verifiers[kind]
	if !ok {
		return nil, domain.NewValidationError("IDENTIFIER_KIND_UNSUPPORTED",
			fmt.Sprintf("identifier kind %q is not enabled on this deployment", kind))
	}
	return v, nil
}

// Register creates (or idempotently re-challenges) an identity for
// the authenticated owner and returns the challenge list to sign.
//
// Idempotent re-add (§4.2): while the owner's row for the same
// canonical value is PENDING_CONTROL, re-registering returns the
// SAME identityId with a fresh nonce (the prior nonce is
// superseded). IDENTIFIER_DUPLICATE is reserved for genuine
// conflicts: already VERIFIED by this owner (rotate instead), or
// proven by another owner.
func (s *IdentityService) Register(ctx context.Context, providerID, rawValue string, opts ...RegisterOptions) (*IdentityChallengeResponse, error) {
	opt := firstRegisterOption(opts)
	if providerID == "" {
		return nil, domain.NewValidationError("INVALID_PROVIDER_ID", "authenticated owner is required")
	}
	if !s.limiter.Allow(providerID, s.clock()) {
		return nil, domain.NewValidationError("RATE_LIMITED",
			"too many identity register/rotate calls; retry later")
	}
	kind, canonical, err := domain.InferIdentifierKind(rawValue)
	if err != nil {
		return nil, err
	}
	if _, err := s.verifierFor(kind); err != nil {
		return nil, err
	}

	now := s.clock().UTC()

	// Existing live row for this owner?
	existing, err := s.identities.FindLive(ctx, providerID, kind, canonical)
	switch {
	case err == nil && existing.Status == domain.IdentityVerified:
		return nil, domain.NewConflictError("IDENTIFIER_DUPLICATE",
			"identifier is already verified by this owner; rotate it with PUT instead")
	case err == nil:
		// PENDING_CONTROL → idempotent re-challenge on the same row.
		return s.challenge(ctx, existing, now, false, opt)
	case errors.Is(err, domain.ErrNotFound):
		// fall through to creation
	default:
		return nil, err
	}

	// Early duplicate feedback when another owner already proved the
	// value. The authoritative guard is the proven-uniqueness index
	// at verify time; this just makes the failure arrive sooner.
	if taken, terr := s.identities.ExistsVerified(ctx, kind, canonical); terr != nil {
		return nil, terr
	} else if taken {
		return nil, domain.NewConflictError("IDENTIFIER_DUPLICATE",
			"identifier is already verified by another owner")
	}

	identityID, err := s.newID()
	if err != nil {
		return nil, domain.NewInternalError("IDENTITY_ID_GENERATION", "could not generate identityId", err)
	}
	identity, err := domain.NewVerifiedIdentity(identityID, providerID, canonical, now)
	if err != nil {
		return nil, err
	}
	return s.challenge(ctx, identity, now, true, opt)
}

// firstRegisterOption collapses the variadic options to a single
// value: the additive register material is at most one struct, so a
// caller passes zero (non-lei kinds, all current callers) or one.
func firstRegisterOption(opts []RegisterOptions) RegisterOptions {
	if len(opts) > 0 {
		return opts[0]
	}
	return RegisterOptions{}
}

// Rotate stages a same-kind replacement (§4.2 PUT) and returns fresh
// challenges over it. The previously sealed state stands until the
// new proof lands; a replacement that never verifies expires with its
// nonce.
func (s *IdentityService) Rotate(ctx context.Context, providerID, identityID, rawValue string, opts ...RegisterOptions) (*IdentityChallengeResponse, error) {
	opt := firstRegisterOption(opts)
	if !s.limiter.Allow(providerID, s.clock()) {
		return nil, domain.NewValidationError("RATE_LIMITED",
			"too many identity register/rotate calls; retry later")
	}
	identity, err := s.ownedIdentityForWrite(ctx, providerID, identityID)
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	if err := identity.StageRotation(rawValue, now); err != nil {
		return nil, err
	}
	return s.challenge(ctx, identity, now, false, opt)
}

// challenge mints a fresh nonce on the identity, runs the kind's
// advisory resolution to seed the per-key challenge list, persists,
// and assembles the 202 response. Shared by Register and Rotate.
//
// isNew selects the persist path: a brand-new identity INSERTs
// (fresh UUIDv7 — unracable); an existing row persists through the
// store's CONDITIONAL StageChallenge — the resolver fetch between
// load and persist spans seconds, and a blind upsert here could
// clobber a verify or revoke that committed in that window (status
// regression = a different owner could then take the identifier).
func (s *IdentityService) challenge(ctx context.Context, identity *domain.VerifiedIdentity, now time.Time, isNew bool, opt RegisterOptions) (*IdentityChallengeResponse, error) {
	verifier, err := s.verifierFor(identity.Kind)
	if err != nil {
		return nil, err
	}

	// Kinds carrying a register-time presentation (lei) submit it to
	// their verifier here, pinning the verifier-derived subject AID on
	// the aggregate before the challenge enumerates it. Discovered by
	// capability — non-presentation kinds skip this entirely.
	var presentationStatus port.PresentationStatus
	if pr, ok := verifier.(presentationRegistrar); ok {
		presentationStatus, err = pr.RegisterPresentation(ctx, identity, opt, now)
		if err != nil {
			return nil, err
		}
	}

	// Load-time snapshot for the conditional persist.
	expectedStatus := identity.Status
	expectedNonce := ""
	if identity.Challenge != nil {
		expectedNonce = identity.Challenge.Nonce
	}

	nonce, err := s.newNonce()
	if err != nil {
		return nil, domain.NewInternalError("CHALLENGE_GENERATION", "could not generate challenge nonce", err)
	}
	if err := identity.IssueChallenge(nonce, s.challengeTTL, now); err != nil {
		return nil, err
	}

	input := anscrypto.IdentityProofInput{
		Identifier: identity.EffectiveValue(),
		IdentityID: identity.IdentityID,
		Nonce:      nonce,
		Purpose:    anscrypto.IdentityProofPurpose,
		RaID:       s.raID(),
		Scheme:     string(identity.Kind),
	}
	signingInput, err := input.SigningInput()
	if err != nil {
		return nil, domain.NewInternalError("CHALLENGE_GENERATION", "could not build signing input", err)
	}

	challenges, err := verifier.Challenges(ctx, identity, signingInput)
	if err != nil {
		return nil, err
	}

	if isNew {
		if err := s.identities.Save(ctx, identity); err != nil {
			return nil, mapIdentitySaveErr(err)
		}
	} else {
		if err := s.identities.StageChallenge(ctx, identity, expectedStatus, expectedNonce, now.Add(-sealClaimTTL)); err != nil {
			return nil, err
		}
	}
	return &IdentityChallengeResponse{
		Identity:           identity,
		PresentationStatus: presentationStatus,
		Nonce:              nonce,
		ExpiresAt:          identity.Challenge.ExpiresAt,
		Challenges:         challenges,
	}, nil
}

// VerifyControl runs the identity's per-kind control proof over the
// submission and, when every proof passes, seals IDENTITY_VERIFIED /
// IDENTITY_UPDATED on the identity's TL stream and THEN flips the
// identity to VERIFIED (or completes a staged rotation), consuming
// the nonce in the commit transaction — seal-before-success (§5.6.1):
// success is reported only after the TL acknowledges the seal, and
// the RA row can never be ahead of the log. One bad proof fails the
// call closed; a failed attempt does NOT consume the nonce (the
// provisional claim taken across the seal round trip is released).
// The per-kind logic lives entirely behind the controlVerifier seam
// (identitykinds.go); this method owns the kind-agnostic discipline.
func (s *IdentityService) VerifyControl(ctx context.Context, providerID, identityID string, sub ProofSubmission) (*domain.VerifiedIdentity, error) {
	identity, err := s.ownedIdentityForWrite(ctx, providerID, identityID)
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	if identity.Status == domain.IdentityRevoked {
		return nil, domain.NewInvalidStateError("IDENTITY_REVOKED", "identity is revoked")
	}
	if err := identity.CheckChallenge(now); err != nil {
		return nil, err
	}
	verifier, err := s.verifierFor(identity.Kind)
	if err != nil {
		return nil, err
	}

	expectedInput := anscrypto.IdentityProofInput{
		Identifier: identity.EffectiveValue(),
		IdentityID: identity.IdentityID,
		Nonce:      identity.Challenge.Nonce,
		Purpose:    anscrypto.IdentityProofPurpose,
		RaID:       s.raID(),
		Scheme:     string(identity.Kind),
	}
	expectedPayload, err := expectedInput.SigningInput()
	if err != nil {
		return nil, domain.NewInternalError("PROOF_INPUT", "could not rebuild signing input", err)
	}

	provenKeys, err := verifier.VerifyProofs(ctx, identity, sub, expectedPayload)
	if err != nil {
		return nil, err
	}

	// Advisory cross-owner duplicate check before sealing — narrows
	// the window in which a competing owner's verify could leave a
	// sealed event whose row transition loses the proven-uniqueness
	// index race. The index at commit stays the authoritative guard;
	// a sealed loser is a benign true fact (control WAS proven) whose
	// row never flips and whose identity never becomes linkable.
	statusBefore := identity.Status
	if statusBefore != domain.IdentityVerified {
		if taken, terr := s.identities.ExistsVerified(ctx, identity.Kind, identity.EffectiveValue()); terr != nil {
			return nil, terr
		} else if taken {
			return nil, domain.NewConflictError("IDENTIFIER_DUPLICATE",
				"identifier is already verified by another owner")
		}
	}

	// Phase A — claim. Serializes concurrent verify attempts on this
	// nonce across the seal round trip: at most one in-flight attempt
	// can seal. A claim is NOT consumption; every failure path below
	// releases it.
	nonce := identity.Challenge.Nonce
	if err := s.identities.ClaimChallenge(ctx, identity.IdentityID, nonce, now, now.Add(-sealClaimTTL)); err != nil {
		return nil, err
	}

	previousValue, err := identity.CompleteVerification(now)
	if err != nil {
		s.releaseClaim(ctx, identity.IdentityID, nonce)
		return nil, err
	}
	eventType := identityevent.TypeIdentityVerified
	if statusBefore == domain.IdentityVerified {
		eventType = identityevent.TypeIdentityUpdated
	}
	inner := s.buildIdentityEvent(identity, eventType, now)
	inner.Keys = provenKeys
	inner.PreviousValue = previousValue
	inner.VerifiedAt = now.Format(time.RFC3339)

	// Phase B — seal. No success without the TL's acknowledgment.
	if err := s.sealIdentityEvent(ctx, inner, now); err != nil {
		s.releaseClaim(ctx, identity.IdentityID, nonce)
		return nil, err
	}

	// Phase C — commit with the ack: consume the nonce (the
	// conditional update stays the authoritative TOCTOU guard) and
	// flip the row.
	err = s.uow.Run(ctx, func(txCtx context.Context) error {
		if err := s.identities.ConsumeChallenge(txCtx, identity.IdentityID, nonce, now); err != nil {
			return err
		}
		consumed := now
		identity.Challenge.ConsumedAt = &consumed
		if err := s.identities.Save(txCtx, identity); err != nil {
			return mapIdentitySaveErr(err)
		}
		return nil
	})
	if err != nil {
		s.releaseClaim(ctx, identity.IdentityID, nonce)
		return nil, err
	}
	return identity, nil
}

// releaseClaim is the best-effort failure-path release of the
// verify-control seal claim — failed attempts never consume (§3.2).
func (s *IdentityService) releaseClaim(ctx context.Context, identityID, nonce string) {
	if err := s.identities.ReleaseChallenge(ctx, identityID, nonce); err != nil {
		// Best-effort by contract, but a leaked claim blocks re-verify
		// until its TTL lapses (~30s) — make that visible rather than
		// silent.
		s.logger.Warn().Err(err).
			Str("identityId", identityID).
			Msg("failed to release verify-control seal claim; it will self-heal at the claim TTL")
	}
}

// Revoke transitions a VERIFIED identity to REVOKED and seals
// IDENTITY_REVOKED — one event; propagation to every linked agent's
// badge is the TL's read-time join, never a write fan-out. Seal
// before success (§5.6.1): the row flips only after the TL ack.
func (s *IdentityService) Revoke(ctx context.Context, providerID, identityID string) (*domain.VerifiedIdentity, error) {
	identity, err := s.ownedIdentityForWrite(ctx, providerID, identityID)
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	if err := identity.Revoke(now); err != nil {
		return nil, err
	}
	inner := s.buildIdentityEvent(identity, identityevent.TypeIdentityRevoked, now)
	inner.RevokedAt = now.Format(time.RFC3339)
	if err := s.sealIdentityEvent(ctx, inner, now); err != nil {
		return nil, err
	}
	// Phase C — CONDITIONAL commit (re-read + compare, §plan W1): the
	// seal round trip is a window a concurrent verify/rotate commit
	// can land in; a blind save would overwrite it with this call's
	// stale snapshot. On conflict the sealed IDENTITY_REVOKED is the
	// benign residue (the TL's read-time status is terminal on ANY
	// revocation leaf) and the caller retries against fresh state.
	if err := s.identities.MarkRevoked(ctx, identity.IdentityID, now); err != nil {
		return nil, err
	}
	return identity, nil
}

// List returns one page of the owner's identities, newest first
// (opaque-cursor pagination, the agent-list convention).
func (s *IdentityService) List(ctx context.Context, providerID string, limit int, cursor string) (*port.CursorPage[*domain.VerifiedIdentity], error) {
	return s.identities.ListByOwner(ctx, providerID, limit, cursor)
}

// LinkedIdentitySummary is one entry of the RA-side computed
// identities[] view on AgentDetails (design §5.4): additive,
// optional, computed — never stored on the registration. The
// authoritative third-party view is the TL badge join; this is the
// owner's convenience mirror.
type LinkedIdentitySummary struct {
	IdentityID     string
	Kind           domain.IdentifierKind
	Value          string
	IdentityStatus domain.IdentityStatus
	LinkedAt       time.Time
}

// LinkedIdentitiesForAgent computes the identities currently linked
// to an agent under the §5.6.3 visibility predicate: link LINKED ∧
// agent live — a terminal agent's view is empty (its links are no
// longer visible; history stays in the TL). REVOKED identities stay
// visible with their status: a reader must see the who behind a
// still-linked agent was revoked. Callers reach this through the
// ownership-gated agent detail route; links are same-owner by
// construction, so no further gate applies here.
func (s *IdentityService) LinkedIdentitiesForAgent(ctx context.Context, agentID string) ([]LinkedIdentitySummary, error) {
	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if !agentLinkable(reg.Status) {
		return []LinkedIdentitySummary{}, nil
	}
	links, err := s.links.ListLiveByAgent(ctx, agentID)
	if err != nil {
		return nil, err
	}
	out := make([]LinkedIdentitySummary, 0, len(links))
	for _, l := range links {
		identity, err := s.identities.FindByID(ctx, l.IdentityID)
		if err != nil {
			return nil, err
		}
		out = append(out, LinkedIdentitySummary{
			IdentityID:     identity.IdentityID,
			Kind:           identity.Kind,
			Value:          identity.Value,
			IdentityStatus: identity.Status,
			LinkedAt:       l.LinkedAt,
		})
	}
	return out, nil
}

// Detail returns one identity plus its visible links — the §5.6.3
// visibility predicate applies to the linked-agent list and count
// exactly as to every other "current" view: a link to a terminal
// agent drops out (its history stays in the TL).
func (s *IdentityService) Detail(ctx context.Context, providerID, identityID string) (*domain.VerifiedIdentity, []*domain.IdentityLink, error) {
	identity, err := s.ownedIdentity(ctx, providerID, identityID)
	if err != nil {
		return nil, nil, err
	}
	links, err := s.links.ListLiveByIdentity(ctx, identityID)
	if err != nil {
		return nil, nil, err
	}
	visible := make([]*domain.IdentityLink, 0, len(links))
	for _, l := range links {
		reg, err := s.agents.FindByAgentID(ctx, l.AgentID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				continue // agent row gone (admin cleanup) — not visible
			}
			return nil, nil, err // infra failure must surface, never under-count
		}
		if !agentLinkable(reg.Status) {
			continue
		}
		visible = append(visible, l)
	}
	return identity, visible, nil
}

// Link binds a batch of the owner's agents to the identity — a
// single owner-gated call, no challenge, no signature (§4.3): the
// caller must own the identity AND every named agent; key possession
// never authorizes a link. Liveness gate (§4.3): the identity must
// be VERIFIED and every agent live (ACTIVE or DEPRECATED — a
// deprecated agent still serves during migration and the who stays
// true); terminal or pre-activation agents are AGENT_NOT_LINKABLE.
// The whole batch seals as ONE IDENTITY_LINKED event on the identity
// stream — before success is reported (§5.6.1) — and agent streams
// are never written. Already-linked agents are skipped idempotently;
// a call that links nothing new seals nothing.
func (s *IdentityService) Link(ctx context.Context, providerID, identityID string, agentIDs []string) (int, error) {
	if !s.linkLimiter.Allow(providerID, s.clock()) {
		return 0, domain.NewValidationError("RATE_LIMITED",
			"too many link/unlink calls; retry later")
	}
	identity, err := s.ownedIdentityForWrite(ctx, providerID, identityID)
	if err != nil {
		return 0, err
	}
	if identity.Status != domain.IdentityVerified {
		return 0, domain.NewInvalidStateError("IDENTITY_NOT_VERIFIED",
			"links attach only while the identity is VERIFIED")
	}
	if len(agentIDs) == 0 {
		return 0, domain.NewValidationError("INVALID_LINK_REQUEST", "agentIds is required")
	}
	if len(agentIDs) > maxLinkBatch {
		return 0, domain.NewValidationError("INVALID_LINK_REQUEST",
			fmt.Sprintf("at most %d agents per link call; chunk larger fleets", maxLinkBatch))
	}
	seen := make(map[string]bool, len(agentIDs))
	deduped := make([]string, 0, len(agentIDs))
	for _, id := range agentIDs {
		if id == "" {
			return 0, domain.NewValidationError("INVALID_LINK_REQUEST", "agentIds contains an empty id")
		}
		if !seen[id] {
			seen[id] = true
			deduped = append(deduped, id)
		}
	}

	// Owner gate, both sides: every agent must exist and belong to
	// the caller. A non-owned agent is reported as not-found — the
	// caller learns nothing about other owners' agents. Then the
	// liveness gate: rejected atomically, all-or-nothing, matching
	// the one-event batch semantics.
	for _, agentID := range deduped {
		reg, err := s.agents.FindByAgentID(ctx, agentID)
		if err != nil {
			return 0, domain.NewNotFoundError("AGENT_NOT_FOUND",
				fmt.Sprintf("agent %q not found", agentID))
		}
		if reg.OwnerID != providerID {
			return 0, domain.NewNotFoundError("AGENT_NOT_FOUND",
				fmt.Sprintf("agent %q not found", agentID))
		}
		if !agentLinkable(reg.Status) {
			return 0, domain.NewValidationError("AGENT_NOT_LINKABLE",
				fmt.Sprintf("agent %q is %s — links require a live agent (ACTIVE or DEPRECATED)", agentID, reg.Status))
		}
	}

	// Compute the batch BEFORE sealing: the sealed ansIds[] must be
	// exactly the pairs this call creates.
	existingLinks, err := s.links.ListLiveByIdentity(ctx, identityID)
	if err != nil {
		return 0, err
	}
	alreadyLinked := make(map[string]bool, len(existingLinks))
	for _, l := range existingLinks {
		alreadyLinked[l.AgentID] = true
	}
	newlyLinked := make([]string, 0, len(deduped))
	for _, agentID := range deduped {
		if !alreadyLinked[agentID] {
			newlyLinked = append(newlyLinked, agentID)
		}
	}
	if len(newlyLinked) == 0 {
		return 0, nil // fully idempotent — nothing to seal
	}

	now := s.clock().UTC()
	inner := s.buildIdentityEvent(identity, identityevent.TypeIdentityLinked, now)
	inner.AnsIDs = newlyLinked

	// Seal before success (§5.6.1), then commit the rows with the
	// ack. A concurrent call winning a pair's row in between is
	// benign: both sealed events assert LINKED, the row upsert is
	// idempotent, and latest-event-wins reads are unaffected.
	if err := s.sealIdentityEvent(ctx, inner, now); err != nil {
		return 0, err
	}
	err = s.uow.Run(ctx, func(txCtx context.Context) error {
		// Re-read + compare (§plan W1): a revoke that committed
		// during the seal round trip must not gain live link rows —
		// the §4.3 VERIFIED gate holds at commit, not just at entry.
		current, err := s.identities.FindByID(txCtx, identityID)
		if err != nil {
			return err
		}
		if current.Status != domain.IdentityVerified {
			return domain.NewInvalidStateError("IDENTITY_NOT_VERIFIED",
				"identity was revoked while the link was sealing; the sealed link event is inert")
		}
		for _, agentID := range newlyLinked {
			if _, err := s.links.Link(txCtx, identityID, agentID, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(newlyLinked), nil
}

// agentLinkable is the link liveness gate (§4.3): live states only.
// DEPRECATED is deliberately linkable; terminal and pre-activation
// states are not (a terminal link is dead on arrival under the
// visibility predicate, and a pre-activation agent has no sealed TL
// presence to join).
func agentLinkable(status domain.RegistrationStatus) bool {
	return status == domain.StatusActive || status == domain.StatusDeprecated
}

// Unlink ends one association and seals IDENTITY_UNLINKED on the
// identity stream — before success is reported (§5.6.1). The
// association's history persists in the log.
func (s *IdentityService) Unlink(ctx context.Context, providerID, identityID, agentID string) error {
	if !s.linkLimiter.Allow(providerID, s.clock()) {
		return domain.NewValidationError("RATE_LIMITED",
			"too many link/unlink calls; retry later")
	}
	identity, err := s.ownedIdentityForWrite(ctx, providerID, identityID)
	if err != nil {
		return err
	}

	// The live link must exist before anything seals.
	existingLinks, err := s.links.ListLiveByIdentity(ctx, identityID)
	if err != nil {
		return err
	}
	live := false
	for _, l := range existingLinks {
		if l.AgentID == agentID {
			live = true
			break
		}
	}
	if !live {
		return domain.NewNotFoundError("LINK_NOT_FOUND",
			"no live link exists for this identity and agent")
	}

	now := s.clock().UTC()
	inner := s.buildIdentityEvent(identity, identityevent.TypeIdentityUnlinked, now)
	inner.AnsIDs = []string{agentID}
	if err := s.sealIdentityEvent(ctx, inner, now); err != nil {
		return err
	}
	return s.uow.Run(ctx, func(txCtx context.Context) error {
		if err := s.links.Unlink(txCtx, identityID, agentID, now); err != nil {
			// A concurrent unlink winning the row after our liveness
			// read is benign: the association ended and both sealed
			// events say so.
			if errors.Is(err, domain.ErrNotFound) {
				return nil
			}
			return err
		}
		return nil
	})
}

// ownedIdentity loads an identity and enforces the owner gate with
// read semantics: a non-owner gets not-found — existence is hidden,
// matching the agent ReadOwnership middleware. No admin override:
// the owner gate is the link mechanism's security boundary (§4.3 —
// the caller MUST be the authenticated owner), so identities are
// stricter than the agent routes here.
func (s *IdentityService) ownedIdentity(ctx context.Context, providerID, identityID string) (*domain.VerifiedIdentity, error) {
	if identityID == "" {
		return nil, domain.NewValidationError("INVALID_IDENTITY_ID", "identityId is required")
	}
	identity, err := s.identities.FindByID(ctx, identityID)
	if err != nil {
		return nil, err
	}
	if identity.ProviderID != providerID {
		return nil, domain.NewNotFoundError("IDENTITY_NOT_FOUND",
			fmt.Sprintf("identity %q not found", identityID))
	}
	return identity, nil
}

// ownedIdentityForWrite is the write-path owner gate: missing → 404,
// present-but-not-owned → 403 (the agent WriteOwnership split — a
// 404-for-not-owned would hide a real authorization failure from
// operators investigating permissions).
func (s *IdentityService) ownedIdentityForWrite(ctx context.Context, providerID, identityID string) (*domain.VerifiedIdentity, error) {
	if identityID == "" {
		return nil, domain.NewValidationError("INVALID_IDENTITY_ID", "identityId is required")
	}
	identity, err := s.identities.FindByID(ctx, identityID)
	if err != nil {
		return nil, err
	}
	if identity.ProviderID != providerID {
		return nil, domain.NewUnauthorizedError("IDENTITY_NOT_OWNED",
			"caller does not own this identity")
	}
	return identity, nil
}

// buildIdentityEvent assembles the common fields of an identity
// event. Type-specific fields (keys, ansIds, previousValue,
// verifiedAt, revokedAt) are set by the caller.
func (s *IdentityService) buildIdentityEvent(
	identity *domain.VerifiedIdentity,
	eventType identityevent.Type,
	now time.Time,
) *identityevent.Event {
	return &identityevent.Event{
		EventType:   eventType,
		IdentityID:  identity.IdentityID,
		Kind:        string(identity.Kind),
		Value:       identity.Value,
		ProviderID:  identity.ProviderID,
		ProofMethod: identity.ProofMethod,
		RaID:        s.raID(),
		Timestamp:   now.Format(time.RFC3339),
	}
}

// sealIdentityEvent JCS-canonicalizes the inner event, signs it once
// with the producer key, and submits it inline to the TL's IDENTITY
// ingest lane, returning only on the TL's acknowledgment —
// seal-before-success (§5.6.1). Identity events never ride the
// outbox: sign once, submit once; a failed submission is a failed
// operation, surfaced retryable (TL_UNAVAILABLE) with nothing
// consumed. A nil sealer fails closed for the same reason — there is
// no "seal later" mode.
func (s *IdentityService) sealIdentityEvent(ctx context.Context, inner *identityevent.Event, now time.Time) error {
	if s.sealer == nil {
		return domain.NewUnavailableError("TL_UNAVAILABLE",
			"identity sealing is not configured; identity operations cannot report success without a sealed event")
	}
	innerCanonical, err := identityevent.CanonicalizeEvent(inner)
	if err != nil {
		return fmt.Errorf("canonicalize identity event: %w", err)
	}
	var producerSig string
	if s.signer != nil {
		producerSig, err = anscrypto.SignDetachedJWS(
			ctx, s.signer.KeyManager, s.signer.KeyID,
			anscrypto.JWSProtectedHeader{
				Typ:       "JWT",
				Timestamp: now.Unix(),
				RAID:      s.signer.RaID,
			},
			innerCanonical,
		)
		if err != nil {
			return fmt.Errorf("sign identity event: %w", err)
		}
	}
	sealCtx, cancel := context.WithTimeout(ctx, s.sealTimeout)
	defer cancel()
	if err := s.sealer.SealIdentityEvent(sealCtx, innerCanonical, producerSig); err != nil {
		ev := s.logger.Error()
		if errors.Is(err, domain.ErrUnavailable) {
			// Transient — the TL didn't confirm; the operation fails
			// retryable and nothing was consumed. WARN, not ERROR.
			ev = s.logger.Warn()
		}
		ev.Err(err).
			Str("identityId", inner.IdentityID).
			Str("eventType", string(inner.EventType)).
			Msg("identity event seal failed")
		return err
	}
	s.logger.Info().
		Str("identityId", inner.IdentityID).
		Str("eventType", string(inner.EventType)).
		Msg("identity event sealed")
	return nil
}

// mapIdentitySaveErr converts the storage layer's generic conflict
// (one of the two partial unique indexes fired) into the wire code
// the design names.
func mapIdentitySaveErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, domain.ErrConflict) {
		return domain.NewConflictError("IDENTIFIER_DUPLICATE",
			"identifier is already registered or verified for this scope")
	}
	return err
}
