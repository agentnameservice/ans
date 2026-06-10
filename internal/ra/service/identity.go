package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	identityevent "github.com/godaddy/ans/internal/tl/event/identity"
)

// identityLane is the outbox schema_version value routing identity
// events to the TL's `POST /v1/internal/identities/event` ingest
// lane. Same producer signature and replay-verbatim invariant as the
// V1/V2 agent lanes; different inner-event schema.
const identityLane = "IDENTITY"

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
	outbox     OutboxEnqueuer
	uow        port.UnitOfWork
	signer     *EventSigner

	// verifiers is the per-kind control-proof registry — THE
	// extension seam (see identitykinds.go). A kind is enabled iff
	// it has an entry here.
	verifiers map[domain.IdentifierKind]controlVerifier

	challengeTTL time.Duration
	limiter      *ownerLimiter
	clock        func() time.Time
	newID        func() (string, error)
	newNonce     func() (string, error)
}

// NewIdentityService constructs an IdentityService.
func NewIdentityService(
	identities port.IdentityStore,
	links port.IdentityLinkStore,
	agents port.AgentStore,
	resolver port.DIDResolver,
	outbox OutboxEnqueuer,
	uow port.UnitOfWork,
) *IdentityService {
	return &IdentityService{
		identities:   identities,
		links:        links,
		agents:       agents,
		verifiers:    newControlVerifiers(resolver),
		outbox:       outbox,
		uow:          uow,
		challengeTTL: time.Hour,
		limiter:      newOwnerLimiter(defaultRegisterPerMinute),
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
// IDENTIFIER_KIND_UNSUPPORTED error when this deployment has none —
// lei is recognized lexically but postponed: the route exists, the
// kind does not until its verifier registers (identitykinds.go).
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
func (s *IdentityService) Register(ctx context.Context, providerID, rawValue string) (*IdentityChallengeResponse, error) {
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
		return s.challenge(ctx, existing, now)
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
	return s.challenge(ctx, identity, now)
}

// Rotate stages a same-kind replacement (§4.2 PUT) and returns fresh
// challenges over it. The previously sealed state stands until the
// new proof lands; a replacement that never verifies expires with its
// nonce.
func (s *IdentityService) Rotate(ctx context.Context, providerID, identityID, rawValue string) (*IdentityChallengeResponse, error) {
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
	return s.challenge(ctx, identity, now)
}

// challenge mints a fresh nonce on the identity, runs the kind's
// advisory resolution to seed the per-key challenge list, persists,
// and assembles the 202 response. Shared by Register and Rotate.
func (s *IdentityService) challenge(ctx context.Context, identity *domain.VerifiedIdentity, now time.Time) (*IdentityChallengeResponse, error) {
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

	verifier, err := s.verifierFor(identity.Kind)
	if err != nil {
		return nil, err
	}
	challenges, err := verifier.Challenges(ctx, identity, signingInput)
	if err != nil {
		return nil, err
	}

	if err := s.identities.Save(ctx, identity); err != nil {
		return nil, mapIdentitySaveErr(err)
	}
	return &IdentityChallengeResponse{
		Identity:   identity,
		Nonce:      nonce,
		ExpiresAt:  identity.Challenge.ExpiresAt,
		Challenges: challenges,
	}, nil
}

// VerifyControl runs the identity's per-kind control proof over the
// submission and, when every proof passes, flips the identity to
// VERIFIED (or completes a staged rotation), consumes the nonce, and
// seals IDENTITY_VERIFIED / IDENTITY_UPDATED on the identity's TL
// stream — all in one transaction. One bad proof fails the call
// closed; a failed attempt does NOT consume the nonce. The per-kind
// logic lives entirely behind the controlVerifier seam
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

	statusBefore := identity.Status
	var sealed *domain.VerifiedIdentity
	err = s.uow.Run(ctx, func(txCtx context.Context) error {
		// Consume the nonce first — the conditional update is the
		// TOCTOU guard; exactly one concurrent verify can win.
		if err := s.identities.ConsumeChallenge(txCtx, identity.IdentityID, identity.Challenge.Nonce, now); err != nil {
			return err
		}
		previousValue, err := identity.CompleteVerification(now)
		if err != nil {
			return err
		}
		consumed := now
		identity.Challenge.ConsumedAt = &consumed
		if err := s.identities.Save(txCtx, identity); err != nil {
			return mapIdentitySaveErr(err)
		}

		eventType := identityevent.TypeIdentityVerified
		if statusBefore == domain.IdentityVerified {
			eventType = identityevent.TypeIdentityUpdated
		}
		inner := s.buildIdentityEvent(identity, eventType, now)
		inner.Keys = provenKeys
		inner.PreviousValue = previousValue
		inner.VerifiedAt = now.Format(time.RFC3339)
		return s.enqueueIdentityEvent(txCtx, inner, now)
	})
	if err != nil {
		return nil, err
	}
	sealed = identity
	return sealed, nil
}

// Revoke transitions a VERIFIED identity to REVOKED and seals
// IDENTITY_REVOKED — one event; propagation to every linked agent's
// badge is the TL's read-time join, never a write fan-out.
func (s *IdentityService) Revoke(ctx context.Context, providerID, identityID string) (*domain.VerifiedIdentity, error) {
	identity, err := s.ownedIdentityForWrite(ctx, providerID, identityID)
	if err != nil {
		return nil, err
	}
	now := s.clock().UTC()
	if err := identity.Revoke(now); err != nil {
		return nil, err
	}
	err = s.uow.Run(ctx, func(txCtx context.Context) error {
		if err := s.identities.Save(txCtx, identity); err != nil {
			return mapIdentitySaveErr(err)
		}
		inner := s.buildIdentityEvent(identity, identityevent.TypeIdentityRevoked, now)
		inner.RevokedAt = now.Format(time.RFC3339)
		return s.enqueueIdentityEvent(txCtx, inner, now)
	})
	if err != nil {
		return nil, err
	}
	return identity, nil
}

// List returns the owner's identities, newest first.
func (s *IdentityService) List(ctx context.Context, providerID string) ([]*domain.VerifiedIdentity, error) {
	return s.identities.ListByOwner(ctx, providerID)
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
// to an agent. Callers reach this through the ownership-gated agent
// detail route; links are same-owner by construction, so no further
// gate applies here.
func (s *IdentityService) LinkedIdentitiesForAgent(ctx context.Context, agentID string) ([]LinkedIdentitySummary, error) {
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

// Detail returns one identity plus its live links.
func (s *IdentityService) Detail(ctx context.Context, providerID, identityID string) (*domain.VerifiedIdentity, []*domain.IdentityLink, error) {
	identity, err := s.ownedIdentity(ctx, providerID, identityID)
	if err != nil {
		return nil, nil, err
	}
	links, err := s.links.ListLiveByIdentity(ctx, identityID)
	if err != nil {
		return nil, nil, err
	}
	return identity, links, nil
}

// Link binds a batch of the owner's agents to the identity — a
// single owner-gated call, no challenge, no signature (§4.3): the
// caller must own the identity AND every named agent; key possession
// never authorizes a link. The whole batch seals as ONE
// IDENTITY_LINKED event on the identity stream; agent streams are
// never written. Already-linked agents are skipped idempotently; a
// call that links nothing new seals nothing.
func (s *IdentityService) Link(ctx context.Context, providerID, identityID string, agentIDs []string) (int, error) {
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
	// caller learns nothing about other owners' agents.
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
	}

	now := s.clock().UTC()
	linked := 0
	err = s.uow.Run(ctx, func(txCtx context.Context) error {
		newlyLinked := make([]string, 0, len(deduped))
		for _, agentID := range deduped {
			created, err := s.links.Link(txCtx, identityID, agentID, now)
			if err != nil {
				return err
			}
			if created {
				newlyLinked = append(newlyLinked, agentID)
			}
		}
		linked = len(newlyLinked)
		if linked == 0 {
			return nil // fully idempotent — nothing to seal
		}
		inner := s.buildIdentityEvent(identity, identityevent.TypeIdentityLinked, now)
		inner.AnsIDs = newlyLinked
		return s.enqueueIdentityEvent(txCtx, inner, now)
	})
	if err != nil {
		return 0, err
	}
	return linked, nil
}

// Unlink ends one association and seals IDENTITY_UNLINKED on the
// identity stream. The association's history persists in the log.
func (s *IdentityService) Unlink(ctx context.Context, providerID, identityID, agentID string) error {
	identity, err := s.ownedIdentityForWrite(ctx, providerID, identityID)
	if err != nil {
		return err
	}
	now := s.clock().UTC()
	return s.uow.Run(ctx, func(txCtx context.Context) error {
		if err := s.links.Unlink(txCtx, identityID, agentID, now); err != nil {
			return err
		}
		inner := s.buildIdentityEvent(identity, identityevent.TypeIdentityUnlinked, now)
		inner.AnsIDs = []string{agentID}
		return s.enqueueIdentityEvent(txCtx, inner, now)
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

// enqueueIdentityEvent JCS-canonicalizes the inner event, signs it
// once with the producer key, and writes the outbox row on the
// IDENTITY lane. Same replay-verbatim invariant as the agent lanes:
// the worker must POST these exact bytes on every retry.
func (s *IdentityService) enqueueIdentityEvent(ctx context.Context, inner *identityevent.Event, now time.Time) error {
	if s.outbox == nil {
		return nil
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
	payload, err := marshalOutboxPayload(innerCanonical, producerSig)
	if err != nil {
		return err
	}
	// The outbox row's subject column carries the identityId — the
	// stream key for identity events, exactly as agent rows carry
	// the agentId.
	if _, err := s.outbox.Enqueue(ctx, string(inner.EventType), inner.IdentityID, identityLane, payload, now); err != nil {
		return err
	}
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
