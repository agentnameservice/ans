package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/tl/event"
	eventv1 "github.com/godaddy/ans/internal/tl/event/v1"
)

// ----- Read: List, Detail, IdentityCerts -----

// ListResult is the return shape of List. The handler maps this to the
// V2 AgentListResponse shape. Ordering is newest-first on
// registrationTimestamp; pagination cursor is opaque per V2 spec.
type ListResult struct {
	Items      []*domain.AgentRegistration
	Endpoints  map[string]*domain.AgentEndpoints // keyed by AgentID; filled for items that have endpoints
	NextCursor string
	HasMore    bool
	Limit      int
}

// List returns the caller-owned agents matching the filter. The
// filter.Statuses default is handled upstream (in the handler) so the
// service sees an explicit list.
func (s *RegistrationService) List(ctx context.Context, ownerID string, filter port.ListFilter) (*ListResult, error) {
	page, err := s.agents.ListByOwner(ctx, ownerID, filter)
	if err != nil {
		return nil, err
	}

	// Bulk-load endpoints in one DB roundtrip (reference
	// SearchApiDelegateImpl does the same to avoid N+1). Empty list is
	// valid — we just return zero items with empty endpoints map.
	endpointsByAgent := map[string]*domain.AgentEndpoints{}
	if len(page.Items) > 0 {
		ids := make([]string, 0, len(page.Items))
		for _, a := range page.Items {
			ids = append(ids, a.AgentID)
		}
		endpointsByAgent, err = s.endpoints.FindByAgentIDs(ctx, ids)
		if err != nil {
			return nil, err
		}
	}

	return &ListResult{
		Items:      page.Items,
		Endpoints:  endpointsByAgent,
		NextCursor: page.NextCursor,
		HasMore:    page.HasMore,
		Limit:      filter.Limit,
	}, nil
}

// DetailResult carries everything the detail handler needs to build
// an AgentDetails response.
type DetailResult struct {
	Registration *domain.AgentRegistration
	Endpoints    []domain.AgentEndpoint
}

// GetByAgentID returns the agent's current state together with its
// endpoints and (if present) its BYOC server certificate. Ownership
// is enforced by middleware before this is called; we trust the
// middleware-attached agent.
//
// We still refetch the registration here rather than using the
// middleware-attached one because the handler can be tested
// independently of the middleware, and the extra read is cheap
// (single indexed lookup).
//
// The handler's pending-block builder uses the BYOC cert to
// materialize the TLSA record in the `registrationPending.dnsRecords`
// list — without it, the record set omits `_443._tcp.<fqdn>`
// entirely and operators can't publish the cert-binding record.
func (s *RegistrationService) GetByAgentID(ctx context.Context, agentID string) (*DetailResult, error) {
	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	eps, err := s.endpoints.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	var epSlice []domain.AgentEndpoint
	if eps != nil {
		epSlice = eps.Endpoints
	}
	// BYOC server cert is optional — absent on CSR-path registrations
	// where the RA signs the server cert itself. A genuinely-absent
	// cert is fine; ComputeRequiredDNSRecords skips the TLSA record
	// when reg.ServerCert is nil. A transient store failure, however,
	// must not masquerade as "no cert" — that would silently drop the
	// TLSA record from the detail response.
	byoc, berr := s.loadServerCert(ctx, agentID)
	if berr != nil {
		return nil, berr
	}
	if byoc != nil {
		reg.ServerCert = byoc
	}
	return &DetailResult{
		Registration: reg,
		Endpoints:    epSlice,
	}, nil
}

// HostRegistrations returns the registrations on agentHost owned by
// ownerID (any version, any status), each with its Endpoints populated,
// for AI Catalog per-host document composition. Endpoints are bulk-loaded
// in one roundtrip to avoid N+1.
//
// Scoping to ownerID is a security boundary, not a convenience. The
// per-host document is meant to be host-complete (catalog §4) under the
// ANS-1 §12.1 one-host-one-owner invariant — but this RA does not enforce
// that invariant (registration uniqueness is keyed on the full versioned
// ANS name, not the host), so two owners can hold different versions on
// the same host. An owner-unscoped read would then disclose one owner's
// registration metadata to another via this route. Filtering by owner
// keeps the document host-complete for the requester (identical output in
// the intended single-owner model) while never leaking a sibling owner's
// agents.
func (s *RegistrationService) HostRegistrations(ctx context.Context, ownerID, agentHost string) ([]*domain.AgentRegistration, error) {
	all, err := s.agents.FindAllByAgentHost(ctx, agentHost)
	if err != nil {
		return nil, err
	}
	regs := make([]*domain.AgentRegistration, 0, len(all))
	for _, r := range all {
		if r.OwnerID == ownerID {
			regs = append(regs, r)
		}
	}
	if len(regs) == 0 {
		return regs, nil
	}
	ids := make([]string, len(regs))
	for i, r := range regs {
		ids[i] = r.AgentID
	}
	eps, err := s.endpoints.FindByAgentIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, r := range regs {
		if e, ok := eps[r.AgentID]; ok && e != nil {
			r.Endpoints = e.Endpoints
		}
	}
	return regs, nil
}

// IdentityCertificates returns every identity certificate the RA has
// issued for this agent — typically just the one from registration,
// but rotations (Stage 5) can add more. Newest-first.
func (s *RegistrationService) IdentityCertificates(ctx context.Context, agentID string) ([]*domain.StoredCertificate, error) {
	return s.certs.FindIdentityCertificatesByAgent(ctx, agentID)
}

// ServerCertificates returns every server certificate stored for the
// agent — both BYOC (operator-submitted) and future CA-issued ones
// (server CSR path, to land with the renewal flow).
//
// Matches the reference RA's
// `CertificateManagementService.getServerCertificates`, which returns
// a list of stored certificates. The reference uses `fromByoc` to
// unify the wire shape; we do the same via
// `domain.StoredCertificateFromByoc`.
func (s *RegistrationService) ServerCertificates(ctx context.Context, agentID string) ([]*domain.StoredCertificate, error) {
	byocs, err := s.byoc.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.StoredCertificate, 0, len(byocs))
	for _, b := range byocs {
		out = append(out, domain.StoredCertificateFromByoc(b))
	}
	return out, nil
}

// ----- CSR submission + status -----

// SubmitIdentityCSR accepts a new identity CSR for an already-ACTIVE
// agent (identity-cert rotation), signs it via the private identity
// CA, and persists the SIGNED CSR row plus the new certificate
// atomically. The previous identity cert stays VALID until it expires
// or the agent is revoked — rotation is additive, matching the
// rotation-array model the TL envelopes carry.
//
// Trust basis: the identity CA is a private root with no validation
// of its own, and rotation deliberately performs no fresh
// domain-control challenge. Ownership of the (unchanged) ANS name was
// proven when the agent reached ACTIVE — the RA's challenge gate plus
// the public provider's own validation on the ACME path — and the
// ACTIVE + identity-bearing guards below scope rotation to exactly
// that population. A recency-bounded revalidation would require
// relaying a fresh challenge through CsrSubmissionResponse, which has
// no challenge surface in the spec.
//
// Per the reference RA's `CertificateManagementService.submitIdentityCsr`,
// identity CSRs are gated on status == ACTIVE. The aggregate method
// `SubmitIdentityCSR` enforces that domain rule.
//
// Returns the new csrId the caller reports as `CsrSubmissionResponse.csrId`.
func (s *RegistrationService) SubmitIdentityCSR(ctx context.Context, agentID, csrPEM string) (string, error) {
	now := s.clock()
	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return "", err
	}

	if reg.Status != domain.StatusActive {
		return "", domain.NewInvalidStateError(
			"AGENT_NOT_ACTIVE",
			fmt.Sprintf("Agent must be ACTIVE to submit identity CSR. Current status: %s", reg.Status),
		)
	}

	// No-add-later guard: an agent that registered without an identity
	// CSR can never obtain one via rotation — it must register a new
	// version instead. Identity-bearing agents have a signed identity
	// certificate by the time they reach ACTIVE (issued at verify-acme);
	// non identity-bearing agents never do.
	idCerts, cerr := s.certs.FindIdentityCertificatesByAgent(ctx, agentID)
	if cerr != nil {
		return "", cerr
	}
	if len(idCerts) == 0 {
		return "", domain.NewConflictError(
			"IDENTITY_CSR_NOT_PERMITTED",
			"agent was registered without an identity CSR; register a new version to obtain an identity certificate",
		)
	}

	if err := s.validator.ValidateIdentityCSR(ctx, csrPEM, reg.AnsName.String()); err != nil {
		return "", domain.NewValidationError("INVALID_IDENTITY_CSR", err.Error())
	}
	csrID := uuid.NewString()
	newCSR, err := reg.SubmitIdentityCSR(csrID, csrPEM, now)
	if err != nil {
		return "", err
	}

	// Issue before the tx (CA work doesn't need the SQLite write
	// lock), persist atomically after: the SIGNED CSR row, the new
	// certificate, and the aggregate's embedded slot commit together
	// so a crash can never leave a SIGNED CSR without its cert.
	signedID, storedID, err := s.signIdentityCSR(ctx, reg, newCSR, now)
	if err != nil {
		return "", err
	}
	reg.IdentityCSR = signedID

	if err := s.uow.Run(ctx, func(txCtx context.Context) error {
		if err := s.agents.Save(txCtx, reg); err != nil {
			return err
		}
		if err := s.certs.SaveCSR(txCtx, agentID, signedID); err != nil {
			return err
		}
		return s.certs.SaveIdentityCertificate(txCtx, agentID, storedID)
	}); err != nil {
		return "", err
	}
	return csrID, nil
}

// SubmitServerCSR accepts a new server CSR for an agent. Unlike the
// identity path, the reference doesn't gate server CSRs on registration
// status — operators may want the RA-signed server cert path at any
// point before the agent goes live.
//
// Server CSRs carry the agent's FQDN as a DNS SAN (TLS server-auth
// convention, distinct from the identity CSR's URI SAN). A CSR with
// the wrong SAN shape is rejected with INVALID_SERVER_CSR.
func (s *RegistrationService) SubmitServerCSR(ctx context.Context, agentID, csrPEM string) (string, error) {
	now := s.clock()
	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return "", err
	}
	if err := s.validator.ValidateServerCSR(ctx, csrPEM, reg.AnsName.FQDN()); err != nil {
		return "", domain.NewValidationError("INVALID_SERVER_CSR", err.Error())
	}
	csrID := uuid.NewString()
	newCSR, err := reg.SubmitServerCSR(csrID, csrPEM, now)
	if err != nil {
		return "", err
	}
	if err := s.agents.Save(ctx, reg); err != nil {
		return "", err
	}
	if err := s.certs.SaveCSR(ctx, agentID, newCSR); err != nil {
		return "", err
	}
	return csrID, nil
}

// GetCSRStatus returns the CSR matching (agentID, csrID) — checking
// the aggregate's embedded slots first for the common "status of the
// CSR I just submitted" case, then falling back to the csrs table
// for historical lookups (signed / rejected CSRs from rotations).
// Mirrors the reference RA's `AgentCsrStatusService.getCsrForAgent`.
func (s *RegistrationService) GetCSRStatus(ctx context.Context, agentID, csrID string) (*domain.AgentCSR, error) {
	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	// Fast path: match against the aggregate's pending slots.
	if reg.IdentityCSR != nil && strings.EqualFold(reg.IdentityCSR.CSRID, csrID) {
		return reg.IdentityCSR, nil
	}
	if reg.ServerCSR != nil && strings.EqualFold(reg.ServerCSR.CSRID, csrID) {
		return reg.ServerCSR, nil
	}
	// Fallback: DB lookup (handles signed/rejected historical CSRs).
	return s.certs.FindCSRByID(ctx, agentID, csrID)
}

// ----- Write: VerifyACME, VerifyDNS, Revoke -----

// VerifyACMEResult is returned by VerifyACME; the handler maps this
// into an AgentStatus response.
type VerifyACMEResult struct {
	Registration *domain.AgentRegistration
	Now          time.Time // propagated so handler timestamps match the outbox row
	// Pending is true when domain validation passed but the
	// certificate provider is finalizing the order asynchronously.
	// The lifecycle status stays PENDING_VALIDATION with the order in
	// ISSUING; the handler reports phase=CERTIFICATE_ISSUANCE and the
	// client re-POSTs verify-acme to drive the order to completion.
	Pending bool
}

// VerifyACME advances the registration from PENDING_VALIDATION to
// PENDING_DNS. This is the choke point where "caller proved domain
// control" meets "caller gets certs": the RA does NOT sign anything
// at register time, because without domain validation the cert
// would vouch for a hostname nobody verified the caller owns.
//
// Steps:
//
//  1. Challenge gate: confirm at least one of the order's
//     domain-control challenge artifacts (DNS-01 TXT record or
//     HTTP-01 resource) is published. Unconditional while the order
//     awaits validation — the issuer is never invoked before the
//     gate passes, regardless of which issuer adapter is wired.
//  2. If a server CSR was submitted at registration (CSR path),
//     finalize the certificate order via the issuer port and persist
//     the resulting cert through the BYOC store (same struct covers
//     both paths downstream). Asynchronous providers may leave the
//     order ISSUING — the call returns Pending (nothing signed) and
//     a later verify-acme re-drives the finalize. BYOC registrations
//     skip this step — the operator's cert was saved at register
//     time.
//  3. Sign the identity CSR via the private identityCA — only after
//     ownership is fully proven (the public provider's validation on
//     the CSR path, the RA's gate for BYOC). Persist the resulting
//     cert + mark the CSR SIGNED.
//  4. Transition the aggregate to PENDING_DNS (the order reaches
//     COMPLETED in the same transaction).
//
// Idempotent: if the registration is already past PENDING_VALIDATION,
// return the current state without erroring — matches the reference's
// "if already progressed, succeed silently" semantics. Re-driven
// calls on an ISSUING order skip the gate (the provider already
// accepted the challenge answer) and only re-attempt the finalize.
func (s *RegistrationService) VerifyACME(ctx context.Context, agentID string, in VerifyInput) (*VerifyACMEResult, error) {
	now := s.clock()
	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}

	// FQDN exclusivity, before the idempotency check: a registration that
	// lost the host to another owner (and was cancelled at that owner's
	// activation) must be rejected here rather than silently treated as
	// "already validated". This is the at-every-level gate before
	// verify-dns.
	if err := s.ensureHostNotTakenByOther(ctx, reg); err != nil {
		return nil, err
	}

	// Idempotent: already past validation → succeed silently.
	if reg.Status != domain.StatusPendingValidation {
		return &VerifyACMEResult{Registration: reg, Now: now}, nil
	}

	// Hydrate endpoints so the identity CSR's signing subject matches
	// what was registered (validator already checked at register
	// time; re-check here would be duplicative).
	eps, err := s.endpoints.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if eps != nil {
		reg.Endpoints = eps.Endpoints
	}

	// 1. Domain-control challenge gate.
	verified, err := s.gateOrderChallenges(ctx, reg, now)
	if err != nil {
		return nil, err
	}

	// 2. CSR-path server cert: finalize the certificate order via the
	//    issuer port — validate + mark up front, persist below inside
	//    the tx. Asynchronous providers may report the order still
	//    pending: persist only the ISSUING order state without
	//    advancing the lifecycle, and let a later verify-acme re-drive
	//    the finalize. Nothing is signed on the pending path — on the
	//    ACME path the provider's own validation is the authoritative
	//    ownership proof, and the identity cert below is provisioned
	//    only once it succeeds.
	serverCSR, err := s.certs.FindLatestPendingCSRByType(ctx, agentID, domain.CSRTypeServer)
	if err != nil {
		return nil, err
	}
	var byocCert *domain.ByocServerCertificate
	var signedSrv domain.AgentCSR
	// Finalize only the server CSR that belongs to this registration's
	// certificate order — one created via the issuer's CreateOrder,
	// which always stamps an OrderRef (the self-CA uses a "selfca-…"
	// handle, ACME the order URL). A BYOC registration's order is
	// self-issued with an empty ref and its cert already exists; a
	// stray server CSR submitted out-of-band to such an agent (the
	// POST /certificates/server route accepts CSRs in any state) must
	// NOT be finalized here — doing so would issue a second cert over
	// the operator's BYOC cert, and against an ACME issuer would 500
	// on the empty order ref. Leave it untouched; the agent advances.
	if serverCSR != nil && reg.CertOrder.OrderRef != "" {
		outcome, err := s.finalizeServerOrder(ctx, reg, serverCSR, verified, now)
		if err != nil {
			return nil, err
		}
		if outcome.pending {
			if err := s.agents.Save(ctx, reg); err != nil {
				return nil, err
			}
			return &VerifyACMEResult{Registration: reg, Now: now, Pending: true}, nil
		}
		byocCert = outcome.cert
		signedSrv = outcome.signedCSR
		reg.ServerCert = byocCert
	}

	// 3. Sign the identity CSR (when the agent registered with one).
	//    The identity CA is a private trust root with no challenge
	//    lifecycle of its own — it signs on the strength of the
	//    ownership proof already established: the RA's gate for BYOC
	//    (no public CA involved), plus the provider's own validation
	//    on the CSR path (the order completed above). That ordering
	//    is deliberate: a terminally failed public-CA order must never
	//    leave a signed identity cert behind.
	//
	//    Issuance + signing run outside the tx so the SQLite write
	//    lock isn't held during work that doesn't need it.
	//
	//    A nil pending identity CSR is NOT an error: an agent may
	//    register without an identity CSR (identityCsrPEM optional), in
	//    which case there is no identity certificate to issue and we
	//    leave signedID/storedID nil so the tx below skips persisting
	//    them. The agent still advances to PENDING_DNS / ACTIVE.
	identityCSR, err := s.certs.FindLatestPendingCSRByType(ctx, agentID, domain.CSRTypeIdentity)
	if err != nil {
		return nil, err
	}
	var signedID *domain.AgentCSR
	var storedID *domain.StoredCertificate
	if identityCSR != nil {
		signedID, storedID, err = s.signIdentityCSR(ctx, reg, identityCSR, now)
		if err != nil {
			return nil, err
		}
		reg.IdentityCSR = signedID
	}

	// 4. Transition to PENDING_DNS in-memory; the tx below commits it.
	//    The order completes in the same step: for the CSR path the
	//    certificate landed, for BYOC domain control was proven — the
	//    only thing its self-issued order tracks. Legacy registrations
	//    without a persisted order have nothing to complete.
	if !reg.CertOrder.IsZero() {
		if err := reg.CertOrder.MarkCompleted(); err != nil {
			return nil, err
		}
	}
	if err := reg.AdvanceToPendingDNS(); err != nil {
		return nil, err
	}

	// 5. Persist atomically: signed CSR rows, the identity cert, the
	//    issued server cert (if any), and the agent's new state.
	//    Pre-tx, agent.Save committed first and a downstream failure
	//    left a PENDING_DNS agent with no associated cert rows.
	if err := s.uow.Run(ctx, func(txCtx context.Context) error {
		// Identity cert: persisted only when the agent registered with
		// an identity CSR. SaveCSR upserts on csr_id so the same row
		// flips PENDING → SIGNED.
		if signedID != nil {
			if err := s.certs.SaveCSR(txCtx, reg.AgentID, signedID); err != nil {
				return err
			}
			if err := s.certs.SaveIdentityCertificate(txCtx, reg.AgentID, storedID); err != nil {
				return err
			}
		}
		if byocCert != nil {
			if err := s.byoc.Save(txCtx, reg.AgentID, byocCert); err != nil {
				return err
			}
			if err := s.certs.SaveCSR(txCtx, reg.AgentID, &signedSrv); err != nil {
				return err
			}
		}
		return s.agents.Save(txCtx, reg)
	}); err != nil {
		return nil, err
	}

	// No TL emit on verify-acme. Both V1 and V2 lanes use the
	// V1-aligned terminal-only event model: the single
	// AGENT_REGISTERED leaf fires at verify-dns (ACTIVE transition).

	return &VerifyACMEResult{Registration: reg, Now: now}, nil
}

// gateOrderChallenges is the domain-control challenge gate. It runs
// before every issuer invocation, regardless of which issuer adapter
// is wired:
//
//   - PENDING order → at least one challenge artifact must be
//     verified as published (DNS-01 TXT or HTTP-01 resource);
//     otherwise 422 ACME_CHALLENGE_MISSING. Expired challenge
//     windows are 422 ACME_CHALLENGE_EXPIRED.
//   - ISSUING order → gate skipped: the provider already accepted a
//     challenge answer on an earlier call, and the operator may have
//     legitimately removed the artifact since. The re-driven call
//     only re-attempts the finalize.
//   - FAILED order → 422 CERT_ORDER_FAILED; the operator cancels and
//     re-registers.
//
// Returns the challenge types found published so ACME-style issuers
// can answer exactly the satisfied challenge (answering an
// unsatisfied one would invalidate the authorization).
//
// NOTE: zero-value orders (registrations predating order persistence)
// skip the gate — no challenge was ever issued to the operator, so
// there is nothing that could be verified. Every registration created
// since order persistence carries one.
func (s *RegistrationService) gateOrderChallenges(
	ctx context.Context, reg *domain.AgentRegistration, now time.Time,
) ([]domain.ChallengeType, error) {
	order := reg.CertOrder
	switch {
	case order.IsZero():
		return nil, nil
	case order.State == domain.OrderStateIssuing:
		return nil, nil
	case order.State == domain.OrderStateFailed:
		// 422 (validation), not 409: the spec documents only 422 on
		// verify-acme. Recovery is to cancel (POST /revoke — cancel
		// permits a failed order) then register a new version; the
		// ANS name is immutable once used.
		return nil, domain.NewValidationError("CERT_ORDER_FAILED",
			"certificate order failed terminally; cancel this registration (POST /revoke) and register a new version")
	case order.State != domain.OrderStatePending:
		// COMPLETED while still PENDING_VALIDATION is unreachable —
		// the order completes in the same transaction that advances
		// the lifecycle. Tolerate rather than brick the row.
		return nil, nil
	}
	if order.IsExpired(now) {
		// A lapsed-window order stays PENDING (expiry doesn't change
		// State), so cancel refuses it — the agent-expiry sweeper
		// retires it instead. Guide the operator to the action that
		// actually works.
		return nil, domain.NewValidationError("ACME_CHALLENGE_EXPIRED",
			"the domain-control challenge window has expired; this registration will auto-expire — register a new version to retry")
	}
	verified, verr := s.verifyChallengeArtifacts(ctx, reg.FQDN(), order.Challenges)
	if len(verified) > 0 {
		return verified, nil
	}
	if verr != nil {
		return nil, fmt.Errorf("acme verify: %w", verr)
	}
	return nil, domain.NewValidationError(
		"ACME_CHALLENGE_MISSING",
		fmt.Sprintf("no domain-control challenge artifact found for %s — publish the DNS-01 TXT record or the HTTP-01 resource from challenges[]", reg.FQDN()),
	)
}

// verifyChallengeArtifacts checks the challenge set and returns the
// type of the FIRST artifact found published. The gate is any-of: the
// owner satisfies whichever challenge is easiest, so the first
// success is sufficient and the loop short-circuits — no point making
// a second (network) probe, and for HTTP-01 that probe is an outbound
// fetch we'd rather not issue needlessly. A configuration with no
// verifier at all is an error — silently passing the gate would
// reopen the very hole this exists to close.
func (s *RegistrationService) verifyChallengeArtifacts(
	ctx context.Context, fqdn string, challenges []domain.Challenge,
) ([]domain.ChallengeType, error) {
	if len(challenges) == 0 {
		return nil, nil
	}
	if s.dnsVerifier == nil && s.httpChallenge == nil {
		return nil, domain.NewInternalError("CHALLENGE_VERIFIER_MISSING",
			"no challenge verifier configured — wire a DNS verifier and/or an HTTP challenge verifier", nil)
	}
	var firstErr error
	for _, ch := range challenges {
		ok, err := s.verifyChallengeArtifact(ctx, fqdn, ch)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if ok {
			return []domain.ChallengeType{ch.Type}, nil
		}
	}
	return nil, firstErr
}

// verifyChallengeArtifact dispatches a single challenge to the
// matching verifier. Challenges with no wired verifier (or of an
// unknown type) report unverified rather than erroring — the any-of
// gate lets a sibling challenge still pass.
func (s *RegistrationService) verifyChallengeArtifact(
	ctx context.Context, fqdn string, ch domain.Challenge,
) (bool, error) {
	switch ch.Type {
	case domain.ChallengeTypeDNS01:
		if s.dnsVerifier == nil {
			return false, nil
		}
		rec := domain.ExpectedDNSRecord{
			Name:     ch.EffectiveDNSRecordName(fqdn),
			Type:     domain.DNSRecordTXT,
			Value:    ch.EffectiveDNSRecordValue(),
			Purpose:  "DOMAIN_VALIDATION",
			Required: true,
		}
		res, err := s.dnsVerifier.VerifyRecords(ctx, fqdn, []domain.ExpectedDNSRecord{rec})
		if err != nil {
			return false, err
		}
		return res != nil && res.AllRequired, nil
	case domain.ChallengeTypeHTTP01:
		if s.httpChallenge == nil {
			return false, nil
		}
		return s.httpChallenge.VerifyHTTPChallenge(ctx, fqdn, ch.EffectiveHTTPPath(), ch.ExpectedHTTPContent())
	default:
		return false, nil
	}
}

// serverOrderOutcome is the result of finalizeServerOrder: either the
// issued cert + SIGNED CSR row, or pending=true when an asynchronous
// provider is still processing.
type serverOrderOutcome struct {
	pending   bool
	cert      *domain.ByocServerCertificate
	signedCSR domain.AgentCSR
}

// finalizeServerOrder asks the issuer to complete the certificate
// order for the pending server CSR, validates the issued cert, and
// returns the BYOC-shape cert struct + the SIGNED CSR row so the
// caller can commit both inside its uow transaction. Extracted from
// VerifyACME to keep the orchestrator under the funlen bound; the
// issuance + validation don't need to hold the SQLite write lock.
//
// Pending orders (port.ErrOrderPending) flip the order to ISSUING and
// report pending. Terminal provider failures (port.ErrOrderFailed)
// mark the order FAILED, persist it, and surface 422 — the lifecycle
// status stays PENDING_VALIDATION so the operator can cancel and
// re-register without the ANS name being burned by a FAILED agent.
func (s *RegistrationService) finalizeServerOrder(
	ctx context.Context, reg *domain.AgentRegistration,
	serverCSR *domain.AgentCSR, verified []domain.ChallengeType, now time.Time,
) (serverOrderOutcome, error) {
	if s.serverCA == nil {
		return serverOrderOutcome{}, domain.NewInternalError("SERVER_CA_DISABLED",
			"server CSR pending but no certificate issuer configured — inconsistent state", nil)
	}
	issued, err := s.serverCA.FinalizeOrder(ctx, port.FinalizeOrderRequest{
		OrderRef: reg.CertOrder.OrderRef,
		CSRPEM:   serverCSR.CSRContent,
		FQDN:     reg.FQDN(),
		Verified: verified,
	})
	switch {
	case errors.Is(err, port.ErrOrderPending):
		if merr := reg.CertOrder.MarkIssuing(); merr != nil {
			return serverOrderOutcome{}, merr
		}
		return serverOrderOutcome{pending: true}, nil
	case errors.Is(err, port.ErrOrderFailed):
		if merr := reg.CertOrder.MarkFailed(); merr != nil {
			return serverOrderOutcome{}, merr
		}
		if perr := s.agents.Save(ctx, reg); perr != nil {
			return serverOrderOutcome{}, perr
		}
		return serverOrderOutcome{}, domain.NewValidationError("CERT_ORDER_FAILED",
			"certificate provider reported a terminal order failure; cancel this registration (POST /revoke) and register a new version")
	case err != nil:
		return serverOrderOutcome{}, domain.NewInternalError("SERVER_CERT_ISSUE_FAILED",
			"failed to issue server cert", err)
	}
	v, err := s.validator.ValidateServerCertificate(ctx,
		issued.CertPEM, issued.ChainPEM, reg.FQDN())
	if err != nil {
		return serverOrderOutcome{}, domain.NewInternalError("SERVER_CERT_SELFVERIFY_FAILED",
			"issued server cert failed self-validation", err)
	}
	byocCert := &domain.ByocServerCertificate{
		LeafCertificatePEM:      v.LeafPEM,
		ChainCertificatesPEM:    v.ChainPEM,
		SubjectCommonName:       v.CN,
		SubjectAlternativeNames: v.SANs,
		IssuerDN:                v.IssuerDN,
		ValidFromTimestamp:      v.ValidFrom,
		ValidToTimestamp:        v.ValidTo,
		Fingerprint:             v.Fingerprint,
	}
	signed, err := serverCSR.MarkSigned(now)
	if err != nil {
		return serverOrderOutcome{}, err
	}
	return serverOrderOutcome{cert: byocCert, signedCSR: signed}, nil
}

// signIdentityCSR asks the private identity CA to sign the pending
// CSR and returns the SIGNED CSR row plus the stored-certificate row
// (carrying the issuer's serial and provider handle for later
// CA-side revocation) for the caller to persist inside its own
// transaction. Callers invoke this only after domain ownership is
// fully proven — the identity CA performs no validation of its own.
func (s *RegistrationService) signIdentityCSR(
	ctx context.Context, reg *domain.AgentRegistration,
	identityCSR *domain.AgentCSR, now time.Time,
) (*domain.AgentCSR, *domain.StoredCertificate, error) {
	issued, err := s.identityCA.IssueIdentityCertificate(ctx, identityCSR.CSRContent, reg.AnsName.String())
	if err != nil {
		return nil, nil, domain.NewInternalError("CERT_ISSUE_FAILED", "failed to issue identity cert", err)
	}
	signed, err := identityCSR.MarkSigned(now)
	if err != nil {
		return nil, nil, err
	}
	stored := &domain.StoredCertificate{
		CSRID:               identityCSR.CSRID,
		CertificateType:     domain.CertTypeIdentity,
		CertificatePEM:      issued.CertPEM,
		ChainPEM:            issued.ChainPEM,
		SerialNumber:        issued.SerialNumber,
		CertificateRef:      issued.CertificateRef,
		Status:              domain.CertStatusValid,
		IssueTimestamp:      issued.IssuedAt,
		ExpirationTimestamp: issued.ExpiresAt,
	}
	return &signed, stored, nil
}

// isV1Lane reports whether the caller asked for V1 TL emission.
// Empty string is treated as V2 (backwards compatible default for
// callers predating the V1 lane).
func isV1Lane(schemaVersion string) bool {
	return schemaVersion == "V1"
}

// VerifyDNSResult is returned by VerifyDNS. DNSMismatches is non-empty
// when records don't match; the handler maps that to 422 per spec.
type VerifyDNSResult struct {
	Registration  *domain.AgentRegistration
	Now           time.Time
	DNSMismatches []DNSMismatch // non-empty → handler emits 422
}

// DNSMismatch names a missing or incorrect record encountered during
// verification. Surface-level shape matches the V2 DnsVerificationError.
type DNSMismatch struct {
	Expected domain.ExpectedDNSRecord
	Found    string // empty if the record was missing entirely
	Code     string // "MISSING" | "MISMATCH"
}

// VerifyDNS checks the operator's authoritative nameserver for the
// required records (computed by domain.ComputeRequiredDNSRecords) and
// advances the registration to ACTIVE on success.
//
// On success, emits an AGENT_ACTIVE event whose attestations carry
// the production-state DNS records + identity/server cert
// fingerprints + per-protocol metadata hashes — the shape a verifier
// uses to audit the agent offline.
func (s *RegistrationService) VerifyDNS(ctx context.Context, agentID string, in VerifyInput) (*VerifyDNSResult, error) {
	now := s.clock()

	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}

	// FQDN exclusivity gate: if a different owner already holds this host
	// live, this registration lost the race and cannot activate — reject
	// before the idempotency/precondition checks below.
	if err := s.ensureHostNotTakenByOther(ctx, reg); err != nil {
		return nil, err
	}

	// Precondition: PENDING_DNS is the only state verify-dns accepts.
	// ACTIVE is idempotent (already done). Anything else is an error.
	if reg.Status == domain.StatusActive {
		return &VerifyDNSResult{Registration: reg, Now: now}, nil
	}
	if reg.Status != domain.StatusPendingDNS {
		return nil, domain.NewInvalidStateError(
			"CANNOT_VERIFY_DNS",
			fmt.Sprintf("verify-dns requires status PENDING_DNS, current: %s", reg.Status),
		)
	}

	// Load endpoints (required for the record-set computation).
	eps, err := s.endpoints.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if eps != nil {
		reg.Endpoints = eps.Endpoints
	}

	// Load the server cert (BYOC store holds both BYOC and CSR-signed
	// server certs — the CSR path re-validates the issued cert through
	// the same store). Needed so ComputeRequiredDNSRecords produces the
	// TLSA `_443._tcp.<fqdn>` record — without the cert in hand, the
	// record set would omit TLSA and an operator running the CSR path
	// would never be asked to publish the cert-binding record.
	//
	// A transient store failure must abort: this transition activates
	// the agent and signs the terminal AGENT_REGISTERED leaf, so a
	// swallowed error here would emit an immutable attestation missing
	// the TLSA record / serverCerts[] from a recoverable fault.
	byoc, berr := s.loadServerCert(ctx, agentID)
	if berr != nil {
		return nil, berr
	}
	if byoc != nil {
		reg.ServerCert = byoc
	}

	expected := domain.ComputeRequiredDNSRecords(reg, s.tlPublicBaseURL)

	mismatches, perRecord, err := s.verifyDNSRecords(ctx, reg.FQDN(), expected)
	if err != nil {
		return nil, fmt.Errorf("dns verify: %w", err)
	}
	if len(mismatches) > 0 {
		return &VerifyDNSResult{Registration: reg, Now: now, DNSMismatches: mismatches}, nil
	}

	// Transition to ACTIVE in-memory before any TL or DB work — Activate
	// is a domain-aggregate state machine that can fail (preconditions on
	// current status), and a precondition failure here shouldn't trigger a
	// TL seal or open a transaction.
	if err := reg.Activate(now); err != nil {
		return nil, err
	}

	// Seal-before-success (ANS-1 §12.3: "the RA MUST NOT activate without a
	// sealed event (step (d) is the point of no return)"). AGENT_REGISTERED
	// is the single terminal transition that marks the agent live in the
	// log; we submit it to the TL INLINE and report the agent ACTIVE only
	// after the TL acknowledges the seal — mirroring the identity lane. A
	// failed seal IS a failed activation: nothing is committed, the agent
	// stays PENDING_DNS, and the operator retries verify-dns once the TL is
	// reachable. This is what makes a downstream catalog entry's
	// SCITT-receipt/badge links point at TL records that actually exist.
	// (Both lanes emit the same eventType token in version-specific
	// envelope shapes; the seal runs outside the tx so the network round
	// trip never holds the SQLite write lock.)
	if err := s.sealActivationEvent(ctx, reg, expected, perRecord, in.SchemaVersion, now); err != nil {
		return nil, err
	}

	// Sealed: commit the ACTIVE transition and cancel any losing pending
	// registrations on this host atomically. The AGENT_REGISTERED event is
	// already durable in the TL, so — unlike the outbox path used by
	// revocation — there is nothing to enqueue here.
	//
	// The seal round trip above is a window a commit failure (SQLITE_BUSY,
	// crash) can land in: the agent then stays PENDING_DNS and the operator
	// retries verify-dns. The retry recomputes `now`, so its
	// AGENT_REGISTERED leaf carries fresh timestamps and a fresh content
	// hash — TL dedup will not match, appending a second AGENT_REGISTERED
	// leaf. That is the intended benign residue, accepted exactly as on the
	// identity lane: agent status keys on the ACTIVE row by agentId and
	// read-side status derives from any terminal leaf, so the duplicate is
	// invisible to verifiers and badges. It is not a dedup regression.
	if err := s.uow.Run(ctx, func(txCtx context.Context) error {
		if err := s.agents.Save(txCtx, reg); err != nil {
			return err
		}
		// The winner now holds the FQDN exclusively: cancel any other
		// owner's still-pending registrations on this host, atomically with
		// this activation (the loser is cancelled the moment the winner
		// goes live — not left to fail later at its own verify-dns).
		return s.cancelConflictingPendings(txCtx, reg.FQDN(), reg.OwnerID)
	}); err != nil {
		return nil, err
	}

	return &VerifyDNSResult{Registration: reg, Now: now}, nil
}

// dnssecKey canonicalizes name+type so the lookup result can be
// matched against an ExpectedDNSRecord regardless of trailing-dot
// or case differences.
func dnssecKey(name, typ string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".") + ":" + strings.ToUpper(typ)
}

// verifyDNSRecords queries the configured DNSVerifier for each
// expected record and returns the list of records that didn't match
// alongside the per-record verification results (for the attestation
// to surface DNSSEC-verified TLSA records to the TL).
//
// Two blocking conditions:
//
//  1. Required record missing or mismatched — the standard rule.
//     Covers the TXT records that drive agent discovery.
//
//  2. DNSSEC-validated TLSA record whose value doesn't match the
//     expected cert fingerprint — even though TLSA is Required=false
//     in the base record set, a DNSSEC-authenticated response
//     proves the operator's zone IS signed, at which point a wrong
//     TLSA value is an active attack vector (someone rewrote the
//     cert-binding record in the signed zone). Returning the
//     mismatch blocks verify-dns the same way a required miss does.
//     A missing TLSA with no DNSSEC evidence stays optional; the
//     operator just hasn't opted into DANE binding yet.
//
// If the verifier is nil, we skip verification and treat DNS as
// correct — local-dev behavior. Production configs must wire a real
// verifier.
func (s *RegistrationService) verifyDNSRecords(ctx context.Context, fqdn string, expected []domain.ExpectedDNSRecord) ([]DNSMismatch, []port.RecordVerification, error) {
	if s.dnsVerifier == nil {
		return nil, nil, nil
	}
	res, err := s.dnsVerifier.VerifyRecords(ctx, fqdn, expected)
	if err != nil {
		return nil, nil, err
	}
	if res == nil {
		return nil, nil, nil
	}
	var out []DNSMismatch
	for _, r := range res.Results {
		// DNSSEC-authenticated TLSA that doesn't match is a hard
		// fail regardless of the Required flag. `r.Found` from the
		// TLSA verifier is true only when the actual matched the
		// expected value after case-insensitive hex normalization,
		// so `DNSSECVerified && !Found` captures "response was
		// signed, but its content disagreed with the cert we
		// issued" — the exact attack we block.
		if r.Record.Type == domain.DNSRecordTLSA && r.DNSSECVerified && !r.Found {
			out = append(out, DNSMismatch{
				Expected: r.Record, Found: r.Actual, Code: "TLSA_DNSSEC_MISMATCH",
			})
			continue
		}
		if !r.Record.Required {
			continue
		}
		switch {
		case !r.Found:
			out = append(out, DNSMismatch{Expected: r.Record, Code: "MISSING"})
		case r.Found && r.Actual != r.Record.Value:
			out = append(out, DNSMismatch{Expected: r.Record, Found: r.Actual, Code: "MISMATCH"})
		}
	}
	return out, res.Results, nil
}

// buildAgentRegisteredEvent assembles the V2 inner event (including
// attestations) that lands in the log when the agent transitions to
// ACTIVE. The attestations shape is the V2 unified-array deviation
// (see internal/tl/event/event.go): typed DNSRecord array for
// provisioned state, identityCerts[] / serverCerts[] arrays with
// algorithm-prefixed fingerprints, optional metadataHashes. The
// eventType token matches V1 (`AGENT_REGISTERED`) — only the
// attestation shape differs between lanes.
func (s *RegistrationService) buildAgentRegisteredEvent(
	ctx context.Context,
	reg *domain.AgentRegistration,
	expected []domain.ExpectedDNSRecord,
	perRecord []port.RecordVerification,
	now time.Time,
) (*event.Event, error) {
	inner := s.baseInnerEvent(reg, event.TypeAgentRegistered, now)

	// Provisioned records: the exact record set the operator was
	// asked to configure, now verified live. ACME challenge records
	// are never on this list by construction — ComputeRequiredDNSRecords
	// doesn't include them.
	//
	// DNSSECVerified carries forward from the per-record verification
	// result (set true by the lookup verifier when a validating
	// resolver marked the response with the AD bit). Only ever true
	// for TLSA today — TXT and HTTPS records don't carry the flag.
	dnssecByKey := make(map[string]bool, len(perRecord))
	for _, r := range perRecord {
		if r.DNSSECVerified {
			dnssecByKey[dnssecKey(r.Record.Name, string(r.Record.Type))] = true
		}
	}
	provisioned := make([]event.DNSRecord, 0, len(expected))
	for _, r := range expected {
		provisioned = append(provisioned, event.DNSRecord{
			Name:           r.Name,
			Data:           r.Value,
			Type:           string(r.Type),
			DNSSECVerified: dnssecByKey[dnssecKey(r.Name, string(r.Type))],
		})
	}

	// Identity certs: every currently-valid one the store knows
	// about (typically one at registration time; rotation adds
	// more).
	identityCerts, err := s.certs.FindIdentityCertificatesByAgent(ctx, reg.AgentID)
	if err != nil {
		return nil, err
	}
	idCertInfos := make([]event.CertificateInfo, 0, len(identityCerts))
	for _, c := range identityCerts {
		if !c.IsValid(now) {
			continue
		}
		fp, ferr := fingerprintOf(c.CertificatePEM)
		if ferr != nil {
			return nil, ferr
		}
		idCertInfos = append(idCertInfos, event.CertificateInfo{
			Fingerprint: fp,
			CertType:    "X509-OV-CLIENT",
			NotAfter:    c.ExpirationTimestamp.UTC().Format(time.RFC3339),
		})
	}

	// Server cert (BYOC or CSR-signed): folded into the terminal
	// attestation's serverCerts[]. A transient store error must abort
	// the build — this leaf is signed and appended to an append-only
	// log, so silently emitting empty serverCerts[] would be a
	// permanently wrong artifact from a recoverable fault.
	var serverCertInfos []event.CertificateInfo
	byocCert, berr := s.loadServerCert(ctx, reg.AgentID)
	if berr != nil {
		return nil, berr
	}
	if byocCert != nil {
		serverCertInfos = []event.CertificateInfo{{
			Fingerprint: "SHA256:" + byocCert.Fingerprint,
			CertType:    "X509-DV-SERVER",
			NotAfter:    byocCert.ValidToTimestamp.UTC().Format(time.RFC3339),
		}}
	}

	// `expiresAt` is required at the event level per the reference TL
	// spec — the min(notAfter) across attested certs.
	inner.ExpiresAt = agentCertExpiry(identityCerts, byocCert, now)

	inner.Attestations = &event.Attestations{
		DomainValidation:      "ACME-DNS-01",
		DNSRecordsProvisioned: provisioned,
		IdentityCerts:         idCertInfos,
		ServerCerts:           serverCertInfos,
		MetadataHashes:        metadataHashesFromEndpoints(reg.Endpoints),
	}
	return inner, nil
}

// RevokeInput carries the caller's stated reason; the domain aggregate
// validates it. `SchemaVersion` selects which TL lane the revocation
// event flows to: "V1" enqueues AGENT_REVOKED to
// /v1/internal/agents/event, "V2" (default) enqueues AGENT_REVOCATION
// to /v2/internal/agents/event.
type RevokeInput struct {
	Reason        domain.RevocationReason
	Comments      string
	SchemaVersion string
}

// VerifyInput is the shared per-call option set for the verify-*
// service methods. `SchemaVersion` decides which TL lane the
// resulting lifecycle event flows to.
//
// For verify-acme, V1 emits nothing to the TL — the V1 enum has no
// intermediate DOMAIN_VALIDATION type; the V1 reference records the
// transition in its domain-level lifecycle store only. For verify-
// dns, V1 emits AGENT_REGISTERED on successful ACTIVE transition
// (V2 emits AGENT_ACTIVE for the same transition).
type VerifyInput struct {
	SchemaVersion string
}

// RevokeResult is returned to the handler; the handler maps it to
// AgentRevocationResponse.
type RevokeResult struct {
	Registration       *domain.AgentRegistration
	RevokedAt          time.Time
	DNSRecordsToRemove []domain.ExpectedDNSRecord
}

// Revoke terminates a registration through the single revoke route,
// per the spec's contract:
//
//   - ACTIVE / DEPRECATED agents are revoked: lifecycle → REVOKED,
//     every valid identity certificate revoked at the issuing CA and
//     flipped in the store, and an AGENT_REVOKED event emitted.
//   - PENDING registrations in the PENDING_CERTS phase (order
//     issuing/failed) or PENDING_DNS are cancelled: same certificate
//     cleanup, but NO TL emit — under the terminal-only event model
//     no leaf was ever written for an agent that never reached
//     ACTIVE, so there is nothing in the log to terminate.
//   - PENDING_VALIDATION registrations still awaiting their challenge
//     are neither: they auto-expire when the challenge window lapses
//     (the agent-expiry sweeper) — matching the spec's "not
//     cancellable and will auto-expire".
//
// The domain aggregate's Revoke/Cancel split enforces the state
// rules; this method routes to whichever applies.
func (s *RegistrationService) Revoke(ctx context.Context, agentID string, in RevokeInput) (*RevokeResult, error) {
	now := s.clock()

	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}

	// Load endpoints before we compute DNS records. The agent
	// aggregate stores endpoints in a separate repository, and
	// without them `ComputeRequiredDNSRecords` returns nothing.
	// Both lanes need this populated for revoke attestations and
	// for the response's `dnsRecordsToRemove` array — including
	// the idempotent already-revoked early return below, which
	// otherwise reported an empty list to the second caller.
	if len(reg.Endpoints) == 0 {
		if eps, err := s.endpoints.FindByAgentID(ctx, reg.AgentID); err == nil && eps != nil {
			reg.Endpoints = eps.Endpoints
		}
	}
	// Hydrate the server cert so DNSRecordsToRemove includes the TLSA
	// binding on every return path (idempotent early-return, cancel,
	// and active revoke all compute it).
	s.hydrateServerCert(ctx, reg)

	// Idempotent: already revoked → return current state without
	// re-emitting the event.
	//
	// Note on `RevokedAt` semantics: the registration aggregate has
	// no persisted revocation timestamp (the canonical record of
	// "when did this happen" lives in the audit-event log, not the
	// agent row). The RevokedAt returned here therefore reflects
	// the **most recent observation** — i.e. the wall-clock time
	// of the latest revoke API call — not the original transition.
	// Callers that need the original event timestamp should query
	// the TL for the agent's AGENT_REVOKED leaf, where the JCS-
	// canonical `eventTime` is replayed byte-for-byte from the
	// outbox per the project's outbox-replay invariant.
	if reg.Status == domain.StatusRevoked {
		return &RevokeResult{
			Registration:       reg,
			RevokedAt:          now,
			DNSRecordsToRemove: domain.ComputeRequiredDNSRecords(reg, s.tlPublicBaseURL),
		}, nil
	}

	// Pending registrations route to the cancel path: same
	// certificate cleanup as a revoke, no TL emit. The domain
	// aggregate enforces which pending states are cancellable.
	if reg.Status.IsPending() {
		return s.cancelPending(ctx, reg, in, now)
	}

	// Domain aggregate validates the reason + state transition.
	// Done in-memory before opening the tx so a precondition failure
	// (ErrInvalidState) doesn't open and immediately roll back a tx.
	if err := reg.Revoke(in.Reason, now); err != nil {
		// Active-or-deprecated precondition not met: surface as
		// 409 via the mapper (ErrInvalidState).
		if errors.Is(err, domain.ErrInvalidState) {
			return nil, err
		}
		return nil, err
	}

	// (Server cert already hydrated above — the AGENT_REVOKED event's
	// `expiresAt` needs its notAfter alongside the identity certs'.)

	// Read every identity cert before the tx. Pre-revoke status is
	// what the AGENT_REVOKED event captures; the in-tx update flips
	// each currently-valid one to REVOKED.
	certs, err := s.certs.FindIdentityCertificatesByAgent(ctx, reg.AgentID)
	if err != nil {
		return nil, err
	}

	// Revoke at the issuing CA before our own transaction so private
	// CRL/OCSP distribution reflects the revocation — flipping only
	// our database row would leave the certificate valid on the
	// trust plane. External side effects can't roll back with the
	// tx; the port's idempotency contract means a crash between CA
	// revocation and the commit is healed by retrying the call.
	if err := s.revokeIdentityCertsAtCA(ctx, certs, in.Reason); err != nil {
		return nil, err
	}

	// Persist atomically: agent state, every cert revocation, and
	// the AGENT_REVOKED outbox row commit together. Pre-tx, agent
	// could be REVOKED while certs were still VALID and the outbox
	// row never landed — leaving the TL with no record of the
	// revocation.
	//
	// AGENT_REVOKED: terminal in both lanes. Same `eventType` token
	// on both V1 and V2 — only the attestation shape differs. The
	// V1 envelope carries the cert fingerprints being revoked
	// (rotation-array `validIdentityCerts[]` / `validServerCerts[]`)
	// plus the DNS records the operator should tear down (map-typed
	// `dnsRecordsProvisioned`). V2 uses the unified cert arrays.
	if err := s.uow.Run(ctx, func(txCtx context.Context) error {
		if err := s.agents.Save(txCtx, reg); err != nil {
			return err
		}
		for _, c := range certs {
			if c.Status == domain.CertStatusValid {
				revoked := c.Revoke()
				if err := s.certs.UpdateCertificateStatus(txCtx, &revoked); err != nil {
					return err
				}
			}
		}
		if isV1Lane(in.SchemaVersion) {
			v1Inner, err := s.buildAgentRevokedV1Event(reg, certs, in.Reason, now)
			if err != nil {
				return err
			}
			return s.enqueueTLEventV1(txCtx, string(eventv1.TypeAgentRevoked), reg, v1Inner, now)
		}
		inner, err := s.buildAgentRevokedV2Event(reg, certs, in.Reason, now)
		if err != nil {
			return err
		}
		return s.enqueueTLEvent(txCtx, string(event.TypeAgentRevoked), reg, inner, now)
	}); err != nil {
		return nil, err
	}

	return &RevokeResult{
		Registration:       reg,
		RevokedAt:          now,
		DNSRecordsToRemove: domain.ComputeRequiredDNSRecords(reg, s.tlPublicBaseURL),
	}, nil
}

// buildAgentRevokedV2Event assembles the V2 AGENT_REVOKED inner
// event: the revoked identity-cert fingerprints as attestations plus
// the event-level `expiresAt`, which is required per the reference TL
// spec even on terminal events. Uses the certs that WERE valid at the
// point of revocation — at this exact moment the original notAfter
// values are still in hand, so they feed through directly.
func (s *RegistrationService) buildAgentRevokedV2Event(
	reg *domain.AgentRegistration, certs []*domain.StoredCertificate,
	reason domain.RevocationReason, now time.Time,
) (*event.Event, error) {
	inner := s.baseInnerEvent(reg, event.TypeAgentRevoked, now)
	inner.RevokedAt = now.UTC().Format(time.RFC3339)
	inner.RevocationReasonCode = string(reason)
	idCertInfos := make([]event.CertificateInfo, 0, len(certs))
	for _, c := range certs {
		fp, ferr := fingerprintOf(c.CertificatePEM)
		if ferr != nil {
			return nil, ferr
		}
		idCertInfos = append(idCertInfos, event.CertificateInfo{
			Fingerprint: fp,
			CertType:    "X509-OV-CLIENT",
			NotAfter:    c.ExpirationTimestamp.UTC().Format(time.RFC3339),
		})
	}
	var minExpiry time.Time
	for _, c := range certs {
		if c.ExpirationTimestamp.IsZero() {
			continue
		}
		if minExpiry.IsZero() || c.ExpirationTimestamp.Before(minExpiry) {
			minExpiry = c.ExpirationTimestamp
		}
	}
	if reg.ServerCert != nil && !reg.ServerCert.ValidToTimestamp.IsZero() {
		if minExpiry.IsZero() || reg.ServerCert.ValidToTimestamp.Before(minExpiry) {
			minExpiry = reg.ServerCert.ValidToTimestamp
		}
	}
	if !minExpiry.IsZero() {
		inner.ExpiresAt = minExpiry.UTC().Format(time.RFC3339)
	}
	inner.Attestations = &event.Attestations{
		IdentityCerts: idCertInfos,
	}
	return inner, nil
}

// cancelPending terminates a pending registration through the revoke
// route: the aggregate's Cancel transition (which enforces the
// spec's eligibility rule), CA-side revocation of any
// already-issued identity certificates, and the store flips —
// committed atomically. Deliberately NO TL emit: under the
// terminal-only event model no leaf was ever written for an agent
// that never reached ACTIVE, so there is nothing in the log to
// terminate; emitting AGENT_REVOKED for an agent the log has never
// seen would strand verifiers on an unresolvable reference.
func (s *RegistrationService) cancelPending(
	ctx context.Context, reg *domain.AgentRegistration,
	in RevokeInput, now time.Time,
) (*RevokeResult, error) {
	if !in.Reason.IsValid() {
		return nil, domain.NewValidationError(
			"INVALID_REVOCATION_REASON", fmt.Sprintf("invalid reason: %q", in.Reason))
	}
	if err := reg.Cancel(now); err != nil {
		return nil, err
	}

	certs, err := s.certs.FindIdentityCertificatesByAgent(ctx, reg.AgentID)
	if err != nil {
		return nil, err
	}
	if err := s.revokeIdentityCertsAtCA(ctx, certs, in.Reason); err != nil {
		return nil, err
	}

	if err := s.uow.Run(ctx, func(txCtx context.Context) error {
		if err := s.agents.Save(txCtx, reg); err != nil {
			return err
		}
		for _, c := range certs {
			if c.Status == domain.CertStatusValid {
				revoked := c.Revoke()
				if err := s.certs.UpdateCertificateStatus(txCtx, &revoked); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return &RevokeResult{
		Registration:       reg,
		RevokedAt:          now,
		DNSRecordsToRemove: domain.ComputeRequiredDNSRecords(reg, s.tlPublicBaseURL),
	}, nil
}

// hydrateServerCert loads the agent's most-recent server certificate
// onto the aggregate when it isn't already populated, so the revoke
// flow can fingerprint it for the AGENT_REVOKED event and include its
// TLSA binding in DNSRecordsToRemove. Best-effort: a missing cert
// (BYOC never submitted, CSR order never finalized) leaves ServerCert
// nil and the TLSA record is simply omitted. FindByAgentID (not
// FindLatestValid) is used because a cert already flipped to REVOKED
// must still be fingerprinted here.
func (s *RegistrationService) hydrateServerCert(ctx context.Context, reg *domain.AgentRegistration) {
	if reg.ServerCert != nil {
		return
	}
	if all, err := s.byoc.FindByAgentID(ctx, reg.AgentID); err == nil && len(all) > 0 {
		reg.ServerCert = all[0]
	}
}

// revokeIdentityCertsAtCA revokes every still-valid identity
// certificate at the issuing CA. Runs BEFORE the caller's
// transaction — CA revocation is an external side effect that cannot
// roll back, and the port contract makes it idempotent, so a crash
// between CA revocation and the commit heals on retry. The serial
// comes from the stored row when present; rows persisted before
// serial tracking fall back to parsing the certificate PEM.
func (s *RegistrationService) revokeIdentityCertsAtCA(
	ctx context.Context, certs []*domain.StoredCertificate, reason domain.RevocationReason,
) error {
	for _, c := range certs {
		if c.Status != domain.CertStatusValid {
			continue
		}
		serial := c.SerialNumber
		if serial == "" {
			parsed, err := serialFromCertPEM(c.CertificatePEM)
			if err != nil {
				return domain.NewInternalError("CERT_REVOKE_FAILED",
					"derive certificate serial for CA revocation", err)
			}
			serial = parsed
		}
		if err := s.identityCA.RevokeCertificate(ctx, port.RevokeCertificateRequest{
			SerialNumber:   serial,
			CertificateRef: c.CertificateRef,
			Reason:         reason,
		}); err != nil {
			return domain.NewInternalError("CERT_REVOKE_FAILED",
				"revoke identity certificate at issuing CA", err)
		}
	}
	return nil
}
