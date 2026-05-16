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
	// where the RA signs the server cert itself. A nil result from
	// the store is fine; ComputeRequiredDNSRecords skips the TLSA
	// record when reg.ServerCert is nil.
	if byoc, berr := s.byoc.FindLatestValidByAgentID(ctx, agentID); berr == nil && byoc != nil {
		reg.ServerCert = byoc
	}
	return &DetailResult{
		Registration: reg,
		Endpoints:    epSlice,
	}, nil
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
// agent (identity-cert rotation). Validates the CSR against the
// agent's ANS name, updates the aggregate's embedded IdentityCSR
// slot, and persists the row in the csrs table so the status endpoint
// can find it.
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
	if err := s.validator.ValidateIdentityCSR(ctx, csrPEM, reg.AnsName.String()); err != nil {
		return "", domain.NewValidationError("INVALID_IDENTITY_CSR", err.Error())
	}
	csrID := uuid.NewString()
	newCSR, err := reg.SubmitIdentityCSR(csrID, csrPEM, now)
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
	if err := s.validator.ValidateServerCSR(ctx, csrPEM, reg.FQDN()); err != nil {
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
// into an AgentStatus response (status=PENDING_DNS, phase=DNS_PROVISIONING).
type VerifyACMEResult struct {
	Registration *domain.AgentRegistration
	Now          time.Time // propagated so handler timestamps match the outbox row
}

// VerifyACME advances the registration from PENDING_VALIDATION to
// PENDING_DNS. This is the choke point where "caller proved domain
// control" meets "caller gets certs": the RA does NOT sign anything
// at register time, because without domain validation the cert
// would vouch for a hostname nobody verified the caller owns.
//
// Steps:
//
//  1. Verify the ACME DNS-01 challenge TXT record resolves to the
//     expected token. (Skipped when dnsVerifier is nil — local dev.)
//  2. Sign the identity CSR via identityCA. Persist the resulting
//     cert + mark the CSR SIGNED.
//  3. If a server CSR was submitted at registration (CSR path),
//     sign it via serverCA and persist the resulting cert through
//     the BYOC store (same struct covers both paths downstream).
//     BYOC registrations skipped this step — the operator's cert
//     was saved at register time.
//  4. Transition the aggregate to PENDING_DNS.
//
// Idempotent: if the registration is already past PENDING_VALIDATION,
// return the current state without erroring — matches the reference's
// "if already progressed, succeed silently" semantics.
func (s *RegistrationService) VerifyACME(ctx context.Context, agentID string, in VerifyInput) (*VerifyACMEResult, error) {
	now := s.clock()
	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
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

	// 1. Verify the ACME DNS-01 challenge record. The expected
	//    value is the token the RA generated at register time; the
	//    record name is `_acme-challenge.<fqdn>`.
	if s.dnsVerifier != nil && !reg.ACMEChallenge.IsZero() {
		acmeRec := domain.ExpectedDNSRecord{
			Name:     "_acme-challenge." + reg.FQDN(),
			Type:     domain.DNSRecordTXT,
			Value:    reg.ACMEChallenge.DNS01Token,
			Purpose:  "DOMAIN_VALIDATION",
			Required: true,
		}
		res, verr := s.dnsVerifier.VerifyRecords(ctx, reg.FQDN(), []domain.ExpectedDNSRecord{acmeRec})
		if verr != nil {
			return nil, fmt.Errorf("acme verify: %w", verr)
		}
		if res != nil && !res.AllRequired {
			return nil, domain.NewInvalidStateError(
				"ACME_CHALLENGE_MISSING",
				fmt.Sprintf("_acme-challenge.%s TXT record is not published or doesn't match the issued token", reg.FQDN()),
			)
		}
	}

	// 2. Sign the identity CSR — only for versioned registrations.
	//    Plan F §3.2.0 base-only registrations carry no Identity CSR
	//    and no Identity Certificate is issued; the lifecycle still
	//    advances through PENDING_DNS to ACTIVE, just without the
	//    cert artifacts. Plan G's non-FQDN anchors (DID, LEI) all
	//    take this path because NON_FQDN_REQUIRES_BASE_ONLY forced
	//    them base-only at registration time.
	//
	//    For versioned registrations the path is unchanged: fetch
	//    pending CSR, sign through the IdentityCertificateAuthority
	//    port, mark the CSR signed, build the StoredCertificate row.
	//    Issuance + signing are CPU-bound and do not touch the DB;
	//    we run them outside the tx so the SQLite write lock isn't
	//    held during work that doesn't need it. Same pattern below
	//    for the server CSR path.
	var (
		signedID    domain.AgentCSR
		storedID    *domain.StoredCertificate
		hasIdentity bool
	)
	if !reg.IsBaseOnly() {
		identityCSR, err := s.certs.FindLatestPendingCSRByType(ctx, agentID, domain.CSRTypeIdentity)
		if err != nil {
			return nil, err
		}
		if identityCSR == nil {
			return nil, domain.NewInvalidStateError(
				"MISSING_IDENTITY_CSR",
				"no pending identity CSR for agent — aggregate in inconsistent state",
			)
		}
		issuedID, err := s.identityCA.IssueIdentityCertificate(ctx, identityCSR.CSRContent, reg.AnsName.String())
		if err != nil {
			return nil, domain.NewInternalError("CERT_ISSUE_FAILED", "failed to issue identity cert", err)
		}
		signedID, err = identityCSR.MarkSigned(now)
		if err != nil {
			return nil, err
		}
		reg.IdentityCSR = &signedID
		storedID = &domain.StoredCertificate{
			CSRID:               identityCSR.CSRID,
			CertificateType:     domain.CertTypeIdentity,
			CertificatePEM:      issuedID.CertPEM,
			ChainPEM:            issuedID.ChainPEM,
			Status:              domain.CertStatusValid,
			IssueTimestamp:      issuedID.IssuedAt,
			ExpirationTimestamp: issuedID.ExpiresAt,
		}
		hasIdentity = true
	}

	// 3. CSR-path server cert: same shape — sign + validate up
	//    front, persist below inside the tx.
	serverCSR, err := s.certs.FindLatestPendingCSRByType(ctx, agentID, domain.CSRTypeServer)
	if err != nil {
		return nil, err
	}
	var byocCert *domain.ByocServerCertificate
	var signedSrv domain.AgentCSR
	if serverCSR != nil {
		var err error
		byocCert, signedSrv, err = s.signServerCSRForVerifyACME(ctx, reg, serverCSR, now)
		if err != nil {
			return nil, err
		}
		reg.ServerCert = byocCert
	}

	// 4. Transition to PENDING_DNS in-memory; the tx below commits it.
	if err := reg.AdvanceToPendingDNS(); err != nil {
		return nil, err
	}

	// 5. Persist atomically: signed CSR rows, the identity cert, the
	//    issued server cert (if any), and the agent's new state.
	//    Pre-tx, agent.Save committed first and a downstream failure
	//    left a PENDING_DNS agent with no associated cert rows.
	//    Base-only registrations skip the identity CSR + cert writes;
	//    the server CSR path is unchanged.
	if err := s.uow.Run(ctx, func(txCtx context.Context) error {
		if hasIdentity {
			// SaveCSR upserts on csr_id so the same row flips
			// PENDING → SIGNED.
			if err := s.certs.SaveCSR(txCtx, reg.AgentID, &signedID); err != nil {
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

// signServerCSRForVerifyACME signs the pending server CSR via the
// configured server CA, validates the issued cert, and returns the
// BYOC-shape cert struct + the SIGNED CSR row so the caller can
// commit both inside its uow transaction. Extracted from VerifyACME
// to keep the orchestrator under the funlen bound; the issuance +
// validation are CPU-only and don't need to hold the SQLite write
// lock.
func (s *RegistrationService) signServerCSRForVerifyACME(
	ctx context.Context, reg *domain.AgentRegistration,
	serverCSR *domain.AgentCSR, now time.Time,
) (*domain.ByocServerCertificate, domain.AgentCSR, error) {
	if s.serverCA == nil {
		return nil, domain.AgentCSR{}, domain.NewInternalError("SERVER_CA_DISABLED",
			"server CSR pending but no server CA configured — inconsistent state", nil)
	}
	issued, err := s.serverCA.IssueServerCertificate(ctx, serverCSR.CSRContent, reg.FQDN())
	if err != nil {
		return nil, domain.AgentCSR{}, domain.NewInternalError("SERVER_CERT_ISSUE_FAILED",
			"failed to issue server cert", err)
	}
	v, err := s.validator.ValidateServerCertificate(ctx,
		issued.CertPEM, issued.ChainPEM, reg.FQDN())
	if err != nil {
		return nil, domain.AgentCSR{}, domain.NewInternalError("SERVER_CERT_SELFVERIFY_FAILED",
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
		return nil, domain.AgentCSR{}, err
	}
	return byocCert, signed, nil
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
	if byoc, berr := s.byoc.FindLatestValidByAgentID(ctx, agentID); berr == nil && byoc != nil {
		reg.ServerCert = byoc
	}

	expected := domain.ComputeRequiredDNSRecords(reg)

	mismatches, perRecord, err := s.verifyDNSRecords(ctx, reg.FQDN(), expected)
	if err != nil {
		return nil, fmt.Errorf("dns verify: %w", err)
	}
	if len(mismatches) > 0 {
		return &VerifyDNSResult{Registration: reg, Now: now, DNSMismatches: mismatches}, nil
	}

	// Transition to ACTIVE in-memory before entering the tx — Activate
	// is a domain-aggregate state machine that can fail (preconditions
	// on current status), and a precondition failure here shouldn't
	// open and then immediately roll back a transaction.
	if err := reg.Activate(now); err != nil {
		return nil, err
	}

	// AGENT_REGISTERED: the single terminal transition that marks
	// the agent live in the log. Both V1 and V2 lanes emit this
	// SAME `eventType` token (the V1 enum is authoritative), but in
	// version-specific envelope shapes — V1 uses singleton +
	// rotation-array + map-typed attestations, V2 uses unified
	// `identityCerts[]` / `serverCerts[]` + typed
	// `dnsRecordsProvisioned[]` per the documented deviation.
	//
	// Build + sign the event before opening the tx so the producer
	// signature (a KMS round-trip) doesn't hold the SQLite write
	// lock open. Persistence of the agent's new status and the
	// outbox row commit atomically inside uow.Run — without the tx,
	// agent.Save committing without the outbox enqueue would mean
	// an ACTIVE agent whose AGENT_REGISTERED event never makes it
	// to the TL.
	if err := s.uow.Run(ctx, func(txCtx context.Context) error {
		if err := s.agents.Save(txCtx, reg); err != nil {
			return err
		}
		if isV1Lane(in.SchemaVersion) {
			v1Inner, err := s.buildAgentRegisteredV1Event(txCtx, reg, expected, now)
			if err != nil {
				return err
			}
			return s.enqueueTLEventV1(txCtx, string(eventv1.TypeAgentRegistered), reg, v1Inner, now)
		}
		inner, err := s.buildAgentRegisteredEvent(txCtx, reg, expected, perRecord, now)
		if err != nil {
			return err
		}
		return s.enqueueTLEvent(txCtx, string(event.TypeAgentRegistered), reg, inner, now)
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

	// BYOC server certs: if the operator provided one at registration.
	var serverCertInfos []event.CertificateInfo
	var byocCert *domain.ByocServerCertificate
	if byoc, berr := s.byoc.FindLatestValidByAgentID(ctx, reg.AgentID); berr == nil && byoc != nil {
		byocCert = byoc
		serverCertInfos = []event.CertificateInfo{{
			Fingerprint: "SHA256:" + byoc.Fingerprint,
			CertType:    "X509-DV-SERVER",
			NotAfter:    byoc.ValidToTimestamp.UTC().Format(time.RFC3339),
		}}
	}

	// `expiresAt` is required at the event level per the reference TL
	// spec — the min(notAfter) across attested certs.
	inner.ExpiresAt = agentCertExpiry(identityCerts, byocCert, now)

	mhashes := metadataHashesFromEndpoints(reg.Endpoints)
	if reg.CapabilitiesHash != "" {
		// The agent-level Trust Card hash sealed at activation per
		// ANS_SPEC.md §A.1. The map key is reserved by the TL event
		// package; agents that registered without agentCardContent
		// have CapabilitiesHash empty, in which case the key is
		// absent and the AIM falls back to TOFU on first fetch.
		if mhashes == nil {
			mhashes = map[string]string{}
		}
		mhashes[event.MetadataHashKeyCapabilitiesHash] = reg.CapabilitiesHash
	}
	inner.Attestations = &event.Attestations{
		DomainValidation:      "ACME-DNS-01",
		DNSRecordsProvisioned: provisioned,
		IdentityCerts:         idCertInfos,
		ServerCerts:           serverCertInfos,
		MetadataHashes:        mhashes,
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

// Revoke transitions the registration to REVOKED, marks every active
// identity certificate REVOKED, and emits an AGENT_REVOCATION event.
//
// Reference parity note: the reference RA refuses revocation from
// PENDING_VALIDATION with a dedicated error (application must
// complete ACME first or expire). We delegate to the domain
// aggregate's own Revoke/Cancel split — Revoke works on ACTIVE or
// DEPRECATED, Cancel works on pending states. Here we wire Revoke
// semantically; callers who want to cancel a pending registration
// should hit a separate endpoint (not in Stage 2).
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
			DNSRecordsToRemove: domain.ComputeRequiredDNSRecords(reg),
		}, nil
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

	// Hydrate the server cert for the same reason — the
	// AGENT_REVOKED event's `expiresAt` needs the server cert's
	// notAfter alongside the identity certs', and `FindLatestValid`
	// returns nothing once the cert has been marked revoked.
	if reg.ServerCert == nil {
		if all, berr := s.byoc.FindByAgentID(ctx, reg.AgentID); berr == nil && len(all) > 0 {
			reg.ServerCert = all[0]
		}
	}

	// Read every identity cert before the tx. Pre-revoke status is
	// what the AGENT_REVOKED event captures; the in-tx update flips
	// each currently-valid one to REVOKED.
	certs, err := s.certs.FindIdentityCertificatesByAgent(ctx, reg.AgentID)
	if err != nil {
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
		inner := s.baseInnerEvent(reg, event.TypeAgentRevoked, now)
		inner.RevokedAt = now.UTC().Format(time.RFC3339)
		inner.RevocationReasonCode = string(in.Reason)
		idCertInfos := make([]event.CertificateInfo, 0, len(certs))
		for _, c := range certs {
			fp, ferr := fingerprintOf(c.CertificatePEM)
			if ferr != nil {
				return ferr
			}
			idCertInfos = append(idCertInfos, event.CertificateInfo{
				Fingerprint: fp,
				CertType:    "X509-OV-CLIENT",
				NotAfter:    c.ExpirationTimestamp.UTC().Format(time.RFC3339),
			})
		}
		// `expiresAt` is required at event level per the reference TL
		// spec, including on terminal events. Use the certs that WERE
		// valid at the point of revocation — `IsValid(now)` returns
		// false post-revocation but at this exact moment we still
		// have the original notAfter values, so feed them through
		// directly.
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
		return s.enqueueTLEvent(txCtx, string(event.TypeAgentRevoked), reg, inner, now)
	}); err != nil {
		return nil, err
	}

	return &RevokeResult{
		Registration:       reg,
		RevokedAt:          now,
		DNSRecordsToRemove: domain.ComputeRequiredDNSRecords(reg),
	}, nil
}
