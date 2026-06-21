package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// renewalChallengeWindow is how long the operator has to publish a
// domain-control challenge artifact for a renewal. Mirrors the
// domain's renewal expiry; the effective window is clamped to the
// provider order's own expiry when that is shorter.
const renewalChallengeWindow = 7 * 24 * time.Hour

// SubmitRenewalInput is what the POST /certificates/server/renewal
// handler passes through. Matches V2 ServerCertificateRenewalRequest
// (§1409): exactly one of ServerCsrPEM / ServerCertificatePEM must
// be set.
type SubmitRenewalInput struct {
	ServerCsrPEM              string
	ServerCertificatePEM      string
	ServerCertificateChainPEM string
}

// SubmitRenewalResult is returned from SubmitServerCertRenewal. The
// handler maps this into the RenewalSubmissionResponse DTO. FQDN is
// carried so the handler can render challenge record names and URLs
// without re-fetching the agent.
type SubmitRenewalResult struct {
	Renewal *domain.ServerCertificateRenewal
	CsrID   string // non-empty for SERVER_CSR renewals
	FQDN    string
}

// SubmitServerCertRenewal initiates a server cert renewal for the
// agent. Mirrors the reference RA's
// `CertificateRenewalOperationsHandler.submitServerCertificateRenewal`
// with the following rules:
//
//   - Agent must be ACTIVE.
//   - At most one pending renewal per agent.
//   - Exactly one of serverCsrPEM / serverCertificatePEM must be set;
//     both or neither → 422.
//   - CSR path validates the PEM against the agent's FQDN and
//     persists a new server CSR in `agent_csrs`.
//   - BYOC path validates the cert against the agent's FQDN +
//     chain.
//
// Returns the created renewal. The handler transforms it into a
// RenewalSubmissionResponse with DNS-01/HTTP-01 challenge info.
func (s *RegistrationService) SubmitServerCertRenewal(
	ctx context.Context,
	agentID string,
	in SubmitRenewalInput,
) (*SubmitRenewalResult, error) {
	now := s.clock()

	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if reg.Status != domain.StatusActive {
		return nil, domain.NewInvalidStateError(
			"AGENT_NOT_ACTIVE",
			fmt.Sprintf("Agent must be ACTIVE to initiate renewal. Current status: %s", reg.Status),
		)
	}

	// 409 if a non-terminal renewal already exists.
	existing, err := s.renewals.FindPendingByAgentID(ctx, agentID)
	if err == nil && existing != nil {
		return nil, domain.NewConflictError("PENDING_RENEWAL_EXISTS",
			fmt.Sprintf("A pending renewal already exists for agent %s", agentID))
	}
	// FindPendingByAgentID returns ErrNotFound (NOT_FOUND domain
	// error) when nothing's there — swallow that, propagate any
	// other error.
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}

	csrSet := in.ServerCsrPEM != ""
	byocSet := in.ServerCertificatePEM != ""
	if csrSet == byocSet {
		return nil, domain.NewValidationError(
			"INVALID_RENEWAL_REQUEST",
			"exactly one of serverCsrPEM or serverCertificatePEM must be provided")
	}

	var renewal *domain.ServerCertificateRenewal
	var csrID string

	switch {
	case csrSet:
		// Server CSRs must carry the agent FQDN as a DNS SAN — TLS
		// server-auth convention, distinct from the identity CSR's
		// URI SAN shape.
		if err := s.validator.ValidateServerCSR(ctx, in.ServerCsrPEM, reg.AnsName.FQDN()); err != nil {
			return nil, domain.NewValidationError("INVALID_SERVER_CSR",
				"Server CSR validation failed: "+err.Error())
		}
		// Require an issuer for finalization at verify-acme time. We
		// fail fast here rather than letting the renewal sit in
		// PENDING_VALIDATION forever when the operator has no issuer
		// wired.
		if s.serverCA == nil {
			return nil, domain.NewValidationError(
				"SERVER_CA_DISABLED",
				"serverCsrPEM renewal submitted but no server CA is configured")
		}
		// The certificate order — and with it the domain-control
		// challenges relayed to the operator — comes from the issuer
		// port, so an ACME provider's own tokens flow through
		// untouched.
		order, err := s.serverCA.CreateOrder(ctx, reg.AnsName.FQDN())
		if err != nil {
			return nil, domain.NewInternalError(
				"CERT_ORDER_FAILED", "create certificate order", err)
		}
		csrID = uuid.NewString()
		newCSR, err := reg.SubmitServerCSR(csrID, in.ServerCsrPEM, now)
		if err != nil {
			return nil, err
		}
		if err := s.agents.Save(ctx, reg); err != nil {
			return nil, err
		}
		if err := s.certs.SaveCSR(ctx, agentID, newCSR); err != nil {
			return nil, err
		}
		renewal = domain.NewCSRRenewal(agentID, reg.ID, csrID, *order, now)

	case byocSet:
		v, err := s.validator.ValidateServerCertificate(ctx,
			in.ServerCertificatePEM, in.ServerCertificateChainPEM, reg.AnsName.FQDN())
		if err != nil {
			return nil, domain.NewCertificateError(
				"INVALID_BYOC_CERT",
				"BYOC certificate validation failed: "+err.Error())
		}
		// Persist the validated cert separately so the BYOC store
		// has it before the renewal completes. The renewal itself
		// carries the raw PEM so "verify-acme" has everything it
		// needs to flip the cert over without a second read.
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
		if err := s.byoc.Save(ctx, agentID, byocCert); err != nil {
			return nil, err
		}
		// BYOC renewals issue no certificate, so no provider order
		// exists — but domain control must still be proven before the
		// operator's cert goes live. The RA self-issues the
		// validation challenges.
		dns01, http01, err := generateChallengeTokens()
		if err != nil {
			return nil, domain.NewInternalError("CHALLENGE_GEN_FAILED", "generate challenge tokens", err)
		}
		renewal = domain.NewBYOCRenewal(agentID, reg.ID,
			in.ServerCertificatePEM, in.ServerCertificateChainPEM,
			domain.NewSelfIssuedOrder(dns01, http01, now.Add(renewalChallengeWindow)), now)
	}

	if err := s.renewals.Save(ctx, renewal); err != nil {
		return nil, err
	}

	return &SubmitRenewalResult{Renewal: renewal, CsrID: csrID, FQDN: reg.AnsName.FQDN()}, nil
}

// GetRenewalResult is returned from GetServerCertRenewal. FQDN lets
// the handler render challenge record names; TLSARecord is the
// DANE-EE record for the renewal's new certificate, set once the
// renewal completed — it is the artifact the WAIT next-step tells the
// operator to poll for.
type GetRenewalResult struct {
	Renewal    *domain.ServerCertificateRenewal
	FQDN       string
	TLSARecord *domain.ExpectedDNSRecord
}

// GetServerCertRenewal returns the most-recent renewal for the agent
// (including completed / failed / expired), for the GET handler. 404
// is produced by the underlying store returning ErrNotFound; callers
// don't need to distinguish "no renewal" from "agent not found"
// because the ownership middleware has already confirmed the agent.
func (s *RegistrationService) GetServerCertRenewal(ctx context.Context, agentID string) (*GetRenewalResult, error) {
	r, err := s.renewals.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	res := &GetRenewalResult{Renewal: r, FQDN: reg.AnsName.FQDN()}
	// Completed renewals surface the TLSA record for the new leaf —
	// the operator updates DNS with it to finish the rollover. A
	// transient store error must propagate rather than silently drop
	// the record the WAIT next-step tells the operator to poll for.
	if !r.CompletedAt.IsZero() && r.FailureReason == "" {
		cert, cerr := s.loadServerCert(ctx, agentID)
		if cerr != nil {
			return nil, cerr
		}
		if cert != nil {
			rec := domain.TLSARecordForCert(res.FQDN, cert.Fingerprint)
			res.TLSARecord = &rec
		}
	}
	return res, nil
}

// CancelServerCertRenewal cancels the most recent renewal for the
// agent. 404 if no renewal exists; 422 if the renewal already
// completed (same 422 status as the reference RA). Idempotent in the
// sense that repeat cancels of an already-deleted renewal return
// the same 404 — the reference uses the same semantic.
func (s *RegistrationService) CancelServerCertRenewal(ctx context.Context, agentID string) error {
	r, err := s.renewals.FindByAgentID(ctx, agentID)
	if err != nil {
		return err
	}
	if !r.CompletedAt.IsZero() {
		return domain.NewValidationError(
			"RENEWAL_ALREADY_COMPLETED",
			"cannot cancel a completed renewal")
	}
	// If the renewal originated from a CSR, flip the CSR to REJECTED
	// as the reference's deleteIncompleteRenewal path does (atomic
	// in the reference; we do it in sequence since SQLite's
	// concurrency model is serializable at this level).
	if r.RenewalType == domain.RenewalTypeCSR && r.ServerCsrID != "" {
		csr, cerr := s.certs.FindCSRByID(ctx, agentID, r.ServerCsrID)
		if cerr == nil && csr != nil && csr.Status == domain.CSRStatusPending {
			rejected, rerr := csr.MarkRejected("Renewal cancelled", s.clock())
			if rerr == nil {
				_ = s.certs.SaveCSR(ctx, agentID, &rejected)
			}
		}
	}
	return s.renewals.Delete(ctx, r.ID)
}

// VerifyRenewalACMEResult is returned to the handler so it can shape
// the response (HTTP 200 vs 202, status string, tlsaDnsRecord).
type VerifyRenewalACMEResult struct {
	Renewal *domain.ServerCertificateRenewal
	// Sync is true when the renewal reached COMPLETED in this call —
	// BYOC after validation, or CSR when the issuer finalized
	// synchronously. False means the issuer is still processing
	// (ISSUING_CERTIFICATE); the operator re-POSTs verify-acme to
	// drive the order to completion.
	Sync bool
	// TLSARecord is the DANE-EE record for the renewal's new leaf
	// certificate; set when the renewal completed in this call so the
	// operator can update DNS immediately.
	TLSARecord *domain.ExpectedDNSRecord
}

// VerifyRenewalACME verifies that the operator published one of the
// renewal's domain-control challenge artifacts, marks the validation
// VERIFIED, and completes the renewal: BYOC by flipping the
// registration's ServerCert to the already-validated cert, CSR by
// finalizing the certificate order via the issuer port.
//
// The challenge gate is unconditional — the issuer is never invoked
// until the RA has confirmed a published artifact, regardless of
// which issuer adapter is wired. Asynchronous issuers may leave the
// order pending; the renewal then stays in ISSUING_CERTIFICATE
// (derived) and a re-POST of verify-acme re-attempts the finalize —
// the gate is skipped on re-driven calls because the provider already
// accepted the challenge answer.
func (s *RegistrationService) VerifyRenewalACME(ctx context.Context, agentID string) (*VerifyRenewalACMEResult, error) {
	now := s.clock()

	r, err := s.renewals.FindPendingByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if r.IsExpired(now) {
		return nil, domain.NewValidationError("RENEWAL_EXPIRED",
			"renewal validation window has expired")
	}

	// Re-driven call: validation already passed on an earlier
	// verify-acme; only the order finalize remains.
	if r.Validation.Status == domain.ValidationVerified {
		if r.RenewalType != domain.RenewalTypeCSR {
			// BYOC renewals complete in the same call that verifies
			// them, so a verified-but-pending BYOC renewal cannot
			// exist; FindPendingByAgentID would not have returned it.
			return nil, domain.NewValidationError("RENEWAL_NOT_PENDING",
				"renewal validation has already been verified")
		}
		return s.finalizeCSRRenewal(ctx, agentID, r, nil, now)
	}

	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}

	// A CSR renewal whose provider order came back already-validated
	// (Let's Encrypt authorization reuse — CreateOrder returned no
	// challenges) has nothing for the owner to publish, so the gate is
	// skipped and the order is finalized directly. This is unambiguous:
	// BYOC renewals always carry the RA's two self-issued challenges,
	// and legacy renewals synthesize a DNS-01/HTTP-01 pair from their
	// token columns, so only a born-ready provider order has none.
	// A born-ready provider order (Let's Encrypt authorization reuse —
	// CreateOrder returned no challenges) has nothing to gate on, so
	// the gate is skipped and the order finalized directly. Otherwise
	// at least one relayed artifact must be published (any-of: DNS-01
	// TXT or HTTP-01 resource).
	var verified []domain.ChallengeType
	bornReady := len(r.Validation.Challenges) == 0 && r.RenewalType == domain.RenewalTypeCSR
	if !bornReady {
		var verr error
		verified, verr = s.verifyChallengeArtifacts(ctx, reg.AnsName.FQDN(), r.Validation.Challenges)
		if len(verified) == 0 {
			if verr != nil {
				return nil, fmt.Errorf("renewal acme verify: %w", verr)
			}
			return nil, domain.NewValidationError(
				"ACME_CHALLENGE_MISSING",
				"no domain-control challenge artifact found — publish the DNS-01 TXT record or the HTTP-01 resource from challenges",
			)
		}
	}

	verifiedValidation, err := r.Validation.MarkVerified(now)
	if err != nil {
		return nil, err
	}
	r.UpdateValidationStatus(verifiedValidation)

	// BYOC completes synchronously. The operator's already-submitted
	// cert becomes the agent's live ServerCert, and the renewal is
	// marked completed.
	if r.RenewalType == domain.RenewalTypeBYOC {
		if err := r.MarkCompleted(now); err != nil {
			return nil, err
		}
		if err := s.renewals.Save(ctx, r); err != nil {
			return nil, err
		}
		res := &VerifyRenewalACMEResult{Renewal: r, Sync: true}
		// The new cert was persisted at submission; surface its TLSA
		// record so the operator can update DNS immediately. A transient
		// store error must propagate rather than silently drop it.
		cert, cerr := s.loadServerCert(ctx, agentID)
		if cerr != nil {
			return nil, cerr
		}
		if cert != nil {
			rec := domain.TLSARecordForCert(reg.AnsName.FQDN(), cert.Fingerprint)
			res.TLSARecord = &rec
		}
		return res, nil
	}

	return s.finalizeCSRRenewal(ctx, agentID, r, verified, now)
}

// finalizeCSRRenewal completes the CSR-path renewal flow: fetch the
// pending CSR, finalize the certificate order via the issuer port,
// validate the issued cert, save the new BYOC cert, mark the CSR
// signed, and flip the renewal to COMPLETED. Lives as its own method
// so the caller doesn't trip the cyclomatic-complexity gate.
//
// Asynchronous issuers may return port.ErrOrderPending: the renewal
// is persisted with its validation VERIFIED but not completed —
// deriveRenewalStatus reports ISSUING_CERTIFICATE — and the operator
// re-POSTs verify-acme to re-drive. Terminal failures
// (port.ErrOrderFailed) mark the renewal FAILED with the provider's
// reason.
func (s *RegistrationService) finalizeCSRRenewal(
	ctx context.Context, agentID string,
	r *domain.ServerCertificateRenewal, verified []domain.ChallengeType, now time.Time,
) (*VerifyRenewalACMEResult, error) {
	if s.serverCA == nil {
		return nil, domain.NewInternalError("SERVER_CA_DISABLED",
			"CSR renewal pending but no certificate issuer configured — inconsistent state", nil)
	}
	csr, err := s.certs.FindCSRByID(ctx, agentID, r.ServerCsrID)
	if err != nil {
		return nil, err
	}
	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	issued, err := s.serverCA.FinalizeOrder(ctx, port.FinalizeOrderRequest{
		OrderRef: r.Validation.OrderRef,
		CSRPEM:   csr.CSRContent,
		FQDN:     reg.AnsName.FQDN(),
		Verified: verified,
	})
	switch {
	case errors.Is(err, port.ErrOrderPending):
		// Persist the VERIFIED validation so the re-driven call skips
		// the gate; the missing CompletedAt keeps the renewal in
		// ISSUING_CERTIFICATE (derived).
		if serr := s.renewals.Save(ctx, r); serr != nil {
			return nil, serr
		}
		return &VerifyRenewalACMEResult{Renewal: r, Sync: false}, nil
	case errors.Is(err, port.ErrOrderFailed):
		if merr := r.MarkFailed("certificate provider reported a terminal order failure", now); merr != nil {
			return nil, merr
		}
		if serr := s.renewals.Save(ctx, r); serr != nil {
			return nil, serr
		}
		return nil, domain.NewValidationError("CERT_ORDER_FAILED",
			"certificate provider reported a terminal order failure; submit a new renewal")
	case err != nil:
		return nil, domain.NewInternalError("SERVER_CERT_ISSUE_FAILED",
			"failed to issue server cert for renewal", err)
	}
	v, err := s.validator.ValidateServerCertificate(ctx,
		issued.CertPEM, issued.ChainPEM, reg.AnsName.FQDN())
	if err != nil {
		return nil, domain.NewInternalError("SERVER_CERT_SELFVERIFY_FAILED",
			"issued renewal cert failed self-validation", err)
	}
	newCert := &domain.ByocServerCertificate{
		LeafCertificatePEM:      v.LeafPEM,
		ChainCertificatesPEM:    v.ChainPEM,
		SubjectCommonName:       v.CN,
		SubjectAlternativeNames: v.SANs,
		IssuerDN:                v.IssuerDN,
		ValidFromTimestamp:      v.ValidFrom,
		ValidToTimestamp:        v.ValidTo,
		Fingerprint:             v.Fingerprint,
	}
	signedCSR, err := csr.MarkSigned(now)
	if err != nil {
		return nil, err
	}
	if err := r.MarkCompleted(now); err != nil {
		return nil, err
	}
	// Commit the new cert, the SIGNED CSR row, and the completed
	// renewal atomically: a crash between them would otherwise leave
	// the agent's live cert and its renewal record disagreeing about
	// whether the rollover happened.
	if err := s.uow.Run(ctx, func(txCtx context.Context) error {
		if err := s.byoc.Save(txCtx, agentID, newCert); err != nil {
			return err
		}
		if err := s.certs.SaveCSR(txCtx, agentID, &signedCSR); err != nil {
			return err
		}
		return s.renewals.Save(txCtx, r)
	}); err != nil {
		return nil, err
	}
	tlsa := domain.TLSARecordForCert(reg.AnsName.FQDN(), v.Fingerprint)
	return &VerifyRenewalACMEResult{Renewal: r, Sync: true, TLSARecord: &tlsa}, nil
}

// generateChallengeTokens returns a pair of base64url-encoded random
// tokens for the RA's self-issued challenges — used only on BYOC
// paths, where no certificate provider participates and the RA itself
// plays the validator. CSR-path challenges come from the issuer
// port's CreateOrder instead. Each token is 32 bytes of crypto/rand
// (~43 base64url chars) — opaque to the verifier, it only needs to be
// unpredictable per-flow. No JWK thumbprint binding: self-issued
// challenges have no account key to bind to (Challenge.
// KeyAuthorization stays empty and verifiers expect the raw token).
func generateChallengeTokens() (string, string, error) {
	dns01Bytes := make([]byte, 32)
	if _, err := rand.Read(dns01Bytes); err != nil {
		return "", "", fmt.Errorf("dns01 token: %w", err)
	}
	http01Bytes := make([]byte, 32)
	if _, err := rand.Read(http01Bytes); err != nil {
		return "", "", fmt.Errorf("http01 token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(dns01Bytes),
		base64.RawURLEncoding.EncodeToString(http01Bytes),
		nil
}
