package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/tl/event"
	eventv1 "github.com/agentnameservice/ans/internal/tl/event/v1"
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
	var newCSR *domain.AgentCSR

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
		order, err := s.createServerOrder(ctx, reg.OwnerID, reg.AnsName.FQDN())
		if err != nil {
			return nil, certificateProviderError(err, "CERT_ORDER_FAILED", "create certificate order")
		}
		prepared, err := orderWithOwnerProof(order, now.Add(renewalChallengeWindow))
		if err != nil {
			return nil, domain.NewInternalError("CERT_ORDER_FAILED", "prepare renewal domain proof", err)
		}
		csrID = uuid.NewString()
		newCSR, err = reg.SubmitServerCSR(csrID, in.ServerCsrPEM, now)
		if err != nil {
			return nil, err
		}
		renewal = domain.NewCSRRenewal(agentID, reg.ID, csrID, prepared, now)

	case byocSet:
		_, err := s.validator.ValidateServerCertificate(ctx,
			in.ServerCertificatePEM, in.ServerCertificateChainPEM, reg.AnsName.FQDN())
		if err != nil {
			return nil, domain.NewCertificateError(
				"INVALID_BYOC_CERT",
				"BYOC certificate validation failed: "+err.Error())
		}
		// Retain the replacement only on the pending renewal. Saving it
		// in byoc now would expose it before proof, even after cancellation.
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

	if err := s.uow.Run(ctx, func(txCtx context.Context) error {
		current, err := s.agents.FindByAgentID(txCtx, agentID)
		if err != nil {
			return err
		}
		if current.Status != domain.StatusActive {
			return domain.NewInvalidStateError("AGENT_NOT_ACTIVE", "agent must remain ACTIVE to initiate renewal")
		}
		if pending, err := s.renewals.FindPendingByAgentID(txCtx, agentID); err == nil && pending != nil {
			return domain.NewConflictError("PENDING_RENEWAL_EXISTS", "a renewal was submitted concurrently")
		} else if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		if newCSR != nil {
			current.ServerCSR = newCSR
			if err := s.agents.Save(txCtx, current); err != nil {
				return err
			}
			if err := s.certs.SaveCSR(txCtx, agentID, newCSR); err != nil {
				return err
			}
		}
		return s.renewals.Save(txCtx, renewal)
	}); err != nil {
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
	// Bind cancellation to the renewal observed on entry, then recheck its
	// state under the same transaction that rejects the CSR and removes it.
	// Completion or replacement between those reads must not be erased.
	return s.uow.Run(ctx, func(txCtx context.Context) error {
		current, err := s.renewals.FindByAgentID(txCtx, agentID)
		if err != nil {
			return err
		}
		if current.ID != r.ID {
			return domain.NewValidationError("RENEWAL_NOT_PENDING", "renewal was replaced during cancellation")
		}
		if !current.CompletedAt.IsZero() {
			return domain.NewValidationError("RENEWAL_ALREADY_COMPLETED", "cannot cancel a completed renewal")
		}
		if err := s.rejectRenewalCSR(txCtx, agentID, current); err != nil {
			return err
		}
		return s.renewals.Delete(txCtx, current.ID)
	})
}

func (s *RegistrationService) rejectRenewalCSR(ctx context.Context, agentID string, r *domain.ServerCertificateRenewal) error {
	if r.RenewalType != domain.RenewalTypeCSR || r.ServerCsrID == "" {
		return nil
	}
	csr, err := s.certs.FindCSRByID(ctx, agentID, r.ServerCsrID)
	if err != nil {
		return err
	}
	if csr.Status != domain.CSRStatusPending {
		return nil
	}
	rejected, err := csr.MarkRejected("Renewal cancelled", s.clock())
	if err != nil {
		return err
	}
	return s.certs.SaveCSR(ctx, agentID, &rejected)
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
// re-driven calls skip the gate only after the RA's successful domain
// proof has been persisted.
func (s *RegistrationService) VerifyRenewalACME(ctx context.Context, agentID string) (*VerifyRenewalACMEResult, error) {
	return s.verifyRenewalACME(ctx, agentID, event.SchemaVersion)
}

// VerifyRenewalACMEV1 completes a renewal and publishes on the V1 event lane.
func (s *RegistrationService) VerifyRenewalACMEV1(ctx context.Context, agentID string) (*VerifyRenewalACMEResult, error) {
	return s.verifyRenewalACME(ctx, agentID, eventv1.SchemaVersion)
}

func (s *RegistrationService) verifyRenewalACME(ctx context.Context, agentID, schemaVersion string) (*VerifyRenewalACMEResult, error) {
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
		return s.finalizeCSRRenewal(ctx, agentID, r, nil, schemaVersion, now)
	}

	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}

	if len(r.Validation.Challenges) == 0 {
		s.logger.Warn().Str("agentId", agentID).Int64("renewalId", r.ID).Msg("pending renewal has no owner proof after upgrade")
		return nil, domain.NewConflictError("CERT_ORDER_UPGRADE_REQUIRED", "renewal has no persisted owner proof; cancel it and submit a new renewal")
	}
	// Cached provider authorization is not proof by the current caller.
	verified, verr := s.verifyChallengeArtifacts(ctx, reg.AnsName.FQDN(), r.Validation.Challenges)
	if len(verified) == 0 {
		if verr != nil {
			return nil, fmt.Errorf("renewal acme verify: %w", verr)
		}
		return nil, domain.NewValidationError(
			"ACME_CHALLENGE_MISSING",
			"no domain-control challenge artifact found — publish the DNS-01 TXT record or the HTTP-01 resource from challenges",
		)
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
		return s.finalizeBYOCRenewal(ctx, reg, r, schemaVersion, now)
	}

	return s.finalizeCSRRenewal(ctx, agentID, r, verified, schemaVersion, now)
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
	r *domain.ServerCertificateRenewal, verified []domain.ChallengeType, schemaVersion string, now time.Time,
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
		OwnerID:  reg.OwnerID,
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
		return nil, certificateProviderError(err, "SERVER_CERT_ISSUE_FAILED", "failed to issue server cert for renewal")
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
	if err := s.commitCertificateRenewal(ctx, reg, r, newCert, &signedCSR, schemaVersion, now); err != nil {
		return nil, err
	}
	tlsa := domain.TLSARecordForCert(reg.AnsName.FQDN(), v.Fingerprint)
	return &VerifyRenewalACMEResult{Renewal: r, Sync: true, TLSARecord: &tlsa}, nil
}

func (s *RegistrationService) finalizeBYOCRenewal(
	ctx context.Context, reg *domain.AgentRegistration, r *domain.ServerCertificateRenewal,
	schemaVersion string, now time.Time,
) (*VerifyRenewalACMEResult, error) {
	v, err := s.validator.ValidateServerCertificate(ctx, r.ByocCertPEM, r.ByocChainPEM, reg.FQDN())
	if err != nil {
		return nil, domain.NewCertificateError("INVALID_BYOC_CERT", "renewal certificate validation failed: "+err.Error())
	}
	newCert := &domain.ByocServerCertificate{
		LeafCertificatePEM: v.LeafPEM, ChainCertificatesPEM: v.ChainPEM,
		SubjectCommonName: v.CN, SubjectAlternativeNames: v.SANs,
		IssuerDN: v.IssuerDN, ValidFromTimestamp: v.ValidFrom,
		ValidToTimestamp: v.ValidTo, Fingerprint: v.Fingerprint,
	}
	if err := s.commitCertificateRenewal(ctx, reg, r, newCert, nil, schemaVersion, now); err != nil {
		return nil, err
	}
	tlsa := domain.TLSARecordForCert(reg.FQDN(), v.Fingerprint)
	return &VerifyRenewalACMEResult{Renewal: r, Sync: true, TLSARecord: &tlsa}, nil
}

// commitCertificateRenewal stores the complete valid-certificate event in the
// same transaction as the certificate and completed renewal.
func (s *RegistrationService) commitCertificateRenewal(
	ctx context.Context, reg *domain.AgentRegistration, r *domain.ServerCertificateRenewal,
	cert *domain.ByocServerCertificate, signedCSR *domain.AgentCSR,
	schemaVersion string, now time.Time,
) error {
	evidence, err := s.observeRenewalDNS(ctx, reg)
	if err != nil {
		return err
	}
	if err := r.MarkCompleted(now); err != nil {
		return err
	}
	return s.uow.Run(ctx, func(txCtx context.Context) error {
		current, err := s.agents.FindByAgentID(txCtx, reg.AgentID)
		if err != nil {
			return err
		}
		if current.Status != domain.StatusActive {
			return domain.NewInvalidStateError("AGENT_NOT_ACTIVE", "agent ceased to be ACTIVE during renewal")
		}
		pending, err := s.renewals.FindPendingByAgentID(txCtx, reg.AgentID)
		if err != nil {
			return err
		}
		if pending.ID != r.ID {
			return domain.NewValidationError("RENEWAL_NOT_PENDING", "renewal was replaced during issuance")
		}
		if err := s.byoc.Save(txCtx, reg.AgentID, cert); err != nil {
			return err
		}
		if signedCSR != nil {
			current.ServerCSR = signedCSR
			if err := s.certs.SaveCSR(txCtx, reg.AgentID, signedCSR); err != nil {
				return err
			}
			if err := s.agents.Save(txCtx, current); err != nil {
				return err
			}
		}
		if err := s.renewals.Save(txCtx, r); err != nil {
			return err
		}
		return s.enqueueCertificateRenewal(txCtx, reg, evidence, schemaVersion)
	})
}

// generateChallengeTokens returns a pair of base64url-encoded random
// tokens for the RA's self-issued challenges. BYOC and cached provider
// authorizations need fresh local owner proof; pending provider orders relay
// their own account-bound challenges. Each token is 32 bytes of crypto/rand
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
