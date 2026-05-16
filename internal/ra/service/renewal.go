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
)

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
// handler maps this into the RenewalSubmissionResponse DTO.
type SubmitRenewalResult struct {
	Renewal *domain.ServerCertificateRenewal
	CsrID   string // non-empty for SERVER_CSR renewals
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

	dns01, http01, err := generateChallengeTokens()
	if err != nil {
		return nil, domain.NewInternalError("CHALLENGE_GEN_FAILED", "generate challenge tokens", err)
	}

	var renewal *domain.ServerCertificateRenewal
	var csrID string

	switch {
	case csrSet:
		// Server CSRs must carry the agent FQDN as a DNS SAN — TLS
		// server-auth convention, distinct from the identity CSR's
		// URI SAN shape.
		if err := s.validator.ValidateServerCSR(ctx, in.ServerCsrPEM, reg.FQDN()); err != nil {
			return nil, domain.NewValidationError("INVALID_SERVER_CSR",
				"Server CSR validation failed: "+err.Error())
		}
		// Require a server CA for issuance at verify-acme time. We
		// fail fast here rather than letting the renewal sit in
		// PENDING_VALIDATION forever when the operator has no CA
		// wired.
		if s.serverCA == nil {
			return nil, domain.NewValidationError(
				"SERVER_CA_DISABLED",
				"serverCsrPEM renewal submitted but no server CA is configured")
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
		renewal = domain.NewCSRRenewal(agentID, reg.ID, csrID, dns01, http01, now)

	case byocSet:
		v, err := s.validator.ValidateServerCertificate(ctx,
			in.ServerCertificatePEM, in.ServerCertificateChainPEM, reg.FQDN())
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
		renewal = domain.NewBYOCRenewal(agentID, reg.ID,
			in.ServerCertificatePEM, in.ServerCertificateChainPEM,
			dns01, http01, now)
	}

	if err := s.renewals.Save(ctx, renewal); err != nil {
		return nil, err
	}

	return &SubmitRenewalResult{Renewal: renewal, CsrID: csrID}, nil
}

// GetServerCertRenewal returns the most-recent renewal for the agent
// (including completed / failed / expired), for the GET handler. 404
// is produced by the underlying store returning ErrNotFound; callers
// don't need to distinguish "no renewal" from "agent not found"
// because the ownership middleware has already confirmed the agent.
func (s *RegistrationService) GetServerCertRenewal(ctx context.Context, agentID string) (*domain.ServerCertificateRenewal, error) {
	return s.renewals.FindByAgentID(ctx, agentID)
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
	// Sync is true when the renewal completed synchronously (BYOC).
	// CSR renewals are async — issuance happens after verification.
	Sync bool
}

// VerifyRenewalACME marks the renewal's validation as VERIFIED and
// (for BYOC) completes the renewal immediately by flipping the
// registration's ServerCert over. Mirrors the reference RA's
// `verifyRenewalAcme` handler.
//
// This build's ACME verification is a noop (same as the existing
// agent-activation verify-acme handler). Production deployments plug
// in a real port.ACMEVerifier at a future extension point.
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
	}

	// CSR path: with a server CA wired, we issue synchronously after
	// verification rather than leaving the renewal in
	// ISSUING_CERTIFICATE forever. Matches the reference
	// CertIssuanceService.issueServerCertificate call from
	// verifyRenewalAcme — the CA signs, we persist the leaf cert as
	// the new live BYOC cert, and the renewal completes.
	//
	// Async issuance (for slow ACME-style CAs) would keep the
	// renewal in ISSUING_CERTIFICATE and finalize via a background
	// job; when that lands, it plugs in here without changing the
	// caller contract.
	if r.RenewalType == domain.RenewalTypeCSR && s.serverCA != nil {
		if err := s.completeCSRRenewal(ctx, agentID, r, now); err != nil {
			return nil, err
		}
	}

	if err := s.renewals.Save(ctx, r); err != nil {
		return nil, err
	}

	// Sync is true whenever the renewal reached COMPLETED in this
	// call — either because it was BYOC (validation suffices) or
	// because the configured server CA signed the CSR synchronously.
	// The handler uses this to choose 200 vs 202 per the reference.
	return &VerifyRenewalACMEResult{
		Renewal: r,
		Sync:    !r.CompletedAt.IsZero(),
	}, nil
}

// completeCSRRenewal extracts the synchronous CSR-path renewal flow:
// fetch the pending CSR, sign it via the server CA, validate the
// issued cert, save the new BYOC cert, mark the CSR signed, and
// flip the renewal to COMPLETED. Lives as its own method so the
// caller doesn't trip the cyclomatic-complexity gate.
func (s *RegistrationService) completeCSRRenewal(ctx context.Context, agentID string, r *domain.ServerCertificateRenewal, now time.Time) error {
	csr, err := s.certs.FindCSRByID(ctx, agentID, r.ServerCsrID)
	if err != nil {
		return err
	}
	reg, err := s.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		return err
	}
	issued, err := s.serverCA.IssueServerCertificate(ctx, csr.CSRContent, reg.FQDN())
	if err != nil {
		return domain.NewInternalError("SERVER_CERT_ISSUE_FAILED",
			"failed to issue server cert for renewal", err)
	}
	v, err := s.validator.ValidateServerCertificate(ctx,
		issued.CertPEM, issued.ChainPEM, reg.FQDN())
	if err != nil {
		return domain.NewInternalError("SERVER_CERT_SELFVERIFY_FAILED",
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
	if err := s.byoc.Save(ctx, agentID, newCert); err != nil {
		return err
	}
	if signedCSR, serr := csr.MarkSigned(now); serr == nil {
		_ = s.certs.SaveCSR(ctx, agentID, &signedCSR)
	}
	return r.MarkCompleted(now)
}

// generateChallengeTokens returns a pair of base64url-encoded random
// tokens the operator uses for DNS-01 and HTTP-01 challenges. Each
// token is 32 bytes of crypto/rand which maps to ~43 base64url chars
// — more than enough entropy to prevent guessing.
//
// Tokens are opaque to the verifier; they only need to be
// unpredictable per-renewal. We don't use JWK thumbprint because our
// verifier is stubbed (noop); a future real-ACME integration will
// replace this with full RFC 8555 token semantics.
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

// Unused imports placeholder so time doesn't get auto-removed if
// future edits need it.
var _ = time.Now
