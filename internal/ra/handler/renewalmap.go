package handler

import (
	"time"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/ra/service"
)

// This file holds the DTO ↔ domain mappers for the server-cert
// renewal routes. Kept separate from dto.go to keep the renewal
// state-machine logic (derived status, challenge info, TLSA
// generation) in one place instead of sprawling across the DTO file.

// Wire-format renewal status strings, matching the V2 spec enum.
// Defined here rather than in domain so the wire shape is consistent
// across the four renewal handlers that emit them.
const (
	renewalStatusPendingValidation  = "PENDING_VALIDATION"
	renewalStatusIssuingCertificate = "ISSUING_CERTIFICATE"
	renewalStatusCompleted          = "COMPLETED"
	renewalStatusFailed             = "FAILED"
	renewalStatusExpired            = "EXPIRED"
)

// deriveRenewalStatus translates the renewal's internal fields into
// the wire-format status enum the V2 spec defines
// (PENDING_VALIDATION | ISSUING_CERTIFICATE | COMPLETED | FAILED |
// EXPIRED). Mirrors the reference RA's
// `CertificateRenewalOperationsHandler.determineRenewalStatus`.
func deriveRenewalStatus(r *domain.ServerCertificateRenewal, now time.Time) string {
	switch {
	case r.FailureReason != "":
		return renewalStatusFailed
	case !r.CompletedAt.IsZero():
		return renewalStatusCompleted
	case r.IsExpired(now):
		return renewalStatusExpired
	case r.Validation.Status == domain.ValidationVerified:
		// BYOC completes synchronously after ACME; CSR needs async issuance.
		if r.RenewalType == domain.RenewalTypeBYOC {
			return renewalStatusCompleted
		}
		return renewalStatusIssuingCertificate
	default:
		return renewalStatusPendingValidation
	}
}

// nextStepFor returns the NextStep guidance block for a renewal in
// the given derived status. Mirrors the reference RA's mapper.
// Endpoint uses our V2 path scheme (includes `/v2/ans/`).
func nextStepFor(agentID, status string) nextStep {
	base := "/v2/ans/agents/" + agentID + "/certificates/server"
	switch status {
	case renewalStatusPendingValidation:
		return nextStep{
			Action:      "VALIDATE_DOMAIN",
			Endpoint:    base + "/renewal/verify-acme",
			Description: "Complete ACME challenges then POST to verify-acme endpoint",
		}
	case renewalStatusIssuingCertificate:
		// Only re-POSTing verify-acme re-drives a pending order — GET
		// /renewal never finalizes it, so pointing the operator there
		// would livelock an async issuance. Mirror the registration
		// lane's PENDING_CERTS guidance.
		return nextStep{
			Action:      "WAIT",
			Endpoint:    base + "/renewal/verify-acme",
			Description: "Certificate issuance in progress — POST verify-acme again to drive the order to completion",
		}
	case renewalStatusCompleted:
		return nextStep{
			Action:      "CONFIGURE_DNS",
			Endpoint:    base,
			Description: "Update TLSA record, then GET /certificates/server for new certificate",
		}
	case renewalStatusFailed, renewalStatusExpired:
		return nextStep{
			Action:      "CONFIGURE_DNS",
			Endpoint:    base + "/renewal",
			Description: "Remove _acme-challenge DNS record, DELETE /renewal, then submit a new renewal request",
		}
	default:
		return nextStep{Action: "WAIT", Endpoint: base + "/renewal"}
	}
}

// buildRenewalChallenges renders the renewal's domain-control
// challenge set in the V2 challenges shape (dns01 / http01 keyed
// object). The entries come verbatim from the certificate order —
// provider-minted for external issuers, self-issued for the
// in-process CA and BYOC validation. The owner publishes one of the
// two artifacts; verify-acme accepts either.
func buildRenewalChallenges(fqdn string, v domain.RenewalValidation) *renewalChallenges {
	expires := v.ExpiresAt.UTC().Format(time.RFC3339)
	out := &renewalChallenges{}
	if ch, ok := v.ChallengeOfType(domain.ChallengeTypeDNS01); ok {
		out.DNS01 = &challengeInfo{
			Type:             string(domain.ChallengeTypeDNS01),
			Token:            ch.Token,
			KeyAuthorization: ch.KeyAuthorization,
			DNSRecord: &challengeDNSRecordDTO{
				Name:  ch.EffectiveDNSRecordName(fqdn),
				Type:  "TXT",
				Value: ch.EffectiveDNSRecordValue(),
			},
			ExpiresAt: expires,
		}
	}
	if ch, ok := v.ChallengeOfType(domain.ChallengeTypeHTTP01); ok {
		out.HTTP01 = &challengeInfo{
			Type:             string(domain.ChallengeTypeHTTP01),
			Token:            ch.Token,
			KeyAuthorization: ch.KeyAuthorization,
			HTTPPath:         ch.EffectiveHTTPPath(),
			ExpiresAt:        expires,
		}
	}
	if out.DNS01 == nil && out.HTTP01 == nil {
		return nil
	}
	return out
}

// tlsaDTOFrom maps the domain TLSA record into the wire DTO. Nil in,
// nil out — completed renewals carry it, pending ones don't.
func tlsaDTOFrom(rec *domain.ExpectedDNSRecord) *dnsRecordDTO {
	if rec == nil {
		return nil
	}
	return &dnsRecordDTO{
		Name:     rec.Name,
		Type:     string(rec.Type),
		Value:    rec.Value,
		Purpose:  string(rec.Purpose),
		Required: rec.Required,
		TTL:      rec.TTL,
	}
}

// mapRenewalSubmission builds the 202 RenewalSubmissionResponse body
// from a successful submission. Matches reference
// `mapToSubmissionResponse`. The challenges block is the operator's
// only copy of the artifacts they must publish before verify-acme —
// it rides on both the submission 202 and the status GET.
func mapRenewalSubmission(agentID string, res *service.SubmitRenewalResult) renewalSubmissionResponse {
	r := res.Renewal
	status := renewalStatusPendingValidation
	return renewalSubmissionResponse{
		RenewalType: string(r.RenewalType),
		Status:      status,
		CsrID:       res.CsrID,
		Challenges:  buildRenewalChallenges(res.FQDN, r.Validation),
		ExpiresAt:   r.Validation.ExpiresAt.Format(time.RFC3339),
		NextStep:    nextStepFor(agentID, status),
		Links: []linkRef{{
			Rel:  "status",
			Href: "/v2/ans/agents/" + agentID + "/certificates/server/renewal",
		}},
	}
}

// mapRenewalStatus builds the 200 RenewalStatusResponse body.
// Pending-validation renewals carry the challenges block (the
// operator may have lost the submission response); completed ones
// carry the TLSA record for the new leaf instead — that record is
// what the ISSUING_CERTIFICATE WAIT step tells the operator to poll
// for.
func mapRenewalStatus(agentID string, res *service.GetRenewalResult) renewalStatusResponse {
	r := res.Renewal
	status := deriveRenewalStatus(r, time.Now())
	resp := renewalStatusResponse{
		RenewalType:   string(r.RenewalType),
		Status:        status,
		CsrID:         r.ServerCsrID,
		TlsaDNSRecord: tlsaDTOFrom(res.TLSARecord),
		ExpiresAt:     r.Validation.ExpiresAt.Format(time.RFC3339),
		NextStep:      nextStepFor(agentID, status),
	}
	if status == renewalStatusPendingValidation {
		resp.Challenges = buildRenewalChallenges(res.FQDN, r.Validation)
	}
	if r.FailureReason != "" {
		resp.FailureReason = r.FailureReason
	}
	return resp
}

// mapRenewalVerification builds the 200/202 RenewalVerificationResponse
// body. Completed renewals (200) include the new leaf's TLSA record so
// the operator can update DNS immediately; ISSUING_CERTIFICATE (202)
// points the operator back at verify-acme via the WAIT next step.
func mapRenewalVerification(agentID string, res *service.VerifyRenewalACMEResult) renewalVerificationResponse {
	r := res.Renewal
	status := renewalStatusIssuingCertificate
	if res.Sync {
		status = renewalStatusCompleted
	}
	return renewalVerificationResponse{
		Status:        status,
		CsrID:         r.ServerCsrID,
		TlsaDNSRecord: tlsaDTOFrom(res.TLSARecord),
		NextStep:      nextStepFor(agentID, status),
	}
}
