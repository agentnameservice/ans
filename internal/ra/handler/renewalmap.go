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
		return nextStep{
			Action:      "WAIT",
			Endpoint:    base + "/renewal",
			Description: "Certificate issuance in progress, poll GET /renewal for TLSA record",
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

// mapRenewalSubmission builds the 202 RenewalSubmissionResponse body
// from a successful submission. Matches reference `mapToSubmissionResponse`.
//
// Note: per the V2 spec, the status-GET response carries the
// challenges[] block; the submission 202 omits it (the caller already
// gets the same set from the response of the matching GET). This
// mapper stays side-effect-free.
func mapRenewalSubmission(agentID string, res *service.SubmitRenewalResult) renewalSubmissionResponse {
	r := res.Renewal
	status := renewalStatusPendingValidation
	return renewalSubmissionResponse{
		RenewalType: string(r.RenewalType),
		Status:      status,
		CsrID:       res.CsrID,
		ExpiresAt:   r.Validation.ExpiresAt.Format(time.RFC3339),
		NextStep:    nextStepFor(agentID, status),
		Links: []linkRef{{
			Rel:  "status",
			Href: "/v2/ans/agents/" + agentID + "/certificates/server/renewal",
		}},
	}
}

// mapRenewalStatus builds the 200 RenewalStatusResponse body. Needs
// the agent FQDN for challenge record naming, which we look up via
// the service layer — but the lifecycle handler already has the
// agent in context, so we wire through the service by not taking
// the FQDN here directly. The challenge-info population is best-
// effort: when the service-layer contract evolves to return the
// FQDN alongside the renewal, we can plumb it through.
func mapRenewalStatus(agentID string, r *domain.ServerCertificateRenewal) renewalStatusResponse {
	status := deriveRenewalStatus(r, time.Now())
	resp := renewalStatusResponse{
		RenewalType: string(r.RenewalType),
		Status:      status,
		CsrID:       r.ServerCsrID,
		ExpiresAt:   r.Validation.ExpiresAt.Format(time.RFC3339),
		NextStep:    nextStepFor(agentID, status),
	}
	if r.FailureReason != "" {
		resp.FailureReason = r.FailureReason
	}
	return resp
}

// mapRenewalVerification builds the 200/202 RenewalVerificationResponse
// body. BYOC returns COMPLETED sync; CSR returns ISSUING_CERTIFICATE
// async.
func mapRenewalVerification(agentID string, res *service.VerifyRenewalACMEResult) renewalVerificationResponse {
	r := res.Renewal
	status := renewalStatusIssuingCertificate
	if res.Sync {
		status = renewalStatusCompleted
	}
	return renewalVerificationResponse{
		Status:   status,
		CsrID:    r.ServerCsrID,
		NextStep: nextStepFor(agentID, status),
	}
}
