package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/ra/service"
)

// V1RenewalHandler wires the V1 server-cert renewal routes:
//
//	POST   /v1/agents/{agentId}/certificates/server/renewal
//	GET    /v1/agents/{agentId}/certificates/server/renewal
//	DELETE /v1/agents/{agentId}/certificates/server/renewal
//	POST   /v1/agents/{agentId}/certificates/server/renewal/verify-acme
//
// Reference-parity observation: the V1 renewal DTOs
// (`ServerCertificateRenewalRequest`, `RenewalSubmissionResponse`,
// `RenewalStatusResponse`, `RenewalVerificationResponse`) are
// byte-identical to V2 — both RA versions reference the same spec
// components. V1 and V2 handlers share the DTO types here; the only
// V1-specific piece is the `nextStep.endpoint` URL scheme (/v1/…
// instead of /v2/ans/…).
//
// TL emit: the V2 renewal service does not enqueue TL events today
// (AGENT_RENEWED emission awaits the async cert-issuance path);
// V1 therefore also emits nothing on the renewal write paths. When
// issuance lands, both lanes will emit on completion — V2 as
// CERTIFICATE_RENEWED, V1 as AGENT_RENEWED.
//
// Both server-cert paths supported (matching the reference): operators
// can submit `serverCsrPEM` to have the configured
// `ServerCertificateIssuer` port issue the cert, or
// `serverCertificatePEM` + chain for BYOC. Exactly one required.
type V1RenewalHandler struct {
	svc *service.RegistrationService
}

// NewV1RenewalHandler constructs a V1RenewalHandler.
func NewV1RenewalHandler(svc *service.RegistrationService) *V1RenewalHandler {
	return &V1RenewalHandler{svc: svc}
}

// SubmitServerCertRenewal handles POST
// /v1/agents/{agentId}/certificates/server/renewal.
func (h *V1RenewalHandler) SubmitServerCertRenewal(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	var req serverCertRenewalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, domain.NewValidationError("BAD_JSON", "invalid JSON body: "+err.Error()))
		return
	}
	res, err := h.svc.SubmitServerCertRenewal(r.Context(), agentID, service.SubmitRenewalInput{
		ServerCsrPEM:              req.ServerCsrPEM,
		ServerCertificatePEM:      req.ServerCertificatePEM,
		ServerCertificateChainPEM: req.ServerCertificateChainPEM,
	})
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, mapV1RenewalSubmission(agentID, res))
}

// GetServerCertRenewal handles GET
// /v1/agents/{agentId}/certificates/server/renewal.
func (h *V1RenewalHandler) GetServerCertRenewal(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	ren, err := h.svc.GetServerCertRenewal(r.Context(), agentID)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, mapV1RenewalStatus(agentID, ren))
}

// CancelServerCertRenewal handles DELETE
// /v1/agents/{agentId}/certificates/server/renewal. 204 on success.
func (h *V1RenewalHandler) CancelServerCertRenewal(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if err := h.svc.CancelServerCertRenewal(r.Context(), agentID); err != nil {
		WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// VerifyRenewalACME handles POST
// /v1/agents/{agentId}/certificates/server/renewal/verify-acme.
func (h *V1RenewalHandler) VerifyRenewalACME(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	res, err := h.svc.VerifyRenewalACME(r.Context(), agentID)
	if err != nil {
		WriteError(w, err)
		return
	}
	status := http.StatusAccepted
	if res.Sync {
		status = http.StatusOK
	}
	WriteJSON(w, status, mapV1RenewalVerification(agentID, res))
}

// ----- V1-scoped renewal DTO mappers -----

// v1NextStepFor returns the NextStep guidance for a renewal in the
// given derived status, with URLs pointing at the V1 path family.
// Structurally identical to `nextStepFor` in renewalmap.go; only the
// URL prefix differs.
func v1NextStepFor(agentID, status string) nextStep {
	base := "/v1/agents/" + agentID + "/certificates/server"
	switch status {
	case renewalStatusPendingValidation:
		return nextStep{
			Action:      "VALIDATE_DOMAIN",
			Endpoint:    base + "/renewal/verify-acme",
			Description: "Complete ACME challenges then POST to verify-acme endpoint",
		}
	case renewalStatusIssuingCertificate:
		// See nextStepFor: GET /renewal never re-drives the order; only
		// a re-POST of verify-acme does.
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

// mapV1RenewalSubmission mirrors mapRenewalSubmission (V2) with V1
// next-step URLs + V1 self link. Reference spec's V1/V2 DTOs are
// byte-identical for these response shapes.
func mapV1RenewalSubmission(agentID string, res *service.SubmitRenewalResult) renewalSubmissionResponse {
	r := res.Renewal
	status := renewalStatusPendingValidation
	return renewalSubmissionResponse{
		RenewalType: string(r.RenewalType),
		Status:      status,
		CsrID:       res.CsrID,
		Challenges:  buildRenewalChallenges(res.FQDN, r.Validation),
		ExpiresAt:   r.Validation.ExpiresAt.Format(time.RFC3339),
		NextStep:    v1NextStepFor(agentID, status),
		Links: []linkRef{{
			Rel:  "status",
			Href: "/v1/agents/" + agentID + "/certificates/server/renewal",
		}},
	}
}

// mapV1RenewalStatus mirrors mapRenewalStatus with V1 next-step URLs.
func mapV1RenewalStatus(agentID string, res *service.GetRenewalResult) renewalStatusResponse {
	r := res.Renewal
	status := deriveRenewalStatus(r, time.Now())
	resp := renewalStatusResponse{
		RenewalType:   string(r.RenewalType),
		Status:        status,
		CsrID:         r.ServerCsrID,
		TlsaDNSRecord: tlsaDTOFrom(res.TLSARecord),
		ExpiresAt:     r.Validation.ExpiresAt.Format(time.RFC3339),
		NextStep:      v1NextStepFor(agentID, status),
	}
	if status == renewalStatusPendingValidation {
		resp.Challenges = buildRenewalChallenges(res.FQDN, r.Validation)
	}
	if r.FailureReason != "" {
		resp.FailureReason = r.FailureReason
	}
	return resp
}

// mapV1RenewalVerification mirrors mapRenewalVerification with V1
// next-step URLs.
func mapV1RenewalVerification(agentID string, res *service.VerifyRenewalACMEResult) renewalVerificationResponse {
	r := res.Renewal
	status := renewalStatusIssuingCertificate
	if res.Sync {
		status = renewalStatusCompleted
	}
	return renewalVerificationResponse{
		Status:        status,
		CsrID:         r.ServerCsrID,
		TlsaDNSRecord: tlsaDTOFrom(res.TLSARecord),
		NextStep:      v1NextStepFor(agentID, status),
	}
}
