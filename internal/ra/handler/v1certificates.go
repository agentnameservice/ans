package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/ra/service"
)

// V1CertificatesHandler wires the V1 certificate-operation routes:
//
//	GET    /v1/agents/{agentId}/certificates/identity
//	POST   /v1/agents/{agentId}/certificates/identity
//	GET    /v1/agents/{agentId}/certificates/server
//	POST   /v1/agents/{agentId}/certificates/server
//	GET    /v1/agents/{agentId}/csrs/{csrId}/status
//
// Reference-parity observation: V1 and V2 certificate DTOs
// (`CertificateResponse`, `CsrSubmissionRequest`,
// `CsrSubmissionResponse`, `CsrStatusResponse`) are byte-identical
// in the reference spec — the V1 and V2 operations reference the
// same component schemas (see api-spec.yaml §562 vs §938 both
// returning `CertificateResponse`). So V1 cert responses reuse the
// V2 DTO types in this file rather than duplicating identical
// shapes. If that diverges in a future spec version, this is the
// place to fork them.
//
// Schema-version note: cert-submission handlers do NOT enqueue TL
// events. The V1 RA emits a TL leaf only on terminal transitions
// (AGENT_REGISTERED / AGENT_REVOKED / AGENT_RENEWED / AGENT_DEPRECATED);
// CSR submission is intermediate state that the reference records
// in its domain-level lifecycle store, not the TL.
type V1CertificatesHandler struct {
	responder
	svc *service.RegistrationService
}

// NewV1CertificatesHandler constructs a V1CertificatesHandler.
func NewV1CertificatesHandler(svc *service.RegistrationService, logger zerolog.Logger) *V1CertificatesHandler {
	return &V1CertificatesHandler{responder: newResponder(logger), svc: svc}
}

// GetIdentityCerts handles GET /v1/agents/{agentId}/certificates/identity.
func (h *V1CertificatesHandler) GetIdentityCerts(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	certs, err := h.svc.IdentityCertificates(r.Context(), agentID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := make([]certificateResponse, 0, len(certs))
	for _, c := range certs {
		out = append(out, mapCertificate(c))
	}
	WriteJSON(w, http.StatusOK, out)
}

// GetServerCerts handles GET /v1/agents/{agentId}/certificates/server.
func (h *V1CertificatesHandler) GetServerCerts(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	certs, err := h.svc.ServerCertificates(r.Context(), agentID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := make([]certificateResponse, 0, len(certs))
	for _, c := range certs {
		out = append(out, mapCertificate(c))
	}
	WriteJSON(w, http.StatusOK, out)
}

// SubmitIdentityCSR handles POST /v1/agents/{agentId}/certificates/identity.
func (h *V1CertificatesHandler) SubmitIdentityCSR(w http.ResponseWriter, r *http.Request) {
	h.submitCSR(w, r, h.svc.SubmitIdentityCSR, "Identity CSR accepted for processing")
}

// SubmitServerCSR handles POST /v1/agents/{agentId}/certificates/server.
func (h *V1CertificatesHandler) SubmitServerCSR(w http.ResponseWriter, r *http.Request) {
	h.submitCSR(w, r, h.svc.SubmitServerCSR, "Server CSR accepted for processing")
}

// GetCSRStatus handles GET /v1/agents/{agentId}/csrs/{csrId}/status.
func (h *V1CertificatesHandler) GetCSRStatus(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	csrID := chi.URLParam(r, "csrId")
	csr, err := h.svc.GetCSRStatus(r.Context(), agentID, csrID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, mapCSRStatus(csr))
}

// submitCSR is the shared body-decode + service-forward helper. Same
// pattern as the V2 LifecycleHandler.submitCSR but scoped to V1
// paths so the two handler types don't import each other.
func (h *V1CertificatesHandler) submitCSR(
	w http.ResponseWriter, r *http.Request,
	submit func(ctx context.Context, agentID, csrPEM string) (string, error),
	okMessage string,
) {
	agentID := chi.URLParam(r, "agentId")
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var req csrSubmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, domain.NewValidationError("BAD_JSON", "invalid JSON body: "+err.Error()))
		return
	}
	if req.CsrPEM == "" {
		h.writeError(w, domain.NewValidationError("MISSING_CSR_PEM", "csrPEM is required"))
		return
	}
	csrID, err := submit(r.Context(), agentID, req.CsrPEM)
	if err != nil {
		h.writeError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, csrSubmissionResponse{
		CsrID:   csrID,
		Message: okMessage,
	})
}
