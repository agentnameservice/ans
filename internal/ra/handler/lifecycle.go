package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/service"
)

// LifecycleHandler groups the non-register routes: list/detail/certs
// (reads) and verify-acme/verify-dns/revoke (writes). All agent-scoped
// routes assume the ownership middleware has already run.
type LifecycleHandler struct {
	svc *service.RegistrationService
}

// NewLifecycleHandler constructs a LifecycleHandler.
func NewLifecycleHandler(svc *service.RegistrationService) *LifecycleHandler {
	return &LifecycleHandler{svc: svc}
}

// ----- GET /v2/ans/agents -----

// List handles GET /v2/ans/agents. Ownership-scoped to the caller;
// default status filter is [ACTIVE] per spec.
func (h *LifecycleHandler) List(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFromRequest(r)
	if !ok {
		WriteError(w, domain.NewUnauthorizedError("NO_IDENTITY", "authentication required"))
		return
	}

	q := r.URL.Query()
	filter := port.ListFilter{
		AgentHost: q.Get("agentHost"),
		Cursor:    q.Get("cursor"),
	}

	// Status filter: multiple values allowed; `ALL` = no filter.
	// Default is ACTIVE (spec §AgentLifecycleStatusFilter).
	if statuses, ok := q["status"]; ok && len(statuses) > 0 {
		for _, s := range statuses {
			if s == "ALL" {
				filter.Statuses = nil
				break
			}
			filter.Statuses = append(filter.Statuses, domain.RegistrationStatus(s))
		}
	} else {
		filter.Statuses = []domain.RegistrationStatus{domain.StatusActive}
	}

	// Limit: 1..100, default 20.
	if lv := q.Get("limit"); lv != "" {
		n, err := strconv.Atoi(lv)
		if err != nil || n < 1 || n > 100 {
			WriteError(w, domain.NewValidationError(
				"INVALID_LIMIT", "limit must be between 1 and 100",
			))
			return
		}
		filter.Limit = n
	} else {
		filter.Limit = 20
	}

	res, err := h.svc.List(r.Context(), id.Subject, filter)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, mapListResponse(res))
}

// ----- GET /v2/ans/agents/{agentId} -----

// Detail handles GET /v2/ans/agents/{agentId}. Ownership verified by
// middleware; the agent is attached to the context but we re-fetch
// (incl. endpoints) through the service so the response carries
// every field the V2 AgentDetails schema requires.
func (h *LifecycleHandler) Detail(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	res, err := h.svc.GetByAgentID(r.Context(), agentID)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, mapAgentDetails(res, r, h.svc))
}

// ----- GET /v2/ans/agents/{agentId}/certificates/identity -----

// GetIdentityCerts handles GET .../certificates/identity.
func (h *LifecycleHandler) GetIdentityCerts(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	certs, err := h.svc.IdentityCertificates(r.Context(), agentID)
	if err != nil {
		WriteError(w, err)
		return
	}
	out := make([]certificateResponse, 0, len(certs))
	for _, c := range certs {
		out = append(out, mapCertificate(c))
	}
	WriteJSON(w, http.StatusOK, out)
}

// ----- GET /v2/ans/agents/{agentId}/certificates/server -----

// GetServerCerts handles GET .../certificates/server. Returns every
// server certificate (BYOC + CA-issued once Stage 5c's server CSR
// flow lands). Matches the reference RA's
// `CertificateOperationsHandler.getAgentServerCertificateByAgentId`.
func (h *LifecycleHandler) GetServerCerts(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	certs, err := h.svc.ServerCertificates(r.Context(), agentID)
	if err != nil {
		WriteError(w, err)
		return
	}
	out := make([]certificateResponse, 0, len(certs))
	for _, c := range certs {
		out = append(out, mapCertificate(c))
	}
	WriteJSON(w, http.StatusOK, out)
}

// ----- POST /v2/ans/agents/{agentId}/certificates/identity -----

// SubmitIdentityCSR handles POST .../certificates/identity. Body is
// a `CsrSubmissionRequest` (V2 §1362) with a single `csrPEM` field.
// Returns 202 with `{csrId, message}` per `CsrSubmissionResponse`.
//
// Parity with reference `CertificateOperationsHandler.submitAgentIdentityCsr`:
// the reference validates + persists the CSR synchronously and emits
// a domain event the infrastructure handler picks up to actually
// issue the cert. We take the same approach — the service saves the
// CSR with status=PENDING; a future job will flip it to SIGNED.
func (h *LifecycleHandler) SubmitIdentityCSR(w http.ResponseWriter, r *http.Request) {
	h.submitCSR(w, r, h.svc.SubmitIdentityCSR, "Identity CSR accepted for processing")
}

// ----- POST /v2/ans/agents/{agentId}/certificates/server -----

// SubmitServerCSR handles POST .../certificates/server. Body is a
// `CsrSubmissionRequest`; returns 202 `CsrSubmissionResponse`.
// Matches `CertificateOperationsHandler.submitAgentServerCsr`.
func (h *LifecycleHandler) SubmitServerCSR(w http.ResponseWriter, r *http.Request) {
	h.submitCSR(w, r, h.svc.SubmitServerCSR, "Server CSR accepted for processing")
}

// submitCSR is the shared body of the two CSR-submission handlers.
// Both paths accept the same CsrSubmissionRequest shape and emit the
// same CsrSubmissionResponse; the only difference is which service
// method handles the work. Extracting a helper keeps the two public
// handlers to 1 line each (matching the reference delegate's
// `operations.submitAgentXCsrByAgentId` forwarding).
func (h *LifecycleHandler) submitCSR(
	w http.ResponseWriter, r *http.Request,
	submit func(ctx context.Context, agentID, csrPEM string) (string, error),
	okMessage string,
) {
	agentID := chi.URLParam(r, "agentId")
	// 32 KiB is well above the typical CSR size (~1-2 KiB for P-256).
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	var req csrSubmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, domain.NewValidationError("BAD_JSON", "invalid JSON body: "+err.Error()))
		return
	}
	if req.CsrPEM == "" {
		WriteError(w, domain.NewValidationError("MISSING_CSR_PEM", "csrPEM is required"))
		return
	}
	csrID, err := submit(r.Context(), agentID, req.CsrPEM)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, csrSubmissionResponse{
		CsrID:   csrID,
		Message: okMessage,
	})
}

// ----- GET /v2/ans/agents/{agentId}/csrs/{csrId}/status -----

// GetCSRStatus handles GET .../csrs/{csrId}/status. Returns the
// V2 `CsrStatusResponse` with {csrId, type, status, submittedAt,
// updatedAt, failureReason}. 404 if the CSR doesn't exist or isn't
// scoped to this agent — matching the reference's ownership check.
func (h *LifecycleHandler) GetCSRStatus(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	csrID := chi.URLParam(r, "csrId")
	csr, err := h.svc.GetCSRStatus(r.Context(), agentID, csrID)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, mapCSRStatus(csr))
}

// ----- POST /v2/ans/agents/{agentId}/certificates/server/renewal -----

// SubmitServerCertRenewal handles POST .../certificates/server/renewal.
// Body is a `ServerCertificateRenewalRequest` with exactly one of
// serverCsrPEM / serverCertificatePEM. Returns 202 on success with
// `RenewalSubmissionResponse`. Matches reference
// `CertificateRenewalOperationsHandler.submitServerCertificateRenewal`.
func (h *LifecycleHandler) SubmitServerCertRenewal(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024) // CSR+chain can be several KB
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
	WriteJSON(w, http.StatusAccepted, mapRenewalSubmission(agentID, res))
}

// ----- GET /v2/ans/agents/{agentId}/certificates/server/renewal -----

// GetServerCertRenewal handles GET .../certificates/server/renewal.
// Returns 200 with `RenewalStatusResponse` or 404 if no renewal
// exists. Status is derived from the renewal's fields via
// determineRenewalStatus — matching the reference RA's handler.
func (h *LifecycleHandler) GetServerCertRenewal(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	ren, err := h.svc.GetServerCertRenewal(r.Context(), agentID)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, mapRenewalStatus(agentID, ren))
}

// ----- DELETE /v2/ans/agents/{agentId}/certificates/server/renewal -----

// CancelServerCertRenewal handles DELETE .../certificates/server/renewal.
// Returns 204 on success, 404 if no renewal exists, 422 if the
// renewal already completed. Matches the reference RA's handler.
func (h *LifecycleHandler) CancelServerCertRenewal(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if err := h.svc.CancelServerCertRenewal(r.Context(), agentID); err != nil {
		WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ----- POST /v2/ans/agents/{agentId}/certificates/server/renewal/verify-acme -----

// VerifyRenewalACME handles POST .../certificates/server/renewal/verify-acme.
// For BYOC renewals verification completes synchronously and we
// return 200; for CSR renewals the issuance is async and we return
// 202 — matching the reference RA's handler.
func (h *LifecycleHandler) VerifyRenewalACME(w http.ResponseWriter, r *http.Request) {
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
	WriteJSON(w, status, mapRenewalVerification(agentID, res))
}

// ----- POST /v2/ans/agents/{agentId}/verify-acme -----

// VerifyACME handles POST .../verify-acme. No request body.
func (h *LifecycleHandler) VerifyACME(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	res, err := h.svc.VerifyACME(r.Context(), agentID, service.VerifyInput{})
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, agentStatus{
		Status:         string(res.Registration.Status),
		Phase:          phaseFromStatus(res.Registration.Status),
		CompletedSteps: completedStepsFor(res.Registration.Status),
		PendingSteps:   pendingStepsFor(res.Registration.Status),
		CreatedAt:      res.Registration.Details.RegistrationTimestamp.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:      res.Now.Format("2006-01-02T15:04:05Z07:00"),
		ExpiresAt:      rfc3339Zero(res.Registration.ACMEChallenge.ExpiresAt),
	})
}

// ----- POST /v2/ans/agents/{agentId}/verify-dns -----

// VerifyDNS handles POST .../verify-dns.
func (h *LifecycleHandler) VerifyDNS(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	res, err := h.svc.VerifyDNS(r.Context(), agentID, service.VerifyInput{})
	if err != nil {
		WriteError(w, err)
		return
	}

	// DNS mismatches come back as a non-empty list on a happy-path
	// return; translate to 422 DnsVerificationError.
	if len(res.DNSMismatches) > 0 {
		WriteJSON(w, http.StatusUnprocessableEntity, dnsVerificationError{
			Status:           "ERROR",
			MissingRecords:   dnsMissingFrom(res.DNSMismatches),
			IncorrectRecords: dnsIncorrectFrom(res.DNSMismatches),
		})
		return
	}

	WriteJSON(w, http.StatusAccepted, agentStatus{
		Status:         string(res.Registration.Status),
		Phase:          phaseFromStatus(res.Registration.Status),
		CompletedSteps: completedStepsFor(res.Registration.Status),
		PendingSteps:   pendingStepsFor(res.Registration.Status),
		CreatedAt:      res.Registration.Details.RegistrationTimestamp.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:      res.Now.Format("2006-01-02T15:04:05Z07:00"),
		ExpiresAt:      rfc3339Zero(res.Registration.ACMEChallenge.ExpiresAt),
	})
}

// ----- POST /v2/ans/agents/{agentId}/revoke -----

// Revoke handles POST .../revoke.
func (h *LifecycleHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KiB

	var req revocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, domain.NewValidationError("BAD_JSON", "invalid request body: "+err.Error()))
		return
	}
	if req.Reason == "" {
		WriteError(w, domain.NewValidationError("MISSING_REASON", "reason is required"))
		return
	}

	agentID := chi.URLParam(r, "agentId")
	res, err := h.svc.Revoke(r.Context(), agentID, service.RevokeInput{
		Reason:   domain.RevocationReason(req.Reason),
		Comments: req.Comments,
	})
	if err != nil {
		WriteError(w, err)
		return
	}

	resp := revocationResponse{
		AgentID:   res.Registration.AgentID,
		AnsName:   res.Registration.AnsName.String(),
		Status:    string(res.Registration.Status),
		RevokedAt: res.RevokedAt.Format("2006-01-02T15:04:05Z07:00"),
		Reason:    req.Reason,
		Links: []linkDTO{
			{Rel: "self", Href: agentURL(r, res.Registration.AgentID)},
		},
	}
	for _, dr := range res.DNSRecordsToRemove {
		resp.DNSRecordsToRemove = append(resp.DNSRecordsToRemove, dnsRecordDTO{
			Name:     dr.Name,
			Type:     string(dr.Type),
			Value:    dr.Value,
			Purpose:  string(dr.Purpose),
			Required: dr.Required,
			TTL:      dr.TTL,
		})
	}
	WriteJSON(w, http.StatusOK, resp)
}
