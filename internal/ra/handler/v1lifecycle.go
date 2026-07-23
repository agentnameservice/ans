package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/ra/service"
)

const (
	maxCommentsLength = 200
)

// V1LifecycleHandler groups the V1 post-registration transitions:
// verify-acme, verify-dns, revoke. Shares the `RegistrationService`
// with V2; diverges only in DTO shape and TL-lane emission.
//
// Every handler method stamps `service.VerifyInput{SchemaVersion:"V1"}`
// (or the revoke equivalent) on the service call so state
// transitions enqueue V1 envelopes to `/v1/internal/agents/event`.
type V1LifecycleHandler struct {
	responder
	svc *service.RegistrationService
}

// NewV1LifecycleHandler constructs a V1LifecycleHandler.
func NewV1LifecycleHandler(svc *service.RegistrationService, logger zerolog.Logger) *V1LifecycleHandler {
	return &V1LifecycleHandler{responder: newResponder(logger), svc: svc}
}

// v1AgentStatusResponse is the V1 shape returned from verify-acme /
// verify-dns on success. Mirrors the V2 `agentStatus` struct;
// separate type so V1-specific spec drift can land without touching
// V2 DTOs.
//
// `expiresAt` carries the ACME challenge deadline (set at register
// time, min 24h from registration per ans default). Production emits
// this with sub-second precision, e.g. "2026-04-24T15:23:30.599636Z".
type v1AgentStatusResponse struct {
	Status         string   `json:"status"`
	Phase          string   `json:"phase"`
	CompletedSteps []string `json:"completedSteps"`
	PendingSteps   []string `json:"pendingSteps"`
	CreatedAt      string   `json:"createdAt"`
	UpdatedAt      string   `json:"updatedAt"`
	ExpiresAt      string   `json:"expiresAt,omitempty"`
}

// v1RevocationRequest mirrors reference `AgentRevocationRequest`
// (api-spec.yaml:1195-1205).
type v1RevocationRequest struct {
	Reason   string `json:"reason"`
	Comments string `json:"comments,omitempty"`
}

// v1RevocationResponse mirrors reference `AgentRevocationResponse`
// (api-spec.yaml:1207-1251). Byte-for-byte parity: agentId, ansName,
// status, revokedAt, reason, dnsRecordsToRemove, links.
type v1RevocationResponse struct {
	AgentID            string           `json:"agentId"`
	AnsName            string           `json:"ansName"`
	Status             string           `json:"status"`
	RevokedAt          string           `json:"revokedAt"`
	Reason             string           `json:"reason"`
	Comments           string           `json:"comments,omitempty"`
	DNSRecordsToRemove []v1DNSRecordDTO `json:"dnsRecordsToRemove,omitempty"`
	Links              []v1LinkDTO      `json:"links,omitempty"`
}

// v1DNSVerificationError mirrors the reference 422 shape for
// verify-dns mismatches. Separate from V2's copy so either can
// evolve independently with the spec.
type v1DNSVerificationError struct {
	Status           string             `json:"status"`
	MissingRecords   []v1DNSRecordDTO   `json:"missingRecords,omitempty"`
	IncorrectRecords []v1DNSMismatchDTO `json:"incorrectRecords,omitempty"`
}

type v1DNSMismatchDTO struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Expected string `json:"expected"`
	Found    string `json:"found"`
}

// VerifyACME handles POST /v1/agents/{agentId}/verify-acme. No body.
// V1 TL receives no leaf for this intermediate transition — the V1
// enum lacks DOMAIN_VALIDATION. The agent's domain state still
// advances to PENDING_DNS.
func (h *V1LifecycleHandler) VerifyACME(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	res, err := h.svc.VerifyACME(r.Context(), agentID, service.VerifyInput{SchemaVersion: "V1"})
	if err != nil {
		h.writeError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, v1AgentStatusResponse{
		Status:         string(res.Registration.Status),
		Phase:          phaseFor(res.Registration),
		CompletedSteps: completedStepsFor(res.Registration),
		PendingSteps:   pendingStepsFor(res.Registration),
		CreatedAt:      res.Registration.Details.RegistrationTimestamp.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:      res.Now.Format("2006-01-02T15:04:05Z07:00"),
		ExpiresAt:      rfc3339Zero(res.Registration.CertOrder.ExpiresAt),
	})
}

// VerifyDNS handles POST /v1/agents/{agentId}/verify-dns. On
// successful ACTIVE transition, enqueues an AGENT_REGISTERED V1
// envelope to the TL — this is the FIRST TL leaf V1 agents get
// (V1 defers emission from /register until the agent is live,
// matching the reference lifecycle).
func (h *V1LifecycleHandler) VerifyDNS(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	res, err := h.svc.VerifyDNS(r.Context(), agentID, service.VerifyInput{SchemaVersion: "V1"})
	if err != nil {
		h.writeError(w, err)
		return
	}
	if len(res.DNSMismatches) > 0 {
		WriteJSON(w, http.StatusUnprocessableEntity, v1DNSVerificationError{
			Status:           "ERROR",
			MissingRecords:   v1DNSMissingFrom(res.DNSMismatches),
			IncorrectRecords: v1DNSIncorrectFrom(res.DNSMismatches),
		})
		return
	}
	WriteJSON(w, http.StatusAccepted, v1AgentStatusResponse{
		Status:         string(res.Registration.Status),
		Phase:          phaseFor(res.Registration),
		CompletedSteps: completedStepsFor(res.Registration),
		PendingSteps:   pendingStepsFor(res.Registration),
		CreatedAt:      res.Registration.Details.RegistrationTimestamp.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:      res.Now.Format("2006-01-02T15:04:05Z07:00"),
		ExpiresAt:      rfc3339Zero(res.Registration.CertOrder.ExpiresAt),
	})
}

// Revoke handles POST /v1/agents/{agentId}/revoke. Enqueues an
// AGENT_REVOKED V1 envelope to the TL. Response shape matches
// `AgentRevocationResponse` in the reference spec.
func (h *V1LifecycleHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KiB
	var req v1RevocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, domain.NewValidationError("BAD_JSON", "invalid request body: "+err.Error()))
		return
	}
	if req.Reason == "" {
		h.writeError(w, domain.NewValidationError("MISSING_REASON", "reason is required"))
		return
	}

	if len(req.Comments) > maxCommentsLength {
		WriteError(w, domain.NewValidationError("COMMENTS_TOO_LONG",
			fmt.Sprintf("comments exceeds %d characters", maxCommentsLength)))
		return
	}

	agentID := chi.URLParam(r, "agentId")
	res, err := h.svc.Revoke(r.Context(), agentID, service.RevokeInput{
		Reason:        domain.RevocationReason(req.Reason),
		Comments:      req.Comments,
		SchemaVersion: "V1",
	})
	if err != nil {
		h.writeError(w, err)
		return
	}

	resp := v1RevocationResponse{
		AgentID:   res.Registration.AgentID,
		AnsName:   res.Registration.AnsName.String(),
		Status:    string(res.Registration.Status),
		RevokedAt: res.RevokedAt.Format("2006-01-02T15:04:05Z07:00"),
		Reason:    req.Reason,
		Comments:  req.Comments,
		Links: []v1LinkDTO{
			{Rel: "self", Href: schemeOf(r) + "://" + r.Host + "/v1/agents/" + res.Registration.AgentID},
		},
	}
	for _, dr := range res.DNSRecordsToRemove {
		resp.DNSRecordsToRemove = append(resp.DNSRecordsToRemove, v1DNSRecordDTO{
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

// v1DNSMissingFrom / v1DNSIncorrectFrom filter the mismatch list
// into the two 422-body arrays. Each DTO carries just the fields the
// V1 spec exposes.
func v1DNSMissingFrom(mismatches []service.DNSMismatch) []v1DNSRecordDTO {
	out := make([]v1DNSRecordDTO, 0)
	for _, m := range mismatches {
		if !m.IsMissing() {
			continue
		}
		out = append(out, v1DNSRecordDTO{
			Name:     m.Expected.Name,
			Type:     string(m.Expected.Type),
			Value:    m.Expected.Value,
			Purpose:  string(m.Expected.Purpose),
			Required: m.Expected.Required,
			TTL:      m.Expected.TTL,
		})
	}
	return out
}

func v1DNSIncorrectFrom(mismatches []service.DNSMismatch) []v1DNSMismatchDTO {
	out := make([]v1DNSMismatchDTO, 0)
	for _, m := range mismatches {
		// Present-but-wrong records — plain MISMATCH or DNSSEC tampering
		// on TLSA/SVCB/HTTPS (<RECORD_TYPE>_DNSSEC_MISMATCH) — surface
		// here as incorrect-record entries. See
		// service.DNSMismatch.IsIncorrect for the classification.
		if !m.IsIncorrect() {
			continue
		}
		out = append(out, v1DNSMismatchDTO{
			Name:     m.Expected.Name,
			Type:     string(m.Expected.Type),
			Expected: m.Expected.Value,
			Found:    m.Found,
		})
	}
	return out
}
