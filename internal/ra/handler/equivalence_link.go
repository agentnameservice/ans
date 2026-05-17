// Package handler: equivalence-link HTTP handler.
//
// Mounts at POST /v2/ans/agents/{agentId}/equivalence-links and emits
// one EQUIVALENCE_LINK event into the Transparency Log. The path
// {agentId} is the primary registration; the body carries the linked
// registration's agent id plus an optional rationale string.
//
// Auth: the writeOwnership middleware confirms the caller owns the
// primary registration before this handler runs. The service then
// re-checks ownership on the linked agent so a caller cannot link
// their own registration to one they do not control.
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/ra/service"
)

// EquivalenceLinkHandler exposes the link-emission endpoint. It owns
// no state; all logic lives in service.RegistrationService.LinkEquivalence.
type EquivalenceLinkHandler struct {
	svc *service.RegistrationService
}

// NewEquivalenceLinkHandler wires the handler against a registration
// service. Returned value is safe to share across request goroutines.
func NewEquivalenceLinkHandler(svc *service.RegistrationService) *EquivalenceLinkHandler {
	return &EquivalenceLinkHandler{svc: svc}
}

// linkRequest is the JSON shape the handler accepts on the body.
// linkedAnsId is the linked registration's agent UUID; rationale is
// the operator's free-text justification persisted in the link event.
type linkRequest struct {
	LinkedAnsID string `json:"linkedAnsId"`
	Rationale   string `json:"rationale,omitempty"`
}

// linkResponse mirrors what the service returns plus the path-derived
// primary agent id. Callers use the returned anchor type and value
// to display the link to operators without re-fetching the linked
// registration.
type linkResponse struct {
	PrimaryAgentID    string `json:"primaryAgentId"`
	PrimaryAnsName    string `json:"primaryAnsName,omitempty"`
	LinkedAnsID       string `json:"linkedAnsId"`
	LinkedAnsName     string `json:"linkedAnsName,omitempty"`
	LinkedAnchorType  string `json:"linkedAnchorType"`
	LinkedAnchorValue string `json:"linkedAnchorValue"`
	Rationale         string `json:"rationale,omitempty"`
	Timestamp         string `json:"timestamp"`
}

// CreateLink handles POST /v2/ans/agents/{agentId}/equivalence-links.
func (h *EquivalenceLinkHandler) CreateLink(w http.ResponseWriter, r *http.Request) {
	primaryID := chi.URLParam(r, "agentId")
	if primaryID == "" {
		WriteError(w, domain.NewValidationError("MISSING_AGENT_ID", "agentId is required"))
		return
	}

	var body linkRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		WriteError(w, domain.NewValidationError("BAD_JSON", "request body is not valid JSON: "+err.Error()))
		return
	}

	id, ok := auth.IdentityFromContext(r.Context())
	if !ok || id.Subject == "" {
		WriteError(w, domain.NewValidationError("MISSING_OWNER", "owner identity is required"))
		return
	}
	ownerID := id.Subject

	res, err := h.svc.LinkEquivalence(r.Context(), service.LinkEquivalenceInput{
		OwnerID:        ownerID,
		PrimaryAgentID: primaryID,
		LinkedAgentID:  body.LinkedAnsID,
		Rationale:      body.Rationale,
	})
	if err != nil {
		WriteError(w, err)
		return
	}

	WriteJSON(w, http.StatusCreated, linkResponse{
		PrimaryAgentID:    res.PrimaryAgentID,
		PrimaryAnsName:    res.PrimaryAnsName,
		LinkedAnsID:       res.LinkedAgentID,
		LinkedAnsName:     res.LinkedAnsName,
		LinkedAnchorType:  res.LinkedAnchorType,
		LinkedAnchorValue: res.LinkedAnchorValue,
		Rationale:         res.Rationale,
		Timestamp:         res.Timestamp,
	})
}
