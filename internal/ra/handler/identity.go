package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/ra/service"
)

// IdentityHandler wires the /v2/ans/identities surface — the "who"
// behind the agents. Ownership is enforced inside the service (the
// owner gate is the link mechanism's security boundary), so these
// handlers only extract the authenticated principal and map DTOs.
type IdentityHandler struct {
	svc *service.IdentityService
}

// NewIdentityHandler constructs an IdentityHandler.
func NewIdentityHandler(svc *service.IdentityService) *IdentityHandler {
	return &IdentityHandler{svc: svc}
}

// identityRegisterRequest is the POST /v2/ans/identities (and PUT
// rotation) body. The kind is inferred from the value's lexical form
// — never caller-asserted.
type identityRegisterRequest struct {
	Value string `json:"value"`
}

// identityChallengeDTO is one entry of the 202 challenge list.
type identityChallengeDTO struct {
	Kid          string `json:"kid,omitempty"`
	SigningInput string `json:"signingInput"`
}

// identityChallengeResponse is the 202 body returned by register and
// rotate: the identity's id plus the challenge round to sign.
type identityChallengeResponse struct {
	IdentityID string                 `json:"identityId"`
	Kind       string                 `json:"kind"`
	Value      string                 `json:"value"`
	Status     string                 `json:"status"`
	Nonce      string                 `json:"nonce"`
	ExpiresAt  string                 `json:"expiresAt"`
	Challenges []identityChallengeDTO `json:"challenges"`
}

// verifyControlRequest is the POST .../verify-control body. Members
// are additive per identifier kind — exactly one family is set per
// kind: the JWS schemes (did:web, did:key, and the future did:plc /
// did:ion) submit signedProofs; future kinds add their own optional
// members (lei: cesrSignature; did:ethr: ethSignature) without
// touching existing ones.
type verifyControlRequest struct {
	// SignedProofs — one compact JWS per proven key, every payload
	// equal to the served signingInput verbatim.
	SignedProofs []string `json:"signedProofs"`
}

// identityDetailResponse is the identity object echoed by
// verify-control, revoke, detail, and list entries.
type identityDetailResponse struct {
	IdentityID   string           `json:"identityId"`
	Kind         string           `json:"kind"`
	Value        string           `json:"value"`
	Status       string           `json:"status"`
	ProofMethod  string           `json:"proofMethod,omitempty"`
	PendingValue string           `json:"pendingValue,omitempty"`
	VerifiedAt   string           `json:"verifiedAt,omitempty"`
	CreatedAt    string           `json:"createdAt"`
	LinkedAgents []linkedAgentDTO `json:"linkedAgents,omitempty"`
}

type linkedAgentDTO struct {
	AgentID  string `json:"agentId"`
	LinkedAt string `json:"linkedAt,omitempty"`
}

// linkRequest is the POST .../links body — the batch of the owner's
// agents to bind. One call, one sealed IDENTITY_LINKED event.
type linkRequest struct {
	AgentIDs []string `json:"agentIds"`
}

type linkResponse struct {
	Linked int `json:"linked"`
}

// Register handles POST /v2/ans/identities → 202 + challenges.
func (h *IdentityHandler) Register(w http.ResponseWriter, r *http.Request) {
	providerID, ok := callerSubject(w, r)
	if !ok {
		return
	}
	var req identityRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, domain.NewValidationError("INVALID_REQUEST_BODY", "request body is not valid JSON"))
		return
	}
	if req.Value == "" {
		WriteError(w, domain.NewValidationError("INVALID_IDENTIFIER", "value is required"))
		return
	}
	res, err := h.svc.Register(r.Context(), providerID, req.Value)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, toChallengeResponse(res))
}

// Rotate handles PUT /v2/ans/identities/{identityId} → 202 + fresh
// challenges over the staged replacement.
func (h *IdentityHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	providerID, ok := callerSubject(w, r)
	if !ok {
		return
	}
	var req identityRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, domain.NewValidationError("INVALID_REQUEST_BODY", "request body is not valid JSON"))
		return
	}
	if req.Value == "" {
		WriteError(w, domain.NewValidationError("INVALID_IDENTIFIER", "value is required"))
		return
	}
	res, err := h.svc.Rotate(r.Context(), providerID, chi.URLParam(r, "identityId"), req.Value)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, toChallengeResponse(res))
}

// VerifyControl handles POST /v2/ans/identities/{identityId}/verify-control.
// Clean proofs flip the identity to VERIFIED (or complete a rotation)
// and seal the event — the 200 echoes the updated identity.
func (h *IdentityHandler) VerifyControl(w http.ResponseWriter, r *http.Request) {
	providerID, ok := callerSubject(w, r)
	if !ok {
		return
	}
	var req verifyControlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, domain.NewValidationError("INVALID_REQUEST_BODY", "request body is not valid JSON"))
		return
	}
	identity, err := h.svc.VerifyControl(r.Context(), providerID, chi.URLParam(r, "identityId"),
		service.ProofSubmission{SignedProofs: req.SignedProofs})
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toDetailResponse(identity, nil))
}

// Revoke handles POST /v2/ans/identities/{identityId}/revoke — a
// state change (an identity cannot be deleted; its history is
// append-only in the TL), mirroring the agent's revoke verb.
func (h *IdentityHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	providerID, ok := callerSubject(w, r)
	if !ok {
		return
	}
	identity, err := h.svc.Revoke(r.Context(), providerID, chi.URLParam(r, "identityId"))
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toDetailResponse(identity, nil))
}

// List handles GET /v2/ans/identities — the caller's identities.
func (h *IdentityHandler) List(w http.ResponseWriter, r *http.Request) {
	providerID, ok := callerSubject(w, r)
	if !ok {
		return
	}
	identities, err := h.svc.List(r.Context(), providerID)
	if err != nil {
		WriteError(w, err)
		return
	}
	out := make([]identityDetailResponse, 0, len(identities))
	for _, identity := range identities {
		out = append(out, toDetailResponse(identity, nil))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"identities": out})
}

// Detail handles GET /v2/ans/identities/{identityId} — the identity
// plus its live links.
func (h *IdentityHandler) Detail(w http.ResponseWriter, r *http.Request) {
	providerID, ok := callerSubject(w, r)
	if !ok {
		return
	}
	identity, links, err := h.svc.Detail(r.Context(), providerID, chi.URLParam(r, "identityId"))
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toDetailResponse(identity, links))
}

// Link handles POST /v2/ans/identities/{identityId}/links — the
// owner-gated batch link. 200 {linked: N}; the batch sealed as ONE
// IDENTITY_LINKED event on the identity stream.
func (h *IdentityHandler) Link(w http.ResponseWriter, r *http.Request) {
	providerID, ok := callerSubject(w, r)
	if !ok {
		return
	}
	var req linkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, domain.NewValidationError("INVALID_REQUEST_BODY", "request body is not valid JSON"))
		return
	}
	linked, err := h.svc.Link(r.Context(), providerID, chi.URLParam(r, "identityId"), req.AgentIDs)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, linkResponse{Linked: linked})
}

// Unlink handles DELETE /v2/ans/identities/{identityId}/links/{agentId}.
// The association ends (204); its history persists in the identity's
// audit chain and the raw log tiles.
func (h *IdentityHandler) Unlink(w http.ResponseWriter, r *http.Request) {
	providerID, ok := callerSubject(w, r)
	if !ok {
		return
	}
	err := h.svc.Unlink(r.Context(), providerID, chi.URLParam(r, "identityId"), chi.URLParam(r, "agentId"))
	if err != nil {
		WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// callerSubject extracts the authenticated principal, writing the
// 401-equivalent problem when absent.
func callerSubject(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, ok := auth.IdentityFromContext(r.Context())
	if !ok || id.Subject == "" {
		WriteError(w, domain.NewUnauthorizedError("NO_IDENTITY", "authentication required"))
		return "", false
	}
	return id.Subject, true
}

func toChallengeResponse(res *service.IdentityChallengeResponse) identityChallengeResponse {
	challenges := make([]identityChallengeDTO, 0, len(res.Challenges))
	for _, c := range res.Challenges {
		challenges = append(challenges, identityChallengeDTO{Kid: c.Kid, SigningInput: c.SigningInput})
	}
	return identityChallengeResponse{
		IdentityID: res.Identity.IdentityID,
		Kind:       string(res.Identity.Kind),
		Value:      res.Identity.EffectiveValue(),
		Status:     string(res.Identity.Status),
		Nonce:      res.Nonce,
		ExpiresAt:  res.ExpiresAt.UTC().Format(time.RFC3339),
		Challenges: challenges,
	}
}

func toDetailResponse(identity *domain.VerifiedIdentity, links []*domain.IdentityLink) identityDetailResponse {
	out := identityDetailResponse{
		IdentityID:   identity.IdentityID,
		Kind:         string(identity.Kind),
		Value:        identity.Value,
		Status:       string(identity.Status),
		ProofMethod:  identity.ProofMethod,
		PendingValue: identity.PendingValue,
		CreatedAt:    identity.CreatedAt.UTC().Format(time.RFC3339),
	}
	if !identity.VerifiedAt.IsZero() {
		out.VerifiedAt = identity.VerifiedAt.UTC().Format(time.RFC3339)
	}
	for _, l := range links {
		dto := linkedAgentDTO{AgentID: l.AgentID}
		if !l.LinkedAt.IsZero() {
			dto.LinkedAt = l.LinkedAt.UTC().Format(time.RFC3339)
		}
		out.LinkedAgents = append(out.LinkedAgents, dto)
	}
	return out
}
