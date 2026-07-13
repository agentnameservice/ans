package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
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
	// VLEIPresentation carries the lei full-chain CESR export at
	// register time (the credential + KELs). Set only for lei; the
	// JWS kinds omit it.
	VLEIPresentation *vleiPresentationDTO `json:"vleiPresentation,omitempty"`
}

// vleiPresentationDTO is the lei register-time credential presentation.
type vleiPresentationDTO struct {
	CESR string `json:"cesr"`
}

// identityChallengeDTO is one entry of the 202 challenge list.
type identityChallengeDTO struct {
	Kid          string `json:"kid,omitempty"`
	SigningInput string `json:"signingInput"`
}

// identityChallengeResponse is the 202 body returned by register and
// rotate: the identity's id plus the challenge round to sign.
type identityChallengeResponse struct {
	IdentityID string `json:"identityId"`
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	Status     string `json:"status"`
	// PresentationStatus is the lei register-time advisory status
	// ("AUTHORIZED" | "PENDING"); omitted for kinds with no
	// register-time presentation (did:web, did:key).
	PresentationStatus string                 `json:"presentationStatus,omitempty"`
	Nonce              string                 `json:"nonce"`
	ExpiresAt          string                 `json:"expiresAt"`
	Challenges         []identityChallengeDTO `json:"challenges"`
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
	// CESRSignature — the lei proof: one CESR signature over the
	// served signingInput by the subject AID's current key. Set only
	// for lei.
	CESRSignature string `json:"cesrSignature"`
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
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB — matches registration.go
	var req identityRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, domain.NewValidationError("INVALID_REQUEST_BODY", "request body is not valid JSON"))
		return
	}
	if req.Value == "" {
		WriteError(w, domain.NewValidationError("INVALID_IDENTIFIER", "value is required"))
		return
	}
	res, err := h.svc.Register(r.Context(), providerID, req.Value, req.registerOptions())
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, toChallengeResponse(res))
}

// registerOptions maps the kind-specific request members to the
// service's additive RegisterOptions. Empty for non-lei kinds.
func (req identityRegisterRequest) registerOptions() service.RegisterOptions {
	var opt service.RegisterOptions
	if req.VLEIPresentation != nil {
		opt.VLEIPresentation = req.VLEIPresentation.CESR
	}
	return opt
}

// Rotate handles PUT /v2/ans/identities/{identityId} → 202 + fresh
// challenges over the staged replacement.
func (h *IdentityHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	providerID, ok := callerSubject(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB — matches registration.go
	var req identityRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, domain.NewValidationError("INVALID_REQUEST_BODY", "request body is not valid JSON"))
		return
	}
	if req.Value == "" {
		WriteError(w, domain.NewValidationError("INVALID_IDENTIFIER", "value is required"))
		return
	}
	res, err := h.svc.Rotate(r.Context(), providerID, chi.URLParam(r, "identityId"), req.Value, req.registerOptions())
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
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB — matches registration.go
	var req verifyControlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, domain.NewValidationError("INVALID_REQUEST_BODY", "request body is not valid JSON"))
		return
	}
	identity, err := h.svc.VerifyControl(r.Context(), providerID, chi.URLParam(r, "identityId"),
		service.ProofSubmission{SignedProofs: req.SignedProofs, CESRSignature: req.CESRSignature})
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

// defaultIdentityListLimit mirrors the store's default page size so
// the reported `limit` is accurate when the caller omits one.
const defaultIdentityListLimit = 20

// identityListResponse is the cursor-paginated list envelope, named
// to match AgentListResponse (`items` + returnedCount/limit/
// nextCursor/hasMore) — one collection-response convention across
// the v2 surface.
type identityListResponse struct {
	Items         []identityDetailResponse `json:"items"`
	ReturnedCount int                      `json:"returnedCount"`
	Limit         int                      `json:"limit"`
	NextCursor    *string                  `json:"nextCursor"`
	HasMore       bool                     `json:"hasMore"`
}

// List handles GET /v2/ans/identities — one page of the caller's
// identities, in the v2 limit + opaque-cursor envelope mirroring
// AgentListResponse (`items` array): one collection convention
// across the v2 surface.
func (h *IdentityHandler) List(w http.ResponseWriter, r *http.Request) {
	providerID, ok := callerSubject(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := 0
	if lv := q.Get("limit"); lv != "" {
		n, err := strconv.Atoi(lv)
		if err != nil || n < 1 || n > 100 {
			WriteError(w, domain.NewValidationError("INVALID_LIMIT", "limit must be between 1 and 100"))
			return
		}
		limit = n
	}
	page, err := h.svc.List(r.Context(), providerID, limit, q.Get("cursor"))
	if err != nil {
		WriteError(w, err)
		return
	}
	out := make([]identityDetailResponse, 0, len(page.Items))
	for _, identity := range page.Items {
		out = append(out, toDetailResponse(identity, nil))
	}
	effectiveLimit := limit
	if effectiveLimit == 0 {
		effectiveLimit = defaultIdentityListLimit
	}
	resp := identityListResponse{
		Items:         out,
		ReturnedCount: len(out),
		Limit:         effectiveLimit,
		HasMore:       page.HasMore,
	}
	if page.NextCursor != "" {
		resp.NextCursor = &page.NextCursor
	}
	WriteJSON(w, http.StatusOK, resp)
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
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10) // 32 KiB — maxLinkBatch (256) UUIDs fit well under this
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
		IdentityID:         res.Identity.IdentityID,
		Kind:               string(res.Identity.Kind),
		Value:              res.Identity.EffectiveValue(),
		Status:             string(res.Identity.Status),
		PresentationStatus: string(res.PresentationStatus),
		Nonce:              res.Nonce,
		ExpiresAt:          res.ExpiresAt.UTC().Format(time.RFC3339),
		Challenges:         challenges,
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
