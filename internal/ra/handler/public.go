package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/service"
)

// PublicHandler groups unauthenticated read-only discovery endpoints.
// Routes served by this handler bypass the auth middleware via anonymous
// path registration.
type PublicHandler struct {
	svc *service.RegistrationService
}

// NewPublicHandler constructs a PublicHandler.
func NewPublicHandler(svc *service.RegistrationService) *PublicHandler {
	return &PublicHandler{svc: svc}
}

const publicAgentsPrefix = "/v2/public/agents/"

// List handles GET /v2/public/agents.
func (h *PublicHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := port.ListFilter{
		AgentHost: q.Get("agentHost"),
		Cursor:    q.Get("cursor"),
	}

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

	res, err := h.svc.ListPublic(r.Context(), filter)
	if err != nil {
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, mapListResponseWithPrefix(res, publicAgentsPrefix))
}

// Detail handles GET /v2/public/agents/{agentId}.
func (h *PublicHandler) Detail(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	res, err := h.svc.GetByAgentID(r.Context(), agentID)
	if err != nil {
		WriteError(w, err)
		return
	}
	d := mapAgentDetails(res, r, h.svc.TLPublicBaseURL())
	d.RegistrationPending = nil
	d.Links = []linkDTO{
		{Rel: "self", Href: publicAgentsPrefix + res.Registration.AgentID},
	}
	WriteJSON(w, http.StatusOK, d)
}
