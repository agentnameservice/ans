package handler

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/ra/service"
)

// V1EventsHandler serves GET /v1/agents/events — the public,
// unauthenticated agent-lifecycle events feed the ANS Finder ingests.
//
// Wire parity: the response is byte-compatible with the production
// swagger's EventPageResponse (consumer mirror: internal/finder/feed).
// The service layer owns the DTO shape, the domain→wire token map, and
// the projection from delivered outbox rows; this handler only parses
// query parameters and serializes the page.
//
// Gating: the feed serves only TL-acked rows (sent_at_ms IS NOT NULL
// AND log_id IS NOT NULL), so an item appearing here means its event
// is sealed in the log and a receipt is resolvable from its logId.
//
// AUTH / ROUTING CONTRACT — the route is registered anonymously via an
// EXACT-path exemption in cmd/ans-ra (WithAnonymousExactPath). Exact,
// not subtree, because this leaf sits beside authenticated wildcard
// siblings: chi backtracks /v1/agents/events/<x> onto the
// /v1/agents/{agentId}/<x> routes (agentId="events"), so a subtree
// exemption would silently disable auth for those write routes. The
// exact exemption matches only this path — never a child, never a
// same-prefix sibling like /v1/agents/eventsfoo.
type V1EventsHandler struct {
	responder
	svc *service.EventsService
}

// NewV1EventsHandler constructs a V1EventsHandler. The embedded
// responder logs the real cause of any 500 server-side; the client only
// ever sees the generic Problem detail (the feed is anonymous, so
// internal fault text must not reach it).
func NewV1EventsHandler(svc *service.EventsService, logger zerolog.Logger) *V1EventsHandler {
	return &V1EventsHandler{responder: newResponder(logger), svc: svc}
}

// List handles GET /v1/agents/events.
//
// Query parameters (all optional):
//   - limit: 1..200, default 100. Out-of-range or non-numeric → 422.
//   - lastLogId: opaque cursor; rows after it are returned. An unknown
//     or aged-out cursor restarts from the oldest retained row (the
//     retention window makes "expired" and "never existed"
//     indistinguishable — documented on the route).
//   - providerId: accepted for production-shape parity. The OSS RA has
//     no provider concept, so any non-empty value yields an empty page.
func (h *V1EventsHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	in := service.EventsInput{
		LastLogID:  q.Get("lastLogId"),
		ProviderID: q.Get("providerId"),
		Limit:      service.EventsFeedDefaultLimit,
	}

	if lv := q.Get("limit"); lv != "" {
		n, err := strconv.Atoi(lv)
		if err != nil || n < 1 || n > service.EventsFeedMaxLimit {
			h.writeError(w, domain.NewValidationError(
				"INVALID_LIMIT",
				fmt.Sprintf("limit must be between 1 and %d", service.EventsFeedMaxLimit),
			))
			return
		}
		in.Limit = n
	}

	page, err := h.svc.ListEvents(r.Context(), in)
	if err != nil {
		// writeError logs the real cause server-side for a 500; the
		// client gets only the generic sanitized detail.
		h.writeError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, page)
}
