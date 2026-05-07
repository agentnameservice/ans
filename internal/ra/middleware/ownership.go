// Package middleware holds HTTP middleware specific to the RA.
//
// Ownership enforcement lives here because it's a cross-cutting concern
// every agent-scoped route needs — putting it in the handlers would
// force every handler to duplicate the store lookup + owner check.
package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	rahandler "github.com/godaddy/ans/internal/ra/handler"
)

// contextKey is a distinct type so we never collide with other
// packages' context values.
type contextKey int

const agentContextKey contextKey = 1

// AgentFromContext returns the ownership-verified agent attached by
// Ownership middleware. Handlers call this instead of re-querying the
// store, ensuring they never operate on an agent they didn't prove
// ownership of.
func AgentFromContext(ctx context.Context) (*domain.AgentRegistration, bool) {
	v, ok := ctx.Value(agentContextKey).(*domain.AgentRegistration)
	return v, ok && v != nil
}

// Ownership wraps a handler that needs the `{agentId}` URL param. It:
//
//  1. Pulls the authenticated Identity out of the request context
//     (set by the auth provider's middleware earlier in the chain).
//  2. Extracts `{agentId}` from the URL.
//  3. Loads the agent from the store.
//  4. Compares `agent.OwnerID` against `identity.Subject`.
//  5. On match: attaches the loaded agent to the request context and
//     calls next.
//  6. On miss: returns a 4xx per the V2 spec's read/write split (see
//     `ReadOwnership` / `WriteOwnership`).
//
// Using the loaded agent directly from context (via AgentFromContext)
// avoids a second store roundtrip in the handler and guarantees the
// handler operates on the authenticated-owner's agent, not a freshly
// looked-up one that could theoretically race.
type ownershipMiddleware struct {
	store     port.AgentStore
	onMissing func(w http.ResponseWriter, r *http.Request, err error)
}

// ReadOwnership returns middleware appropriate for GET handlers. A
// missing-or-not-owned agent produces 404 — the V2 spec deliberately
// collapses "doesn't exist" and "not yours" to hide existence from
// unauthorized callers.
func ReadOwnership(store port.AgentStore) func(http.Handler) http.Handler {
	m := &ownershipMiddleware{
		store: store,
		onMissing: func(w http.ResponseWriter, _ *http.Request, err error) {
			rahandler.WriteError(w, domain.NewNotFoundError(
				"AGENT_NOT_FOUND",
				"agent not found or not accessible",
			))
			_ = err
		},
	}
	return m.wrap
}

// WriteOwnership returns middleware appropriate for write (POST/DELETE)
// handlers. Missing agent → 404; present but not owned → 403. Writes
// use the explicit split because a 404-for-not-owned would hide a real
// authorization failure from operators investigating permissions.
func WriteOwnership(store port.AgentStore) func(http.Handler) http.Handler {
	m := &ownershipMiddleware{
		store: store,
		onMissing: func(w http.ResponseWriter, _ *http.Request, err error) {
			if errors.Is(err, errNotOwned) {
				rahandler.WriteError(w, domain.NewUnauthorizedError(
					"AGENT_NOT_OWNED",
					"caller does not own this agent",
				))
				return
			}
			rahandler.WriteError(w, domain.NewNotFoundError(
				"AGENT_NOT_FOUND",
				"agent not found",
			))
		},
	}
	return m.wrap
}

// errNotOwned is returned from the internal lookup when the agent
// exists but is owned by someone else. Only the WriteOwnership path
// distinguishes this from a plain not-found; ReadOwnership treats
// both identically.
var errNotOwned = errors.New("ownership: agent present but not owned by caller")

func (m *ownershipMiddleware) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := auth.IdentityFromContext(r.Context())
		if !ok {
			rahandler.WriteError(w, domain.NewUnauthorizedError(
				"NO_IDENTITY", "authentication required",
			))
			return
		}

		agentID := chi.URLParam(r, "agentId")
		if agentID == "" {
			rahandler.WriteError(w, domain.NewValidationError(
				"MISSING_AGENT_ID", "agentId is required",
			))
			return
		}

		agent, err := m.store.FindByAgentID(r.Context(), agentID)
		if err != nil {
			// Store returns domain.ErrNotFound; we don't care to
			// distinguish underlying SQL errors from actual-not-found
			// at this layer — both mean the caller gets the
			// appropriate 4xx.
			m.onMissing(w, r, err)
			return
		}

		if agent.OwnerID != identity.Subject && !identity.IsAdmin {
			m.onMissing(w, r, errNotOwned)
			return
		}

		ctx := context.WithValue(r.Context(), agentContextKey, agent)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
