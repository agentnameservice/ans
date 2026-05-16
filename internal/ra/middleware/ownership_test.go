package middleware_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/middleware"
)

// TestReadOwnership_AttachesAgentOnMatch is the happy-path: a
// matching owner sees the handler run, and the handler can retrieve
// the pre-loaded agent from the request context.
func TestReadOwnership_AttachesAgentOnMatch(t *testing.T) {
	t.Parallel()
	agent := mkAgent(t, "a1", "owner-1", "agent.example.com")
	store := &fakeAgentStore{byID: map[string]*domain.AgentRegistration{"a1": agent}}

	var handlerSawAgent *domain.AgentRegistration
	r := chi.NewRouter()
	r.With(
		identityMiddleware("owner-1", false),
		middleware.ReadOwnership(store),
	).Get("/agents/{agentId}", func(w http.ResponseWriter, req *http.Request) {
		handlerSawAgent, _ = middleware.AgentFromContext(req.Context())
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/a1", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body=%s)", rec.Code, rec.Body)
	}
	if handlerSawAgent == nil || handlerSawAgent.AgentID != "a1" {
		t.Fatalf("handler did not receive the loaded agent from context")
	}
}

// TestReadOwnership_ReturnsGeneric404ForNotOwned — V2 spec deliberately
// hides existence. The response must look identical to the unknown-
// agent case; no distinguishing hint in the body.
func TestReadOwnership_ReturnsGeneric404ForNotOwned(t *testing.T) {
	t.Parallel()
	agent := mkAgent(t, "a1", "owner-X", "agent.example.com")
	store := &fakeAgentStore{byID: map[string]*domain.AgentRegistration{"a1": agent}}

	r := chi.NewRouter()
	r.With(
		identityMiddleware("owner-1", false), // not the agent's owner
		middleware.ReadOwnership(store),
	).Get("/agents/{agentId}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/a1", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404 (body=%s)", rec.Code, rec.Body)
	}
	var prob struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if prob.Code != "AGENT_NOT_FOUND" {
		t.Errorf("code: got %q, want AGENT_NOT_FOUND", prob.Code)
	}
}

func TestReadOwnership_Returns404ForMissing(t *testing.T) {
	t.Parallel()
	store := &fakeAgentStore{byID: map[string]*domain.AgentRegistration{}}

	r := chi.NewRouter()
	r.With(
		identityMiddleware("owner-1", false),
		middleware.ReadOwnership(store),
	).Get("/agents/{agentId}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/does-not-exist", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", rec.Code)
	}
}

// TestWriteOwnership_Returns403ForNotOwned — write path uses the
// explicit split so an authenticated caller knows their token worked
// but they hit a wrong-agent error.
func TestWriteOwnership_Returns403ForNotOwned(t *testing.T) {
	t.Parallel()
	agent := mkAgent(t, "a1", "owner-X", "agent.example.com")
	store := &fakeAgentStore{byID: map[string]*domain.AgentRegistration{"a1": agent}}

	r := chi.NewRouter()
	r.With(
		identityMiddleware("owner-1", false),
		middleware.WriteOwnership(store),
	).Post("/agents/{agentId}/revoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/a1/revoke", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", rec.Code)
	}
	var prob struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if prob.Code != "AGENT_NOT_OWNED" {
		t.Errorf("code: got %q, want AGENT_NOT_OWNED", prob.Code)
	}
}

func TestWriteOwnership_Returns404ForMissing(t *testing.T) {
	t.Parallel()
	store := &fakeAgentStore{byID: map[string]*domain.AgentRegistration{}}

	r := chi.NewRouter()
	r.With(
		identityMiddleware("owner-1", false),
		middleware.WriteOwnership(store),
	).Post("/agents/{agentId}/revoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/does-not-exist/revoke", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404 (body=%s)", rec.Code, rec.Body)
	}
}

func TestOwnership_AdminBypassesCheck(t *testing.T) {
	t.Parallel()
	agent := mkAgent(t, "a1", "owner-X", "agent.example.com")
	store := &fakeAgentStore{byID: map[string]*domain.AgentRegistration{"a1": agent}}

	r := chi.NewRouter()
	r.With(
		identityMiddleware("some-admin", true),
		middleware.ReadOwnership(store),
	).Get("/agents/{agentId}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/a1", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("admin should bypass ownership, got %d", rec.Code)
	}
}

// TestOwnership_RejectsMissingAgentID covers the empty agentID
// guard in the middleware. The router can't reach this branch
// (chi declines empty path segments), so we set up a chi route
// context with an empty agentId param and call the middleware
// chain directly via ServeHTTP.
func TestOwnership_RejectsMissingAgentID(t *testing.T) {
	t.Parallel()
	store := &fakeAgentStore{byID: map[string]*domain.AgentRegistration{}}

	chain := middleware.ReadOwnership(store)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("downstream handler should not run when agentID is empty")
	}))

	// Build a request with identity attached + empty chi agentId.
	identity := &port.Identity{Subject: "alice"}
	req := httptest.NewRequest(http.MethodGet, "/agents/", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("agentId", "")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422 for empty agentID", rec.Code)
	}
}

func TestOwnership_RejectsMissingIdentity(t *testing.T) {
	t.Parallel()
	store := &fakeAgentStore{byID: map[string]*domain.AgentRegistration{}}

	r := chi.NewRouter()
	r.With(middleware.ReadOwnership(store)).Get("/agents/{agentId}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/a1", nil))

	// No identity attached → 403 (NewUnauthorizedError).
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", rec.Code)
	}
}

// ----- helpers -----

func mkAgent(t *testing.T, id, ownerID, host string) *domain.AgentRegistration {
	t.Helper()
	semver, err := domain.ParseSemVer("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	an, err := domain.NewAnsName(semver, host)
	if err != nil {
		t.Fatal(err)
	}
	return &domain.AgentRegistration{
		AgentID: id,
		OwnerID: ownerID,
		AnsName: an,
		Status:  domain.StatusActive,
	}
}

// identityMiddleware attaches a fake Identity to the request context.
// In production the real auth middleware does this; here we synthesize
// a known-good identity so we can drive ownership tests directly.
func identityMiddleware(subject string, isAdmin bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := &port.Identity{Subject: subject, IsAdmin: isAdmin}
			ctx := auth.WithIdentity(r.Context(), id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ----- minimal fake AgentStore for ownership tests -----

type fakeAgentStore struct {
	byID map[string]*domain.AgentRegistration
}

func (f *fakeAgentStore) Save(_ context.Context, _ *domain.AgentRegistration) error { return nil }
func (f *fakeAgentStore) FindByID(_ context.Context, _ int64) (*domain.AgentRegistration, error) {
	return nil, domain.NewNotFoundError("AGENT_NOT_FOUND", "not found")
}
func (f *fakeAgentStore) FindByAgentID(_ context.Context, agentID string) (*domain.AgentRegistration, error) {
	if a, ok := f.byID[agentID]; ok {
		return a, nil
	}
	return nil, domain.NewNotFoundError("AGENT_NOT_FOUND", "not found")
}
func (f *fakeAgentStore) FindByAnsName(_ context.Context, _ domain.AnsName) (*domain.AgentRegistration, error) {
	return nil, domain.NewNotFoundError("AGENT_NOT_FOUND", "not found")
}
func (f *fakeAgentStore) ExistsByAnsName(_ context.Context, _ domain.AnsName) (bool, error) {
	return false, nil
}
func (f *fakeAgentStore) ExistsActiveBaseOnlyByAgentHost(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (f *fakeAgentStore) FindAllByAgentHost(_ context.Context, _ string) ([]*domain.AgentRegistration, error) {
	return nil, nil
}
func (f *fakeAgentStore) FindExistingByFQDN(_ context.Context, _ string) ([]*domain.AgentRegistration, error) {
	return nil, nil
}
func (f *fakeAgentStore) ListByOwner(_ context.Context, _ string, _ port.ListFilter) (*port.CursorPage[*domain.AgentRegistration], error) {
	return nil, nil
}
func (f *fakeAgentStore) Delete(_ context.Context, _ int64) error { return nil }

// Silence "unused" on timing imports the testbed may shed.
var _ = time.Now
