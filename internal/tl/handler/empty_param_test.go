package handler_test

// Drives the "empty path-param" branch of every handler that has a
// chi.URLParam(...)-based early-return guard. These can't be hit
// through the router (chi declines to bind an empty path segment),
// but they're production guards for direct ServeHTTP calls (tests,
// programmatic dispatch, future RPC wrappers). Pre-coverage these
// guards sat at 50% — the chi-routed case covered, the empty case
// dark.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/tl/handler"
	"github.com/godaddy/ans/internal/tl/producerkey"
)

// emptyParamReq builds a request with a chi route context whose
// agentId param is the empty string. Reaches handlers' early-exit
// guards without going through the router.
func emptyParamReq(method, path string, paramKey string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(paramKey, "")
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestGetBadge_EmptyAgentID(t *testing.T) {
	t.Parallel()
	// Build a Handlers with all services nil; the empty-agentID guard
	// fires before any service is touched.
	h := handler.NewHandlers(nil, nil, nil, nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.GetBadge(rec, emptyParamReq(http.MethodGet, "/v1/agents/", "agentId"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422", rec.Code)
	}
}

func TestGetAudit_EmptyAgentID(t *testing.T) {
	t.Parallel()
	h := handler.NewHandlers(nil, nil, nil, nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.GetAudit(rec, emptyParamReq(http.MethodGet, "/v1/agents//audit", "agentId"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422", rec.Code)
	}
}

func TestGetReceipt_EmptyAgentID(t *testing.T) {
	t.Parallel()
	h := handler.NewHandlers(nil, nil, nil, nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.GetReceipt(rec, emptyParamReq(http.MethodGet, "/v1/agents//receipt", "agentId"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422", rec.Code)
	}
}

// TestGetStatusToken_DisabledReturns501 covers the
// "h.statusToken == nil" branch — production deployments that
// don't want to hold a third signing key leave the service
// unwired and clients see 501 rather than a misleading 500.
func TestGetStatusToken_DisabledReturns501(t *testing.T) {
	t.Parallel()
	h := handler.NewHandlers(nil, nil, nil, nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.GetStatusToken(rec, emptyParamReq(http.MethodGet, "/v1/agents/x/status-token", "agentId"))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status: got %d want 501", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("content-type: got %q want application/problem+json", got)
	}
}

// TestGetCheckpointJSON_DisabledReturnsInternal covers the
// "h.checkpoint == nil" branch.
func TestGetCheckpointJSON_DisabledReturnsInternal(t *testing.T) {
	t.Parallel()
	h := handler.NewHandlers(nil, nil, nil, nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.GetCheckpointJSON(rec, httptest.NewRequest(http.MethodGet, "/v1/log/checkpoint", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d want 500", rec.Code)
	}
}

// TestGetCheckpointHistory_DisabledReturnsInternal mirrors the
// same guard on the history route.
func TestGetCheckpointHistory_DisabledReturnsInternal(t *testing.T) {
	t.Parallel()
	h := handler.NewHandlers(nil, nil, nil, nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.GetCheckpointHistory(rec, httptest.NewRequest(http.MethodGet, "/v1/log/checkpoint/history", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d want 500", rec.Code)
	}
}

// TestGetSchema_DisabledReturnsInternal covers the
// "h.schema == nil" branch.
func TestGetSchema_DisabledReturnsInternal(t *testing.T) {
	t.Parallel()
	h := handler.NewHandlers(nil, nil, nil, nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.GetSchema(rec, emptyParamReq(http.MethodGet, "/v1/log/schema/V2", "version"))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d want 500", rec.Code)
	}
}

// ----- Admin producer-key handler empty-id guards -----
//
// Each admin handler has a chi.URLParam(...)-derived empty-id guard
// the router can't reach (chi declines empty path segments). Drive
// each one directly to lift coverage on those guards.

// adminHandlersWithNilStore builds an AdminHandlers whose keys field
// is nil; the empty-id guard at the top of each handler fires before
// the store is touched.
func adminHandlersWithNilStore() *handler.AdminHandlers {
	return handler.NewAdminHandlers(nil)
}

func TestAdmin_ListByRAID_EmptyID(t *testing.T) {
	t.Parallel()
	h := adminHandlersWithNilStore()
	rec := httptest.NewRecorder()
	h.ListByRAID(rec, emptyParamReq(http.MethodGet, "/internal/v1/producer-keys/ra/", "ra_id"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422", rec.Code)
	}
}

func TestAdmin_GetByKeyID_EmptyID(t *testing.T) {
	t.Parallel()
	h := adminHandlersWithNilStore()
	rec := httptest.NewRecorder()
	h.GetByKeyID(rec, emptyParamReq(http.MethodGet, "/internal/v1/producer-keys/", "key_id"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422", rec.Code)
	}
}

func TestAdmin_RevokeKey_EmptyID(t *testing.T) {
	t.Parallel()
	h := adminHandlersWithNilStore()
	rec := httptest.NewRecorder()
	h.RevokeKey(rec, emptyParamReq(http.MethodDelete, "/internal/v1/producer-keys/", "key_id"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422", rec.Code)
	}
}

// ----- Admin handler non-NotFound error paths -----
//
// The not-found branches for GetByKeyID / RevokeKey are tested via
// the integration tests' double-revoke / nonexistent-key paths.
// The "non-NotFound store error" branch — covering arbitrary
// storage failures — is not. Drive it with a fake store.

// failingAdminStore returns a configurable error from every method.
// Used to drive the non-NotFound error branch in admin handlers.
type failingAdminStore struct {
	err error
}

func (f *failingAdminStore) Get(_ context.Context, _, _ string) (string, error) {
	return "", f.err
}

func (f *failingAdminStore) Register(_ context.Context, _ producerkey.Entry) (*producerkey.Record, error) {
	return nil, f.err
}

func (f *failingAdminStore) Revoke(_ context.Context, _ string) error {
	return f.err
}

func (f *failingAdminStore) GetByKeyID(_ context.Context, _ string) (*producerkey.Record, error) {
	return nil, f.err
}

func (f *failingAdminStore) ListByRAID(_ context.Context, _ string) ([]*producerkey.Record, error) {
	return nil, f.err
}

func TestAdmin_GetByKeyID_NonNotFoundError(t *testing.T) {
	t.Parallel()
	store := &failingAdminStore{err: errors.New("storage on fire")}
	h := handler.NewAdminHandlers(store)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/producer-keys/some-key", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("key_id", "some-key")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.GetByKeyID(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d want 500", rec.Code)
	}
}

func TestAdmin_RevokeKey_NonNotFoundError(t *testing.T) {
	t.Parallel()
	store := &failingAdminStore{err: errors.New("storage on fire")}
	h := handler.NewAdminHandlers(store)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/internal/v1/producer-keys/some-key", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("key_id", "some-key")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.RevokeKey(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d want 500", rec.Code)
	}
}

// TestAppendEvent_BadBodyReturns422 covers the BAD_BODY branch in
// appendEvent when ReadAll fails with a non-MaxBytesError. Plug an
// erroring io.Reader into the request body to trigger.
func TestAppendEvent_BadBodyReturns422(t *testing.T) {
	t.Parallel()
	tb := newTLTestbed(t)
	req := httptest.NewRequest(http.MethodPost, "/v2/internal/agents/event",
		erroringReader{err: errors.New("simulated I/O failure")})
	req.Header.Set("X-Signature", "doesnt.matter.for.this.test")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	tb.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("status: got %d want 422; body=%s", rec.Code, rec.Body)
	}
}

// erroringReader implements io.Reader and io.Closer; every Read
// returns the configured error so the handler's ReadAll fails.
type erroringReader struct {
	err error
}

func (r erroringReader) Read(_ []byte) (int, error) { return 0, r.err }
func (r erroringReader) Close() error               { return nil }

func TestAdmin_ListByRAID_NonNotFoundError(t *testing.T) {
	t.Parallel()
	store := &failingAdminStore{err: errors.New("storage on fire")}
	h := handler.NewAdminHandlers(store)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/producer-keys/ra/some-ra", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("ra_id", "some-ra")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	h.ListByRAID(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status: got %d want 500", rec.Code)
	}
}
