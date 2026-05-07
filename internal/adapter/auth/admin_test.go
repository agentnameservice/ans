package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/godaddy/ans/internal/adapter/auth"
	"github.com/godaddy/ans/internal/port"
)

// downstream is a no-op handler that writes 204 so tests can
// distinguish "middleware let the request through" from "middleware
// short-circuited".
func downstream() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestRequireAdmin_NoIdentity(t *testing.T) {
	h := auth.RequireAdmin()(downstream())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/thing", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401", rec.Code)
	}
	var prob struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	if prob.Code != "UNAUTHORIZED" {
		t.Errorf("code: got %q, want UNAUTHORIZED", prob.Code)
	}
}

func TestRequireAdmin_NotAdmin(t *testing.T) {
	h := auth.RequireAdmin()(downstream())
	req := httptest.NewRequest(http.MethodGet, "/admin/thing", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), &port.Identity{
		Subject: "user-1",
		Scopes:  []string{"ans:read"},
		IsAdmin: false,
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403", rec.Code)
	}
	var prob struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if prob.Code != "ACCESS_DENIED" {
		t.Errorf("code: got %q, want ACCESS_DENIED", prob.Code)
	}
}

func TestRequireAdmin_Allowed(t *testing.T) {
	h := auth.RequireAdmin()(downstream())
	req := httptest.NewRequest(http.MethodGet, "/admin/thing", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), &port.Identity{
		Subject: "admin-1",
		IsAdmin: true,
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204 (downstream)", rec.Code)
	}
}
