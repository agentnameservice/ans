package handler_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
	"github.com/godaddy/ans/internal/tl/handler"
)

// adminRouter wires just the admin handlers against a fresh :memory:
// SQLite-backed store. Keeps admin tests independent of the
// append/badge/receipt testbed.
func adminRouter(t *testing.T) (chi.Router, *sqlitetl.ProducerKeyStore) {
	t.Helper()
	db, err := sqlitetl.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlitetl.NewProducerKeyStore(db)

	r := chi.NewRouter()
	h := handler.NewAdminHandlers(store)
	h.Mount(r)
	return r, store
}

// adminTestPEM returns a fresh ES256 public-key PEM. Each call returns
// a different key; callers that care about stability should call once.
func adminTestPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(k.Public())
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// basicCreateBody returns a snake_case ProducerKeyRequest body with
// sensible defaults. Callers override any field.
func basicCreateBody(t *testing.T, keyID, raID string) map[string]any {
	return map[string]any{
		"key_id":         keyID,
		"ra_id":          raID,
		"algorithm":      "ES256",
		"public_key_pem": adminTestPEM(t),
		"valid_from":     time.Now().UTC().Format(time.RFC3339),
		"expires_at":     time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}
}

func TestAdmin_CreateKey_200(t *testing.T) {
	r, _ := adminRouter(t)

	body := basicCreateBody(t, "ra-test-key-1", "ra-test-1")
	body["metadata"] = map[string]any{"environment": "local", "region": "na"}

	rec := doAdmin(r, http.MethodPost, "/internal/v1/producer-keys", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", rec.Code, rec.Body)
	}
	// Reference response shape (ProducerKeyResponse §1411):
	// {key_id, status, fingerprint, created_at, ...}
	var resp struct {
		KeyID       string `json:"key_id"`
		Status      string `json:"status"`
		Fingerprint string `json:"fingerprint"`
		CreatedAt   string `json:"created_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.KeyID != "ra-test-key-1" {
		t.Errorf("key_id: got %q", resp.KeyID)
	}
	if resp.Status != "active" {
		t.Errorf("status: got %q, want active", resp.Status)
	}
	if resp.Fingerprint == "" {
		t.Error("fingerprint missing")
	}
	if resp.CreatedAt == "" {
		t.Error("created_at missing")
	}
}

func TestAdmin_CreateKey_Duplicate_409(t *testing.T) {
	r, _ := adminRouter(t)

	body := basicCreateBody(t, "dup-1", "ra-1")
	if rec := doAdmin(r, http.MethodPost, "/internal/v1/producer-keys", body); rec.Code != http.StatusOK {
		t.Fatalf("first POST: got %d", rec.Code)
	}
	body["public_key_pem"] = adminTestPEM(t)
	rec := doAdmin(r, http.MethodPost, "/internal/v1/producer-keys", body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second POST: got %d, want 409; body=%s", rec.Code, rec.Body)
	}
	assertProblemCode(t, rec, "PRODUCER_KEY_EXISTS")
}

func TestAdmin_CreateKey_InvalidRange_422(t *testing.T) {
	r, _ := adminRouter(t)

	now := time.Now().UTC()
	body := basicCreateBody(t, "bad-range", "ra-1")
	body["valid_from"] = now.Add(24 * time.Hour).Format(time.RFC3339)
	body["expires_at"] = now.Format(time.RFC3339)

	rec := doAdmin(r, http.MethodPost, "/internal/v1/producer-keys", body)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d, want 422; body=%s", rec.Code, rec.Body)
	}
	assertProblemCode(t, rec, "INVALID_DATE_RANGE")
}

func TestAdmin_CreateKey_BadJSON_422(t *testing.T) {
	r, _ := adminRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/producer-keys",
		bytes.NewReader([]byte("{not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d, want 422", rec.Code)
	}
	assertProblemCode(t, rec, "BAD_JSON")
}

func TestAdmin_CreateKey_BadPEM_422(t *testing.T) {
	r, _ := adminRouter(t)

	body := basicCreateBody(t, "bad-pem", "ra-1")
	body["public_key_pem"] = "not a pem"

	rec := doAdmin(r, http.MethodPost, "/internal/v1/producer-keys", body)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d, want 422; body=%s", rec.Code, rec.Body)
	}
	assertProblemCode(t, rec, "INVALID_PUBLIC_KEY_PEM")
}

func TestAdmin_ListByRAID(t *testing.T) {
	r, _ := adminRouter(t)

	for i, args := range []struct{ ra, kid string }{
		{"ra-one", "k1"},
		{"ra-one", "k2"},
		{"ra-two", "k3"},
	} {
		body := basicCreateBody(t, args.kid, args.ra)
		body["valid_from"] = time.Now().Add(time.Duration(i) * time.Second).UTC().Format(time.RFC3339)
		if rec := doAdmin(r, http.MethodPost, "/internal/v1/producer-keys", body); rec.Code != http.StatusOK {
			t.Fatalf("seed %d: got %d", i, rec.Code)
		}
	}

	// ra-one → two keys.
	rec := doAdmin(r, http.MethodGet, "/internal/v1/producer-keys/ra/ra-one", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list ra-one: got %d", rec.Code)
	}
	var resp struct {
		Keys       []map[string]any `json:"keys"`
		TotalCount int64            `json:"total_count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.TotalCount != 2 || len(resp.Keys) != 2 {
		t.Errorf("ra-one list: total_count=%d len=%d want 2/2", resp.TotalCount, len(resp.Keys))
	}

	// Unknown ra_id → 404 (matches reference §874: "No producer keys found for this RA ID").
	rec = doAdmin(r, http.MethodGet, "/internal/v1/producer-keys/ra/ra-nonexistent", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown ra_id: got %d, want 404", rec.Code)
	}
	assertProblemCode(t, rec, "NOT_FOUND")
}

func TestAdmin_GetByKeyID(t *testing.T) {
	r, _ := adminRouter(t)

	body := basicCreateBody(t, "get-me", "ra-1")
	if rec := doAdmin(r, http.MethodPost, "/internal/v1/producer-keys", body); rec.Code != http.StatusOK {
		t.Fatalf("seed: got %d", rec.Code)
	}

	rec := doAdmin(r, http.MethodGet, "/internal/v1/producer-keys/get-me", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: got %d", rec.Code)
	}

	rec = doAdmin(r, http.MethodGet, "/internal/v1/producer-keys/nope", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get nonexistent: got %d, want 404", rec.Code)
	}
	assertProblemCode(t, rec, "NOT_FOUND")
}

func TestAdmin_Revoke(t *testing.T) {
	r, _ := adminRouter(t)

	body := basicCreateBody(t, "revoke-me", "ra-1")
	if rec := doAdmin(r, http.MethodPost, "/internal/v1/producer-keys", body); rec.Code != http.StatusOK {
		t.Fatalf("seed: got %d", rec.Code)
	}

	rec := doAdmin(r, http.MethodDelete, "/internal/v1/producer-keys/revoke-me", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: got %d, want 204", rec.Code)
	}

	rec = doAdmin(r, http.MethodGet, "/internal/v1/producer-keys/revoke-me", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get after revoke: got %d", rec.Code)
	}
	var resp struct {
		Status    string `json:"status"`
		RevokedAt string `json:"revoked_at"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "revoked" {
		t.Errorf("status: got %q, want revoked", resp.Status)
	}
	if resp.RevokedAt == "" {
		t.Error("revoked_at not populated")
	}

	rec = doAdmin(r, http.MethodDelete, "/internal/v1/producer-keys/revoke-me", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("double revoke: got %d, want 404", rec.Code)
	}
}

// ----- helpers -----

// doAdmin POSTs/GETs/DELETEs a JSON body against the admin router and
// returns the response recorder. body=nil sends no body.
func doAdmin(r chi.Router, method, path string, body any) *httptest.ResponseRecorder {
	var buf *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewReader(b)
	} else {
		buf = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// assertProblemCode reads an RFC 7807 problem+json body and asserts
// the `code` matches. Fails the test (not skip) so call sites with
// wrong expectations surface loudly.
func assertProblemCode(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	var prob struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &prob); err != nil {
		t.Fatalf("problem+json parse: %v body=%s", err, rec.Body)
	}
	if prob.Code != want {
		t.Fatalf("problem code: got %q, want %q (full body: %s)", prob.Code, want, rec.Body)
	}
}
