package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/ra/handler"
	"github.com/godaddy/ans/internal/ra/service"
)

type stubGen struct {
	body []byte
	err  error
}

func (s *stubGen) Generate(_ context.Context, _ string) ([]byte, error) {
	return s.body, s.err
}

// newAttRouter wires a chi router that mirrors how cmd/ans-ra/main.go
// will register the attestation route — minus the readOwnership
// middleware (anonymous per spec).
func newAttRouter(svc handler.AttestationGenerator) *chi.Mux {
	r := chi.NewRouter()
	h := handler.NewAttestationHandler(svc)
	r.Get("/v2/ans/agents/{agentId}/attestation", h.Get)
	return r
}

func do(t *testing.T, r *chi.Mux, path string) *http.Response {
	t.Helper()
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func TestAttestation_OK(t *testing.T) {
	t.Parallel()
	body := []byte{0xD2, 0x84, 0x40, 0xA0, 0x42, 'h', 'i', 0x40} // any binary
	resp := do(t, newAttRouter(&stubGen{body: body}),
		"/v2/ans/agents/11111111-2222-3333-4444-555555555555/attestation")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != service.AttestationMediaType {
		t.Errorf("Content-Type = %q, want %q", got, service.AttestationMediaType)
	}
	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length = %q, want %d", got, len(body))
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytesEqual(got, body) {
		t.Errorf("body mismatch")
	}
}

func TestAttestation_404AgentNotFound(t *testing.T) {
	t.Parallel()
	resp := do(t, newAttRouter(&stubGen{err: service.ErrAttestationAgentNotFound}),
		"/v2/ans/agents/00000000-0000-0000-0000-000000000000/attestation")
	defer resp.Body.Close()
	assertProblem(t, resp, http.StatusNotFound, "AGENT_NOT_FOUND")
}

func TestAttestation_410AgentRevoked(t *testing.T) {
	t.Parallel()
	resp := do(t, newAttRouter(&stubGen{err: service.ErrAttestationAgentRevoked}),
		"/v2/ans/agents/00000000-0000-0000-0000-000000000000/attestation")
	defer resp.Body.Close()
	assertProblem(t, resp, http.StatusGone, "AGENT_REVOKED")
}

func TestAttestation_503LeafUncommitted(t *testing.T) {
	t.Parallel()
	resp := do(t, newAttRouter(&stubGen{err: service.ErrAttestationLeafUncommitted}),
		"/v2/ans/agents/00000000-0000-0000-0000-000000000000/attestation")
	defer resp.Body.Close()
	assertProblem(t, resp, http.StatusServiceUnavailable, "TL_LEAF_UNCOMMITTED")
	if got := resp.Header.Get("Retry-After"); got == "" {
		t.Error("Retry-After missing on TL_LEAF_UNCOMMITTED")
	}
}

func TestAttestation_503TLNotReachable(t *testing.T) {
	t.Parallel()
	resp := do(t, newAttRouter(&stubGen{err: service.ErrAttestationTLNotReachable}),
		"/v2/ans/agents/00000000-0000-0000-0000-000000000000/attestation")
	defer resp.Body.Close()
	assertProblem(t, resp, http.StatusServiceUnavailable, "TL_NOT_REACHABLE")
	if got := resp.Header.Get("Retry-After"); got == "" {
		t.Error("Retry-After missing on TL_NOT_REACHABLE")
	}
}

func TestAttestation_500OnUnknownError(t *testing.T) {
	t.Parallel()
	resp := do(t, newAttRouter(&stubGen{err: errors.New("unexpected: hsm offline")}),
		"/v2/ans/agents/00000000-0000-0000-0000-000000000000/attestation")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

// assertProblem decodes the body as a Problem and checks status + code.
func assertProblem(t *testing.T, resp *http.Response, wantStatus int, wantCode string) {
	t.Helper()
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d", resp.StatusCode, wantStatus)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var p handler.Problem
	_ = json.NewDecoder(resp.Body).Decode(&p)
	if p.Code != wantCode {
		t.Errorf("code = %q, want %q", p.Code, wantCode)
	}
	if p.Status != wantStatus {
		t.Errorf("body.status = %d, want %d", p.Status, wantStatus)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
