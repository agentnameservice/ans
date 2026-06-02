package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/ra/service"
)

// AttestationGenerator is the seam the handler depends on — the
// minimal surface of service.AttestationService a test can stub
// without standing up four storage adapters.
type AttestationGenerator interface {
	Generate(ctx context.Context, agentID string) ([]byte, error)
}

// AttestationHandler serves GET /v2/ans/agents/{agentId}/attestation.
// Anonymous read per spec — the attestation IS the document a third-
// party verifier fetches to verify an agent.
type AttestationHandler struct {
	svc AttestationGenerator
}

// NewAttestationHandler wires the handler to its service.
func NewAttestationHandler(svc AttestationGenerator) *AttestationHandler {
	return &AttestationHandler{svc: svc}
}

// Get implements GET /v2/ans/agents/{agentId}/attestation.
//
// Response shape per spec/api-spec-v2.yaml § /ans/agents/{agentId}/attestation:
//
//   - 200 application/cose         — binary COSE_Sign1 body.
//     Cache-Control: public, max-age=3600.
//   - 404 application/problem+json — AGENT_NOT_FOUND.
//   - 410 application/problem+json — AGENT_REVOKED.
//   - 503 application/problem+json — TL_LEAF_UNCOMMITTED (with Retry-After)
//     or TL_NOT_REACHABLE.
//
// Cache-Control max-age matches the COSE payload's `exp` lifetime so
// HTTP intermediaries and the cryptographic expiry decay together —
// a CDN can't serve a stale attestation past its signed expiry.
func (h *AttestationHandler) Get(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		WriteError(w, errors.New("agentId path parameter is required"))
		return
	}

	cose, err := h.svc.Generate(r.Context(), agentID)
	if err != nil {
		h.writeAttestationError(w, err)
		return
	}

	w.Header().Set("Content-Type", service.AttestationMediaType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Length", strconv.Itoa(len(cose)))
	w.WriteHeader(http.StatusOK)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	// Binary COSE_Sign1 body (application/cose); not HTML, no user-controlled input.
	_, _ = w.Write(cose) //nolint:gosec // G705: binary COSE body, no XSS surface
}

// writeAttestationError maps service sentinels to the spec's wire
// shape. Kept separate from WriteError because the attestation
// surface has its own status-code vocabulary (410 for revoked, 503
// with structured codes for TL state) that the generic domain
// error mapper doesn't cover.
func (h *AttestationHandler) writeAttestationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrAttestationAgentNotFound):
		writeProblem(w, http.StatusNotFound, "Agent Not Found", "AGENT_NOT_FOUND",
			"no registration exists for the given agentId", nil)
	case errors.Is(err, service.ErrAttestationAgentRevoked):
		writeProblem(w, http.StatusGone, "Agent Revoked", "AGENT_REVOKED",
			"the agent's registration has been revoked", nil)
	case errors.Is(err, service.ErrAttestationLeafUncommitted):
		writeProblem(w, http.StatusServiceUnavailable,
			"Transparency Log Inclusion Pending", "TL_LEAF_UNCOMMITTED",
			"the registration event has been appended but no signed checkpoint yet covers it; retry after Retry-After",
			map[string]string{"Retry-After": "2"})
	case errors.Is(err, service.ErrAttestationTLNotReachable):
		writeProblem(w, http.StatusServiceUnavailable,
			"Transparency Log Unreachable", "TL_NOT_REACHABLE",
			"the configured transparency log is not currently reachable",
			map[string]string{"Retry-After": "10"})
	default:
		// Fall through to the generic mapper; any other error from
		// the service is operational (cert lookup failure, key sign
		// failure, etc.) and surfaces as 500.
		WriteError(w, err)
	}
}

// writeProblem emits an RFC 7807 problem-details response with
// optional response headers (used for Retry-After on 503s).
func writeProblem(w http.ResponseWriter, status int, title, code, detail string, extraHeaders map[string]string) {
	for k, v := range extraHeaders {
		w.Header().Set(k, v)
	}
	WriteJSON(w, status, Problem{
		Type:   ProblemTypeBlank,
		Title:  title,
		Status: status,
		Code:   code,
		Detail: detail,
	})
}
