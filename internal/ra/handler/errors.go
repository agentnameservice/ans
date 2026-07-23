// Package handler contains the HTTP-facing adapters for the RA V2 API.
// Handlers map between OpenAPI JSON DTOs and the service-layer domain
// types. Errors are surfaced as RFC 7807 Problem Details.
package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/domain"
)

// Problem is the RFC 7807 response body for errors.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code,omitempty"`
}

// responder is the shared error/JSON response seam embedded by every RA
// handler. It carries the logger used to record the real cause of an
// unexpected (non-domain) 500 server-side.
//
// Why a shared embedded seam rather than a free function: the 500
// response detail is sanitized to a fixed generic string so internal
// fault text (storage errors, paths) never leaks to clients — including
// anonymous ones on the events feed. That sanitization would otherwise
// SWALLOW the cause entirely, because the RA has no request-logging
// middleware and the request-path service layer does not log. Routing
// every error through responder.writeError makes "log the cause before
// hiding it" enforced by construction: a handler embeds responder and
// calls h.writeError, so it cannot emit a sanitized 500 without the
// cause being logged. One logger is injected (newResponder) and shared
// by every handler via embedding.
type responder struct {
	logger zerolog.Logger
}

// newResponder builds the shared responder. A zero-value zerolog.Logger
// is a valid silent logger, so tests can embed responder{} directly.
func newResponder(logger zerolog.Logger) responder {
	return responder{logger: logger.With().Str("component", "ra-handler").Logger()}
}

// WriteJSON writes value as JSON with the given status. Pure response
// writer — success payloads carry no error to log.
func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

// writeError maps err to an RFC 7807 Problem and writes it. A
// *domain.Error carries a caller-safe Message and is surfaced verbatim.
// Any other error is an unexpected fault: the client gets a fixed
// generic 500 detail (no internal text), and the real cause is logged
// here at ERROR so it is never swallowed. This is the error response
// path every handler uses (handlers embed responder).
func (re responder) writeError(w http.ResponseWriter, err error) {
	p := mapError(err)
	if p.Status >= http.StatusInternalServerError {
		// Non-domain fault — the client-facing detail is sanitized to a
		// generic string, so record the real cause server-side or it is
		// lost entirely (the RA has no request-logging middleware).
		re.logger.Error().Err(err).Int("status", p.Status).Msg("request failed with internal error")
	}
	writeProblem(w, p)
}

// WriteError writes an RFC 7807 Problem for a caller-safe error. It is
// the entry point for callers OUTSIDE the handler package — currently
// only the ownership middleware, which constructs *domain.Error values
// inline. It does NOT log: a *domain.Error carries no internal detail,
// and these callers never pass an unexpected (non-domain) error. The
// general handler path uses responder.writeError, which logs the cause
// of a non-domain 500. WriteError still sanitizes the 500 branch, so
// even a misuse cannot leak internal text — it would only fail to log.
func WriteError(w http.ResponseWriter, err error) {
	writeProblem(w, mapError(err))
}

// writeProblem serializes a Problem as application/problem+json.
func writeProblem(w http.ResponseWriter, p Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// genericInternalDetail is the fixed 500 detail returned for unexpected
// (non-domain) errors so internal fault text never reaches the client.
const genericInternalDetail = "An internal error occurred."

func mapError(err error) Problem {
	var de *domain.Error
	if errors.As(err, &de) {
		return Problem{
			Type:   "about:blank",
			Title:  titleForCause(de.Cause),
			Status: statusForCause(de.Cause),
			Detail: de.Message,
			Code:   de.Code,
		}
	}
	return Problem{
		Type:   "about:blank",
		Title:  "Internal Server Error",
		Status: http.StatusInternalServerError,
		Detail: genericInternalDetail,
	}
}

func statusForCause(cause error) int {
	switch {
	case errors.Is(cause, domain.ErrValidation):
		return http.StatusUnprocessableEntity
	case errors.Is(cause, domain.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(cause, domain.ErrConflict):
		return http.StatusConflict
	case errors.Is(cause, domain.ErrInvalidState):
		return http.StatusConflict
	case errors.Is(cause, domain.ErrCertificate):
		return http.StatusUnprocessableEntity
	case errors.Is(cause, domain.ErrUnauthorized):
		return http.StatusForbidden
	case errors.Is(cause, domain.ErrUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func titleForCause(cause error) string {
	switch {
	case errors.Is(cause, domain.ErrValidation):
		return "Validation Failed"
	case errors.Is(cause, domain.ErrNotFound):
		return "Not Found"
	case errors.Is(cause, domain.ErrConflict):
		return "Conflict"
	case errors.Is(cause, domain.ErrInvalidState):
		return "Invalid State"
	case errors.Is(cause, domain.ErrCertificate):
		return "Certificate Error"
	case errors.Is(cause, domain.ErrUnauthorized):
		return "Forbidden"
	case errors.Is(cause, domain.ErrUnavailable):
		return "Service Unavailable"
	default:
		return "Internal Server Error"
	}
}
