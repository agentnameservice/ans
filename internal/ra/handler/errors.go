// Package handler contains the HTTP-facing adapters for the RA V2 API.
// Handlers map between OpenAPI JSON DTOs and the service-layer domain
// types. Errors are surfaced as RFC 7807 Problem Details.
package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/godaddy/ans/internal/domain"
)

// Problem is the RFC 7807 response body for errors.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code,omitempty"`
}

// WriteJSON writes value as JSON with the given status.
func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

// WriteError maps a domain error to an RFC 7807 Problem response.
// Unknown errors produce 500; known sentinel errors map to specific
// statuses. Error messages are safe to include in responses because
// the domain layer never embeds internal details in Error.Message.
func WriteError(w http.ResponseWriter, err error) {
	p := mapError(err)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

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
		Detail: err.Error(),
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
