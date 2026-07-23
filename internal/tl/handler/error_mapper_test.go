package handler

// Direct unit tests for the problem-mapper helpers in handler.go.
// statusForCause and titleForCause both contain a five-case switch
// that the integration tests hit only on the validation branch
// (the others require the service layer to surface the matching
// domain.Err* sentinel). Pinning every case here lets a future
// refactor reorder the switch without dropping a status code.

import (
	"errors"
	"net/http"
	"testing"

	"github.com/agentnameservice/ans/internal/domain"
)

func TestStatusForCause_AllArms(t *testing.T) {
	cases := map[error]int{
		domain.ErrValidation:        http.StatusUnprocessableEntity,
		domain.ErrNotFound:          http.StatusNotFound,
		domain.ErrConflict:          http.StatusConflict,
		domain.ErrInvalidState:      http.StatusConflict,
		domain.ErrUnauthorized:      http.StatusForbidden,
		errors.New("anything else"): http.StatusInternalServerError,
	}
	for cause, want := range cases {
		if got := statusForCause(cause); got != want {
			t.Errorf("statusForCause(%v): got %d want %d", cause, got, want)
		}
	}
}

func TestTitleForCause_AllArms(t *testing.T) {
	cases := map[error]string{
		domain.ErrValidation:   "Validation Failed",
		domain.ErrNotFound:     "Not Found",
		domain.ErrConflict:     "Conflict",
		domain.ErrInvalidState: "Invalid State",
		domain.ErrUnauthorized: "Forbidden",
		errors.New("anything"): "Internal Server Error",
	}
	for cause, want := range cases {
		if got := titleForCause(cause); got != want {
			t.Errorf("titleForCause(%v): got %q want %q", cause, got, want)
		}
	}
}

// TestMapError_PassthroughForNonDomainError covers the second arm
// of mapError: an unwrapped error that doesn't match the domain.Error
// type returns a generic Internal Server Error problem.
func TestMapError_PassthroughForNonDomainError(t *testing.T) {
	p := mapError(errors.New("rogue error"))
	if p.Status != http.StatusInternalServerError {
		t.Errorf("status: got %d want %d", p.Status, http.StatusInternalServerError)
	}
	if p.Title != "Internal Server Error" {
		t.Errorf("title: got %q", p.Title)
	}
	if p.Detail == "" {
		t.Error("detail should pass through")
	}
}

// TestMapError_DomainErrorWiresThroughTitleStatus covers the first
// arm of mapError: a domain.Error wrapped error gets its title and
// status from the cause-mapping helpers, and its Code passes through.
func TestMapError_DomainErrorWiresThroughTitleStatus(t *testing.T) {
	in := domain.NewNotFoundError("AGENT_MISSING", "no such agent")
	p := mapError(in)
	if p.Status != http.StatusNotFound {
		t.Errorf("status: got %d want 404", p.Status)
	}
	if p.Title != "Not Found" {
		t.Errorf("title: got %q want Not Found", p.Title)
	}
	if p.Code != "AGENT_MISSING" {
		t.Errorf("code: got %q want AGENT_MISSING", p.Code)
	}
	if p.Detail != "no such agent" {
		t.Errorf("detail: got %q", p.Detail)
	}
}
