package handler

import (
	"errors"
	"net/http"
	"testing"

	"github.com/agentnameservice/ans/internal/domain"
)

// TestStatusAndTitleForCause pins the sentinel→HTTP mapping table,
// including the seal-before-success 503 (ErrUnavailable: retryable,
// nothing consumed) and the unknown-error fallthrough.
func TestStatusAndTitleForCause(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cause  error
		status int
		title  string
	}{
		{domain.ErrValidation, http.StatusUnprocessableEntity, "Validation Failed"},
		{domain.ErrNotFound, http.StatusNotFound, "Not Found"},
		{domain.ErrConflict, http.StatusConflict, "Conflict"},
		{domain.ErrInvalidState, http.StatusConflict, "Invalid State"},
		{domain.ErrCertificate, http.StatusUnprocessableEntity, "Certificate Error"},
		{domain.ErrUnauthorized, http.StatusForbidden, "Forbidden"},
		{domain.ErrUnavailable, http.StatusServiceUnavailable, "Service Unavailable"},
		{errors.New("mystery"), http.StatusInternalServerError, "Internal Server Error"},
	}
	for _, tc := range cases {
		if got := statusForCause(tc.cause); got != tc.status {
			t.Errorf("status(%v) = %d, want %d", tc.cause, got, tc.status)
		}
		if got := titleForCause(tc.cause); got != tc.title {
			t.Errorf("title(%v) = %q, want %q", tc.cause, got, tc.title)
		}
	}
}
