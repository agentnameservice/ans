package domain

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainError_Error(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		e := NewValidationError("BAD", "bad input")
		assert.Contains(t, e.Error(), "BAD")
		assert.Contains(t, e.Error(), "bad input")
		assert.Contains(t, e.Error(), "validation")
	})

	t.Run("without cause", func(t *testing.T) {
		e := &Error{Code: "X", Message: "m"}
		assert.Equal(t, "X: m", e.Error())
	})
}

func TestDomainError_Unwrap(t *testing.T) {
	e := NewValidationError("BAD", "bad input")
	assert.ErrorIs(t, e, ErrValidation)

	nf := NewNotFoundError("X", "x")
	assert.ErrorIs(t, nf, ErrNotFound)

	c := NewConflictError("X", "x")
	assert.ErrorIs(t, c, ErrConflict)

	is := NewInvalidStateError("X", "x")
	assert.ErrorIs(t, is, ErrInvalidState)

	ce := NewCertificateError("X", "x")
	assert.ErrorIs(t, ce, ErrCertificate)

	u := NewUnauthorizedError("X", "x")
	assert.ErrorIs(t, u, ErrUnauthorized)

	ua := NewUnavailableError("X", "x")
	assert.ErrorIs(t, ua, ErrUnavailable)
}

func TestNewInternalError_WrapsCause(t *testing.T) {
	cause := errors.New("sql dead")
	e := NewInternalError("DB", "database failure", cause)
	assert.ErrorIs(t, e, ErrInternal)
	assert.ErrorIs(t, e, cause)
}
