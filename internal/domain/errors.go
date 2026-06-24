// Package domain contains the pure domain model for the Agent Name Service.
// It has zero external dependencies — no framework, no database, no HTTP.
package domain

import (
	"errors"
	"fmt"
)

// Sentinel errors for broad error classification.
var (
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrInvalidState = errors.New("invalid state")
	ErrValidation   = errors.New("validation")
	ErrUnauthorized = errors.New("unauthorized")
	ErrCertificate  = errors.New("certificate")
	ErrInternal     = errors.New("internal")
	// ErrUnavailable marks a transient upstream failure: the request
	// was valid but a dependency (the TL, the vlei-verifier) could
	// not confirm it. Maps to 503; the operation is retryable and no
	// state was consumed.
	ErrUnavailable = errors.New("unavailable")
)

// Error is the base error type for all domain errors.
// It wraps a sentinel error for type-based classification and
// carries a machine-readable code and human-readable message.
type Error struct {
	// Code is a machine-readable error code (e.g., "INVALID_ANS_NAME").
	Code string
	// Message is a human-readable description.
	Message string
	// Cause is the underlying sentinel or wrapped error.
	Cause error
}

// NewValidationError creates a validation domain error.
func NewValidationError(code, message string) *Error {
	return &Error{Code: code, Message: message, Cause: ErrValidation}
}

// NewNotFoundError creates a not-found domain error.
func NewNotFoundError(code, message string) *Error {
	return &Error{Code: code, Message: message, Cause: ErrNotFound}
}

// NewConflictError creates a conflict domain error.
func NewConflictError(code, message string) *Error {
	return &Error{Code: code, Message: message, Cause: ErrConflict}
}

// NewInvalidStateError creates an invalid-state domain error.
func NewInvalidStateError(code, message string) *Error {
	return &Error{Code: code, Message: message, Cause: ErrInvalidState}
}

// NewCertificateError creates a certificate domain error.
func NewCertificateError(code, message string) *Error {
	return &Error{Code: code, Message: message, Cause: ErrCertificate}
}

// NewUnauthorizedError creates an unauthorized domain error.
func NewUnauthorizedError(code, message string) *Error {
	return &Error{Code: code, Message: message, Cause: ErrUnauthorized}
}

// NewInternalError creates an internal domain error wrapping a cause.
func NewInternalError(code, message string, cause error) *Error {
	return &Error{Code: code, Message: message, Cause: fmt.Errorf("%w: %w", ErrInternal, cause)}
}

// NewUnavailableError creates a retryable upstream-unavailable error.
func NewUnavailableError(code, message string) *Error {
	return &Error{Code: code, Message: message, Cause: ErrUnavailable}
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *Error) Unwrap() error {
	return e.Cause
}
