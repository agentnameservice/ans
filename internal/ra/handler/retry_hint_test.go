package handler

import (
	"github.com/agentnameservice/ans/internal/domain"
	"net/http/httptest"
	"testing"
)

func TestRetryHintIsHeaderNotResponseField(t *testing.T) {
	rec := httptest.NewRecorder()
	err := domain.NewUnavailableError("CERT_PROVIDER_THROTTLED", "retry later")
	err.RetryAfter = "120"
	WriteError(rec, err)
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "120" {
		t.Fatalf("retry response: %d %v", rec.Code, rec.Header())
	}
	other := httptest.NewRecorder()
	err.Cause = domain.ErrConflict
	WriteError(other, err)
	if other.Header().Get("Retry-After") != "" {
		t.Fatal("retry hint attached to nonretryable response")
	}
}
