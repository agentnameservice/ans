package handler

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/rs/zerolog"
)

func TestProviderThrottlingIsLoggedAsUnavailable(t *testing.T) {
	var logs bytes.Buffer
	re := newResponder(zerolog.New(&logs))
	err := domain.NewUnavailableError("CERT_PROVIDER_THROTTLED", "retry later")
	err.RetryAfter = "120"
	rec := httptest.NewRecorder()
	re.writeError(rec, err)
	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("decode diagnostic: %v", err)
	}
	if rec.Code != 503 || entry["level"] != "warn" || entry["code"] != "CERT_PROVIDER_THROTTLED" || entry["retryAfter"] != "120" {
		t.Fatalf("provider unavailability diagnostic: HTTP %d, %v", rec.Code, entry)
	}
}

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
