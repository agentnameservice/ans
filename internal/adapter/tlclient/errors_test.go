package tlclient

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestTransientError_NoStatus covers the second arm of
// TransientError.Error(): Status == 0 returns a status-less message.
// In production this fires on transport-level failures (connection
// refused, DNS error) where there's no HTTP response.
func TestTransientError_NoStatus(t *testing.T) {
	e := &TransientError{Message: "connection refused", Cause: errors.New("dial: refused")}
	got := e.Error()
	if !strings.Contains(got, "connection refused") {
		t.Errorf("Error() should contain message; got %q", got)
	}
	if strings.Contains(got, "status 0") || strings.Contains(got, "status: 0") {
		t.Errorf("Error() shouldn't include zero status; got %q", got)
	}
}

// TestTransientError_WithStatus covers the first arm with a non-zero
// HTTP status (e.g. 5xx response).
func TestTransientError_WithStatus(t *testing.T) {
	e := &TransientError{Status: 503, Message: "server unavailable", Body: "down"}
	got := e.Error()
	if !strings.Contains(got, "503") {
		t.Errorf("Error() should include status; got %q", got)
	}
	if !strings.Contains(got, "down") {
		t.Errorf("Error() should include body; got %q", got)
	}
}

// TestTransientError_Unwrap pins the errors.Is(err, target) chain
// so callers can switch on net.ErrClosed etc through the wrapper.
func TestTransientError_Unwrap(t *testing.T) {
	target := errors.New("inner")
	e := &TransientError{Cause: target}
	if !errors.Is(e, target) {
		t.Error("errors.Is should walk through TransientError.Unwrap")
	}
}

// TestPermanentError_FormatIncludesStatus pins the same shape for
// permanent errors. Permanent errors always carry a status (4xx
// from the server) so there's no zero-status fallback to test.
func TestPermanentError_FormatIncludesStatus(t *testing.T) {
	e := &PermanentError{Status: 422, Message: "MISMATCH_SIGNATURE", Body: "bad sig"}
	got := e.Error()
	if !strings.Contains(got, "422") {
		t.Errorf("Error() missing status; got %q", got)
	}
	if !strings.Contains(got, "MISMATCH_SIGNATURE") {
		t.Errorf("Error() missing message; got %q", got)
	}
}

// TestNew_DefaultsTimeoutToTenSeconds covers the timeout-defaulting
// branch in New: a zero or negative timeout falls back to 10s.
func TestNew_DefaultsTimeoutToTenSeconds(t *testing.T) {
	c := New("http://localhost", "k", 0)
	if c.http.Timeout != 10*time.Second {
		t.Errorf("New(0): timeout got %v want 10s", c.http.Timeout)
	}
	c = New("http://localhost", "k", -time.Second)
	if c.http.Timeout != 10*time.Second {
		t.Errorf("New(-1s): timeout got %v want 10s", c.http.Timeout)
	}
}

// TestNew_PreservesNonZeroTimeout covers the no-default arm.
func TestNew_PreservesNonZeroTimeout(t *testing.T) {
	c := New("http://localhost", "k", 7*time.Second)
	if c.http.Timeout != 7*time.Second {
		t.Errorf("New(7s): timeout got %v want 7s", c.http.Timeout)
	}
}

// TestIsTransient_NilAndUnrelated verifies the convenience helpers
// return false for nil and unrelated errors.
func TestIsTransient_NilAndUnrelated(t *testing.T) {
	if IsTransient(nil) {
		t.Error("IsTransient(nil) should be false")
	}
	if IsTransient(errors.New("plain")) {
		t.Error("IsTransient(plain error) should be false")
	}
}

func TestIsPermanent_NilAndUnrelated(t *testing.T) {
	if IsPermanent(nil) {
		t.Error("IsPermanent(nil) should be false")
	}
	if IsPermanent(errors.New("plain")) {
		t.Error("IsPermanent(plain error) should be false")
	}
}
