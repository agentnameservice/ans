package cert

import (
	"errors"
	"net/http"
	"testing"

	"github.com/agentnameservice/ans/internal/port"
	"golang.org/x/crypto/acme"
)

func TestProviderFailurePreservesRetryHint(t *testing.T) {
	for _, status := range []int{429, 503} {
		original := &acme.Error{StatusCode: status, Header: http.Header{"Retry-After": []string{"120"}}}
		var retry *port.ProviderThrottledError
		if err := providerFailure(original); !errors.As(err, &retry) || retry.RetryAfter != "120" || !errors.Is(err, original) {
			t.Fatalf("throttle classification failed: %v", err)
		}
	}
	normal := errors.New("transport failure")
	if !errors.Is(providerFailure(normal), normal) {
		t.Fatal("non-throttle error changed")
	}
	if providerFailure(nil) != nil {
		t.Fatal("success changed")
	}
}
func TestRetryAfterRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"-1", "bad", "120\r\nX-Test: injected"} {
		if validRetryAfter(value) != "" {
			t.Fatalf("invalid retry hint accepted: %q", value)
		}
	}
	value := "Wed, 21 Oct 2015 07:28:00 GMT"
	if validRetryAfter(value) != value {
		t.Fatal("HTTP date not preserved")
	}
}
