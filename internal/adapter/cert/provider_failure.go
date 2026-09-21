package cert

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/agentnameservice/ans/internal/port"
	"golang.org/x/crypto/acme"
)

func providerFailure(err error) error {
	if err == nil {
		return nil
	}
	var existing *port.ProviderThrottled
	if errors.As(err, &existing) {
		return err
	}
	var upstream *acme.Error
	if errors.As(err, &upstream) && (upstream.StatusCode == http.StatusTooManyRequests || upstream.StatusCode == http.StatusServiceUnavailable) {
		return &port.ProviderThrottled{RetryAfter: validRetryAfter(upstream.Header.Get("Retry-After")), Cause: err}
	}
	return err
}

func validRetryAfter(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if n, err := strconv.ParseUint(value, 10, 32); err == nil {
		return strconv.FormatUint(n, 10)
	}
	if at, err := http.ParseTime(value); err == nil {
		return at.UTC().Format(http.TimeFormat)
	}
	return ""
}
