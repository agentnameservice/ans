package service

import (
	"errors"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
	"testing"
)

func TestCertificateProviderFailureClassification(t *testing.T) {
	var de *domain.Error
	err := certificateProviderError(&port.ProviderThrottled{RetryAfter: "120"}, "ISSUE_FAILED", "failed")
	if !errors.As(err, &de) || de.Code != "CERT_PROVIDER_THROTTLED" || de.RetryAfter != "120" || !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("throttle mapping: %v", err)
	}
	err = certificateProviderError(port.ErrLegacyOrder, "ISSUE_FAILED", "failed")
	if !errors.As(err, &de) || de.Code != "CERT_ORDER_UPGRADE_REQUIRED" || !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("legacy mapping: %v", err)
	}
	err = certificateProviderError(port.ErrOrderOwnerMismatch, "ISSUE_FAILED", "failed")
	if !errors.As(err, &de) || de.Code != "CERT_ORDER_OWNER_MISMATCH" {
		t.Fatalf("owner mapping: %v", err)
	}
	err = certificateProviderError(errors.New("unavailable storage"), "ISSUE_FAILED", "failed")
	if !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("unexpected error lost: %v", err)
	}
}
