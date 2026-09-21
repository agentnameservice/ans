package service

import (
	"errors"
	"fmt"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

func certificateProviderError(err error, fallbackCode, detail string) error {
	var throttled *port.ProviderThrottled
	if errors.As(err, &throttled) {
		return &domain.Error{Code: "CERT_PROVIDER_THROTTLED", Message: "certificate provider is temporarily rate limited; retry later",
			RetryAfter: throttled.RetryAfter, Cause: fmt.Errorf("%w: %w", domain.ErrUnavailable, err)}
	}
	if errors.Is(err, port.ErrLegacyOrder) {
		return domain.NewConflictError("CERT_ORDER_UPGRADE_REQUIRED", "legacy certificate order cannot continue; cancel the pending renewal or registration where supported and create a new order")
	}
	if errors.Is(err, port.ErrOrderOwnerMismatch) {
		return domain.NewConflictError("CERT_ORDER_OWNER_MISMATCH", "certificate order does not belong to the authenticated owner")
	}
	return domain.NewInternalError(fallbackCode, detail, err)
}
