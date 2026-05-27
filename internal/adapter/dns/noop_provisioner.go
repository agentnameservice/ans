package dns

import (
	"context"

	"github.com/godaddy/ans/internal/domain"
)

// NoopProvisioner is a no-op DNSProvisioner for dev and test
// environments. It accepts any input and always succeeds.
type NoopProvisioner struct{}

func NewNoopProvisioner() *NoopProvisioner { return &NoopProvisioner{} }

func (NoopProvisioner) ProvisionRecords(_ context.Context, _ string, _ []domain.ExpectedDNSRecord) error {
	return nil
}

func (NoopProvisioner) DeleteRecords(_ context.Context, _ string, _ []domain.ExpectedDNSRecord) error {
	return nil
}
