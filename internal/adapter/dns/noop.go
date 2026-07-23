// Package dns provides DNSVerifier implementations. ANS is verification-only:
// operators manage their own DNS and the RA only confirms that records exist.
package dns

import (
	"context"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// NoopVerifier always reports all records as verified. Intended for the
// zero-config quickstart where the operator does not want to configure
// real DNS. It must NOT be used in any environment where trust claims
// depend on DNS verification.
type NoopVerifier struct{}

// NewNoopVerifier returns a Noop DNS verifier.
func NewNoopVerifier() *NoopVerifier { return &NoopVerifier{} }

// VerifyRecords always returns success for every record.
func (NoopVerifier) VerifyRecords(
	_ context.Context,
	_ string,
	expected []domain.ExpectedDNSRecord,
) (*port.VerificationResult, error) {
	results := make([]port.RecordVerification, len(expected))
	for i, r := range expected {
		results[i] = port.RecordVerification{
			Record: r,
			Found:  true,
			Actual: r.Value,
		}
	}
	return &port.VerificationResult{AllRequired: true, Results: results}, nil
}
