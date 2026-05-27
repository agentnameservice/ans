package port

import (
	"context"

	"github.com/godaddy/ans/internal/domain"
)

// RecordVerification is the result of checking a single DNS record.
type RecordVerification struct {
	Record domain.ExpectedDNSRecord
	Found  bool
	Actual string // What was actually returned by DNS (empty if not found).
	Error  string // Lookup error, if any.
	// DNSSECVerified is true when the response carried an
	// authenticated-data (AD) bit from a validating resolver. Only
	// meaningful for TLSA records — surfacing this to the TL lets a
	// downstream verifier trust the cert-binding assertion without
	// re-querying DNS themselves.
	DNSSECVerified bool
}

// VerificationResult aggregates per-record results from a DNS verification run.
type VerificationResult struct {
	// AllRequired is true when every record marked Required was found
	// with a matching value.
	AllRequired bool
	Results     []RecordVerification
}

// DNSProvisioner creates and deletes DNS records on behalf of the RA.
// Implementations must be idempotent: provisioning a record that already
// exists with the correct value is a no-op; deleting a record that does
// not exist succeeds silently.
type DNSProvisioner interface {
	ProvisionRecords(ctx context.Context, fqdn string, records []domain.ExpectedDNSRecord) error
	DeleteRecords(ctx context.Context, fqdn string, records []domain.ExpectedDNSRecord) error
}

// DNSVerifier checks that the operator's DNS zone contains the records
// the domain expects. It does NOT create, update, or delete records —
// ANS is verification-only. Operators manage their own DNS.
type DNSVerifier interface {
	// VerifyRecords performs DNS lookups for each expected record and
	// returns a per-record report plus an overall pass/fail summary.
	// A VerificationResult is always returned even on partial failures;
	// a non-nil error indicates a systemic failure (e.g., DNS unreachable).
	VerifyRecords(
		ctx context.Context,
		fqdn string,
		expected []domain.ExpectedDNSRecord,
	) (*VerificationResult, error)
}
