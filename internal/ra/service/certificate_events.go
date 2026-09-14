package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
	"github.com/agentnameservice/ans/internal/tl/event"
	eventv1 "github.com/agentnameservice/ans/internal/tl/event/v1"
)

// renewalEvidence is captured before the certificate transaction. A renewal
// must not attest that a replacement TLSA record is already published merely
// because a certificate was issued; only observed DNS enters its event.
type renewalEvidence struct {
	records []domain.ExpectedDNSRecord
	results []port.RecordVerification
}

func (s *RegistrationService) observeRenewalDNS(ctx context.Context, reg *domain.AgentRegistration) (*renewalEvidence, error) {
	eps, err := s.endpoints.FindByAgentID(ctx, reg.AgentID)
	if err != nil {
		return nil, err
	}
	if eps != nil {
		reg.Endpoints = eps.Endpoints
	}
	reg.ServerCert, err = s.loadServerCert(ctx, reg.AgentID)
	if err != nil {
		return nil, err
	}
	evidence := &renewalEvidence{}
	if s.dnsVerifier == nil {
		return evidence, nil
	}
	expected := s.ComputeRequiredDNSRecords(reg)
	result, err := s.dnsVerifier.VerifyRecords(ctx, reg.FQDN(), expected)
	if err != nil {
		return nil, fmt.Errorf("observe renewal DNS: %w", err)
	}
	if result == nil {
		return nil, errors.New("observe renewal DNS: verifier returned no result")
	}
	evidence.results = result.Results
	for _, r := range result.Results {
		if r.Found {
			evidence.records = append(evidence.records, r.Record)
		}
	}
	return evidence, nil
}

// enqueueCertificateRenewal runs inside the same transaction that stores the
// new certificate. Reading both certificate families here includes concurrent
// rotations committed before this transaction and preserves valid overlap.
func (s *RegistrationService) enqueueCertificateRenewal(
	ctx context.Context, reg *domain.AgentRegistration,
	evidence *renewalEvidence, schemaVersion string,
) error {
	if s.outbox == nil || s.signer == nil {
		return domain.NewInternalError("RENEWAL_PUBLICATION_UNAVAILABLE",
			"certificate renewal requires a signer and durable event outbox",
			errors.New("renewal publication is not configured"))
	}
	// Issuance can finish out of order. Timestamp the committed snapshot,
	// not the earlier CA request, so later snapshots cannot look stale.
	now := s.clock()
	if isV1Lane(schemaVersion) {
		inner, err := s.buildAgentRegisteredV1Event(ctx, reg, evidence.records, now)
		if err != nil {
			return err
		}
		inner.EventType = eventv1.TypeAgentRenewed
		inner.RenewalStatus = "SUCCESS"
		return s.enqueueTLEventV1(ctx, string(inner.EventType), reg, inner, now)
	}
	inner, err := s.buildAgentRegisteredEvent(ctx, reg, evidence.records, evidence.results, now)
	if err != nil {
		return err
	}
	inner.EventType = event.TypeAgentRenewed
	inner.RenewalStatus = "SUCCESS"
	return s.enqueueTLEvent(ctx, string(inner.EventType), reg, inner, now)
}

// attestedIdentityCerts keeps every usable overlap certificate. If the family
// has lapsed, its last-expiring certificate remains as evidence of that lapse;
// renewing the other family must not turn it into an optional, absent family.
func attestedIdentityCerts(certs []*domain.StoredCertificate, now time.Time) []*domain.StoredCertificate {
	valid := make([]*domain.StoredCertificate, 0, len(certs))
	var lastExpired *domain.StoredCertificate
	for _, c := range certs {
		if c == nil || c.Status != domain.CertStatusValid || now.Before(c.IssueTimestamp) || c.ExpirationTimestamp.IsZero() {
			continue
		}
		if now.Before(c.ExpirationTimestamp) {
			valid = append(valid, c)
		} else if lastExpired == nil || c.ExpirationTimestamp.After(lastExpired.ExpirationTimestamp) {
			lastExpired = c
		}
	}
	if len(valid) == 0 && lastExpired != nil {
		return []*domain.StoredCertificate{lastExpired}
	}
	return valid
}

func (s *RegistrationService) attestedServerCerts(ctx context.Context, agentID string, now time.Time) ([]*domain.ByocServerCertificate, error) {
	certs, err := s.byoc.FindByAgentID(ctx, agentID)
	if err != nil {
		return nil, err
	}
	return serverCertsForAttestation(certs, now), nil
}

// serverCertsForAttestation applies the same lapse-evidence rule as the identity
// family. Only certificates committed after successful proof enter this store.
func serverCertsForAttestation(certs []*domain.ByocServerCertificate, now time.Time) []*domain.ByocServerCertificate {
	valid := make([]*domain.ByocServerCertificate, 0, len(certs))
	seen := make(map[string]bool, len(certs))
	var lastExpired *domain.ByocServerCertificate
	for _, c := range certs {
		if c == nil || now.Before(c.ValidFromTimestamp) || c.ValidToTimestamp.IsZero() || seen[c.Fingerprint] {
			continue
		}
		seen[c.Fingerprint] = true
		if now.Before(c.ValidToTimestamp) {
			valid = append(valid, c)
		} else if lastExpired == nil || c.ValidToTimestamp.After(lastExpired.ValidToTimestamp) {
			lastExpired = c
		}
	}
	if len(valid) == 0 && lastExpired != nil {
		return []*domain.ByocServerCertificate{lastExpired}
	}
	return valid
}
