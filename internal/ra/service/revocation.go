package service

import (
	"context"
	"errors"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
)

func revocationCertsCovered(revoked, current []*domain.StoredCertificate) bool {
	for _, c := range current {
		if c.Status != domain.CertStatusValid {
			continue
		}
		found := false
		for _, prior := range revoked {
			if prior.Status == domain.CertStatusValid && prior.InternalID == c.InternalID && prior.CertificatePEM == c.CertificatePEM {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// cancelAgentModifications runs only within the revocation transaction. Provider
// work already in flight may finish, but its commit must recheck agent/renewal
// state. Publication claims are invalidated in the same commit as REVOKED.
func (s *RegistrationService) cancelAgentModifications(ctx context.Context, agentID string, now time.Time) error {
	if s.outbox != nil {
		if err := s.outbox.CancelPending(ctx, agentID); err != nil {
			return err
		}
	}
	if err := s.cancelRenewalForRevocation(ctx, agentID, now); err != nil {
		return err
	}
	for _, kind := range []domain.CSRType{domain.CSRTypeIdentity, domain.CSRTypeServer} {
		for {
			csr, err := s.certs.FindLatestPendingCSRByType(ctx, agentID, kind)
			if err != nil {
				return err
			}
			if csr == nil {
				break
			}
			rejected, err := csr.MarkRejected("Agent revoked", now)
			if err != nil {
				return err
			}
			if err := s.certs.SaveCSR(ctx, agentID, &rejected); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *RegistrationService) cancelRenewalForRevocation(ctx context.Context, agentID string, now time.Time) error {
	if s.renewals == nil {
		return nil
	}
	pending, err := s.renewals.FindPendingByAgentID(ctx, agentID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if pending == nil {
		return nil
	}
	if err := pending.MarkFailed("Agent revoked", now); err != nil {
		return err
	}
	return s.renewals.Save(ctx, pending)
}
