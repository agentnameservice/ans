package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

func (s *RegistrationService) createServerOrder(ctx context.Context, ownerID, fqdn string) (*domain.CertificateOrder, error) {
	if scoped, ok := s.serverCA.(port.OwnerScopedServerCertificateIssuer); ok {
		return scoped.CreateOrderForOwner(ctx, ownerID, fqdn)
	}
	return s.serverCA.CreateOrder(ctx, fqdn)
}

// orderWithOwnerProof separates provider authorization from this registration's
// proof. A shared CA account's cached authorization is not proof by its caller.
// Already-authorized orders therefore receive fresh, persisted RA challenges;
// the provider handle is retained for finalization after that proof succeeds.
func orderWithOwnerProof(created *domain.CertificateOrder, deadline time.Time) (domain.CertificateOrder, error) {
	if created == nil {
		return domain.CertificateOrder{}, errors.New("certificate issuer returned no order")
	}
	if created.State != domain.OrderStatePending && created.State != domain.OrderStateIssuing {
		return domain.CertificateOrder{}, fmt.Errorf("certificate issuer returned unusable order state %q", created.State)
	}
	order := *created
	order.VerifiedChallenge = ""
	if order.ExpiresAt.IsZero() || deadline.Before(order.ExpiresAt) {
		order.ExpiresAt = deadline
	}
	if len(order.Challenges) == 0 {
		dns01, http01, err := generateChallengeTokens()
		if err != nil {
			return domain.CertificateOrder{}, err
		}
		local := domain.NewSelfIssuedOrder(dns01, http01, order.ExpiresAt)
		local.OrderRef = order.OrderRef
		return local, nil
	}
	order.State = domain.OrderStatePending
	return order, nil
}
