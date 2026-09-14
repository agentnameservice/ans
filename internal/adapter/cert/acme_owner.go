package cert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

const scopedOrderPrefix = "ans-acme-owner:"

// CreateOrderForOwner gives each authenticated RA owner a persistent account
// key. Both valid and pending CA authorizations are account-scoped, so one
// customer's published challenge cannot authorize another customer's order.
func (a *ACMEIssuer) CreateOrderForOwner(ctx context.Context, ownerID, fqdn string) (*domain.CertificateOrder, error) {
	if ownerID == "" {
		return nil, errors.New("cert: ACME owner is required")
	}
	accountID := ownerAccountID(ownerID)
	owner, err := a.ownerIssuer(accountID)
	if err != nil {
		return nil, err
	}
	order, err := owner.CreateOrder(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	order.OrderRef = scopedOrderPrefix + accountID + ":" + order.OrderRef
	return order, nil
}

func ownerAccountID(ownerID string) string {
	sum := sha256.Sum256([]byte(ownerID))
	return hex.EncodeToString(sum[:])
}

func (a *ACMEIssuer) ownerIssuer(accountID string) (*ACMEIssuer, error) {
	a.ownersMu.Lock()
	defer a.ownersMu.Unlock()
	if a.owners == nil {
		cache, err := lru.New[string, *ACMEIssuer](256)
		if err != nil {
			return nil, err
		}
		a.owners = cache
	}
	if issuer, ok := a.owners.Get(accountID); ok {
		return issuer, nil
	}
	issuer, err := NewACMEIssuer(a.directoryURL, a.email, filepath.Join(a.dataDir, "owners", accountID), a.options...)
	if err != nil {
		return nil, fmt.Errorf("cert: load owner ACME account: %w", err)
	}
	a.owners.Add(accountID, issuer)
	return issuer, nil
}

func (a *ACMEIssuer) finalizeOwnerOrder(ctx context.Context, req port.FinalizeOrderRequest) (*port.IssuedCert, error) {
	accountID, orderURL, ok := strings.Cut(strings.TrimPrefix(req.OrderRef, scopedOrderPrefix), ":")
	id, err := hex.DecodeString(accountID)
	if !ok || err != nil || len(id) != sha256.Size || orderURL == "" {
		return nil, errors.New("cert: invalid owner-scoped ACME order reference")
	}
	// Decode and re-encode rather than using the input as a filesystem path.
	owner, err := a.ownerIssuer(hex.EncodeToString(id))
	if err != nil {
		return nil, err
	}
	req.OrderRef = orderURL
	// The parent has checked the authenticated owner against this handle.
	// The child manages only that account and uses the provider's URL.
	req.OwnerID = ""
	issued, err := owner.FinalizeOrder(ctx, req)
	if err != nil {
		return nil, err
	}
	root, err := owner.GetCACertificate(ctx)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.chainRootPEM = root
	a.mu.Unlock()
	return issued, nil
}
