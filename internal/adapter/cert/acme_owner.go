package cert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

const scopedOrderPrefix = "ans-acme-owner:"

// OwnerScopedACMEIssuer owns account selection; ACMEIssuer is a single-account client.
type OwnerScopedACMEIssuer struct {
	dataDir      string
	logger       zerolog.Logger
	ownersMu     sync.Mutex
	owners       *lru.Cache[string, *ACMEIssuer]
	newAccount   func(string) (*ACMEIssuer, error)
	mu           sync.Mutex
	chainRootPEM string
}

// NewACMEIssuer configures owner isolation without creating an unused parent account.
func NewACMEIssuer(directoryURL, email, dataDir string, opts ...ACMEIssuerOption) (*OwnerScopedACMEIssuer, error) {
	if directoryURL == "" || dataDir == "" {
		return nil, errors.New("cert: ACME directory URL and data directory are required")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create ACME directory: %w", err)
	}
	options := append([]ACMEIssuerOption(nil), opts...)
	config := &ACMEIssuer{logger: zerolog.Nop()}
	for _, opt := range options {
		opt(config)
	}
	return &OwnerScopedACMEIssuer{dataDir: dataDir, logger: config.logger,
		newAccount: func(path string) (*ACMEIssuer, error) { return newACMEAccount(directoryURL, email, path, options...) }}, nil
}

func (a *OwnerScopedACMEIssuer) GetCACertificate(context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.chainRootPEM == "" {
		return "", errors.New("ACME root certificate is not available before issuance")
	}
	return a.chainRootPEM, nil
}

// FinalizeOrder validates ownership before selecting any account or performing network I/O.
func (a *OwnerScopedACMEIssuer) FinalizeOrder(ctx context.Context, req port.FinalizeOrderRequest) (*port.IssuedCert, error) {
	if req.OwnerID == "" {
		a.logger.Warn().Msg("ACME finalize rejected: authenticated owner missing")
		return nil, fmt.Errorf("%w: authenticated owner required", port.ErrOrderOwnerMismatch)
	}
	if !strings.HasPrefix(req.OrderRef, scopedOrderPrefix) {
		return nil, port.ErrLegacyOrder
	}
	if !strings.HasPrefix(req.OrderRef, scopedOrderPrefix+ownerAccountID(req.OwnerID)+":") {
		a.logger.Warn().Str("ownerAccount", ownerAccountID(req.OwnerID)).Msg("ACME finalize rejected: order owner mismatch")
		return nil, port.ErrOrderOwnerMismatch
	}
	issued, err := a.finalizeOwnerOrder(ctx, req)
	if err != nil {
		a.logger.Warn().Err(err).Str("ownerAccount", ownerAccountID(req.OwnerID)).Msg("owner ACME finalization unavailable")
	}
	return issued, providerFailure(err)
}

// CreateOrder gives each authenticated RA owner a persistent account
// key. Both valid and pending CA authorizations are account-scoped, so one
// customer's published challenge cannot authorize another customer's order.
func (a *OwnerScopedACMEIssuer) CreateOrder(ctx context.Context, req port.CreateOrderRequest) (*domain.CertificateOrder, error) {
	if req.OwnerID == "" {
		return nil, errors.New("cert: ACME owner is required")
	}
	accountID := ownerAccountID(req.OwnerID)
	owner, err := a.ownerIssuer(accountID)
	if err != nil {
		return nil, err
	}
	order, err := owner.createOrder(ctx, req.FQDN)
	if err != nil {
		a.logger.Warn().Err(err).Str("ownerAccount", accountID).Msg("owner ACME order unavailable")
		return nil, providerFailure(err)
	}
	order.OrderRef = scopedOrderPrefix + accountID + ":" + order.OrderRef
	return order, nil
}

func ownerAccountID(ownerID string) string {
	sum := sha256.Sum256([]byte(ownerID))
	return hex.EncodeToString(sum[:])
}

func (a *OwnerScopedACMEIssuer) ownerIssuer(accountID string) (*ACMEIssuer, error) {
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
	issuer, err := a.newAccount(filepath.Join(a.dataDir, "owners", accountID))
	if err != nil {
		return nil, fmt.Errorf("cert: load owner ACME account: %w", err)
	}
	a.logger.Info().Str("ownerAccount", accountID).Msg("owner ACME account loaded")
	a.owners.Add(accountID, issuer)
	return issuer, nil
}

func (a *OwnerScopedACMEIssuer) finalizeOwnerOrder(ctx context.Context, req port.FinalizeOrderRequest) (*port.IssuedCert, error) {
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
	issued, err := owner.finalizeOrder(ctx, req)
	if err != nil {
		return nil, err
	}
	root, err := owner.GetCACertificate(ctx)
	if err == nil {
		a.mu.Lock()
		a.chainRootPEM = root
		a.mu.Unlock()
	} else {
		a.logger.Warn().Err(err).Msg("ACME certificate issued without informational root copy")
	}
	return issued, nil
}

var _ port.ServerCertificateIssuer = (*OwnerScopedACMEIssuer)(nil)
