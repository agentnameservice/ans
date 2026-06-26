package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/crypto/acme"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// pemTypePrivateKey is the PEM block type for PKCS#8 private keys,
// shared by the self-signed CAs' root keys and the ACME account key.
const pemTypePrivateKey = "PRIVATE KEY"

// acmeAccountKeyFile is the PKCS#8 PEM file holding the ACME account
// key, persisted under the issuer's data dir so the account survives
// restarts (re-registering the same key resolves to the same account
// per RFC 8555 §7.3.1).
const acmeAccountKeyFile = "acme-account.key"

// defaultFinalizeBudget bounds how long a single FinalizeOrder call
// blocks on the provider before reporting port.ErrOrderPending. The
// verify-acme request that triggers the finalize runs under the
// router's 30s timeout; 10s leaves headroom for the rest of the
// request while still completing most Let's Encrypt validations
// in-call.
const defaultFinalizeBudget = 10 * time.Second

// ACME challenge type identifiers (RFC 8555 §9.7.8) mapped to the
// domain's wire-cased enum.
const (
	acmeChallengeDNS01  = "dns-01"
	acmeChallengeHTTP01 = "http-01"
)

// ACMEIssuer implements port.ServerCertificateIssuer against an
// RFC 8555 CA — Let's Encrypt being the canonical target (use the
// staging directory for testing, production for live issuance).
//
// Order-lifecycle mapping:
//
//   - CreateOrder → new-order. The provider's challenges are relayed
//     with their account-bound key authorizations and the computed
//     DNS-01 TXT digest, so the pending-registration response hands
//     the domain owner exactly the artifacts to publish. ANS never
//     publishes them — the owner does, exactly as with the
//     self-signed issuer.
//   - FinalizeOrder → answer the RA-verified challenge, wait briefly
//     for validation + issuance, then finalize with the CSR and
//     download the chain. Validation that outlives the in-call
//     budget reports port.ErrOrderPending; the re-driven verify-acme
//     picks the order back up by its URL. Orders the provider moves
//     to `invalid` report port.ErrOrderFailed.
//
// Account handling: the account key is generated once and persisted
// under dataDir; registration happens lazily on first use and
// auto-accepts the provider's terms of service — choosing
// `ca.server.type: acme` in config is the operator's ToS consent,
// per standard ACME automation practice.
type ACMEIssuer struct {
	client         *acme.Client
	contact        []string
	finalizeBudget time.Duration
	logger         zerolog.Logger

	mu         sync.Mutex
	registered bool
	// chainRootPEM caches the top of the most recently downloaded
	// chain for GetCACertificate. Informational for ACME providers —
	// relying parties already hold the public root in system stores.
	chainRootPEM string
}

// ACMEIssuerOption configures the issuer at construction time.
type ACMEIssuerOption func(*ACMEIssuer)

// WithFinalizeBudget overrides how long FinalizeOrder blocks on the
// provider before reporting port.ErrOrderPending.
func WithFinalizeBudget(d time.Duration) ACMEIssuerOption {
	return func(a *ACMEIssuer) { a.finalizeBudget = d }
}

// WithLogger attaches a structured logger (default: a no-op logger).
// Issuance against an external CA is the part of the flow operators
// cannot see from the wire — order open / finalize transitions are
// logged at INFO and upstream-provider failures at ERROR so a stuck or
// rejected order can be debugged from the RA logs.
func WithLogger(logger zerolog.Logger) ACMEIssuerOption {
	return func(a *ACMEIssuer) {
		a.logger = logger.With().Str("component", "acme-issuer").Logger()
	}
}

// NewACMEIssuer opens (or creates) the ACME account key under
// dataDir and returns an issuer speaking to the given directory URL
// (e.g. Let's Encrypt staging:
// https://acme-staging-v02.api.letsencrypt.org/directory). The
// optional email becomes the account contact for expiry and incident
// notices. No network I/O happens here — account registration is
// deferred to first use so the RA can boot while the provider is
// unreachable.
func NewACMEIssuer(directoryURL, email, dataDir string, opts ...ACMEIssuerOption) (*ACMEIssuer, error) {
	if directoryURL == "" {
		return nil, errors.New("cert: acme directory-url is required")
	}
	if dataDir == "" {
		return nil, errors.New("cert: acme data-dir is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("cert: create acme dir: %w", err)
	}
	key, err := loadOrCreateAccountKey(filepath.Join(dataDir, acmeAccountKeyFile))
	if err != nil {
		return nil, err
	}
	a := &ACMEIssuer{
		client:         &acme.Client{Key: key, DirectoryURL: directoryURL},
		finalizeBudget: defaultFinalizeBudget,
		logger:         zerolog.Nop(),
	}
	if email != "" {
		a.contact = []string{"mailto:" + email}
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// CreateOrder opens an RFC 8555 order for the FQDN and relays the
// provider's pending challenges.
//
// A new order is not always 'pending': per RFC 8555 §7.1.3 a CA that
// still holds a valid authorization for this account+identifier
// returns the order already 'ready' (Let's Encrypt reuses
// authorizations for ~30 days). The RA uses a single ACME account, so
// a renewal or re-registration of a recently-validated FQDN hits this
// routinely. In that case there is nothing for the owner to publish:
// the order is relayed as ISSUING with no challenges, the RA's gate
// skips ISSUING orders, and the next verify-acme finalizes directly.
func (a *ACMEIssuer) CreateOrder(ctx context.Context, fqdn string) (*domain.CertificateOrder, error) {
	if fqdn == "" {
		return nil, errors.New("cert: create order: fqdn is required")
	}
	if err := a.ensureRegistered(ctx); err != nil {
		return nil, err
	}
	order, err := a.client.AuthorizeOrder(ctx, acme.DomainIDs(fqdn))
	if err != nil {
		a.logger.Error().Err(err).Str("fqdn", fqdn).Msg("acme new-order failed")
		return nil, fmt.Errorf("cert: acme new-order: %w", err)
	}
	a.logger.Info().
		Str("fqdn", fqdn).
		Str("orderRef", order.URI).
		Str("acmeStatus", order.Status).
		Msg("acme order opened")

	switch order.Status {
	case acme.StatusPending:
		challenges, cerr := a.collectChallenges(ctx, order)
		if cerr != nil {
			a.logger.Error().Err(cerr).Str("orderRef", order.URI).Msg("acme collect challenges failed")
			return nil, cerr
		}
		a.logger.Debug().
			Str("orderRef", order.URI).
			Str("state", string(domain.OrderStatePending)).
			Int("challenges", len(challenges)).
			Msg("acme order pending — relaying challenges for the owner to publish")
		return &domain.CertificateOrder{
			OrderRef:   order.URI,
			State:      domain.OrderStatePending,
			Challenges: challenges,
			ExpiresAt:  order.Expires,
		}, nil
	case acme.StatusReady, acme.StatusProcessing, acme.StatusValid:
		// Authorizations already satisfied (reuse) or issuance already
		// underway — no domain-control artifact for the owner to
		// publish. Relay as ISSUING so verify-acme drives FinalizeOrder.
		a.logger.Info().
			Str("orderRef", order.URI).
			Str("acmeStatus", order.Status).
			Str("state", string(domain.OrderStateIssuing)).
			Msg("acme order already authorized (reuse) — no challenges to publish")
		return &domain.CertificateOrder{
			OrderRef:  order.URI,
			State:     domain.OrderStateIssuing,
			ExpiresAt: order.Expires,
		}, nil
	default: // acme.StatusInvalid or unknown
		a.logger.Error().
			Str("orderRef", order.URI).
			Str("acmeStatus", order.Status).
			Msg("acme new-order returned unusable status")
		return nil, fmt.Errorf("cert: acme new-order returned unusable status %q", order.Status)
	}
}

// collectChallenges walks the order's pending authorizations and
// maps their dns-01 / http-01 challenges to the domain shape. The
// DNS TXT value is the provider-mandated digest of the key
// authorization, NOT the raw token — relayed precomputed so the
// domain owner publishes an opaque name/value pair without knowing
// ACME exists.
func (a *ACMEIssuer) collectChallenges(ctx context.Context, order *acme.Order) ([]domain.Challenge, error) {
	var out []domain.Challenge
	for _, zurl := range order.AuthzURLs {
		authz, err := a.client.GetAuthorization(ctx, zurl)
		if err != nil {
			return nil, fmt.Errorf("cert: acme get authorization: %w", err)
		}
		if authz.Status != acme.StatusPending {
			continue
		}
		for _, ch := range authz.Challenges {
			keyAuth, err := a.client.HTTP01ChallengeResponse(ch.Token)
			if err != nil {
				return nil, fmt.Errorf("cert: acme key authorization: %w", err)
			}
			switch ch.Type {
			case acmeChallengeDNS01:
				value, err := a.client.DNS01ChallengeRecord(ch.Token)
				if err != nil {
					return nil, fmt.Errorf("cert: acme dns-01 record: %w", err)
				}
				out = append(out, domain.Challenge{
					Type:             domain.ChallengeTypeDNS01,
					Token:            ch.Token,
					KeyAuthorization: keyAuth,
					DNSRecordValue:   value,
				})
			case acmeChallengeHTTP01:
				out = append(out, domain.Challenge{
					Type:             domain.ChallengeTypeHTTP01,
					Token:            ch.Token,
					KeyAuthorization: keyAuth,
					HTTPPath:         a.client.HTTP01ChallengePath(ch.Token),
				})
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("cert: acme order offered no supported challenges (dns-01 / http-01)")
	}
	return out, nil
}

// FinalizeOrder drives the order to completion: answer the challenges
// the RA verified, wait (bounded) for the provider's validation, then
// finalize with the CSR and download the chain.
func (a *ACMEIssuer) FinalizeOrder(ctx context.Context, req port.FinalizeOrderRequest) (*port.IssuedCert, error) {
	csr, err := anscrypto.ValidateServerCSR(req.CSRPEM, req.FQDN)
	if err != nil {
		return nil, err
	}
	if req.OrderRef == "" {
		return nil, errors.New("cert: acme finalize: order ref is required")
	}
	if err := a.ensureRegistered(ctx); err != nil {
		return nil, err
	}
	a.logger.Info().
		Str("fqdn", req.FQDN).
		Str("orderRef", req.OrderRef).
		Msg("acme finalizing order")

	order, err := a.client.GetOrder(ctx, req.OrderRef)
	if err != nil {
		a.logger.Error().Err(err).Str("orderRef", req.OrderRef).Msg("acme get order failed")
		return nil, fmt.Errorf("cert: acme get order: %w", err)
	}

	if order.Status == acme.StatusPending {
		if err := a.answerVerifiedChallenges(ctx, order, req.Verified); err != nil {
			a.logger.Error().Err(err).Str("orderRef", req.OrderRef).Msg("acme answer challenges failed")
			return nil, err
		}
		if order, err = a.waitOrder(ctx, req.OrderRef); err != nil {
			a.logOrderWaitErr(req.OrderRef, "acme wait order", err)
			return nil, err
		}
	}

	var issued *port.IssuedCert
	switch order.Status {
	case acme.StatusReady:
		issued, err = a.finalizeWithCSR(ctx, order.FinalizeURL, csr.Raw)
	case acme.StatusProcessing, acme.StatusPending:
		// Validation or issuance is still running provider-side; the
		// re-driven verify-acme picks the order back up.
		a.logger.Debug().
			Str("orderRef", req.OrderRef).
			Str("acmeStatus", order.Status).
			Msg("acme order still pending — will re-drive on next verify-acme")
		return nil, fmt.Errorf("cert: acme order %s: %w", order.Status, port.ErrOrderPending)
	case acme.StatusValid:
		der, ferr := a.client.FetchCert(ctx, order.CertURL, true)
		if ferr != nil {
			a.logger.Error().Err(ferr).Str("orderRef", req.OrderRef).Msg("acme fetch cert failed")
			return nil, fmt.Errorf("cert: acme fetch cert: %w", ferr)
		}
		issued, err = a.issuedFromChain(der, order.CertURL)
	case acme.StatusInvalid:
		a.logger.Error().
			Str("fqdn", req.FQDN).
			Str("orderRef", req.OrderRef).
			Msg("acme order invalid — provider rejected domain validation")
		return nil, fmt.Errorf("cert: acme order invalid: %w", port.ErrOrderFailed)
	default:
		a.logger.Error().
			Str("orderRef", req.OrderRef).
			Str("acmeStatus", order.Status).
			Msg("acme order in unexpected status")
		return nil, fmt.Errorf("cert: acme order in unexpected status %q", order.Status)
	}
	if err != nil {
		a.logOrderWaitErr(req.OrderRef, "acme finalize", err)
		return nil, err
	}

	a.logger.Info().
		Str("fqdn", req.FQDN).
		Str("orderRef", req.OrderRef).
		Str("serialNumber", issued.SerialNumber).
		Msg("acme order finalized — certificate issued")
	return issued, nil
}

// logOrderWaitErr logs a FinalizeOrder-path error at the right level:
// port.ErrOrderPending is the expected async signal (the order is still
// running and a later verify-acme re-drives it), so it is debug, not an
// error; everything else is a real upstream failure worth an ERROR line
// for debugging.
func (a *ACMEIssuer) logOrderWaitErr(orderRef, stage string, err error) {
	if errors.Is(err, port.ErrOrderPending) {
		a.logger.Debug().
			Str("orderRef", orderRef).
			Msg("acme order still running — will re-drive on next verify-acme")
		return
	}
	a.logger.Error().Err(err).Str("orderRef", orderRef).Msg(stage + " failed")
}

// answerVerifiedChallenges tells the provider to validate exactly the
// challenges the RA's pre-flight gate found published. Answering an
// unsatisfied challenge would move its authorization to invalid and
// kill the order — which is why the port contract threads Verified
// through. Already-answered challenges (re-driven calls) are skipped
// by their non-pending status.
func (a *ACMEIssuer) answerVerifiedChallenges(ctx context.Context, order *acme.Order, verified []domain.ChallengeType) error {
	wanted := map[string]bool{}
	for _, t := range verified {
		switch t {
		case domain.ChallengeTypeDNS01:
			wanted[acmeChallengeDNS01] = true
		case domain.ChallengeTypeHTTP01:
			wanted[acmeChallengeHTTP01] = true
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	for _, zurl := range order.AuthzURLs {
		authz, err := a.client.GetAuthorization(ctx, zurl)
		if err != nil {
			return fmt.Errorf("cert: acme get authorization: %w", err)
		}
		if authz.Status != acme.StatusPending {
			continue
		}
		for _, ch := range authz.Challenges {
			if !wanted[ch.Type] || ch.Status != acme.StatusPending {
				continue
			}
			if _, err := a.client.Accept(ctx, ch); err != nil {
				return fmt.Errorf("cert: acme accept %s challenge: %w", ch.Type, err)
			}
			// One accepted challenge satisfies the authorization;
			// answering more buys nothing and risks a race with the
			// provider marking the authz valid mid-loop.
			break
		}
	}
	return nil
}

// waitOrder polls the order within the finalize budget. A budget
// overrun is not an error — the order is simply still pending and a
// later verify-acme re-drives it.
func (a *ACMEIssuer) waitOrder(ctx context.Context, orderRef string) (*acme.Order, error) {
	waitCtx, cancel := context.WithTimeout(ctx, a.finalizeBudget)
	defer cancel()
	order, err := a.client.WaitOrder(waitCtx, orderRef)
	switch {
	case err == nil:
		return order, nil
	case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
		return nil, fmt.Errorf("cert: acme validation still running: %w", port.ErrOrderPending)
	default:
		var oe *acme.OrderError
		if errors.As(err, &oe) {
			return nil, fmt.Errorf("cert: acme order %s: %w", oe.Status, port.ErrOrderFailed)
		}
		return nil, fmt.Errorf("cert: acme wait order: %w", err)
	}
}

// finalizeWithCSR submits the CSR and downloads the issued chain. A
// budget overrun after submission is reported pending — the next
// re-drive finds the order processing/valid and fetches the cert.
func (a *ACMEIssuer) finalizeWithCSR(ctx context.Context, finalizeURL string, csrDER []byte) (*port.IssuedCert, error) {
	waitCtx, cancel := context.WithTimeout(ctx, a.finalizeBudget)
	defer cancel()
	der, certURL, err := a.client.CreateOrderCert(waitCtx, finalizeURL, csrDER, true)
	switch {
	case err == nil:
		return a.issuedFromChain(der, certURL)
	case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
		return nil, fmt.Errorf("cert: acme issuance still running: %w", port.ErrOrderPending)
	default:
		var oe *acme.OrderError
		if errors.As(err, &oe) {
			return nil, fmt.Errorf("cert: acme order %s: %w", oe.Status, port.ErrOrderFailed)
		}
		return nil, fmt.Errorf("cert: acme finalize: %w", err)
	}
}

// issuedFromChain converts the downloaded DER chain (leaf first) into
// the port shape and caches the chain top for GetCACertificate. The
// certificate URL becomes the provider handle (CertificateRef) — the
// stable reference for audit and for RFC 8555 §7.6 revocation.
func (a *ACMEIssuer) issuedFromChain(der [][]byte, certURL string) (*port.IssuedCert, error) {
	if len(der) == 0 {
		return nil, errors.New("cert: acme returned an empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return nil, fmt.Errorf("cert: parse acme leaf: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der[0]})
	var chainPEM []byte
	for _, d := range der[1:] {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}

	a.mu.Lock()
	if len(der) > 1 {
		a.chainRootPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der[len(der)-1]}))
	}
	a.mu.Unlock()

	return &port.IssuedCert{
		CertPEM:        string(certPEM),
		ChainPEM:       string(chainPEM),
		SerialNumber:   fmt.Sprintf("%x", leaf.SerialNumber),
		CertificateRef: certURL,
		ExpiresAt:      leaf.NotAfter,
		IssuedAt:       leaf.NotBefore,
	}, nil
}

// GetCACertificate returns the top of the most recently downloaded
// chain. Informational for ACME providers — relying parties already
// trust the public root via system stores, so an error before first
// issuance is expected and harmless.
func (a *ACMEIssuer) GetCACertificate(_ context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.chainRootPEM == "" {
		return "", errors.New("cert: acme issuer has not downloaded a chain yet — the provider's public root is already in system trust stores")
	}
	return a.chainRootPEM, nil
}

// ensureRegistered lazily registers the account on first use. An
// already-registered key (same key, prior run) is success per
// RFC 8555 §7.3.1.
func (a *ACMEIssuer) ensureRegistered(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.registered {
		return nil
	}
	_, err := a.client.Register(ctx, &acme.Account{Contact: a.contact}, acme.AcceptTOS)
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("cert: acme account registration: %w", err)
	}
	a.registered = true
	return nil
}

// loadOrCreateAccountKey reads the persisted ACME account key, or
// generates an ECDSA P-256 key on first run.
func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != pemTypePrivateKey {
			return nil, errors.New("cert: acme account key is not a PKCS#8 PRIVATE KEY PEM")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cert: parse acme account key: %w", err)
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("cert: acme account key is not an ECDSA key")
		}
		return ec, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("cert: read acme account key: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cert: generate acme account key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("cert: marshal acme account key: %w", err)
	}
	if err := os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der}), 0o600); err != nil {
		return nil, fmt.Errorf("cert: write acme account key: %w", err)
	}
	return key, nil
}
