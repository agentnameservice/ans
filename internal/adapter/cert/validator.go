package cert

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/port"
)

// X509Validator implements port.CertificateValidator using Go crypto/x509.
// BYOC server certificates are validated for format, FQDN match, validity
// period, algorithm allowlist, and key strength. Chain validation against
// public roots is performed with the OS root pool; callers can opt out of
// chain verification for local-dev flows via WithSkipChainVerify.
type X509Validator struct {
	skipChainVerify bool
}

// ValidatorOption configures an X509Validator.
type ValidatorOption func(*X509Validator)

// WithSkipChainVerify disables chain verification against public roots.
// Use only in local-dev configurations where the operator may submit
// self-signed BYOC certificates for testing.
func WithSkipChainVerify() ValidatorOption {
	return func(v *X509Validator) { v.skipChainVerify = true }
}

// NewX509Validator constructs a validator with the given options.
func NewX509Validator(opts ...ValidatorOption) *X509Validator {
	v := &X509Validator{}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// ValidateServerCertificate implements port.CertificateValidator.
func (v *X509Validator) ValidateServerCertificate(
	ctx context.Context,
	leafPEM, chainPEM, expectedFQDN string,
) (*port.ValidatedCert, error) {
	leaf, err := anscrypto.ParseCertificatePEM(leafPEM)
	if err != nil {
		return nil, err
	}

	if err := anscrypto.CheckSignatureAlgorithm(leaf.SignatureAlgorithm); err != nil {
		return nil, err
	}
	if err := anscrypto.CheckKeyStrength(leaf.PublicKey); err != nil {
		return nil, err
	}
	if err := anscrypto.CheckCertificateValidity(leaf, leaf.NotBefore.Add(0)); err == nil {
		// re-check with current time to get the sentinel
		if err := anscrypto.CheckCertificateValidity(leaf, time.Now()); err != nil {
			return nil, err
		}
	}
	if err := anscrypto.MatchCertificateToFQDN(leaf, expectedFQDN); err != nil {
		return nil, err
	}

	var chain []*x509.Certificate
	if chainPEM != "" {
		chain, err = anscrypto.ParseCertificateChainPEM(chainPEM)
		if err != nil {
			return nil, err
		}
	}

	if !v.skipChainVerify {
		if err := anscrypto.VerifyChain(leaf, chain, nil); err != nil {
			// Surface the sentinel so callers can distinguish chain errors
			// from format errors.
			if !errors.Is(err, anscrypto.ErrChainInvalid) {
				return nil, fmt.Errorf("%w: %w", anscrypto.ErrChainInvalid, err)
			}
			return nil, err
		}
	}

	return &port.ValidatedCert{
		LeafPEM:      leafPEM,
		ChainPEM:     chainPEM,
		CN:           leaf.Subject.CommonName,
		SANs:         leaf.DNSNames,
		IssuerDN:     leaf.Issuer.String(),
		ValidFrom:    leaf.NotBefore,
		ValidTo:      leaf.NotAfter,
		Fingerprint:  anscrypto.CertificateFingerprint(leaf),
		SerialNumber: leaf.SerialNumber.Text(16),
	}, nil
}

// ValidateIdentityCSR implements port.CertificateValidator.
func (v *X509Validator) ValidateIdentityCSR(
	ctx context.Context,
	csrPEM string,
	expectedAnsName string,
) error {
	_, err := anscrypto.ValidateIdentityCSR(csrPEM, expectedAnsName)
	return err
}

// ValidateServerCSR implements port.CertificateValidator for the
// server-cert issuance path. Server CSRs carry the agent's FQDN as
// a DNS SAN (TLS server-auth convention, distinct from the identity
// CSR's URI SAN).
func (v *X509Validator) ValidateServerCSR(
	ctx context.Context,
	csrPEM string,
	expectedFQDN string,
) error {
	_, err := anscrypto.ValidateServerCSR(csrPEM, expectedFQDN)
	return err
}
