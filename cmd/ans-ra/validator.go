package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/agentnameservice/ans/internal/adapter/cert"
	"github.com/agentnameservice/ans/internal/config"
	"github.com/agentnameservice/ans/internal/port"
)

func buildCertificateValidator(ctx context.Context, cfg config.CA, issuer port.ServerCertificateIssuer) (*cert.X509Validator, error) {
	selfIssuer := cfg.Server != nil && !cfg.Server.IsACME()
	if cfg.Validation.RootsFile == "" && !selfIssuer {
		return cert.NewX509Validator(), nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system roots: %w", err)
	}
	if cfg.Validation.RootsFile != "" {
		pem, err := os.ReadFile(cfg.Validation.RootsFile)
		if err != nil {
			return nil, fmt.Errorf("read certificate roots: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("certificate roots file contains no certificates")
		}
	}
	// Selecting the self issuer explicitly trusts that issuer's root. It
	// does not disable verification or trust arbitrary caller-supplied roots.
	if selfIssuer {
		if issuer == nil {
			return nil, errors.New("self server issuer is not initialized")
		}
		pem, err := issuer.GetCACertificate(ctx)
		if err != nil {
			return nil, fmt.Errorf("load self server root: %w", err)
		}
		if !roots.AppendCertsFromPEM([]byte(pem)) {
			return nil, errors.New("self server issuer returned no root certificate")
		}
	}
	return cert.NewX509Validator(cert.WithTrustedRoots(roots)), nil
}
