package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentnameservice/ans/internal/adapter/cert"
	"github.com/agentnameservice/ans/internal/config"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

func TestCertificateValidator_TrustsOnlySystemOrConfiguredRoots(t *testing.T) {
	issuer, err := cert.NewServerSelfCA(t.TempDir(), "Local demo CA", 90)
	if err != nil {
		t.Fatal(err)
	}
	issued := issueValidatorTestCert(t, issuer)
	defaultValidator, err := buildCertificateValidator(t.Context(), config.CA{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := defaultValidator.ValidateServerCertificate(t.Context(), issued.CertPEM, issued.ChainPEM, "agent.example.com"); err == nil {
		t.Fatal("default executable wiring trusted an arbitrary private CA")
	}
	local, err := buildCertificateValidator(t.Context(), config.CA{Server: &config.CAServer{Type: "self"}}, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := local.ValidateServerCertificate(t.Context(), issued.CertPEM, issued.ChainPEM, "agent.example.com"); err != nil {
		t.Fatalf("explicit local issuer rejected: %v", err)
	}
	untrusted, err := cert.NewServerSelfCA(t.TempDir(), "Unrelated CA", 90)
	if err != nil {
		t.Fatal(err)
	}
	other := issueValidatorTestCert(t, untrusted)
	if _, err := local.ValidateServerCertificate(t.Context(), other.CertPEM, other.ChainPEM, "agent.example.com"); err == nil {
		t.Fatal("local issuer selection disabled chain verification")
	}
	root, err := issuer.GetCACertificate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trusted.pem")
	if err := os.WriteFile(path, []byte(root), 0600); err != nil {
		t.Fatal(err)
	}
	configured, err := buildCertificateValidator(t.Context(), config.CA{
		Validation: config.CertificateValidation{RootsFile: path},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configured.ValidateServerCertificate(t.Context(), issued.CertPEM, issued.ChainPEM, "agent.example.com"); err != nil {
		t.Fatalf("configured root rejected: %v", err)
	}
	if _, err := configured.ValidateServerCertificate(t.Context(), issued.CertPEM, issued.ChainPEM, "different.example.com"); err == nil {
		t.Fatal("configured root disabled hostname verification")
	}
}

func issueValidatorTestCert(t *testing.T, issuer port.ServerCertificateIssuer) *port.IssuedCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "agent.example.com"}, DNSNames: []string{"agent.example.com"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	order, err := issuer.CreateOrder(t.Context(), "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: order.OrderRef, FQDN: "agent.example.com",
		CSRPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		Verified: []domain.ChallengeType{domain.ChallengeTypeDNS01},
	})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func TestCertificateValidator_InvalidConfigurationFailsStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []config.CA{
		{Server: &config.CAServer{Type: "self"}},
		{Validation: config.CertificateValidation{RootsFile: path}},
		{Validation: config.CertificateValidation{RootsFile: path + ".missing"}},
	} {
		if _, err := buildCertificateValidator(t.Context(), cfg, nil); err == nil {
			t.Fatalf("invalid CA configuration accepted: %+v", cfg)
		}
	}
}
