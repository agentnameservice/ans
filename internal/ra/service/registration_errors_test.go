package service_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// asDomainErr is a small helper to unwrap a *domain.Error from an
// arbitrary error chain. Local to this file so it doesn't conflict
// with similar helpers elsewhere in the test corpus.
func asDomainErr(err error, target **domain.Error) bool {
	return errors.As(err, target)
}

// buildSelfSignedServerCert returns a (leafPEM, chainPEM) pair for a
// self-signed cert with the given DNS SAN. Used by the BYOC-shape
// tests below — the validator's WithSkipChainVerify config makes
// these acceptable.
func buildSelfSignedServerCert(t *testing.T, fqdn string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: fqdn},
		DNSNames:              []string{fqdn},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return leafPEM, leafPEM
}

// TestRegisterAgent_RejectsBothCSRAndCert verifies the
// "exactly one of serverCsrPEM or serverCertificatePEM" check at
// the top of RegisterAgent. Pre-coverage we only saw the happy
// (CSR-only) path through the integration tests.
func TestRegisterAgent_RejectsBothCSRAndCert(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	req := fx.req
	// Set both — request should be rejected with 422.
	leafPEM, chainPEM := buildSelfSignedServerCert(t, fx.req.AnsName.FQDN())
	req.ServerCertificatePEM = leafPEM
	req.ServerCertificateChainPEM = chainPEM

	_, err := fx.svc.RegisterAgent(context.Background(), req)
	if err == nil {
		t.Fatal("RegisterAgent should reject when both CSR and BYOC cert provided")
	}
	if !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("error message: got %q, expected to mention 'exactly one'", err.Error())
	}
}

// TestRegisterAgent_RejectsNeitherCSRNorCert covers the same check
// when both paths are empty.
func TestRegisterAgent_RejectsNeitherCSRNorCert(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	req := fx.req
	req.ServerCsrPEM = ""
	req.ServerCertificatePEM = ""

	_, err := fx.svc.RegisterAgent(context.Background(), req)
	if err == nil {
		t.Fatal("RegisterAgent should reject when neither CSR nor BYOC cert provided")
	}
	var de *domain.Error
	if !asDomainErr(err, &de) {
		t.Fatalf("error: %v", err)
	}
	if de.Code != "INVALID_SERVER_CERT_INPUT" {
		t.Errorf("code: got %q want INVALID_SERVER_CERT_INPUT", de.Code)
	}
}

// TestRegisterAgent_RejectsDuplicateAnsName covers the
// ExistsByAnsName→ANS_NAME_TAKEN early-return branch.
func TestRegisterAgent_RejectsDuplicateAnsName(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	// Register once successfully.
	if _, err := fx.svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("first register: %v", err)
	}

	// Re-register with the same ANS name → ANS_NAME_TAKEN.
	_, err := fx.svc.RegisterAgent(context.Background(), fx.req)
	if err == nil {
		t.Fatal("duplicate registration should fail with ANS_NAME_TAKEN")
	}
	var de *domain.Error
	if !asDomainErr(err, &de) {
		t.Fatalf("error: %v", err)
	}
	if de.Code != "ANS_NAME_TAKEN" {
		t.Errorf("code: got %q want ANS_NAME_TAKEN", de.Code)
	}
}

// TestRegisterAgent_BYOCCertWithBadFQDN exercises the
// ValidateServerCertificate error path through to the
// INVALID_SERVER_CERT branch.
func TestRegisterAgent_BYOCCertWithBadFQDN(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	req := fx.req
	req.ServerCsrPEM = ""
	// Generate a cert for a *different* FQDN.
	leafPEM, chainPEM := buildSelfSignedServerCert(t, "wrong.example.com")
	req.ServerCertificatePEM = leafPEM
	req.ServerCertificateChainPEM = chainPEM

	_, err := fx.svc.RegisterAgent(context.Background(), req)
	if err == nil {
		t.Fatal("RegisterAgent should reject a BYOC cert whose SAN doesn't include the agent FQDN")
	}
}

// TestRegisterAgent_BadIdentityCSR exercises the identity-CSR
// validation error branch — a CSR whose URI SAN doesn't match the
// ANS name should be rejected.
func TestRegisterAgent_BadIdentityCSR(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	req := fx.req
	// Build a CSR with a different URI SAN than the request's ANS name.
	semver, _ := domain.ParseSemVer("9.9.9")
	otherANS, _ := domain.NewAnsName(semver, "other.example.com")
	req.IdentityCSRPEM = testCSR(t, otherANS.String())

	_, err := fx.svc.RegisterAgent(context.Background(), req)
	if err == nil {
		t.Fatal("RegisterAgent should reject a mismatched identity CSR")
	}
}

// TestRegisterAgent_NoIdentityCSR_Succeeds covers the optional
// identity-CSR path: a registration that omits identityCsrPEM (server
// CSR still present) is accepted, lands PENDING_VALIDATION, and creates
// no identity CSR row. The empty PEM must not reach ValidateIdentityCSR.
func TestRegisterAgent_NoIdentityCSR_Succeeds(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	req := fx.req
	req.IdentityCSRPEM = "" // omit the identity CSR

	resp, err := fx.svc.RegisterAgent(context.Background(), req)
	if err != nil {
		t.Fatalf("register without identity CSR should succeed; got: %v", err)
	}
	if resp.Registration.IdentityCSR != nil {
		t.Fatalf("registration without an identity CSR must have nil IdentityCSR; got %+v", resp.Registration.IdentityCSR)
	}
	if resp.Registration.Status != domain.StatusPendingValidation {
		t.Fatalf("status got %q want PENDING_VALIDATION", resp.Registration.Status)
	}
	csr, err := fx.certs.FindLatestPendingCSRByType(context.Background(), resp.Registration.AgentID, domain.CSRTypeIdentity)
	if err != nil {
		t.Fatalf("FindLatestPendingCSRByType: %v", err)
	}
	if csr != nil {
		t.Fatalf("no identity CSR row expected for an agent registered without an identity CSR; got %+v", csr)
	}
}

// TestRegisterAgent_WithIdentityCSR_Unchanged is a regression pin: when
// identityCsrPEM IS supplied, a pending identity CSR row is created.
// Guards against an over-broad edit that drops the supplied-CSR case.
func TestRegisterAgent_WithIdentityCSR_Unchanged(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	resp, err := fx.svc.RegisterAgent(context.Background(), fx.req)
	if err != nil {
		t.Fatalf("register with identity CSR must behave as before; got: %v", err)
	}
	if resp.Registration.IdentityCSR == nil {
		t.Fatal("supplying identityCsrPEM must populate IdentityCSR")
	}
	csr, err := fx.certs.FindLatestPendingCSRByType(context.Background(), resp.Registration.AgentID, domain.CSRTypeIdentity)
	if err != nil {
		t.Fatalf("FindLatestPendingCSRByType: %v", err)
	}
	if csr == nil {
		t.Fatal("a pending identity CSR row must exist")
	}
}
