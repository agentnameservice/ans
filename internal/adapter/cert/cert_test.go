package cert

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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

// ----- Test helpers -----

// buildCSR constructs a PEM-encoded CSR with the given URI SAN or DNS SANs.
func buildCSR(t *testing.T, cn string, uri *url.URL, dns []string) string {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cn},
		DNSNames:           dns,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	if uri != nil {
		tmpl.URIs = []*url.URL{uri}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// buildByocLeafAndChain returns (leafPEM, chainPEM). Both are self-signed
// with the given FQDN as DNS SAN + CN, suitable for exercising the
// validator in skip-chain mode.
func buildByocLeafAndChain(t *testing.T, fqdn string, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: fqdn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{fqdn},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	// Chain is the same cert repeated as a stand-in intermediate; the
	// validator tolerates arbitrary chain bytes when skipChainVerify is set.
	return certPEM, certPEM
}

// ----- SelfCA -----

func TestNewSelfCA_RejectsBadValidity(t *testing.T) {
	_, err := NewSelfCA(t.TempDir(), "org", 0)
	if err == nil {
		t.Error("expected error for validityDays=0")
	}
}

func TestNewSelfCA_RespectsIdentityTTLOption(t *testing.T) {
	ca, err := NewSelfCA(t.TempDir(), "org", 365, WithIdentityTTL(13*time.Hour))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if ca.identityTTL != 13*time.Hour {
		t.Errorf("WithIdentityTTL ignored: got %v", ca.identityTTL)
	}
}

func TestSelfCA_IssueIdentityCertificate_AndGetCA(t *testing.T) {
	ca, err := NewSelfCA(t.TempDir(), "TestOrg", 365)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	ansURI, _ := url.Parse("ans://v1.0.0.agent.example.com")
	csrPEM := buildCSR(t, "ignored", ansURI, nil)

	issued, err := ca.IssueIdentityCertificate(context.Background(), csrPEM, ansURI.String())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.CertPEM == "" || issued.ChainPEM == "" {
		t.Error("expected non-empty PEM output")
	}
	if issued.SerialNumber == "" {
		t.Error("expected non-empty serial")
	}
	if !issued.ExpiresAt.After(issued.IssuedAt) {
		t.Error("ExpiresAt must be after IssuedAt")
	}

	// Verify the cert parses + contains the URI SAN we asked for.
	block, _ := pem.Decode([]byte(issued.CertPEM))
	if block == nil {
		t.Fatal("cert PEM did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != ansURI.String() {
		t.Errorf("URI SAN: got %v, want [%s]", cert.URIs, ansURI)
	}

	// GetCACertificate returns the root PEM block.
	rootPEM, err := ca.GetCACertificate(context.Background())
	if err != nil {
		t.Fatalf("get ca: %v", err)
	}
	if !strings.Contains(rootPEM, "BEGIN CERTIFICATE") {
		t.Errorf("GetCACertificate: missing PEM block: %s", rootPEM)
	}
}

func TestSelfCA_IssueIdentityCertificate_RejectsBadCSR(t *testing.T) {
	ca, _ := NewSelfCA(t.TempDir(), "org", 365)
	// No URI SAN → ValidateIdentityCSR rejects.
	csrPEM := buildCSR(t, "cn", nil, nil)
	_, err := ca.IssueIdentityCertificate(context.Background(), csrPEM, "ans://v1.0.0.x")
	if err == nil {
		t.Error("expected rejection")
	}
}

func TestSelfCA_RevokeAndIsRevoked(t *testing.T) {
	ca, _ := NewSelfCA(t.TempDir(), "org", 365)
	serial := "DEADBEEF"
	if ca.IsRevoked(serial) {
		t.Error("fresh CA should have no revocations")
	}
	if err := ca.RevokeCertificate(context.Background(), port.RevokeCertificateRequest{
		SerialNumber: serial,
		Reason:       domain.RevocationKeyCompromise,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !ca.IsRevoked(serial) {
		t.Error("IsRevoked should be true after Revoke")
	}
	// Idempotent per the port contract.
	if err := ca.RevokeCertificate(context.Background(), port.RevokeCertificateRequest{
		SerialNumber: serial,
		Reason:       domain.RevocationKeyCompromise,
	}); err != nil {
		t.Fatalf("re-revoke must be idempotent: %v", err)
	}
	// Serial is mandatory.
	if err := ca.RevokeCertificate(context.Background(), port.RevokeCertificateRequest{
		Reason: domain.RevocationKeyCompromise,
	}); err == nil {
		t.Error("want error for missing serial")
	}
}

func TestSelfCA_PersistsRootAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	ca1, err := NewSelfCA(dir, "org", 365)
	if err != nil {
		t.Fatal(err)
	}
	pem1, _ := ca1.GetCACertificate(context.Background())

	// Second instance should load the same root.
	ca2, err := NewSelfCA(dir, "org", 365)
	if err != nil {
		t.Fatal(err)
	}
	pem2, _ := ca2.GetCACertificate(context.Background())
	if pem1 != pem2 {
		t.Error("root should persist across NewSelfCA calls")
	}
}

func TestSelfCA_LoadRoot_MalformedKey(t *testing.T) {
	dir := t.TempDir()
	// Seed a broken root key so loadRoot fails.
	if err := os.WriteFile(filepath.Join(dir, "root.key"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.crt"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewSelfCA(dir, "org", 365)
	if err == nil {
		t.Error("expected error on malformed root files")
	}
}

// ----- ServerSelfCA -----

func TestNewServerSelfCA_RejectsBadValidity(t *testing.T) {
	_, err := NewServerSelfCA(t.TempDir(), "org", 0)
	if err == nil {
		t.Error("expected error for validityDays=0")
	}
}

func TestNewServerSelfCA_RespectsTTLOption(t *testing.T) {
	ca, err := NewServerSelfCA(t.TempDir(), "org", 365, WithServerCertTTL(42*time.Hour))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if ca.serverTTL != 42*time.Hour {
		t.Errorf("WithServerCertTTL ignored: got %v", ca.serverTTL)
	}
}

func TestServerSelfCA_OrderLifecycle_And_GetCA(t *testing.T) {
	ca, err := NewServerSelfCA(t.TempDir(), "ServerOrg", 365)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// CreateOrder self-issues both challenge types with distinct
	// tokens and a non-empty order ref.
	order, err := ca.CreateOrder(context.Background(), "agent.example.com")
	if err != nil {
		t.Fatalf("create order: %v", err)
	}
	if order.OrderRef == "" || order.State != domain.OrderStatePending {
		t.Errorf("order shape: ref=%q state=%q", order.OrderRef, order.State)
	}
	dns01, ok := order.ChallengeOfType(domain.ChallengeTypeDNS01)
	if !ok || dns01.Token == "" {
		t.Error("missing DNS-01 challenge")
	}
	http01, ok := order.ChallengeOfType(domain.ChallengeTypeHTTP01)
	if !ok || http01.Token == "" {
		t.Error("missing HTTP-01 challenge")
	}
	if dns01.Token == http01.Token {
		t.Error("challenge tokens must be independent")
	}
	if order.ExpiresAt.Before(time.Now()) {
		t.Error("order must expire in the future")
	}

	// CSR with DNS SAN matching expected FQDN.
	csrPEM := buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"})
	issued, err := ca.FinalizeOrder(context.Background(), port.FinalizeOrderRequest{
		OrderRef: order.OrderRef,
		CSRPEM:   csrPEM,
		FQDN:     "agent.example.com",
		Verified: []domain.ChallengeType{domain.ChallengeTypeDNS01},
	})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if issued.CertPEM == "" || issued.ChainPEM == "" {
		t.Error("expected non-empty PEM output")
	}
	block, _ := pem.Decode([]byte(issued.CertPEM))
	cert, _ := x509.ParseCertificate(block.Bytes)
	// Server cert must have ExtKeyUsageServerAuth.
	hasServerAuth := false
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("server cert missing ExtKeyUsageServerAuth")
	}

	// GetCACertificate returns PEM.
	rootPEM, err := ca.GetCACertificate(context.Background())
	if err != nil || !strings.Contains(rootPEM, "BEGIN CERTIFICATE") {
		t.Errorf("GetCACertificate: err=%v, pem=%q", err, rootPEM)
	}
}

func TestServerSelfCA_PersistsRootAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	ca1, err := NewServerSelfCA(dir, "org", 365)
	if err != nil {
		t.Fatal(err)
	}
	pem1, _ := ca1.GetCACertificate(context.Background())

	ca2, err := NewServerSelfCA(dir, "org", 365)
	if err != nil {
		t.Fatal(err)
	}
	pem2, _ := ca2.GetCACertificate(context.Background())
	if pem1 != pem2 {
		t.Error("server CA root should persist across instances")
	}
}

func TestServerSelfCA_LoadRoot_MalformedKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server-root.key"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server-root.crt"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServerSelfCA(dir, "org", 365); err == nil {
		t.Error("expected error on malformed server root files")
	}
}

func TestServerSelfCA_FinalizeOrder_RejectsBadCSR(t *testing.T) {
	ca, _ := NewServerSelfCA(t.TempDir(), "o", 365)
	// CN doesn't match, no DNS SAN → ValidateServerCSR rejects.
	csrPEM := buildCSR(t, "other.example.com", nil, nil)
	_, err := ca.FinalizeOrder(context.Background(), port.FinalizeOrderRequest{
		CSRPEM: csrPEM,
		FQDN:   "agent.example.com",
	})
	if err == nil {
		t.Error("expected FQDN-mismatch rejection")
	}
}

func TestServerSelfCA_CreateOrder_RequiresFQDN(t *testing.T) {
	ca, _ := NewServerSelfCA(t.TempDir(), "o", 365)
	if _, err := ca.CreateOrder(context.Background(), ""); err == nil {
		t.Error("expected error for empty fqdn")
	}
}

// TestServerSelfCA_FinalizeOrder_RequiresOrderRef pins the contract
// guard: even though the stateless self-CA never looks anything up by
// the order ref, it must reject an empty ref so a caller that drops the
// persisted ref fails the same way it would against an ACME provider
// rather than silently issuing.
func TestServerSelfCA_FinalizeOrder_RequiresOrderRef(t *testing.T) {
	ca, _ := NewServerSelfCA(t.TempDir(), "o", 365)
	csrPEM := buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"})
	_, err := ca.FinalizeOrder(context.Background(), port.FinalizeOrderRequest{
		OrderRef: "",
		CSRPEM:   csrPEM,
		FQDN:     "agent.example.com",
		Verified: []domain.ChallengeType{domain.ChallengeTypeDNS01},
	})
	if err == nil {
		t.Error("expected error for empty order ref")
	}
}

func TestNewServerSelfCA_RespectsOrderTTLOption(t *testing.T) {
	ca, err := NewServerSelfCA(t.TempDir(), "org", 365, WithOrderTTL(3*time.Hour))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if ca.orderTTL != 3*time.Hour {
		t.Errorf("WithOrderTTL ignored: got %v", ca.orderTTL)
	}
	order, err := ca.CreateOrder(context.Background(), "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if remaining := time.Until(order.ExpiresAt); remaining > 3*time.Hour || remaining < 2*time.Hour {
		t.Errorf("order expiry should honor the 3h TTL, got %v remaining", remaining)
	}
}

// ----- X509Validator -----

func TestX509Validator_SkipChainVerify_HappyPath(t *testing.T) {
	v := NewX509Validator(WithSkipChainVerify())
	leaf, chain := buildByocLeafAndChain(t, "agent.example.com",
		time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	vc, err := v.ValidateServerCertificate(context.Background(), leaf, chain, "agent.example.com")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if vc.CN != "agent.example.com" {
		t.Errorf("CN: got %q", vc.CN)
	}
	if vc.Fingerprint == "" {
		t.Error("fingerprint missing")
	}
}

func TestX509Validator_RejectsBadLeafPEM(t *testing.T) {
	v := NewX509Validator(WithSkipChainVerify())
	_, err := v.ValidateServerCertificate(context.Background(), "not a pem", "", "agent.example.com")
	if !errors.Is(err, anscrypto.ErrPEMParse) {
		t.Errorf("want ErrPEMParse, got %v", err)
	}
}

func TestX509Validator_RejectsExpiredLeaf(t *testing.T) {
	v := NewX509Validator(WithSkipChainVerify())
	leaf, _ := buildByocLeafAndChain(t, "agent.example.com",
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	_, err := v.ValidateServerCertificate(context.Background(), leaf, "", "agent.example.com")
	if !errors.Is(err, anscrypto.ErrCertExpired) {
		t.Errorf("want ErrCertExpired, got %v", err)
	}
}

func TestX509Validator_RejectsFQDNMismatch(t *testing.T) {
	v := NewX509Validator(WithSkipChainVerify())
	leaf, _ := buildByocLeafAndChain(t, "other.example.com",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, err := v.ValidateServerCertificate(context.Background(), leaf, "", "agent.example.com")
	if !errors.Is(err, anscrypto.ErrFQDNMismatch) {
		t.Errorf("want ErrFQDNMismatch, got %v", err)
	}
}

func TestX509Validator_RejectsBadChainPEM(t *testing.T) {
	v := NewX509Validator(WithSkipChainVerify())
	leaf, _ := buildByocLeafAndChain(t, "agent.example.com",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	garbageChain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bogus")}))
	_, err := v.ValidateServerCertificate(context.Background(), leaf, garbageChain, "agent.example.com")
	if !errors.Is(err, anscrypto.ErrCertParse) {
		t.Errorf("want ErrCertParse, got %v", err)
	}
}

func TestX509Validator_ChainVerifyFailsOnSelfSigned(t *testing.T) {
	// No WithSkipChainVerify; a self-signed cert has no path to system roots.
	v := NewX509Validator()
	leaf, _ := buildByocLeafAndChain(t, "agent.example.com",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, err := v.ValidateServerCertificate(context.Background(), leaf, "", "agent.example.com")
	if !errors.Is(err, anscrypto.ErrChainInvalid) {
		t.Errorf("want ErrChainInvalid, got %v", err)
	}
}

// ----- ValidateIdentityCSR + ValidateServerCSR pass-throughs -----

func TestX509Validator_ValidateIdentityCSR_HappyAndBad(t *testing.T) {
	v := NewX509Validator()
	ansURI, _ := url.Parse("ans://v1.0.0.agent.example.com")
	good := buildCSR(t, "ignored", ansURI, nil)
	if err := v.ValidateIdentityCSR(context.Background(), good, ansURI.String()); err != nil {
		t.Errorf("good csr: %v", err)
	}
	bad := buildCSR(t, "cn", nil, nil)
	if err := v.ValidateIdentityCSR(context.Background(), bad, ansURI.String()); err == nil {
		t.Error("missing URI SAN should fail")
	}
}

func TestX509Validator_ValidateServerCSR_HappyAndBad(t *testing.T) {
	v := NewX509Validator()
	good := buildCSR(t, "cn", nil, []string{"agent.example.com"})
	if err := v.ValidateServerCSR(context.Background(), good, "agent.example.com"); err != nil {
		t.Errorf("good: %v", err)
	}
	bad := buildCSR(t, "other", nil, []string{"other.example.com"})
	if err := v.ValidateServerCSR(context.Background(), bad, "agent.example.com"); err == nil {
		t.Error("mismatch should fail")
	}
}
