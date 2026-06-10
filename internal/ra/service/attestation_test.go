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
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/godaddy/ans/internal/adapter/tlclient"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/service"
)

// --- fakes ---

type fakeAgentStore struct {
	reg *domain.AgentRegistration
	err error
}

func (f *fakeAgentStore) FindByAgentID(_ context.Context, _ string) (*domain.AgentRegistration, error) {
	return f.reg, f.err
}
func (f *fakeAgentStore) Save(context.Context, *domain.AgentRegistration) error { return nil }
func (f *fakeAgentStore) FindByID(context.Context, int64) (*domain.AgentRegistration, error) {
	return nil, nil
}
func (f *fakeAgentStore) FindByAnsName(context.Context, domain.AnsName) (*domain.AgentRegistration, error) {
	return nil, nil
}
func (f *fakeAgentStore) ExistsByAnsName(context.Context, domain.AnsName) (bool, error) {
	return false, nil
}
func (f *fakeAgentStore) FindAllByAgentHost(context.Context, string) ([]*domain.AgentRegistration, error) {
	return nil, nil
}
func (f *fakeAgentStore) FindExistingByFQDN(context.Context, string) ([]*domain.AgentRegistration, error) {
	return nil, nil
}
func (f *fakeAgentStore) ListByOwner(_ context.Context, _ string, _ port.ListFilter) (*port.CursorPage[*domain.AgentRegistration], error) {
	return nil, nil
}
func (f *fakeAgentStore) Delete(context.Context, int64) error { return nil }

type fakeCertStore struct {
	identity []*domain.StoredCertificate
	err      error
}

func (f *fakeCertStore) FindIdentityCertificatesByAgent(_ context.Context, _ string) ([]*domain.StoredCertificate, error) {
	return f.identity, f.err
}
func (f *fakeCertStore) SaveIdentityCertificate(context.Context, string, *domain.StoredCertificate) error {
	return nil
}
func (f *fakeCertStore) UpdateCertificateStatus(context.Context, *domain.StoredCertificate) error {
	return nil
}
func (f *fakeCertStore) SaveCSR(context.Context, string, *domain.AgentCSR) error { return nil }
func (f *fakeCertStore) FindCSRByID(context.Context, string, string) (*domain.AgentCSR, error) {
	return nil, nil
}
func (f *fakeCertStore) FindLatestPendingCSRByType(context.Context, string, domain.CSRType) (*domain.AgentCSR, error) {
	return nil, nil
}

type fakeByocStore struct {
	cert *domain.ByocServerCertificate
	err  error
}

func (f *fakeByocStore) FindLatestValidByAgentID(_ context.Context, _ string) (*domain.ByocServerCertificate, error) {
	return f.cert, f.err
}
func (f *fakeByocStore) Save(context.Context, string, *domain.ByocServerCertificate) error {
	return nil
}
func (f *fakeByocStore) FindByAgentID(context.Context, string) ([]*domain.ByocServerCertificate, error) {
	return nil, nil
}

type fakeTLClient struct {
	receipt []byte
	proof   *tlclient.MerkleProof
	err     error
}

func (f *fakeTLClient) GetReceipt(_ context.Context, _ string) ([]byte, *tlclient.MerkleProof, error) {
	return f.receipt, f.proof, f.err
}

type stubSigner struct{ sig []byte }

func (s *stubSigner) Sign(_ context.Context, _ []byte) ([]byte, error) {
	if s.sig != nil {
		return s.sig, nil
	}
	return make([]byte, 64), nil
}

// --- helpers ---

// mintTestCert produces a real self-signed X.509 cert (PEM) so the
// SPKI-hash path is exercised end-to-end. Subject DN doesn't matter
// — only the SPKI does.
func mintTestCert(t *testing.T) (string, time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBlock), tmpl.NotAfter
}

func validReg(t *testing.T) *domain.AgentRegistration {
	t.Helper()
	v, err := domain.ParseSemVer("1.0.0")
	if err != nil {
		t.Fatalf("parse semver: %v", err)
	}
	name, err := domain.NewAnsName(v, "agent.example.com")
	if err != nil {
		t.Fatalf("new ans name: %v", err)
	}
	return &domain.AgentRegistration{
		AgentID: "11111111-2222-3333-4444-555555555555",
		AnsName: name,
		Status:  domain.StatusActive,
		Details: domain.RegistrationDetails{
			RegistrationTimestamp: time.Unix(1700000000, 0).UTC(),
		},
	}
}

func newServiceForTest(t *testing.T,
	agents *fakeAgentStore,
	certs *fakeCertStore,
	byoc *fakeByocStore,
	tl *fakeTLClient,
) *service.AttestationService {
	t.Helper()
	s, err := service.NewAttestationService(agents, certs, byoc, tl,
		service.AttestationServiceConfig{
			Issuer:   "https://ra.example.com",
			TLLogURL: "https://tl.example.com",
			KeyHash:  []byte{0xAA, 0xBB, 0xCC, 0xDD},
			Signer:   &stubSigner{},
		})
	if err != nil {
		t.Fatalf("NewAttestationService: %v", err)
	}
	return s.WithClock(func() time.Time { return time.Unix(1700001000, 0).UTC() })
}

func validProof() *tlclient.MerkleProof {
	return &tlclient.MerkleProof{
		TreeSize:  5,
		LeafIndex: 2,
		LeafHash:  bytesPattern(0x11, 32),
		RootHash:  bytesPattern(0x22, 32),
		Path:      [][]byte{},
	}
}

// --- tests ---

func TestGenerate_HappyPath(t *testing.T) {
	t.Parallel()
	idPEM, idExp := mintTestCert(t)
	srvPEM, _ := mintTestCert(t)

	reg := validReg(t)
	agents := &fakeAgentStore{reg: reg}
	certs := &fakeCertStore{identity: []*domain.StoredCertificate{{
		CertificatePEM:      idPEM,
		Status:              domain.CertStatusValid,
		ExpirationTimestamp: idExp,
	}}}
	byoc := &fakeByocStore{cert: &domain.ByocServerCertificate{
		LeafCertificatePEM: srvPEM,
		ValidFromTimestamp: time.Unix(1700000000, 0).UTC(),
		ValidToTimestamp:   time.Unix(1800000000, 0).UTC(),
	}}
	tl := &fakeTLClient{
		receipt: []byte("RECEIPT-BYTES"),
		proof:   validProof(),
	}

	s := newServiceForTest(t, agents, certs, byoc, tl)
	out, err := s.Generate(context.Background(), reg.AgentID)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Decode the COSE_Sign1 envelope and assert: tag 18, payload is
	// CBOR, payload's `sub` equals the agent host.
	var tag cbor.Tag
	if err := cbor.Unmarshal(out, &tag); err != nil {
		t.Fatalf("decode cose tag: %v", err)
	}
	if tag.Number != 18 {
		t.Errorf("tag = %d, want 18", tag.Number)
	}
	arr := tag.Content.([]any)
	payloadBytes := arr[2].([]byte)
	var payload map[string]any
	if err := cbor.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload["sub"] != "agent.example.com" {
		t.Errorf("sub = %v, want agent.example.com", payload["sub"])
	}
	if payload["did"] != "did:web:agent.example.com" {
		t.Errorf("did = %v, want did:web:agent.example.com", payload["did"])
	}
	tlMap := payload["tl"].(map[any]any)
	if string(tlMap["receipt"].([]byte)) != "RECEIPT-BYTES" {
		t.Errorf("tl.receipt mismatch")
	}
}

func TestGenerate_AgentNotFound(t *testing.T) {
	t.Parallel()
	s := newServiceForTest(t,
		&fakeAgentStore{err: domain.ErrNotFound},
		&fakeCertStore{}, &fakeByocStore{}, &fakeTLClient{})
	_, err := s.Generate(context.Background(), "any")
	if !errors.Is(err, service.ErrAttestationAgentNotFound) {
		t.Fatalf("err = %v, want ErrAttestationAgentNotFound", err)
	}
}

func TestGenerate_AgentRevoked(t *testing.T) {
	t.Parallel()
	reg := validReg(t)
	reg.Status = domain.StatusRevoked
	s := newServiceForTest(t,
		&fakeAgentStore{reg: reg},
		&fakeCertStore{}, &fakeByocStore{}, &fakeTLClient{})
	_, err := s.Generate(context.Background(), reg.AgentID)
	if !errors.Is(err, service.ErrAttestationAgentRevoked) {
		t.Fatalf("err = %v, want ErrAttestationAgentRevoked", err)
	}
}

func TestGenerate_TLLeafUncommitted(t *testing.T) {
	t.Parallel()
	idPEM, idExp := mintTestCert(t)
	srvPEM, _ := mintTestCert(t)
	reg := validReg(t)
	s := newServiceForTest(t,
		&fakeAgentStore{reg: reg},
		&fakeCertStore{identity: []*domain.StoredCertificate{{
			CertificatePEM: idPEM, Status: domain.CertStatusValid, ExpirationTimestamp: idExp,
		}}},
		&fakeByocStore{cert: &domain.ByocServerCertificate{
			LeafCertificatePEM: srvPEM,
			ValidFromTimestamp: time.Unix(1700000000, 0).UTC(),
			ValidToTimestamp:   time.Unix(1800000000, 0).UTC(),
		}},
		&fakeTLClient{err: tlclient.ErrTLLeafUncommitted})
	_, err := s.Generate(context.Background(), reg.AgentID)
	if !errors.Is(err, service.ErrAttestationLeafUncommitted) {
		t.Fatalf("err = %v, want ErrAttestationLeafUncommitted", err)
	}
}

func TestGenerate_TLNotReachable(t *testing.T) {
	t.Parallel()
	idPEM, idExp := mintTestCert(t)
	srvPEM, _ := mintTestCert(t)
	reg := validReg(t)
	s := newServiceForTest(t,
		&fakeAgentStore{reg: reg},
		&fakeCertStore{identity: []*domain.StoredCertificate{{
			CertificatePEM: idPEM, Status: domain.CertStatusValid, ExpirationTimestamp: idExp,
		}}},
		&fakeByocStore{cert: &domain.ByocServerCertificate{
			LeafCertificatePEM: srvPEM,
			ValidFromTimestamp: time.Unix(1700000000, 0).UTC(),
			ValidToTimestamp:   time.Unix(1800000000, 0).UTC(),
		}},
		&fakeTLClient{err: tlclient.ErrTLNotReachable})
	_, err := s.Generate(context.Background(), reg.AgentID)
	if !errors.Is(err, service.ErrAttestationTLNotReachable) {
		t.Fatalf("err = %v, want ErrAttestationTLNotReachable", err)
	}
}

func TestGenerate_TLReturnsAgentNotFound(t *testing.T) {
	t.Parallel()
	idPEM, idExp := mintTestCert(t)
	srvPEM, _ := mintTestCert(t)
	reg := validReg(t)
	s := newServiceForTest(t,
		&fakeAgentStore{reg: reg},
		&fakeCertStore{identity: []*domain.StoredCertificate{{
			CertificatePEM: idPEM, Status: domain.CertStatusValid, ExpirationTimestamp: idExp,
		}}},
		&fakeByocStore{cert: &domain.ByocServerCertificate{
			LeafCertificatePEM: srvPEM,
			ValidFromTimestamp: time.Unix(1700000000, 0).UTC(),
			ValidToTimestamp:   time.Unix(1800000000, 0).UTC(),
		}},
		&fakeTLClient{err: tlclient.ErrTLAgentNotFound})
	_, err := s.Generate(context.Background(), reg.AgentID)
	if !errors.Is(err, service.ErrAttestationAgentNotFound) {
		t.Fatalf("err = %v, want ErrAttestationAgentNotFound", err)
	}
}

func TestGenerate_NoIdentityCert(t *testing.T) {
	t.Parallel()
	reg := validReg(t)
	s := newServiceForTest(t,
		&fakeAgentStore{reg: reg},
		&fakeCertStore{identity: nil}, // empty
		&fakeByocStore{}, &fakeTLClient{})
	_, err := s.Generate(context.Background(), reg.AgentID)
	if err == nil {
		t.Fatal("want error when no identity cert exists")
	}
}

func TestGenerate_NoServerCert(t *testing.T) {
	t.Parallel()
	idPEM, idExp := mintTestCert(t)
	reg := validReg(t)
	s := newServiceForTest(t,
		&fakeAgentStore{reg: reg},
		&fakeCertStore{identity: []*domain.StoredCertificate{{
			CertificatePEM: idPEM, Status: domain.CertStatusValid, ExpirationTimestamp: idExp,
		}}},
		&fakeByocStore{cert: nil},
		&fakeTLClient{})
	_, err := s.Generate(context.Background(), reg.AgentID)
	if err == nil {
		t.Fatal("want error when no server cert exists")
	}
}

func TestNewAttestationService_Validation(t *testing.T) {
	t.Parallel()
	good := service.AttestationServiceConfig{
		Issuer:   "https://ra.example.com",
		TLLogURL: "https://tl.example.com",
		KeyHash:  []byte{1, 2, 3, 4},
		Signer:   &stubSigner{},
	}
	a, c, b, tl := &fakeAgentStore{}, &fakeCertStore{}, &fakeByocStore{}, &fakeTLClient{}

	cases := map[string]func(*service.AttestationServiceConfig){
		"missing signer":  func(c *service.AttestationServiceConfig) { c.Signer = nil },
		"missing issuer":  func(c *service.AttestationServiceConfig) { c.Issuer = "" },
		"missing log url": func(c *service.AttestationServiceConfig) { c.TLLogURL = "" },
		"wrong key hash":  func(c *service.AttestationServiceConfig) { c.KeyHash = []byte{1, 2, 3} },
		"nil key hash":    func(c *service.AttestationServiceConfig) { c.KeyHash = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := good
			mutate(&cfg)
			if _, err := service.NewAttestationService(a, c, b, tl, cfg); err == nil {
				t.Errorf("want error for %s", name)
			}
		})
	}

	// Nil deps
	if _, err := service.NewAttestationService(nil, c, b, tl, good); err == nil {
		t.Error("want error for nil agents")
	}
	if _, err := service.NewAttestationService(a, nil, b, tl, good); err == nil {
		t.Error("want error for nil certs")
	}
	if _, err := service.NewAttestationService(a, c, nil, tl, good); err == nil {
		t.Error("want error for nil byoc")
	}
	if _, err := service.NewAttestationService(a, c, b, nil, good); err == nil {
		t.Error("want error for nil tl")
	}

	// TTL default
	cfg := good
	cfg.TTL = 0
	if _, err := service.NewAttestationService(a, c, b, tl, cfg); err != nil {
		t.Errorf("default TTL: %v", err)
	}
}

func bytesPattern(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
