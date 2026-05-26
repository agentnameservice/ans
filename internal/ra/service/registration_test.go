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
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/adapter/cert"
	"github.com/godaddy/ans/internal/adapter/eventbus"
	"github.com/godaddy/ans/internal/adapter/keymanager"
	"github.com/godaddy/ans/internal/adapter/store/sqlite"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/service"
)

// TestRegistration_NoOutboxEmit pins the V1-aligned terminal-only
// event model: POST /v2/ans/agents (like POST /v1/agents/register)
// does NOT enqueue anything to the outbox. The single AGENT_REGISTERED
// leaf fires at verify-dns ACTIVE transition — that emit path is
// covered by TestVerifyDNS_EmitsAgentRegistered in lifecycle_test.go.
//
// This test exists so a future regression that re-introduces an
// intermediate eager-emit (AGENT_REGISTRATION / DOMAIN_VALIDATION)
// at register time gets caught before it ships.
func TestRegistration_NoOutboxEmit(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	resp, err := fx.svc.RegisterAgent(context.Background(), fx.req)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}
	if resp.Registration.Status != domain.StatusPendingValidation {
		t.Fatalf("status: got %q want PENDING_VALIDATION", resp.Registration.Status)
	}

	rows, err := fx.outboxStore.Claim(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("outbox rows: want 0 after registration (terminal-only event model), got %d: %+v",
			len(rows), rows)
	}
}

// TestRegistration_NoSigner proves the service doesn't crash when no
// RA signer is configured. Under the V1-aligned terminal-only event
// model there's no register-time outbox emit to sign, so the assertion
// is simply that RegisterAgent returns cleanly.
func TestRegistration_NoSigner(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	// Drop the signer — rebuild without WithSigner. Keep the server
	// CA wired so the default request (which uses the CSR path)
	// still succeeds.
	svcNoSig := service.NewRegistrationService(
		fx.agents, fx.endpoints, fx.certs, fx.byoc, fx.renewals,
		fx.validator, fx.identityCA, fx.bus, fx.outboxStore, fx.uow,
		fx.discoveryReg,
	).WithServerCertificateAuthority(fx.serverCA)

	// Use a fresh ANS name + matching CSR + matching endpoints so
	// every validation that checks FQDN/SAN passes.
	semver, _ := domain.ParseSemVer("2.0.0")
	an, _ := domain.NewAnsName(semver, "other.example.com")
	req := fx.req
	req.AnsName = an
	req.IdentityCSRPEM = testCSR(t, an.String())
	req.ServerCsrPEM = testServerCSR(t, an.FQDN())
	req.Endpoints = []domain.AgentEndpoint{{
		Protocol:   domain.Protocol("MCP"),
		AgentURL:   "https://other.example.com/mcp",
		Transports: []domain.Transport{domain.Transport("SSE")},
	}}

	if _, err := svcNoSig.RegisterAgent(context.Background(), req); err != nil {
		t.Fatalf("RegisterAgent unsigned: %v", err)
	}
	// No outbox rows at register time — terminal-only event model.
	rows, err := fx.outboxStore.Claim(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("outbox rows at register time: want 0, got %d", len(rows))
	}
}

// TestRegistration_RollsBackOnPartialFailure pins the transactional
// invariant of RegisterAgent: if any store write inside the
// persistence chain fails, the whole batch must roll back and the
// caller must see no partial state. We swap the real EndpointStore
// for a fake that errors on Save and assert the agent row never
// landed in the agents table — proving uow.Run rolled the
// already-written agent row back.
//
// This is the regression guard for the original bug: pre-UnitOfWork,
// RegisterAgent committed agents.Save before calling endpoints.Save,
// so a downstream failure left an orphaned agent that subsequent
// FindByAgentID calls would still return.
func TestRegistration_RollsBackOnPartialFailure(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	failingEndpoints := &failingEndpointStore{
		err: domain.NewInternalError("ENDPOINT_SAVE_FAIL", "simulated", nil),
	}

	// Rebuild the service with the failing endpoint store and the
	// real UoW from the fixture. The agent.Save call inside the tx
	// hits the live DB — that's the point: the tx must roll it back
	// when the subsequent endpoints.Save errors.
	svc := service.NewRegistrationService(
		fx.agents, failingEndpoints, fx.certs, fx.byoc, fx.renewals,
		fx.validator, fx.identityCA, fx.bus, fx.outboxStore, fx.uow,
		fx.discoveryReg,
	).WithServerCertificateAuthority(fx.serverCA)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err == nil {
		t.Fatal("RegisterAgent should have surfaced the endpoint-store error")
	}

	// The agent row must NOT exist — uow.Run rolled it back. Pre-fix,
	// agents.Save would have committed before endpoints.Save ran, so
	// FindByAnsName here would have returned the orphaned row.
	got, err := fx.agents.FindByAnsName(context.Background(), fx.req.AnsName)
	if err == nil && got != nil {
		t.Fatalf("agent row leaked past rollback: %+v", got)
	}
	if !errors.Is(err, domain.ErrNotFound) && err != nil {
		// Either ErrNotFound or a non-fatal NOT_FOUND error from the
		// SQLite mapper is acceptable; both prove the row is absent.
		// A nil error with non-nil `got` is the rollback failure.
		t.Logf("FindByAnsName error after rollback (non-fatal): %v", err)
	}
}

type failingEndpointStore struct{ err error }

func (f *failingEndpointStore) Save(_ context.Context, _ *domain.AgentEndpoints) error {
	return f.err
}

func (f *failingEndpointStore) FindByAgentID(_ context.Context, _ string) (*domain.AgentEndpoints, error) {
	return nil, f.err
}

func (f *failingEndpointStore) FindByAgentIDs(_ context.Context, _ []string) (map[string]*domain.AgentEndpoints, error) {
	return nil, f.err
}

// TestRevoke_RollsBackOnOutboxFailure pins the same transactional
// invariant for Revoke: agent state, identity-cert status updates,
// and the outbox row must commit atomically. We swap the outbox for
// a fake that errors on Enqueue, drive the agent to ACTIVE, then
// call Revoke and assert (a) the agent is still ACTIVE (Revoke's
// agents.Save was rolled back), and (b) every identity cert is still
// VALID (the loop's UpdateCertificateStatus calls were rolled back
// too). Pre-uow, Revoke would have committed agents.Save and the
// cert updates before the outbox enqueue failed, leaving the agent
// REVOKED with no TL record of why.
func TestRevoke_RollsBackOnOutboxFailure(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	// Drive a fresh registration to ACTIVE through the real service
	// before swapping in the failing outbox; we want pre-revoke state
	// (ACTIVE agent + VALID identity cert) to be the rollback target.
	if _, err := fx.svc.RegisterAgent(context.Background(), fx.req); err == nil {
		// Pre-conditions for the test: agent committed, identity cert
		// signed via verify-acme, agent moved to ACTIVE via verify-dns.
		if _, err := fx.svc.VerifyACME(context.Background(),
			anyAgentID(t, fx, fx.req.AnsName), service.VerifyInput{}); err != nil {
			t.Fatalf("verify-acme prereq: %v", err)
		}
		if _, err := fx.svc.VerifyDNS(context.Background(),
			anyAgentID(t, fx, fx.req.AnsName), service.VerifyInput{}); err != nil {
			t.Fatalf("verify-dns prereq: %v", err)
		}
	} else {
		t.Fatalf("register prereq: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	// Rebuild the service with a failing outbox; everything else
	// stays real so the agent.Save + cert-status writes inside the
	// tx hit the live DB.
	svc := service.NewRegistrationService(
		fx.agents, fx.endpoints, fx.certs, fx.byoc, fx.renewals,
		fx.validator, fx.identityCA, fx.bus, &failingOutbox{}, fx.uow,
		fx.discoveryReg,
	).WithServerCertificateAuthority(fx.serverCA)

	if _, err := svc.Revoke(context.Background(), agentID, service.RevokeInput{
		Reason: domain.RevocationKeyCompromise,
	}); err == nil {
		t.Fatal("Revoke should have surfaced the outbox-enqueue error")
	}

	// Agent must still be ACTIVE — uow.Run rolled the agents.Save back.
	got, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatalf("FindByAgentID after rollback: %v", err)
	}
	if got.Status != domain.StatusActive {
		t.Errorf("agent status leaked past rollback: got %q want %q",
			got.Status, domain.StatusActive)
	}

	// Identity cert must still be VALID — same rollback covers the
	// UpdateCertificateStatus loop.
	certs, err := fx.certs.FindIdentityCertificatesByAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("FindIdentityCertificatesByAgent: %v", err)
	}
	for _, c := range certs {
		if c.Status != domain.CertStatusValid {
			t.Errorf("cert %s status leaked past rollback: %q", c.CSRID, c.Status)
		}
	}
}

// failingOutbox is the OutboxEnqueuer the rollback test injects to
// force the in-tx outbox write to fail. Mirrors the failingEndpointStore
// pattern above.
type failingOutbox struct{}

func (failingOutbox) Enqueue(_ context.Context, _, _, _ string, _ []byte, _ time.Time) (int64, error) {
	return 0, errors.New("simulated outbox failure")
}

// anyAgentID looks up the agentID for the given ANS name. Helpers
// only — the AnsName is unique per fixture, so the lookup is
// deterministic.
func anyAgentID(t *testing.T, fx *regFixture, ans domain.AnsName) string {
	t.Helper()
	reg, err := fx.agents.FindByAnsName(context.Background(), ans)
	if err != nil {
		t.Fatalf("FindByAnsName: %v", err)
	}
	return reg.AgentID
}

// ----- fixture -----

type regFixture struct {
	svc          *service.RegistrationService
	req          service.RegisterRequest
	outboxStore  *sqlite.OutboxStore
	uow          port.UnitOfWork
	agents       port.AgentStore
	endpoints    port.EndpointStore
	certs        port.CertificateStore
	byoc         port.ByocCertificateStore
	renewals     port.RenewalStore
	validator    port.CertificateValidator
	identityCA   port.IdentityCertificateAuthority
	serverCA     port.ServerCertificateAuthority
	bus          port.EventBus
	discoveryReg port.DiscoveryRegistry
	signerPubPEM string
}

func newRegFixture(t *testing.T) *regFixture {
	t.Helper()
	dir := t.TempDir()

	// Real in-memory SQLite db for the outbox + agent stores.
	db, err := sqlite.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	agents := sqlite.NewAgentStore(db)
	endpoints := sqlite.NewEndpointStore(db)
	certsStore := sqlite.NewCertificateStore(db)
	byoc := sqlite.NewByocCertificateStore(db)
	renewals := sqlite.NewRenewalStore(db)
	outbox := sqlite.NewOutboxStore(db)

	// Real SelfCA.
	identityCA, err := cert.NewSelfCA(dir+"/ca", "Test CA", 365)
	if err != nil {
		t.Fatal(err)
	}

	// Real validator that skips chain verification (local-dev config).
	validator := cert.NewX509Validator(cert.WithSkipChainVerify())

	bus := eventbus.NewInMemoryBus(zerolog.Nop())

	// Signer key for the RA.
	km, err := keymanager.NewFileKeyManager(dir + "/keys")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := km.EnsureKey(context.Background(), "ra-signer", port.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	pub, err := km.GetPublicKey(context.Background(), "ra-signer")
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	// Wire a server CA so the default CSR path exercises the full
	// sign flow. Without this the service rejects registrations that
	// don't supply either serverCsrPEM or serverCertificatePEM.
	serverCA, err := cert.NewServerSelfCA(dir+"/server-ca", "Test Server CA", 365)
	if err != nil {
		t.Fatal(err)
	}

	discoveryReg, err := service.NewDefaultDiscoveryRegistry()
	if err != nil {
		t.Fatal(err)
	}

	svc := service.NewRegistrationService(
		agents, endpoints, certsStore, byoc, renewals, validator, identityCA, bus, outbox, db, discoveryReg,
	).WithSigner(service.EventSigner{
		KeyManager: km,
		KeyID:      "ra-signer",
		RaID:       "ra-test",
	}).WithServerCertificateAuthority(serverCA)

	// Build a valid identity CSR whose URI SAN matches the ANS name
	// and a server CSR whose DNS SAN matches the FQDN.
	semver, _ := domain.ParseSemVer("1.0.0")
	ansName, _ := domain.NewAnsName(semver, "agent.example.com")
	csrPEM := testCSR(t, ansName.String())
	serverCSR := testServerCSR(t, ansName.FQDN())

	return &regFixture{
		svc:          svc,
		outboxStore:  outbox,
		uow:          db,
		agents:       agents,
		endpoints:    endpoints,
		certs:        certsStore,
		byoc:         byoc,
		renewals:     renewals,
		validator:    validator,
		identityCA:   identityCA,
		serverCA:     serverCA,
		bus:          bus,
		discoveryReg: discoveryReg,
		signerPubPEM: pubPEM,
		req: service.RegisterRequest{
			OwnerID:     "owner-1",
			AnsName:     ansName,
			DisplayName: "test-agent",
			Description: "a test agent",
			Endpoints: []domain.AgentEndpoint{{
				Protocol:   domain.Protocol("MCP"),
				AgentURL:   "https://agent.example.com/mcp",
				Transports: []domain.Transport{domain.Transport("SSE")},
			}},
			IdentityCSRPEM: csrPEM,
			ServerCsrPEM:   serverCSR,
		},
	}
}

// testServerCSR builds a server-shaped CSR (DNS SAN matching the
// agent FQDN) suitable for the server-cert issuance path.
func testServerCSR(t *testing.T, fqdn string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: fqdn},
		DNSNames:           []string{fqdn},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// testCSR builds a valid PEM-encoded ECDSA P-256 CSR with a URI SAN
// set to `uri` (our ANS name). Uses ecdsa.SignASN1 so the signature is
// acceptable to the X509Validator.
func testCSR(t *testing.T, uri string) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: uri},
		URIs:               parseTestURI(t, uri),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func parseTestURI(t *testing.T, s string) []*url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return []*url.URL{u}
}
