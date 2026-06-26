package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/adapter/cert"
	"github.com/godaddy/ans/internal/adapter/cert/acmetest"
	"github.com/godaddy/ans/internal/adapter/dns"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
	"github.com/godaddy/ans/internal/ra/service"
)

// errStrayFinalize is returned by refOnlyIssuer when handed an empty
// order ref — a stray-CSR finalize that should never happen.
var errStrayFinalize = errors.New("refOnlyIssuer: finalize with empty order ref")

// errTransientByoc is a non-ErrNotFound store failure — a busy
// timeout / I/O blip — used to prove the service aborts rather than
// treating a recoverable read failure as "no cert".
var errTransientByoc = errors.New("byoc: database is locked")

// toggleByocStore wraps a real BYOC store and, when fail is set,
// returns a transient error from the lookup. Save and everything else
// delegate to the embedded store so the happy-path setup is unaffected.
type toggleByocStore struct {
	port.ByocCertificateStore
	fail *bool
}

func (s toggleByocStore) FindLatestValidByAgentID(
	ctx context.Context, agentID string,
) (*domain.ByocServerCertificate, error) {
	if *s.fail {
		return nil, errTransientByoc
	}
	return s.ByocCertificateStore.FindLatestValidByAgentID(ctx, agentID)
}

// TestVerifyDNS_TransientServerCertError_Aborts is the regression test
// for the swallow bug: a transient (non-ErrNotFound) failure loading
// the server cert during verify-dns must abort the transition, NOT
// silently activate the agent and sign a terminal AGENT_REGISTERED
// leaf with empty serverCerts[] / no TLSA. An append-only log can never
// take back a wrong leaf, so a recoverable fault must never produce one.
func TestVerifyDNS_TransientServerCertError_Aborts(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	fail := false
	byoc := toggleByocStore{ByocCertificateStore: fx.byoc, fail: &fail}
	svc := service.NewRegistrationService(
		fx.agents, fx.endpoints, fx.certs, byoc, fx.renewals,
		fx.validator, fx.identityCA, fx.bus, fx.outboxStore, fx.uow,
		fx.discoveryReg,
	).WithServerCertificateIssuer(fx.serverCA).WithDNSVerifier(dns.NewNoopVerifier())

	// Register + verify-acme with the store healthy so the CSR-issued
	// server cert is persisted and the agent reaches the pre-DNS state.
	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	if _, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-acme: %v", err)
	}

	// Now make the server-cert load fail transiently and drive verify-dns.
	fail = true
	if _, err := svc.VerifyDNS(context.Background(), agentID, service.VerifyInput{}); !errors.Is(err, errTransientByoc) {
		t.Fatalf("verify-dns must propagate the transient store error, got %v", err)
	}
	// The read path (GetByAgentID) must likewise surface the transient
	// failure rather than returning a detail block with a silently
	// dropped TLSA record.
	if _, err := svc.GetByAgentID(context.Background(), agentID); !errors.Is(err, errTransientByoc) {
		t.Fatalf("GetByAgentID must propagate the transient store error, got %v", err)
	}

	// The agent must NOT have advanced to ACTIVE on a swallowed error.
	fail = false
	reg, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatalf("reload agent: %v", err)
	}
	if reg.Status == domain.StatusActive {
		t.Fatal("agent activated despite a transient server-cert load failure — a corrupted leaf would have been signed")
	}
}

// mustErrCode fails unless err is a *domain.Error carrying exactly the
// given RFC 7807 code. The code is the programmatic contract (per
// CLAUDE.md), so the negative-path tests assert it directly rather
// than settling for "some error occurred" — which would let a
// regression that swaps one failure code for another pass silently.
func mustErrCode(t *testing.T, err error, wantCode string) {
	t.Helper()
	var de *domain.Error
	if !asDomainErr(err, &de) {
		t.Fatalf("want *domain.Error with code %q, got %T: %v", wantCode, err, err)
	}
	if de.Code != wantCode {
		t.Fatalf("error code: got %q want %q (%v)", de.Code, wantCode, err)
	}
}

// asyncIssuer wraps the real self-signed CA but simulates an
// asynchronous provider (an ACME CA such as Let's Encrypt): the first
// `pendingCalls` FinalizeOrder invocations report the order still
// processing, and `failOrder` simulates a terminal provider failure.
// CreateOrder delegates to the real CA so challenge relay stays
// realistic.
type asyncIssuer struct {
	real         port.ServerCertificateIssuer
	pendingCalls int
	failOrder    bool
	// lastVerified records what the service claimed was verified, so
	// tests can assert the RA only tells providers about challenges
	// it actually checked.
	lastVerified []domain.ChallengeType
}

func (a *asyncIssuer) CreateOrder(ctx context.Context, fqdn string) (*domain.CertificateOrder, error) {
	return a.real.CreateOrder(ctx, fqdn)
}

func (a *asyncIssuer) FinalizeOrder(ctx context.Context, req port.FinalizeOrderRequest) (*port.IssuedCert, error) {
	a.lastVerified = req.Verified
	if a.failOrder {
		return nil, port.ErrOrderFailed
	}
	if a.pendingCalls > 0 {
		a.pendingCalls--
		return nil, port.ErrOrderPending
	}
	return a.real.FinalizeOrder(ctx, req)
}

func (a *asyncIssuer) GetCACertificate(ctx context.Context) (string, error) {
	return a.real.GetCACertificate(ctx)
}

// failingDNSVerifier reports every record as unpublished.
type failingDNSVerifier struct{}

func (failingDNSVerifier) VerifyRecords(_ context.Context, _ string, expected []domain.ExpectedDNSRecord) (*port.VerificationResult, error) {
	return &port.VerificationResult{AllRequired: false}, nil
}

// staticHTTPVerifier answers every HTTP-01 check with a fixed result.
type staticHTTPVerifier struct{ ok bool }

func (s staticHTTPVerifier) VerifyHTTPChallenge(_ context.Context, _, _, _ string) (bool, error) {
	return s.ok, nil
}

// rebuildWithIssuer swaps the fixture service's issuer + verifiers.
func rebuildWithIssuer(fx *regFixture, issuer port.ServerCertificateIssuer, dnsV port.DNSVerifier, httpV port.HTTPChallengeVerifier) *service.RegistrationService {
	svc := service.NewRegistrationService(
		fx.agents, fx.endpoints, fx.certs, fx.byoc, fx.renewals,
		fx.validator, fx.identityCA, fx.bus, fx.outboxStore, fx.uow,
		fx.discoveryReg,
	).WithServerCertificateIssuer(issuer)
	if dnsV != nil {
		svc = svc.WithDNSVerifier(dnsV)
	}
	if httpV != nil {
		svc = svc.WithHTTPChallengeVerifier(httpV)
	}
	return svc
}

// TestVerifyACME_AsyncIssuer_PendingThenCompletes drives the full
// asynchronous-provider flow: the first verify-acme passes the gate,
// signs the identity cert, parks the order in ISSUING without
// advancing the lifecycle, and a re-POSTed verify-acme skips the gate
// and finalizes to PENDING_DNS. This is the contract an ACME adapter
// (Let's Encrypt) plugs into.
func TestVerifyACME_AsyncIssuer_PendingThenCompletes(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	issuer := &asyncIssuer{real: fx.serverCA, pendingCalls: 1}
	svc := rebuildWithIssuer(fx, issuer, dns.NewNoopVerifier(), nil)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	// First call: gate passes (noop DNS), provider reports pending.
	res, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	if err != nil {
		t.Fatalf("verify-acme #1: %v", err)
	}
	if !res.Pending {
		t.Fatal("want Pending=true while the provider finalizes")
	}
	if res.Registration.Status != domain.StatusPendingValidation {
		t.Fatalf("lifecycle must stay PENDING_VALIDATION, got %s", res.Registration.Status)
	}
	if res.Registration.CertOrder.State != domain.OrderStateIssuing {
		t.Fatalf("order state: got %s want ISSUING", res.Registration.CertOrder.State)
	}
	if len(issuer.lastVerified) == 0 {
		t.Error("FinalizeOrder must receive the verified challenge types")
	}

	// The ISSUING order state must have been persisted.
	stored, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CertOrder.State != domain.OrderStateIssuing {
		t.Fatalf("persisted order state: got %s want ISSUING", stored.CertOrder.State)
	}
	// The identity cert is provisioned only once the public provider's
	// validation succeeds — the order completing is that proof. While
	// the order is still ISSUING nothing may be signed: a terminally
	// failed order must never leave an identity cert behind.
	idCerts, err := fx.certs.FindIdentityCertificatesByAgent(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(idCerts) != 0 {
		t.Fatalf("identity cert must NOT be issued while the order is pending: certs=%d", len(idCerts))
	}

	// Re-driven call: gate skipped (order ISSUING), finalize succeeds.
	res2, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	if err != nil {
		t.Fatalf("verify-acme #2: %v", err)
	}
	if res2.Pending {
		t.Fatal("second call should complete the order")
	}
	if res2.Registration.Status != domain.StatusPendingDNS {
		t.Fatalf("status after completion: got %s want PENDING_DNS", res2.Registration.Status)
	}
	if res2.Registration.CertOrder.State != domain.OrderStateCompleted {
		t.Fatalf("order state after completion: got %s want COMPLETED", res2.Registration.CertOrder.State)
	}
	if res2.Registration.ServerCert == nil {
		t.Fatal("server cert missing after async completion")
	}
	// Identity cert lands with the completion, carrying the serial
	// captured for later CA-side revocation.
	idCerts, err = fx.certs.FindIdentityCertificatesByAgent(context.Background(), agentID)
	if err != nil || len(idCerts) != 1 {
		t.Fatalf("identity cert must be issued at order completion: certs=%d err=%v", len(idCerts), err)
	}
	if idCerts[0].SerialNumber == "" {
		t.Error("stored identity cert must carry its serial number")
	}
}

// TestVerifyACME_AsyncIssuer_TerminalFailure pins the ErrOrderFailed
// contract: the order flips FAILED (persisted), the lifecycle stays
// PENDING_VALIDATION so the ANS name isn't burned, and subsequent
// verify-acme calls surface the dead order.
func TestVerifyACME_AsyncIssuer_TerminalFailure(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	issuer := &asyncIssuer{real: fx.serverCA, failOrder: true}
	svc := rebuildWithIssuer(fx, issuer, dns.NewNoopVerifier(), nil)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	_, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	mustErrCode(t, err, "CERT_ORDER_FAILED")
	stored, ferr := fx.agents.FindByAgentID(context.Background(), agentID)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if stored.CertOrder.State != domain.OrderStateFailed {
		t.Fatalf("order state: got %s want FAILED", stored.CertOrder.State)
	}
	if stored.Status != domain.StatusPendingValidation {
		t.Fatalf("lifecycle must stay PENDING_VALIDATION, got %s", stored.Status)
	}

	// Re-POST: the gate reports the dead order.
	if _, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{}); err == nil {
		t.Fatal("want CERT_ORDER_FAILED from the gate on a FAILED order")
	}
}

// TestVerifyACME_Gate_MissingArtifact pins the unconditional gate: a
// DNS verifier that finds nothing and no HTTP verifier → 422, no
// issuance, no lifecycle movement.
func TestVerifyACME_Gate_MissingArtifact(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, failingDNSVerifier{}, nil)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	_, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	mustErrCode(t, err, "ACME_CHALLENGE_MISSING")
	stored, _ := fx.agents.FindByAgentID(context.Background(), agentID)
	if stored.Status != domain.StatusPendingValidation {
		t.Fatalf("gate failure must not advance the lifecycle, got %s", stored.Status)
	}
}

// TestVerifyACME_Gate_HTTP01Satisfies pins the any-of semantics: DNS
// artifact absent but the HTTP-01 resource is live → gate passes and
// the registration advances.
func TestVerifyACME_Gate_HTTP01Satisfies(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, failingDNSVerifier{}, staticHTTPVerifier{ok: true})

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	res, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	if err != nil {
		t.Fatalf("verify-acme with live HTTP-01: %v", err)
	}
	if res.Registration.Status != domain.StatusPendingDNS {
		t.Fatalf("status: got %s want PENDING_DNS", res.Registration.Status)
	}
}

// TestVerifyACME_Gate_NoVerifierConfigured pins the misconfiguration
// guard: challenges exist but nothing can check them → error, never a
// silent pass.
func TestVerifyACME_Gate_NoVerifierConfigured(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, nil, nil)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	_, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	mustErrCode(t, err, "CHALLENGE_VERIFIER_MISSING")
}

// TestVerifyACME_Gate_ExpiredChallengeWindow pins expiry enforcement —
// the relayed expiresAt is honored, not decorative.
func TestVerifyACME_Gate_ExpiredChallengeWindow(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	// Age the order past its window directly in the store.
	stored, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	stored.CertOrder.ExpiresAt = time.Now().Add(-time.Minute)
	if err := fx.agents.Save(context.Background(), stored); err != nil {
		t.Fatal(err)
	}

	_, err = svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	mustErrCode(t, err, "ACME_CHALLENGE_EXPIRED")
}

// TestRenewal_AsyncIssuer_PendingThenCompletes drives the renewal
// lane's async path: verify-acme verifies the challenge, the provider
// reports pending (ISSUING_CERTIFICATE), and a re-POST completes the
// renewal with the new TLSA record surfaced.
func TestRenewal_AsyncIssuer_PendingThenCompletes(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	// Activate against the synchronous issuer, then renew against an
	// asynchronous one.
	activateSvc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
	agentID := registerAndActivate(t, fx, activateSvc)

	issuer := &asyncIssuer{real: fx.serverCA, pendingCalls: 1}
	svc := rebuildWithIssuer(fx, issuer, dns.NewNoopVerifier(), nil)

	sub, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
		ServerCsrPEM: testServerCSR(t, fx.req.AnsName.FQDN()),
	})
	if err != nil {
		t.Fatalf("submit renewal: %v", err)
	}
	if len(sub.Renewal.Validation.Challenges) == 0 {
		t.Fatal("renewal must relay the order's challenges")
	}
	if sub.FQDN != fx.req.AnsName.FQDN() {
		t.Fatalf("submission FQDN: got %q", sub.FQDN)
	}

	// First verify: gate passes, provider pending → Sync=false.
	v1, err := svc.VerifyRenewalACME(context.Background(), agentID)
	if err != nil {
		t.Fatalf("verify renewal #1: %v", err)
	}
	if v1.Sync {
		t.Fatal("want Sync=false while the provider finalizes")
	}
	if v1.Renewal.Validation.Status != domain.ValidationVerified {
		t.Fatalf("validation: got %s want VERIFIED", v1.Renewal.Validation.Status)
	}

	// Re-POST: gate skipped (already VERIFIED), finalize completes.
	v2, err := svc.VerifyRenewalACME(context.Background(), agentID)
	if err != nil {
		t.Fatalf("verify renewal #2: %v", err)
	}
	if !v2.Sync {
		t.Fatal("second call should complete the renewal")
	}
	if v2.Renewal.CompletedAt.IsZero() {
		t.Fatal("renewal must be COMPLETED")
	}
	if v2.TLSARecord == nil || v2.TLSARecord.Type != domain.DNSRecordTLSA {
		t.Fatalf("completed renewal must carry the new TLSA record, got %+v", v2.TLSARecord)
	}

	// The status GET surfaces the TLSA record too — it's what the
	// WAIT next-step tells the operator to poll for.
	got, err := svc.GetServerCertRenewal(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TLSARecord == nil {
		t.Fatal("GetServerCertRenewal must carry the TLSA record once completed")
	}
}

// TestRenewal_Gate_MissingArtifact pins the renewal-lane gate — the
// pre-change noop is dead: no published artifact, no issuance.
func TestRenewal_Gate_MissingArtifact(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	// Activate with a passing verifier first…
	activateSvc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
	agentID := registerAndActivate(t, fx, activateSvc)

	// …then verify the renewal against a failing one.
	svc := rebuildWithIssuer(fx, fx.serverCA, failingDNSVerifier{}, nil)
	if _, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
		ServerCsrPEM: testServerCSR(t, fx.req.AnsName.FQDN()),
	}); err != nil {
		t.Fatalf("submit renewal: %v", err)
	}
	_, err := svc.VerifyRenewalACME(context.Background(), agentID)
	mustErrCode(t, err, "ACME_CHALLENGE_MISSING")
}

// TestRenewal_AsyncIssuer_TerminalFailure pins ErrOrderFailed on the
// renewal lane: the renewal is marked FAILED with a reason.
func TestRenewal_AsyncIssuer_TerminalFailure(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	activateSvc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
	agentID := registerAndActivate(t, fx, activateSvc)

	issuer := &asyncIssuer{real: fx.serverCA, failOrder: true}
	svc := rebuildWithIssuer(fx, issuer, dns.NewNoopVerifier(), nil)
	if _, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
		ServerCsrPEM: testServerCSR(t, fx.req.AnsName.FQDN()),
	}); err != nil {
		t.Fatalf("submit renewal: %v", err)
	}
	_, verr := svc.VerifyRenewalACME(context.Background(), agentID)
	mustErrCode(t, verr, "CERT_ORDER_FAILED")
	got, err := svc.GetServerCertRenewal(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Renewal.FailureReason == "" {
		t.Fatal("failed renewal must carry the failure reason")
	}
}

// erroringDNSVerifier simulates a systemic lookup failure (resolver
// unreachable) — distinct from "record not found".
type erroringDNSVerifier struct{}

func (erroringDNSVerifier) VerifyRecords(_ context.Context, _ string, _ []domain.ExpectedDNSRecord) (*port.VerificationResult, error) {
	return nil, context.DeadlineExceeded
}

// brokenIssuer returns a non-sentinel error from FinalizeOrder.
type brokenIssuer struct{ port.ServerCertificateIssuer }

func (b brokenIssuer) FinalizeOrder(_ context.Context, _ port.FinalizeOrderRequest) (*port.IssuedCert, error) {
	return nil, context.Canceled
}

// TestVerifyACME_LegacyZeroOrder_SkipsGate pins backwards
// compatibility: registrations persisted before order-tracking (zero
// order, no challenge ever issued) skip the gate and advance.
func TestVerifyACME_LegacyZeroOrder_SkipsGate(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, failingDNSVerifier{}, nil)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	// Rewrite the row into its legacy shape: no order at all.
	stored, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	stored.CertOrder = domain.CertificateOrder{}
	if err := fx.agents.Save(context.Background(), stored); err != nil {
		t.Fatal(err)
	}

	res, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	if err != nil {
		t.Fatalf("legacy rows must not be gated on challenges they never received: %v", err)
	}
	if res.Registration.Status != domain.StatusPendingDNS {
		t.Fatalf("status: got %s want PENDING_DNS", res.Registration.Status)
	}
}

// TestVerifyACME_Gate_SystemicDNSFailure: a resolver outage (lookup
// error, not a missing record) surfaces as an error, never a silent
// pass.
func TestVerifyACME_Gate_SystemicDNSFailure(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, erroringDNSVerifier{}, nil)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	if _, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{}); err == nil {
		t.Fatal("want systemic verification error")
	}
}

// TestVerifyACME_Gate_DNSVerifierAbsent_HTTPStillChecks: a DNS_01
// challenge with no DNS verifier wired reports unverified, while the
// wired HTTP verifier satisfies the any-of gate.
func TestVerifyACME_Gate_DNSVerifierAbsent_HTTPStillChecks(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, nil, staticHTTPVerifier{ok: true})

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	res, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	if err != nil {
		t.Fatalf("HTTP-01 alone must satisfy the gate: %v", err)
	}
	if res.Registration.Status != domain.StatusPendingDNS {
		t.Fatalf("status: got %s", res.Registration.Status)
	}
}

// TestVerifyACME_Gate_UnknownChallengeType: challenges of a type the
// RA cannot verify report unverified; with nothing else satisfied the
// gate fails closed.
func TestVerifyACME_Gate_UnknownChallengeType(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	stored, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	stored.CertOrder.Challenges = []domain.Challenge{{Type: domain.ChallengeType("TLS_ALPN_01"), Token: "t"}}
	if err := fx.agents.Save(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	_, err = svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	mustErrCode(t, err, "ACME_CHALLENGE_MISSING")
}

// TestVerifyACME_IssuerGenericError maps non-sentinel issuer failures
// to SERVER_CERT_ISSUE_FAILED without touching the order state.
func TestVerifyACME_IssuerGenericError(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, brokenIssuer{fx.serverCA}, dns.NewNoopVerifier(), nil)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	_, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	mustErrCode(t, err, "SERVER_CERT_ISSUE_FAILED")
	stored, _ := fx.agents.FindByAgentID(context.Background(), agentID)
	if stored.CertOrder.State != domain.OrderStatePending {
		t.Fatalf("transient issuer errors must leave the order retryable, got %s", stored.CertOrder.State)
	}
}

// TestVerifyRenewalACME_VerifiedBYOC_Rejected guards the re-drive
// branch: a VERIFIED-but-incomplete BYOC renewal is an impossible
// state via the public API (BYOC completes in the verifying call), so
// a directly-persisted one is rejected rather than re-verified.
func TestVerifyRenewalACME_VerifiedBYOC_Rejected(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
	agentID := registerAndActivate(t, fx, svc)

	now := time.Now()
	reg, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	r := domain.NewBYOCRenewal(agentID, reg.ID, "LEAF", "CHAIN",
		domain.NewSelfIssuedOrder("d", "h", now.Add(time.Hour)), now)
	verified, err := r.Validation.MarkVerified(now)
	if err != nil {
		t.Fatal(err)
	}
	r.UpdateValidationStatus(verified)
	if err := fx.renewals.Save(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	_, err = svc.VerifyRenewalACME(context.Background(), agentID)
	mustErrCode(t, err, "RENEWAL_NOT_PENDING")
}

// registerAndActivate drives a fresh registration through
// register → verify-acme → verify-dns so renewal tests start from an
// ACTIVE agent.
func registerAndActivate(t *testing.T, fx *regFixture, svc *service.RegistrationService) string {
	t.Helper()
	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	if _, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-acme: %v", err)
	}
	if _, err := svc.VerifyDNS(context.Background(), agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-dns: %v", err)
	}
	return agentID
}

// TestVerifyACME_ACMEIssuer_EndToEnd wires the real ACME adapter
// (the Let's Encrypt-shaped issuer) into the registration service
// against an in-process fake RFC 8555 provider, and drives the whole
// flow: register relays the provider's challenges, the first
// verify-acme parks the order in ISSUING while provider-side
// validation runs, and the re-driven verify-acme finalizes the order
// and lands the provider-issued chain. This is the wiring a real
// deployment gets with `ca.server.type: acme` pointed at Let's
// Encrypt staging.
func TestVerifyACME_ACMEIssuer_EndToEnd(t *testing.T) {
	t.Parallel()
	fake, err := acmetest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if perr := fake.Err(); perr != nil {
			t.Errorf("fake acme observed a protocol violation: %v", perr)
		}
		fake.Close()
	})

	issuer, err := cert.NewACMEIssuer(fake.DirectoryURL(), "ops@example.com", t.TempDir(),
		cert.WithFinalizeBudget(300*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}

	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, issuer, dns.NewNoopVerifier(), nil)

	// The fake provider authorizes agent.example.com — matching the
	// fixture's default request.
	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	// The 202's challenges are the provider's: the order ref is the
	// provider order URL and the DNS TXT value is the key-auth
	// digest, not the raw token.
	reg, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if reg.CertOrder.OrderRef != fake.OrderURL() {
		t.Fatalf("order ref: got %q want provider order URL", reg.CertOrder.OrderRef)
	}
	dns01, ok := reg.CertOrder.ChallengeOfType(domain.ChallengeTypeDNS01)
	if !ok || dns01.EffectiveDNSRecordValue() == dns01.Token || dns01.KeyAuthorization == "" {
		t.Fatalf("provider DNS challenge not relayed faithfully: %+v", dns01)
	}

	// First verify-acme: gate passes (noop DNS plays the published
	// artifact), provider validation outlives the finalize budget →
	// order parks in ISSUING.
	fake.SetHoldPending(true)
	res, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	if err != nil {
		t.Fatalf("verify-acme #1: %v", err)
	}
	if !res.Pending || res.Registration.CertOrder.State != domain.OrderStateIssuing {
		t.Fatalf("want pending/ISSUING while provider validates, got pending=%v state=%s",
			res.Pending, res.Registration.CertOrder.State)
	}

	// Provider finishes validation; the re-driven verify-acme
	// finalizes and the provider-issued chain lands.
	fake.SetHoldPending(false)
	fake.SetOrderStatus("ready")
	res2, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	if err != nil {
		t.Fatalf("verify-acme #2: %v", err)
	}
	if res2.Pending || res2.Registration.Status != domain.StatusPendingDNS {
		t.Fatalf("want completed PENDING_DNS, got pending=%v status=%s", res2.Pending, res2.Registration.Status)
	}
	if res2.Registration.ServerCert == nil ||
		!strings.Contains(res2.Registration.ServerCert.IssuerDN, "acmetest Root") {
		t.Fatalf("server cert must be the provider-issued chain, got %+v", res2.Registration.ServerCert)
	}
}

// bornReadyIssuer models Let's Encrypt authorization reuse: CreateOrder
// returns an ISSUING order with NO challenges, and FinalizeOrder
// succeeds straight away (no challenge was ever published locally).
type bornReadyIssuer struct{ real port.ServerCertificateIssuer }

func (b bornReadyIssuer) CreateOrder(ctx context.Context, fqdn string) (*domain.CertificateOrder, error) {
	o, err := b.real.CreateOrder(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	o.State = domain.OrderStateIssuing
	o.Challenges = nil
	return o, nil
}

func (b bornReadyIssuer) FinalizeOrder(ctx context.Context, req port.FinalizeOrderRequest) (*port.IssuedCert, error) {
	return b.real.FinalizeOrder(ctx, req)
}
func (b bornReadyIssuer) GetCACertificate(ctx context.Context) (string, error) {
	return b.real.GetCACertificate(ctx)
}

// TestVerifyACME_BornReadyOrder_SkipsGateAndFinalizes pins the
// authorization-reuse path: a registration whose order came back
// ISSUING with no challenges advances straight through verify-acme
// without the operator publishing anything — the gate skips ISSUING
// and the order finalizes.
func TestVerifyACME_BornReadyOrder_SkipsGateAndFinalizes(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	// failingDNS proves the gate is genuinely skipped (not passed): if
	// the gate ran, this verifier would reject and verify-acme would
	// 422. It must reach PENDING_DNS regardless.
	svc := rebuildWithIssuer(fx, bornReadyIssuer{real: fx.serverCA}, failingDNSVerifier{}, nil)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	stored, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.CertOrder.State != domain.OrderStateIssuing || len(stored.CertOrder.Challenges) != 0 {
		t.Fatalf("born-ready registration order: state=%s challenges=%d",
			stored.CertOrder.State, len(stored.CertOrder.Challenges))
	}

	res, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	if err != nil {
		t.Fatalf("born-ready verify-acme must finalize without a gate: %v", err)
	}
	if res.Registration.Status != domain.StatusPendingDNS {
		t.Fatalf("status: got %s want PENDING_DNS", res.Registration.Status)
	}
	if res.Registration.ServerCert == nil {
		t.Fatal("server cert missing after born-ready finalize")
	}
}

// badCertIssuer's FinalizeOrder succeeds at the issuer but returns a
// certificate that fails the RA's own self-validation — exercising
// the SERVER_CERT_SELFVERIFY_FAILED guard on both lanes.
type badCertIssuer struct{ real port.ServerCertificateIssuer }

func (b badCertIssuer) CreateOrder(ctx context.Context, fqdn string) (*domain.CertificateOrder, error) {
	return b.real.CreateOrder(ctx, fqdn)
}
func (b badCertIssuer) FinalizeOrder(_ context.Context, _ port.FinalizeOrderRequest) (*port.IssuedCert, error) {
	return &port.IssuedCert{CertPEM: "-----BEGIN CERTIFICATE-----\nbogus\n-----END CERTIFICATE-----\n"}, nil
}
func (b badCertIssuer) GetCACertificate(ctx context.Context) (string, error) {
	return b.real.GetCACertificate(ctx)
}

// TestVerifyACME_SelfVerifyFailure pins the registration-lane guard:
// an issuer that returns an unparseable cert is caught by the RA's
// post-issuance validation rather than being persisted.
func TestVerifyACME_SelfVerifyFailure(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, badCertIssuer{fx.serverCA}, dns.NewNoopVerifier(), nil)
	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	_, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	mustErrCode(t, err, "SERVER_CERT_SELFVERIFY_FAILED")
}

// TestRenewal_SelfVerifyFailure pins the same guard on the renewal lane.
func TestRenewal_SelfVerifyFailure(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	activateSvc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
	agentID := registerAndActivate(t, fx, activateSvc)

	svc := rebuildWithIssuer(fx, badCertIssuer{fx.serverCA}, dns.NewNoopVerifier(), nil)
	if _, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
		ServerCsrPEM: testServerCSR(t, fx.req.AnsName.FQDN()),
	}); err != nil {
		t.Fatalf("submit renewal: %v", err)
	}
	_, err := svc.VerifyRenewalACME(context.Background(), agentID)
	mustErrCode(t, err, "SERVER_CERT_SELFVERIFY_FAILED")
}

// TestRenewal_IssuerGenericError maps a non-sentinel issuer failure
// on the renewal lane to SERVER_CERT_ISSUE_FAILED (a retryable 500),
// distinct from the terminal ErrOrderFailed path.
func TestRenewal_IssuerGenericError(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	activateSvc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
	agentID := registerAndActivate(t, fx, activateSvc)

	svc := rebuildWithIssuer(fx, brokenIssuer{fx.serverCA}, dns.NewNoopVerifier(), nil)
	if _, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
		ServerCsrPEM: testServerCSR(t, fx.req.AnsName.FQDN()),
	}); err != nil {
		t.Fatalf("submit renewal: %v", err)
	}
	_, err := svc.VerifyRenewalACME(context.Background(), agentID)
	mustErrCode(t, err, "SERVER_CERT_ISSUE_FAILED")
}

// TestRenewal_BornReadyOrder_SkipsGate pins the renewal-lane twin of
// authorization reuse: a CSR renewal whose order came back with no
// challenges finalizes without the operator publishing anything, even
// against a failing DNS verifier (proving the gate is skipped).
func TestRenewal_BornReadyOrder_SkipsGate(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	activateSvc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
	agentID := registerAndActivate(t, fx, activateSvc)

	svc := rebuildWithIssuer(fx, bornReadyIssuer{real: fx.serverCA}, failingDNSVerifier{}, nil)
	sub, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
		ServerCsrPEM: testServerCSR(t, fx.req.AnsName.FQDN()),
	})
	if err != nil {
		t.Fatalf("submit renewal: %v", err)
	}
	if len(sub.Renewal.Validation.Challenges) != 0 {
		t.Fatalf("born-ready renewal must carry no challenges, got %d", len(sub.Renewal.Validation.Challenges))
	}

	res, err := svc.VerifyRenewalACME(context.Background(), agentID)
	if err != nil {
		t.Fatalf("born-ready renewal verify-acme must finalize without a gate: %v", err)
	}
	if !res.Sync || res.Renewal.CompletedAt.IsZero() {
		t.Fatalf("born-ready renewal must complete synchronously: sync=%v completed=%v",
			res.Sync, !res.Renewal.CompletedAt.IsZero())
	}
	if res.TLSARecord == nil {
		t.Error("completed renewal must carry the new TLSA record")
	}
}

// TestVerifyACME_BYOCWithStrayServerCSR_IgnoresIt pins the guard: a
// BYOC registration (self-issued order, empty OrderRef) that also has
// a server CSR submitted out-of-band must NOT finalize that CSR —
// doing so would 500 against an ACME issuer and issue a duplicate
// cert against the self-CA. The agent advances on its BYOC cert.
func TestVerifyACME_BYOCWithStrayServerCSR_IgnoresIt(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	// An ACME-style issuer that 500s on an empty order ref — proving
	// the stray CSR is never handed to it.
	issuer := &refOnlyIssuer{real: fx.serverCA}
	svc := rebuildWithIssuer(fx, issuer, dns.NewNoopVerifier(), nil)

	// BYOC registration: server cert supplied, no server CSR.
	leaf, chain := buildSelfSignedServerCert(t, fx.req.AnsName.FQDN())
	req := fx.req
	req.ServerCsrPEM = ""
	req.ServerCertificatePEM = leaf
	req.ServerCertificateChainPEM = chain
	if _, err := svc.RegisterAgent(context.Background(), req); err != nil {
		t.Fatalf("register BYOC: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	// Operator submits a stray server CSR out-of-band.
	if _, err := svc.SubmitServerCSR(context.Background(), agentID, testServerCSR(t, fx.req.AnsName.FQDN())); err != nil {
		t.Fatalf("submit stray server CSR: %v", err)
	}

	// verify-acme must ignore the stray CSR (empty OrderRef) and
	// advance on the BYOC cert — not hand it to the issuer.
	res, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{})
	if err != nil {
		t.Fatalf("BYOC verify-acme must not touch the stray CSR: %v", err)
	}
	if res.Registration.Status != domain.StatusPendingDNS {
		t.Fatalf("status: got %s want PENDING_DNS", res.Registration.Status)
	}
	if issuer.finalizeCalls != 0 {
		t.Errorf("issuer.FinalizeOrder must not be called for a BYOC registration, got %d calls", issuer.finalizeCalls)
	}
}

// TestGetByAgentID_NoServerCertYet pins the absence path: a freshly-
// registered CSR-path agent has no server cert on file yet, so the
// detail lookup must succeed with a nil ServerCert (and the BYOC
// store's ErrNotFound treated as "none", not an error).
func TestGetByAgentID_NoServerCertYet(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatalf("register: %v", err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	res, err := svc.GetByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatalf("GetByAgentID must tolerate a missing server cert, got %v", err)
	}
	if res.Registration.ServerCert != nil {
		t.Error("a pre-verify-acme CSR agent must have no server cert attached")
	}
}

// TestGetServerCertRenewal_TransientServerCertError_Propagates pins the
// renewal read path: once a renewal has completed, the detail lookup
// surfaces the new leaf's TLSA record — a transient failure loading
// that cert must propagate rather than silently omit the record the
// WAIT next-step tells the operator to publish.
func TestGetServerCertRenewal_TransientServerCertError_Propagates(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	fail := false
	byoc := toggleByocStore{ByocCertificateStore: fx.byoc, fail: &fail}
	svc := service.NewRegistrationService(
		fx.agents, fx.endpoints, fx.certs, byoc, fx.renewals,
		fx.validator, fx.identityCA, fx.bus, fx.outboxStore, fx.uow,
		fx.discoveryReg,
	).WithServerCertificateIssuer(fx.serverCA).WithDNSVerifier(dns.NewNoopVerifier())

	agentID := registerAndActivate(t, fx, svc)
	// BYOC renewal completes synchronously, leaving a completed renewal
	// whose detail surfaces the TLSA record.
	leaf, chain := buildSelfSignedServerCert(t, fx.req.AnsName.FQDN())
	if _, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
		ServerCertificatePEM:      leaf,
		ServerCertificateChainPEM: chain,
	}); err != nil {
		t.Fatalf("submit BYOC renewal: %v", err)
	}
	if _, err := svc.VerifyRenewalACME(context.Background(), agentID); err != nil {
		t.Fatalf("verify renewal: %v", err)
	}

	fail = true
	if _, err := svc.GetServerCertRenewal(context.Background(), agentID); !errors.Is(err, errTransientByoc) {
		t.Fatalf("GetServerCertRenewal must propagate the transient store error, got %v", err)
	}
}

// TestSubmitRenewal_BYOC_HappyPath pins the bring-your-own-cert
// renewal branch: no provider order is created (the operator supplies
// the cert), the validated leaf is persisted to the BYOC store, and
// the RA self-issues domain-control challenges the operator must prove
// before the new cert goes live.
func TestSubmitRenewal_BYOC_HappyPath(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
	agentID := registerAndActivate(t, fx, svc)

	leaf, chain := buildSelfSignedServerCert(t, fx.req.AnsName.FQDN())
	res, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
		ServerCertificatePEM:      leaf,
		ServerCertificateChainPEM: chain,
	})
	if err != nil {
		t.Fatalf("BYOC renewal submit: %v", err)
	}
	if res.CsrID != "" {
		t.Errorf("BYOC renewal must not mint a CSR id, got %q", res.CsrID)
	}
	if res.Renewal == nil || len(res.Renewal.Validation.Challenges) == 0 {
		t.Fatalf("BYOC renewal must self-issue challenges: %+v", res.Renewal)
	}
	// The validated cert must be persisted to the BYOC store before the
	// renewal completes.
	stored, err := fx.byoc.FindLatestValidByAgentID(context.Background(), agentID)
	if err != nil || stored == nil {
		t.Fatalf("BYOC cert not persisted at submit: cert=%v err=%v", stored, err)
	}
}

// TestSubmitRenewal_ValidationErrors pins the early reject branches.
func TestSubmitRenewal_ValidationErrors(t *testing.T) {
	t.Parallel()

	// Non-active agent: a freshly-registered (still PENDING_VALIDATION)
	// agent cannot renew.
	t.Run("not active", func(t *testing.T) {
		t.Parallel()
		fx := newRegFixture(t)
		svc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
		if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
			t.Fatalf("register: %v", err)
		}
		agentID := anyAgentID(t, fx, fx.req.AnsName)
		_, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
			ServerCsrPEM: testServerCSR(t, fx.req.AnsName.FQDN()),
		})
		mustErrCode(t, err, "AGENT_NOT_ACTIVE")
	})

	// Exactly one of CSR / BYOC must be set — both and neither reject.
	for name, in := range map[string]service.SubmitRenewalInput{
		"neither": {},
		"both":    {ServerCsrPEM: "x", ServerCertificatePEM: "y"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fx := newRegFixture(t)
			svc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
			agentID := registerAndActivate(t, fx, svc)
			_, err := svc.SubmitServerCertRenewal(context.Background(), agentID, in)
			mustErrCode(t, err, "INVALID_RENEWAL_REQUEST")
		})
	}

	// Malformed server CSR rejects before any order is created.
	t.Run("bad csr", func(t *testing.T) {
		t.Parallel()
		fx := newRegFixture(t)
		svc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
		agentID := registerAndActivate(t, fx, svc)
		_, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
			ServerCsrPEM: "-----BEGIN CERTIFICATE REQUEST-----\nnope\n-----END CERTIFICATE REQUEST-----\n",
		})
		mustErrCode(t, err, "INVALID_SERVER_CSR")
	})
}

// TestSubmitRenewal_PendingExists pins the 409: a second submit while a
// renewal is still in flight is rejected.
func TestSubmitRenewal_PendingExists(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	svc := rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil)
	agentID := registerAndActivate(t, fx, svc)

	csr := testServerCSR(t, fx.req.AnsName.FQDN())
	if _, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
		ServerCsrPEM: csr,
	}); err != nil {
		t.Fatalf("first renewal submit: %v", err)
	}
	_, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
		ServerCsrPEM: csr,
	})
	mustErrCode(t, err, "PENDING_RENEWAL_EXISTS")
}

// TestSubmitRenewal_NoIssuer pins the fail-fast: a CSR renewal with no
// server CA wired is rejected at submit rather than parked in a state
// that can never finalize.
func TestSubmitRenewal_NoIssuer(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	// Activate with a working issuer, then rebuild with none.
	agentID := registerAndActivate(t, fx, rebuildWithIssuer(fx, fx.serverCA, dns.NewNoopVerifier(), nil))
	svc := rebuildWithIssuer(fx, nil, dns.NewNoopVerifier(), nil)
	_, err := svc.SubmitServerCertRenewal(context.Background(), agentID, service.SubmitRenewalInput{
		ServerCsrPEM: testServerCSR(t, fx.req.AnsName.FQDN()),
	})
	mustErrCode(t, err, "SERVER_CA_DISABLED")
}

// refOnlyIssuer finalizes only when given a non-empty order ref (like
// the ACME adapter) and counts finalize calls.
type refOnlyIssuer struct {
	real          port.ServerCertificateIssuer
	finalizeCalls int
}

func (r *refOnlyIssuer) CreateOrder(ctx context.Context, fqdn string) (*domain.CertificateOrder, error) {
	return r.real.CreateOrder(ctx, fqdn)
}
func (r *refOnlyIssuer) FinalizeOrder(ctx context.Context, req port.FinalizeOrderRequest) (*port.IssuedCert, error) {
	r.finalizeCalls++
	if req.OrderRef == "" {
		return nil, errStrayFinalize
	}
	return r.real.FinalizeOrder(ctx, req)
}
func (r *refOnlyIssuer) GetCACertificate(ctx context.Context) (string, error) {
	return r.real.GetCACertificate(ctx)
}

// Compile-time interface checks for the fakes and the ACME adapter.
var (
	_ port.ServerCertificateIssuer = (*asyncIssuer)(nil)
	_ port.ServerCertificateIssuer = (*cert.ACMEIssuer)(nil)
	_ port.DNSVerifier             = failingDNSVerifier{}
	_ port.HTTPChallengeVerifier   = staticHTTPVerifier{}
	_                              = cert.ServerSelfCA{}
)
