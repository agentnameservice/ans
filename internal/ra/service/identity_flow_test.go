package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/adapter/cert"
	"github.com/godaddy/ans/internal/adapter/dns"
	"github.com/godaddy/ans/internal/adapter/store/sqlite"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/ra/service"
)

// selfCAOf unwraps the fixture's identity CA so tests can assert
// CA-side revocation through IsRevoked.
func selfCAOf(t *testing.T, fx *regFixture) *cert.SelfCA {
	t.Helper()
	ca, ok := fx.identityCA.(*cert.SelfCA)
	if !ok {
		t.Fatalf("fixture identity CA is %T, want *cert.SelfCA", fx.identityCA)
	}
	return ca
}

// TestSubmitIdentityCSR_RotationSignsImmediately pins the rotation
// flow: an ACTIVE agent's new identity CSR is signed at submission —
// the CSR row flips to SIGNED and a second identity certificate
// (carrying its serial) lands in the store. Pre-fix, rotation CSRs
// sat PENDING forever because nothing ever signed them.
func TestSubmitIdentityCSR_RotationSignsImmediately(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	agentID := registerAndActivate(t, fx, fx.svc)

	rotationCSR := testCSR(t, fx.req.AnsName.String())
	csrID, err := fx.svc.SubmitIdentityCSR(context.Background(), agentID, rotationCSR)
	if err != nil {
		t.Fatalf("rotation submit: %v", err)
	}

	csr, err := fx.svc.GetCSRStatus(context.Background(), agentID, csrID)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Status != domain.CSRStatusSigned {
		t.Fatalf("rotation CSR status: got %s want SIGNED", csr.Status)
	}

	certs, err := fx.certs.FindIdentityCertificatesByAgent(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("identity certs after rotation: got %d want 2 (rotation is additive)", len(certs))
	}
	for _, c := range certs {
		if c.Status != domain.CertStatusValid {
			t.Errorf("cert %s: status %s, want VALID (old cert stays valid until expiry)", c.CSRID, c.Status)
		}
		if c.SerialNumber == "" {
			t.Errorf("cert %s: missing serial number", c.CSRID)
		}
	}
}

// TestRevoke_RevokesIdentityCertsAtCA pins CA-side revocation: the
// revoke flow must tell the issuing CA, not just flip database rows —
// with a cloud private CA that call is what lands the cert on the
// CRL/OCSP plane. Pre-fix the port method was never invoked.
func TestRevoke_RevokesIdentityCertsAtCA(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	agentID := registerAndActivate(t, fx, fx.svc)

	certs, err := fx.certs.FindIdentityCertificatesByAgent(context.Background(), agentID)
	if err != nil || len(certs) != 1 {
		t.Fatalf("precondition: certs=%d err=%v", len(certs), err)
	}
	serial := certs[0].SerialNumber
	if serial == "" {
		t.Fatal("precondition: stored cert must carry its serial")
	}

	if _, err := fx.svc.Revoke(context.Background(), agentID, service.RevokeInput{
		Reason: domain.RevocationKeyCompromise,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if !selfCAOf(t, fx).IsRevoked(serial) {
		t.Error("identity cert was not revoked at the issuing CA")
	}
	after, err := fx.certs.FindIdentityCertificatesByAgent(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if after[0].Status != domain.CertStatusRevoked {
		t.Errorf("stored cert status: got %s want REVOKED", after[0].Status)
	}
}

// TestRevoke_LegacyRowsDeriveSerialFromPEM pins the fallback: rows
// persisted before serial tracking (migration 009) have no stored
// serial, so CA revocation parses it out of the certificate PEM.
func TestRevoke_LegacyRowsDeriveSerialFromPEM(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	agentID := registerAndActivate(t, fx, fx.svc)

	certs, _ := fx.certs.FindIdentityCertificatesByAgent(context.Background(), agentID)
	serial := certs[0].SerialNumber

	// Age the row into its pre-007 shape.
	db, ok := fx.uow.(*sqlite.DB)
	if !ok {
		t.Fatalf("fixture uow is %T, want *sqlite.DB", fx.uow)
	}
	if _, err := db.DBX().Exec(
		`UPDATE issued_certificates SET serial_number = NULL, certificate_ref = NULL WHERE agent_id = ?`,
		agentID); err != nil {
		t.Fatal(err)
	}

	if _, err := fx.svc.Revoke(context.Background(), agentID, service.RevokeInput{
		Reason: domain.RevocationKeyCompromise,
	}); err != nil {
		t.Fatalf("revoke with legacy rows: %v", err)
	}
	if !selfCAOf(t, fx).IsRevoked(serial) {
		t.Error("legacy-row revocation must derive the serial from the PEM")
	}
}

// TestRevoke_PendingDNS_CancelsWithoutTLEmit pins the cancel path:
// a PENDING_DNS registration terminates through the revoke route —
// lifecycle to REVOKED, identity cert revoked at the CA and in the
// store — and emits NOTHING to the TL, because no leaf exists for an
// agent that never reached ACTIVE.
func TestRevoke_PendingDNS_CancelsWithoutTLEmit(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	if _, err := fx.svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatal(err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	if _, err := fx.svc.VerifyACME(context.Background(), agentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-acme: %v", err)
	}

	certs, _ := fx.certs.FindIdentityCertificatesByAgent(context.Background(), agentID)
	if len(certs) != 1 {
		t.Fatalf("precondition: identity cert expected at PENDING_DNS, got %d", len(certs))
	}

	res, err := fx.svc.Revoke(context.Background(), agentID, service.RevokeInput{
		Reason: domain.RevocationCessationOfOperation,
	})
	if err != nil {
		t.Fatalf("cancel via revoke route: %v", err)
	}
	if res.Registration.Status != domain.StatusRevoked {
		t.Fatalf("status: got %s want REVOKED", res.Registration.Status)
	}
	if !selfCAOf(t, fx).IsRevoked(certs[0].SerialNumber) {
		t.Error("cancelled registration's identity cert must be revoked at the CA")
	}

	rows, err := fx.outboxStore.Claim(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("cancel must not emit to the TL (no leaf exists pre-ACTIVE), got %d rows", len(rows))
	}
}

// TestRevoke_AwaitingValidation_NotCancellable pins the spec rule:
// a registration whose challenge is still outstanding is not
// cancellable — it auto-expires instead.
func TestRevoke_AwaitingValidation_NotCancellable(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	if _, err := fx.svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatal(err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	_, err := fx.svc.Revoke(context.Background(), agentID, service.RevokeInput{
		Reason: domain.RevocationCessationOfOperation,
	})
	mustErrCode(t, err, "CANNOT_CANCEL")
}

// TestRevoke_FailedOrder_Cancellable pins the recovery path for a
// terminally failed provider order: the registration is cancellable
// so the operator can clean up explicitly.
func TestRevoke_FailedOrder_Cancellable(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	issuer := &asyncIssuer{real: fx.serverCA, failOrder: true}
	svc := rebuildWithIssuer(fx, issuer, dns.NewNoopVerifier(), nil)

	if _, err := svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatal(err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	if _, err := svc.VerifyACME(context.Background(), agentID, service.VerifyInput{}); err == nil {
		t.Fatal("precondition: verify-acme should fail terminally")
	}

	res, err := svc.Revoke(context.Background(), agentID, service.RevokeInput{
		Reason: domain.RevocationCessationOfOperation,
	})
	if err != nil {
		t.Fatalf("failed-order registration must be cancellable: %v", err)
	}
	if res.Registration.Status != domain.StatusRevoked {
		t.Fatalf("status: got %s want REVOKED", res.Registration.Status)
	}
}

// TestRevoke_Cancel_InvalidReason mirrors the active-path validation
// on the cancel branch.
func TestRevoke_Cancel_InvalidReason(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	if _, err := fx.svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatal(err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	if _, err := fx.svc.VerifyACME(context.Background(), agentID, service.VerifyInput{}); err != nil {
		t.Fatal(err)
	}
	_, err := fx.svc.Revoke(context.Background(), agentID, service.RevokeInput{
		Reason: domain.RevocationReason("NOT_A_REASON"),
	})
	mustErrCode(t, err, "INVALID_REVOCATION_REASON")
}

// TestExpireAgentsOnce_FlipsLapsedPendingValidation pins the
// auto-expiry promise: PENDING_VALIDATION registrations whose
// challenge window lapsed flip to EXPIRED; everything else is
// untouched. Idempotent — the second sweep finds nothing.
func TestExpireAgentsOnce_FlipsLapsedPendingValidation(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	if _, err := fx.svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatal(err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)

	// Not yet lapsed → untouched.
	n, err := service.ExpireAgentsOnce(context.Background(), fx.agents, time.Now())
	if err != nil || n != 0 {
		t.Fatalf("fresh registration must not expire: n=%d err=%v", n, err)
	}

	// Age the challenge window past its deadline.
	reg, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	reg.CertOrder.ExpiresAt = time.Now().Add(-time.Minute)
	if err := fx.agents.Save(context.Background(), reg); err != nil {
		t.Fatal(err)
	}

	n, err = service.ExpireAgentsOnce(context.Background(), fx.agents, time.Now())
	if err != nil || n != 1 {
		t.Fatalf("sweep: n=%d err=%v, want 1", n, err)
	}
	after, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != domain.StatusExpired {
		t.Fatalf("status: got %s want EXPIRED", after.Status)
	}

	// Idempotent.
	n, err = service.ExpireAgentsOnce(context.Background(), fx.agents, time.Now())
	if err != nil || n != 0 {
		t.Fatalf("second sweep: n=%d err=%v, want 0", n, err)
	}
}

// TestExpireAgentsOnce_SkipsInFlightAndFailedOrders pins the guard
// that protects the async-issuer re-drive design: a lapsed
// PENDING_VALIDATION row whose order is ISSUING (provider validating)
// or FAILED (terminal, cancel-only) must NOT be auto-expired, even
// though its challenge window has passed. Only PENDING orders expire.
func TestExpireAgentsOnce_SkipsInFlightAndFailedOrders(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)

	seed := func(host string, mutate func(*domain.CertificateOrder)) string {
		req := fx.req
		sv, _ := domain.ParseSemVer("1.0.0")
		an, _ := domain.NewAnsName(sv, host)
		req.AnsName = an
		req.IdentityCSRPEM = testCSR(t, an.String())
		req.ServerCsrPEM = testServerCSR(t, an.FQDN())
		req.Endpoints = []domain.AgentEndpoint{{
			Protocol:   domain.Protocol("MCP"),
			AgentURL:   "https://" + host + "/mcp",
			Transports: []domain.Transport{domain.Transport("SSE")},
		}}
		if _, err := fx.svc.RegisterAgent(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		reg, err := fx.agents.FindByAgentID(context.Background(), anyAgentID(t, fx, an))
		if err != nil {
			t.Fatal(err)
		}
		reg.CertOrder.ExpiresAt = time.Now().Add(-time.Minute) // window lapsed
		mutate(&reg.CertOrder)
		if err := fx.agents.Save(context.Background(), reg); err != nil {
			t.Fatal(err)
		}
		return reg.AgentID
	}

	issuingID := seed("issuing.example.com", func(o *domain.CertificateOrder) {
		_ = o.MarkIssuing()
	})
	failedID := seed("failed.example.com", func(o *domain.CertificateOrder) {
		_ = o.MarkFailed()
	})
	pendingID := seed("pending.example.com", func(_ *domain.CertificateOrder) {})

	n, err := service.ExpireAgentsOnce(context.Background(), fx.agents, time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("only the PENDING-order row should expire: got n=%d want 1", n)
	}
	assertStatus := func(id string, want domain.RegistrationStatus) {
		got, gerr := fx.agents.FindByAgentID(context.Background(), id)
		if gerr != nil {
			t.Fatal(gerr)
		}
		if got.Status != want {
			t.Errorf("agent %s: status %s, want %s", id, got.Status, want)
		}
	}
	assertStatus(issuingID, domain.StatusPendingValidation)
	assertStatus(failedID, domain.StatusPendingValidation)
	assertStatus(pendingID, domain.StatusExpired)
}

// TestExpireAgentsOnce_StoreError surfaces the store error rather than
// swallowing it (the worker logs-and-continues on this; here we pin
// the error propagation deterministically by closing the DB first).
func TestExpireAgentsOnce_StoreError(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	db, ok := fx.uow.(*sqlite.DB)
	if !ok {
		t.Fatalf("fixture uow is %T, want *sqlite.DB", fx.uow)
	}
	_ = db.Close()
	if _, err := service.ExpireAgentsOnce(context.Background(), fx.agents, time.Now()); err == nil {
		t.Fatal("want error from a closed store")
	}
}

// TestRunAgentExpiryChecker_ExitsOnContextCancel proves the worker
// honors shutdown — the cmd/ans-ra SIGTERM path.
func TestRunAgentExpiryChecker_ExitsOnContextCancel(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		service.RunAgentExpiryChecker(runCtx, fx.agents, zerolog.Nop(), service.ExpiryCheckerOptions{
			Interval: 50 * time.Millisecond,
		})
		close(done)
	}()
	time.Sleep(80 * time.Millisecond) // let the empty-sweep tick fire
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunAgentExpiryChecker did not exit on ctx cancel")
	}
}

// TestRunAgentExpiryChecker_DefaultInterval covers the zero-interval
// fallback; pre-cancelled ctx returns on the first select.
func TestRunAgentExpiryChecker_DefaultInterval(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	runCtx, cancel := context.WithCancel(context.Background())
	cancel()
	service.RunAgentExpiryChecker(runCtx, fx.agents, zerolog.Nop(), service.ExpiryCheckerOptions{})
}

// TestRunAgentExpiryChecker_SweepsAndLogsErrors drives both ticker
// branches: a productive sweep (seeded lapsed registration) and a
// failing sweep (database closed mid-run) — neither may tear the
// worker down.
func TestRunAgentExpiryChecker_SweepsAndLogsErrors(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	if _, err := fx.svc.RegisterAgent(context.Background(), fx.req); err != nil {
		t.Fatal(err)
	}
	agentID := anyAgentID(t, fx, fx.req.AnsName)
	reg, err := fx.agents.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	reg.CertOrder.ExpiresAt = time.Now().Add(-time.Minute)
	if err := fx.agents.Save(context.Background(), reg); err != nil {
		t.Fatal(err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		service.RunAgentExpiryChecker(runCtx, fx.agents, zerolog.Nop(), service.ExpiryCheckerOptions{
			Interval: 30 * time.Millisecond,
		})
		close(done)
	}()

	// Wait for the productive sweep to land.
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, gerr := fx.agents.FindByAgentID(context.Background(), agentID)
		if gerr == nil && got.Status == domain.StatusExpired {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("sweep never expired the lapsed registration")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Close the DB out from under the worker: the next sweep errors
	// and is logged, not fatal.
	db, ok := fx.uow.(*sqlite.DB)
	if !ok {
		t.Fatalf("fixture uow is %T, want *sqlite.DB", fx.uow)
	}
	_ = db.Close()
	time.Sleep(80 * time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not exit on ctx cancel")
	}
}
