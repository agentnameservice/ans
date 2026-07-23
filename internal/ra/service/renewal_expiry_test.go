package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/adapter/store/sqlite"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/ra/service"
)

// TestExpireRenewalsOnce_MarksStaleAsFailed seeds a PENDING renewal
// whose validation window has already elapsed, runs one sweep, and
// asserts the renewal flips to FAILED with a "validation expired"
// reason — matching the reference RenewalExpiryCheckJob behaviour.
func TestExpireRenewalsOnce_MarksStaleAsFailed(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	renewals := sqlite.NewRenewalStore(db)
	certs := sqlite.NewCertificateStore(db)

	// Seed a BYOC renewal whose window expired 1h ago. We have to
	// insert the agent_registrations row first because the renewal
	// has an FK to it.
	agentStore := sqlite.NewAgentStore(db)
	reg := seedAgent(ctx, t, agentStore, "expiry-agent", "alice")

	pastExpiry := time.Now().Add(-1 * time.Hour)
	r := &domain.ServerCertificateRenewal{
		AgentID:        reg.AgentID,
		RegistrationID: reg.ID,
		RenewalType:    domain.RenewalTypeBYOC,
		ByocCertPEM:    "-----BEGIN CERTIFICATE-----\nabcd\n-----END CERTIFICATE-----",
		CreatedAt:      pastExpiry.Add(-24 * time.Hour),
		Validation: domain.RenewalValidation{
			Challenges: []domain.Challenge{
				{Type: domain.ChallengeTypeDNS01, Token: "dns"},
				{Type: domain.ChallengeTypeHTTP01, Token: "http"},
			},
			Status:    domain.ValidationPending,
			CreatedAt: pastExpiry.Add(-24 * time.Hour),
			ExpiresAt: pastExpiry,
			UpdatedAt: pastExpiry.Add(-24 * time.Hour),
		},
	}
	if err := renewals.Save(ctx, r); err != nil {
		t.Fatal(err)
	}

	n, err := service.ExpireRenewalsOnce(ctx, renewals, certs, time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("swept: got %d want 1", n)
	}

	got, err := renewals.FindByAgentID(ctx, reg.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailureReason == "" {
		t.Error("failureReason not populated after expiry")
	}
	if got.CompletedAt.IsZero() {
		t.Error("completedAt not populated after expiry")
	}
	if got.Validation.Status != domain.ValidationFailed {
		t.Errorf("validation.status: got %q want FAILED", got.Validation.Status)
	}
}

// TestExpireRenewalsOnce_CSRPath_RejectsAttachedCSR exercises the
// CSR-side branch: an expired CSR-type renewal must also flip its
// linked agent_csrs row to REJECTED so the GET CSR-status endpoint
// surfaces the failure. Pre-coverage only the BYOC arm landed.
func TestExpireRenewalsOnce_CSRPath_RejectsAttachedCSR(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	agentStore := sqlite.NewAgentStore(db)
	renewals := sqlite.NewRenewalStore(db)
	certs := sqlite.NewCertificateStore(db)
	reg := seedAgent(ctx, t, agentStore, "expiry-csr-agent", "alice")

	// Seed a server CSR row that the renewal will be linked to.
	csr := &domain.AgentCSR{
		CSRID:               "csr-pending-1",
		Type:                domain.CSRTypeServer,
		Status:              domain.CSRStatusPending,
		CSRContent:          "-----BEGIN CERTIFICATE REQUEST-----\nabcd\n-----END CERTIFICATE REQUEST-----",
		SubmissionTimestamp: time.Now().Add(-24 * time.Hour),
	}
	if err := certs.SaveCSR(ctx, reg.AgentID, csr); err != nil {
		t.Fatal(err)
	}

	pastExpiry := time.Now().Add(-1 * time.Hour)
	r := &domain.ServerCertificateRenewal{
		AgentID:        reg.AgentID,
		RegistrationID: reg.ID,
		RenewalType:    domain.RenewalTypeCSR,
		ServerCsrID:    csr.CSRID,
		CreatedAt:      pastExpiry.Add(-24 * time.Hour),
		Validation: domain.RenewalValidation{
			Challenges: []domain.Challenge{
				{Type: domain.ChallengeTypeDNS01, Token: "dns"},
				{Type: domain.ChallengeTypeHTTP01, Token: "http"},
			},
			Status:    domain.ValidationPending,
			CreatedAt: pastExpiry.Add(-24 * time.Hour),
			ExpiresAt: pastExpiry,
			UpdatedAt: pastExpiry.Add(-24 * time.Hour),
		},
	}
	if err := renewals.Save(ctx, r); err != nil {
		t.Fatal(err)
	}

	n, err := service.ExpireRenewalsOnce(ctx, renewals, certs, time.Now())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("swept: got %d want 1", n)
	}

	// The linked CSR should now be REJECTED with the renewal-expiry
	// reason.
	gotCSR, err := certs.FindCSRByID(ctx, reg.AgentID, csr.CSRID)
	if err != nil {
		t.Fatalf("FindCSRByID: %v", err)
	}
	if gotCSR.Status != domain.CSRStatusRejected {
		t.Errorf("csr.Status: got %q want REJECTED", gotCSR.Status)
	}
}

// TestExpireRenewalsOnce_IgnoresCompletedRenewals confirms the sweep
// doesn't re-fail completed rows — required for idempotency.
func TestExpireRenewalsOnce_IgnoresCompletedRenewals(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	renewals := sqlite.NewRenewalStore(db)
	certs := sqlite.NewCertificateStore(db)
	agentStore := sqlite.NewAgentStore(db)
	reg := seedAgent(ctx, t, agentStore, "expiry-completed-agent", "alice")

	// A renewal that's already completed. ListPendingExpired filters
	// out completed rows, so the sweep should find zero to expire.
	now := time.Now()
	r := &domain.ServerCertificateRenewal{
		AgentID:        reg.AgentID,
		RegistrationID: reg.ID,
		RenewalType:    domain.RenewalTypeBYOC,
		CompletedAt:    now,
		CreatedAt:      now.Add(-24 * time.Hour),
		Validation: domain.RenewalValidation{
			Challenges: []domain.Challenge{
				{Type: domain.ChallengeTypeDNS01, Token: "dns"},
				{Type: domain.ChallengeTypeHTTP01, Token: "http"},
			},
			Status:    domain.ValidationVerified,
			CreatedAt: now.Add(-24 * time.Hour),
			ExpiresAt: now.Add(-1 * time.Hour), // past, but completed
			UpdatedAt: now,
		},
	}
	if err := renewals.Save(ctx, r); err != nil {
		t.Fatal(err)
	}

	n, err := service.ExpireRenewalsOnce(ctx, renewals, certs, now)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 0 {
		t.Errorf("completed renewal got processed: n=%d", n)
	}
}

// seedAgent inserts a minimal active registration row so the FK on
// server_cert_renewals.registration_id resolves. Returns the saved
// registration with its assigned ID.
func seedAgent(ctx context.Context, t *testing.T, store *sqlite.AgentStore, agentID, owner string) *domain.AgentRegistration {
	t.Helper()
	sv, _ := domain.ParseSemVer("1.0.0")
	ansName, _ := domain.NewAnsName(sv, agentID+".example.com")
	reg := &domain.AgentRegistration{
		AgentID: agentID,
		OwnerID: owner,
		AnsName: ansName,
		Status:  domain.StatusActive,
		Endpoints: []domain.AgentEndpoint{{
			Protocol:   domain.Protocol("MCP"),
			AgentURL:   "https://" + agentID + ".example.com/mcp",
			Transports: []domain.Transport{"SSE"},
		}},
		Details: domain.RegistrationDetails{
			RegistrationTimestamp: time.Now(),
			DisplayName:           "Test",
		},
	}
	if err := store.Save(ctx, reg); err != nil {
		t.Fatal(err)
	}
	return reg
}

// TestRunExpiryChecker_ExitsOnContextCancel verifies the long-running
// loop returns when the context is cancelled. This is the primary
// shutdown path the cmd/ans-ra binary relies on at SIGTERM. We don't
// assert on a sweep happening — that's covered by the
// ExpireRenewalsOnce tests above; here we only need to prove the
// goroutine doesn't outlive its context.
func TestRunExpiryChecker_ExitsOnContextCancel(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	renewals := sqlite.NewRenewalStore(db)
	certs := sqlite.NewCertificateStore(db)

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		// 50ms tick lets us exercise the tick branch + the ctx.Done
		// branch in one short test run.
		service.RunExpiryChecker(runCtx, renewals, certs, zerolog.Nop(), service.ExpiryCheckerOptions{
			Interval: 50 * time.Millisecond,
		})
		close(done)
	}()
	// Let the ticker fire at least once so the empty-sweep branch
	// (`expired = []` + `n == 0`) gets covered.
	time.Sleep(80 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunExpiryChecker did not return within 2s of ctx cancel")
	}
}

// TestRunExpiryChecker_DefaultInterval covers the branch where the
// caller passes a zero-valued Interval — the function falls back to
// 5 minutes. We cancel immediately so the timer never fires; this
// test only proves the constructor logic and the ctx.Done exit
// don't depend on the timer firing.
func TestRunExpiryChecker_DefaultInterval(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	runCtx, cancel := context.WithCancel(ctx)
	cancel() // pre-cancel so the function returns on the first select.
	service.RunExpiryChecker(runCtx,
		sqlite.NewRenewalStore(db),
		sqlite.NewCertificateStore(db),
		zerolog.Nop(),
		service.ExpiryCheckerOptions{}, // Interval == 0 → 5m default
	)
}
