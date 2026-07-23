package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/ra/service"
)

// These tests pin commitActivation's in-tx exclusivity decision — the
// interleavings the pre-seal check cannot see because a rival commits
// during the seal round trip. The sealer double's hook runs inside that
// window (after the TL "ack", before this racer's transaction), exactly
// where a real rival's commit lands under the store's single writer.

// registerRival registers a second owner's registration on the fixture's
// host (a different version keeps the ANS name unique) and drives it to
// PENDING_DNS, returning its agentID.
func registerRival(t *testing.T, fx *regFixture, ownerID, version string) string {
	t.Helper()
	ctx := context.Background()

	sv, err := domain.ParseSemVer(version)
	if err != nil {
		t.Fatalf("ParseSemVer(%q): %v", version, err)
	}
	ansName, err := domain.NewAnsName(sv, fx.req.AnsName.AgentHost())
	if err != nil {
		t.Fatalf("NewAnsName: %v", err)
	}
	req := fx.req
	req.OwnerID = ownerID
	req.AnsName = ansName
	req.IdentityCSRPEM = testCSR(t, ansName.String())
	req.ServerCsrPEM = testServerCSR(t, ansName.FQDN())

	resp, err := fx.svc.RegisterAgent(ctx, req)
	if err != nil {
		t.Fatalf("register rival: %v", err)
	}
	if _, err := fx.svc.VerifyACME(ctx, resp.Registration.AgentID, service.VerifyInput{}); err != nil {
		t.Fatalf("rival verify-acme: %v", err)
	}
	return resp.Registration.AgentID
}

// driveToPendingDNS drives the fixture's own request to PENDING_DNS and
// returns its agentID.
func driveToPendingDNS(t *testing.T, fx *regFixture) string {
	t.Helper()
	ctx := context.Background()
	resp, err := fx.svc.RegisterAgent(ctx, fx.req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := fx.svc.VerifyACME(ctx, resp.Registration.AgentID, service.VerifyInput{}); err != nil {
		t.Fatalf("verify-acme: %v", err)
	}
	return resp.Registration.AgentID
}

// mustHostTaken asserts err is the AGENT_HOST_TAKEN conflict.
func mustHostTaken(t *testing.T, err error) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "AGENT_HOST_TAKEN" {
		t.Fatalf("want AGENT_HOST_TAKEN, got %v", err)
	}
}

// TestVerifyDNS_RivalActivatedMidSeal_LoserAborts covers the two-owner
// activation race: both pass the pre-seal check, the rival commits ACTIVE
// while this racer is inside its seal round trip. commitActivation's
// in-tx re-check must abort THIS racer with AGENT_HOST_TAKEN — never
// commit a second ACTIVE holder (which would wedge the host: every later
// call 409ing each owner against the other with no API path out). The
// loser's already-sealed leaf is the accepted benign residue.
func TestVerifyDNS_RivalActivatedMidSeal_LoserAborts(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	ctx := context.Background()

	loserID := driveToPendingDNS(t, fx)
	rivalID := registerRival(t, fx, "owner-2", "2.0.0")

	// Inside the loser's seal round trip, the rival's activation commits.
	fx.sealer.hook = func() {
		fx.sealer.hook = nil // fire once — only for the loser's seal
		rival, err := fx.agents.FindByAgentID(ctx, rivalID)
		if err != nil {
			t.Errorf("load rival: %v", err)
			return
		}
		if err := rival.Activate(time.Now()); err != nil {
			t.Errorf("activate rival: %v", err)
			return
		}
		if err := fx.agents.Save(ctx, rival); err != nil {
			t.Errorf("save rival: %v", err)
		}
	}

	_, err := fx.svc.VerifyDNS(ctx, loserID, service.VerifyInput{})
	mustHostTaken(t, err)

	loser, err := fx.agents.FindByAgentID(ctx, loserID)
	if err != nil {
		t.Fatal(err)
	}
	if loser.Status != domain.StatusPendingDNS {
		t.Fatalf("loser must stay PENDING_DNS after aborting, got %q", loser.Status)
	}
	rival, err := fx.agents.FindByAgentID(ctx, rivalID)
	if err != nil {
		t.Fatal(err)
	}
	if rival.Status != domain.StatusActive {
		t.Fatalf("rival must remain the sole ACTIVE holder, got %q", rival.Status)
	}

	// No wedge: the loser's retry gets the same clean 409 (the host is
	// genuinely held), not a mutual-409 deadlock.
	_, err = fx.svc.VerifyDNS(ctx, loserID, service.VerifyInput{})
	mustHostTaken(t, err)
}

// TestVerifyDNS_ConflictCancelledMidSeal_NotResurrected covers the
// resurrection hazard: the rival's activation conflict-cancels THIS
// racer mid-seal (its row flips REVOKED); saving the stale in-memory
// ACTIVE aggregate would silently resurrect it. commitActivation's
// own-row guard must abort instead and leave the row REVOKED.
func TestVerifyDNS_ConflictCancelledMidSeal_NotResurrected(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	ctx := context.Background()

	loserID := driveToPendingDNS(t, fx)
	rivalID := registerRival(t, fx, "owner-2", "2.0.0")

	fx.sealer.hook = func() {
		fx.sealer.hook = nil
		// The rival's committed transaction: rival ACTIVE, loser
		// conflict-cancelled.
		rival, err := fx.agents.FindByAgentID(ctx, rivalID)
		if err != nil {
			t.Errorf("load rival: %v", err)
			return
		}
		if err := rival.Activate(time.Now()); err != nil {
			t.Errorf("activate rival: %v", err)
			return
		}
		if err := fx.agents.Save(ctx, rival); err != nil {
			t.Errorf("save rival: %v", err)
			return
		}
		loser, err := fx.agents.FindByAgentID(ctx, loserID)
		if err != nil {
			t.Errorf("load loser: %v", err)
			return
		}
		if err := loser.CancelForHostConflict(); err != nil {
			t.Errorf("cancel loser: %v", err)
			return
		}
		if err := fx.agents.Save(ctx, loser); err != nil {
			t.Errorf("save loser: %v", err)
		}
	}

	_, err := fx.svc.VerifyDNS(ctx, loserID, service.VerifyInput{})
	mustHostTaken(t, err)

	loser, err := fx.agents.FindByAgentID(ctx, loserID)
	if err != nil {
		t.Fatal(err)
	}
	if loser.Status != domain.StatusRevoked {
		t.Fatalf("cancelled loser must stay REVOKED (no resurrection), got %q", loser.Status)
	}
}

// TestVerifyDNS_ConflictCancelRevokesLoserCerts covers the credential
// half of conflict-cancellation: a loser at PENDING_DNS already holds a
// VALID identity certificate (signed at verify-acme), and losing the
// host must revoke it — CA-side before the winner's transaction, store
// rows inside it — exactly as the owner-initiated cancelPending path
// does. Otherwise the loser keeps a live credential asserting an ANS
// name on a host it lost, for up to its full term, with no API path to
// fix it (Revoke's already-REVOKED branch returns early).
func TestVerifyDNS_ConflictCancelRevokesLoserCerts(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	ctx := context.Background()

	loserID := driveToPendingDNS(t, fx)
	// Precondition: the loser holds a VALID identity cert.
	preCerts, err := fx.certs.FindIdentityCertificatesByAgent(ctx, loserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(preCerts) == 0 || preCerts[0].Status != domain.CertStatusValid {
		t.Fatalf("precondition: loser must hold a VALID identity cert, got %+v", preCerts)
	}

	winnerID := registerRival(t, fx, "owner-2", "2.0.0")
	if _, err := fx.svc.VerifyDNS(ctx, winnerID, service.VerifyInput{}); err != nil {
		t.Fatalf("winner verify-dns: %v", err)
	}

	loser, err := fx.agents.FindByAgentID(ctx, loserID)
	if err != nil {
		t.Fatal(err)
	}
	if loser.Status != domain.StatusRevoked {
		t.Fatalf("loser must be conflict-cancelled, got %q", loser.Status)
	}
	postCerts, err := fx.certs.FindIdentityCertificatesByAgent(ctx, loserID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range postCerts {
		if c.Status == domain.CertStatusValid {
			t.Fatalf("loser certificate %s must not stay VALID after conflict-cancellation", c.CertificateRef)
		}
	}
}

// TestRevoke_IdempotentSweepsLingeringCerts covers the self-healing
// repair: a REVOKED registration that somehow kept a VALID identity
// cert (the conflict-cancellation window, or rows from before the flip
// existed) is fixed by the idempotent revoke call rather than being
// permanently unreachable behind the early return.
func TestRevoke_IdempotentSweepsLingeringCerts(t *testing.T) {
	t.Parallel()
	fx := newRegFixture(t)
	ctx := context.Background()

	agentID := driveToPendingDNS(t, fx)

	// Manufacture the broken state: registration REVOKED, cert left VALID.
	reg, err := fx.agents.FindByAgentID(ctx, agentID)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.CancelForHostConflict(); err != nil {
		t.Fatal(err)
	}
	if err := fx.agents.Save(ctx, reg); err != nil {
		t.Fatal(err)
	}

	res, err := fx.svc.Revoke(ctx, agentID, service.RevokeInput{Reason: domain.RevocationCessationOfOperation})
	if err != nil {
		t.Fatalf("idempotent revoke must succeed and repair, got: %v", err)
	}
	if res.Registration.Status != domain.StatusRevoked {
		t.Fatalf("status = %q, want REVOKED", res.Registration.Status)
	}
	certs, err := fx.certs.FindIdentityCertificatesByAgent(ctx, agentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) == 0 {
		t.Fatal("precondition failure: expected an identity cert to sweep")
	}
	for _, c := range certs {
		if c.Status == domain.CertStatusValid {
			t.Fatalf("idempotent revoke must sweep VALID certs; %s still VALID", c.CertificateRef)
		}
	}
}
