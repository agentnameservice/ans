package service_test

import (
	"context"
	"testing"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/ra/service"
)

// This regression test checks the boundary between a CA account's cached
// authorization and the authorization of a different RA customer.
func TestRegression_ACMEReuseRequiresNewOwnerProof(t *testing.T) {
	ctx := context.Background()
	fx := newRegFixture(t)
	first, err := fx.svc.RegisterAgent(ctx, fx.req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.svc.VerifyACME(ctx, first.Registration.AgentID, service.VerifyInput{}); err != nil {
		t.Fatal(err)
	}

	secondReq := fx.req
	secondReq.OwnerID = "different-authenticated-owner"
	version, err := domain.ParseSemVer("2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	secondReq.AnsName, err = domain.NewAnsName(version, fx.req.AnsName.FQDN())
	if err != nil {
		t.Fatal(err)
	}
	secondReq.IdentityCSRPEM = testCSR(t, secondReq.AnsName.String())
	secondReq.ServerCsrPEM = testServerCSR(t, secondReq.AnsName.FQDN())
	svc := rebuildWithIssuer(fx, bornReadyIssuer{real: fx.serverCA}, failingDNSVerifier{}, nil)
	second, err := svc.RegisterAgent(ctx, secondReq)
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.VerifyACME(ctx, second.Registration.AgentID, service.VerifyInput{})
	if err == nil {
		certs, certErr := fx.certs.FindIdentityCertificatesByAgent(ctx, second.Registration.AgentID)
		if certErr != nil {
			t.Fatal(certErr)
		}
		t.Fatalf("a different owner with no published challenge obtained status=%s serverCert=%t identityCerts=%d while first registration was pending DNS",
			result.Registration.Status, result.Registration.ServerCert != nil, len(certs))
	}
}

func TestRegression_ServerRenewalPublishesUpdatedBinding(t *testing.T) {
	ctx := context.Background()
	fx := newRegFixture(t)
	registration, err := fx.svc.RegisterAgent(ctx, fx.req)
	if err != nil {
		t.Fatal(err)
	}
	agentID := registration.Registration.AgentID
	if _, err := fx.svc.VerifyACME(ctx, agentID, service.VerifyInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.svc.VerifyDNS(ctx, agentID, service.VerifyInput{}); err != nil {
		t.Fatal(err)
	}
	before, err := fx.byoc.FindLatestValidByAgentID(ctx, agentID)
	if err != nil {
		t.Fatal(err)
	}
	initialSeals := len(fx.sealer.sealed())
	if _, err := fx.svc.SubmitServerCertRenewal(ctx, agentID, service.SubmitRenewalInput{
		ServerCsrPEM: testServerCSR(t, fx.req.AnsName.FQDN()),
	}); err != nil {
		t.Fatal(err)
	}
	result, err := fx.svc.VerifyRenewalACME(ctx, agentID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Renewal.CompletedAt.IsZero() {
		t.Fatal("renewal did not complete")
	}
	after, err := fx.byoc.FindLatestValidByAgentID(ctx, agentID)
	if err != nil {
		t.Fatal(err)
	}
	if before.Fingerprint == after.Fingerprint {
		t.Fatal("renewal fixture did not change the certificate")
	}
	// Re-driving verify-dns on the active agent must not be assumed to
	// repair the missing renewal event: exercise that path as well.
	if _, err := fx.svc.VerifyDNS(ctx, agentID, service.VerifyInput{}); err != nil {
		t.Fatal(err)
	}
	pending, err := fx.outboxStore.Claim(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(fx.sealer.sealed()) == initialSeals && len(pending) == 0 {
		t.Fatalf("server certificate changed from %s to %s, but renewal and a repeated verify-dns produced no TL seal or pending outbox event",
			before.Fingerprint, after.Fingerprint)
	}
}
