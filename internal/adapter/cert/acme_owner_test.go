package cert

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/port"
)

func TestACMEIssuer_OwnerAccountsIsolatePendingAuthorizationsAndPersist(t *testing.T) {
	f := newFakeACME(t)
	dir := t.TempDir()
	issuer, err := NewACMEIssuer(f.DirectoryURL(), "ops@example.com", dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := issuer.CreateOrderForOwner(t.Context(), "owner-a", "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := issuer.CreateOrderForOwner(t.Context(), "owner-b", "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := first.ChallengeOfType(domain.ChallengeTypeDNS01)
	b, _ := second.ChallengeOfType(domain.ChallengeTypeDNS01)
	// The fake deliberately reuses a pending token. Account key binding must
	// still make the artifacts different for different authenticated owners.
	if a.Token != b.Token || a.DNSRecordValue == b.DNSRecordValue || a.KeyAuthorization == b.KeyAuthorization {
		t.Fatal("pending provider authorization is shared across owners")
	}
	repeated, err := issuer.CreateOrderForOwner(t.Context(), "owner-a", "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	repeatDNS, _ := repeated.ChallengeOfType(domain.ChallengeTypeDNS01)
	if repeatDNS.DNSRecordValue != a.DNSRecordValue {
		t.Fatal("same owner did not reuse its account key")
	}

	restarted, err := NewACMEIssuer(f.DirectoryURL(), "ops@example.com", dir)
	if err != nil {
		t.Fatal(err)
	}
	afterRestart, err := restarted.CreateOrderForOwner(t.Context(), "owner-a", "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	restartDNS, _ := afterRestart.ChallengeOfType(domain.ChallengeTypeDNS01)
	if restartDNS.DNSRecordValue != a.DNSRecordValue {
		t.Fatal("restart changed the owner account key")
	}
	issued, err := restarted.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OwnerID:  "owner-a",
		OrderRef: first.OrderRef, FQDN: "agent.example.com",
		CSRPEM:   buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"}),
		Verified: []domain.ChallengeType{domain.ChallengeTypeDNS01},
	})
	if err != nil || issued == nil || issued.CertPEM == "" {
		t.Fatalf("persisted owner order did not finalize after restart: %v", err)
	}
	root, err := restarted.GetCACertificate(t.Context())
	if err != nil || !strings.Contains(root, "BEGIN CERTIFICATE") {
		t.Fatalf("root unavailable after owner issuance: %v", err)
	}
	if strings.Contains(first.OrderRef, "owner-a") || !strings.HasSuffix(first.OrderRef, f.OrderURL()) {
		t.Fatal("opaque order reference leaked owner ID or lost provider handle")
	}
}

func TestACMEIssuer_OwnerOrderValidation(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)
	for _, ref := range []string{
		f.OrderURL(), // An old shared-account order cannot establish owner proof.
		scopedOrderPrefix + ownerAccountID("different-owner") + ":" + f.OrderURL(),
	} {
		if _, err := issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
			OwnerID: "owner-a", OrderRef: ref,
		}); !errors.Is(err, port.ErrOrderFailed) {
			t.Fatalf("unbound owner order accepted: %v", err)
		}
	}
	if _, err := issuer.CreateOrderForOwner(t.Context(), "", "agent.example.com"); err == nil {
		t.Fatal("empty owner accepted")
	}
	for _, ref := range []string{
		scopedOrderPrefix, scopedOrderPrefix + "../escape:http://provider/order",
		scopedOrderPrefix + strings.Repeat("0", 64) + ":",
		scopedOrderPrefix + strings.Repeat("g", 64) + ":http://provider/order",
	} {
		if _, err := issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{OrderRef: ref}); err == nil {
			t.Fatalf("invalid order reference accepted: %q", ref)
		}
	}
	if _, err := issuer.CreateOrderForOwner(t.Context(), "owner-a", ""); err == nil {
		t.Fatal("empty fqdn accepted")
	}
	// A broken account directory must fail before contacting the provider.
	broken := newTestACMEIssuer(t, f)
	if err := os.WriteFile(filepath.Join(broken.dataDir, "owners"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := broken.CreateOrderForOwner(t.Context(), "owner-a", "agent.example.com"); err == nil {
		t.Fatal("account storage failure swallowed")
	}
	if _, err := broken.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: scopedOrderPrefix + strings.Repeat("0", 64) + ":" + f.OrderURL(),
	}); err == nil {
		t.Fatal("finalize account storage failure swallowed")
	}
}
