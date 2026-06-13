package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/godaddy/ans/internal/domain"
)

// seedOrderAgent saves a minimal registration carrying the given
// order and returns it reloaded from disk.
func seedOrderAgent(t *testing.T, db *DB, agentID string, order domain.CertificateOrder) *domain.AgentRegistration {
	t.Helper()
	store := NewAgentStore(db)
	sv, _ := domain.ParseSemVer("1.0.0")
	ansName, _ := domain.NewAnsName(sv, agentID+".example.com")
	reg := &domain.AgentRegistration{
		AgentID:   agentID,
		OwnerID:   "owner",
		AnsName:   ansName,
		Status:    domain.StatusPendingValidation,
		CertOrder: order,
		Details: domain.RegistrationDetails{
			RegistrationTimestamp: time.Now(),
		},
	}
	if err := store.Save(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	got, err := store.FindByAgentID(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestAgentStore_CertOrderRoundTrip pins the full order persistence:
// provider ref, state, challenge set (including provider-computed
// overrides), and expiry survive a write/read cycle.
func TestAgentStore_CertOrderRoundTrip(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	exp := time.Now().Add(2 * time.Hour).Truncate(time.Millisecond)
	order := domain.CertificateOrder{
		OrderRef: "https://acme.example/order/123",
		State:    domain.OrderStatePending,
		Challenges: []domain.Challenge{
			{
				Type:             domain.ChallengeTypeDNS01,
				Token:            "tok-dns",
				KeyAuthorization: "tok-dns.thumb",
				DNSRecordValue:   "digest-value",
			},
			{
				Type:             domain.ChallengeTypeHTTP01,
				Token:            "tok-http",
				KeyAuthorization: "tok-http.thumb",
				HTTPPath:         "/.well-known/acme-challenge/tok-http",
			},
		},
		ExpiresAt: exp,
	}
	got := seedOrderAgent(t, db, "order-roundtrip", order)

	if got.CertOrder.OrderRef != order.OrderRef {
		t.Errorf("orderRef: got %q", got.CertOrder.OrderRef)
	}
	if got.CertOrder.State != domain.OrderStatePending {
		t.Errorf("state: got %q", got.CertOrder.State)
	}
	if !got.CertOrder.ExpiresAt.Equal(exp) {
		t.Errorf("expiresAt: got %v want %v", got.CertOrder.ExpiresAt, exp)
	}
	dns01, ok := got.CertOrder.ChallengeOfType(domain.ChallengeTypeDNS01)
	if !ok || dns01.DNSRecordValue != "digest-value" || dns01.KeyAuthorization != "tok-dns.thumb" {
		t.Errorf("dns01 challenge lost provider fields: %+v", dns01)
	}
	http01, ok := got.CertOrder.ChallengeOfType(domain.ChallengeTypeHTTP01)
	if !ok || http01.HTTPPath != "/.well-known/acme-challenge/tok-http" {
		t.Errorf("http01 challenge lost fields: %+v", http01)
	}

	// State updates persist through the UPDATE path too.
	if err := got.CertOrder.MarkIssuing(); err != nil {
		t.Fatal(err)
	}
	if err := NewAgentStore(db).Save(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	again, err := NewAgentStore(db).FindByAgentID(context.Background(), "order-roundtrip")
	if err != nil {
		t.Fatal(err)
	}
	if again.CertOrder.State != domain.OrderStateIssuing {
		t.Errorf("updated state: got %q want ISSUING", again.CertOrder.State)
	}
}

// TestAgentStore_ZeroOrderStaysZero: registrations without an order
// (zero value) read back as zero — NULL columns, no synthesis.
func TestAgentStore_ZeroOrderStaysZero(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	got := seedOrderAgent(t, db, "zero-order", domain.CertificateOrder{})
	if !got.CertOrder.IsZero() {
		t.Errorf("zero order should round-trip as zero, got %+v", got.CertOrder)
	}
}

// TestAgentStore_LegacyRowSynthesizesOrder: a row written before
// migration 006 (bare acme_dns01_token, NULL order columns) reads as
// a self-issued single-DNS-01 PENDING order, so in-flight
// registrations keep working across the upgrade.
func TestAgentStore_LegacyRowSynthesizesOrder(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	got := seedOrderAgent(t, db, "legacy-agent", domain.CertificateOrder{})

	// Rewrite the row into its pre-006 shape: legacy token column set,
	// order columns NULL.
	expMs := time.Now().Add(time.Hour).Truncate(time.Millisecond)
	if _, err := db.DBX().Exec(`
        UPDATE agent_registrations SET
            acme_dns01_token = 'legacy-tok',
            acme_challenge_expires_at_ms = ?,
            cert_order_ref = NULL, cert_order_state = NULL, cert_order_challenges = NULL
        WHERE agent_id = 'legacy-agent'`, expMs.UnixMilli()); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewAgentStore(db).FindByAgentID(context.Background(), "legacy-agent")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.CertOrder.State != domain.OrderStatePending {
		t.Fatalf("legacy synthesis state: got %q want PENDING", reloaded.CertOrder.State)
	}
	dns01, ok := reloaded.CertOrder.ChallengeOfType(domain.ChallengeTypeDNS01)
	if !ok || dns01.Token != "legacy-tok" {
		t.Fatalf("legacy synthesis challenge: %+v ok=%v", dns01, ok)
	}
	if _, hasHTTP := reloaded.CertOrder.ChallengeOfType(domain.ChallengeTypeHTTP01); hasHTTP {
		t.Error("legacy rows never carried an HTTP-01 token; none should be synthesized")
	}
	if !reloaded.CertOrder.ExpiresAt.Equal(expMs) {
		t.Errorf("legacy expiry: got %v want %v", reloaded.CertOrder.ExpiresAt, expMs)
	}
	if !got.CertOrder.IsZero() {
		t.Error("precondition: seeded order should have been zero")
	}
}

// TestAgentStore_MalformedChallengeJSON surfaces a decode error
// instead of silently dropping the order.
func TestAgentStore_MalformedChallengeJSON(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedOrderAgent(t, db, "bad-json", domain.CertificateOrder{})
	// `{"not":"array"}` passes the json_valid CHECK but cannot decode
	// into []Challenge.
	if _, err := db.DBX().Exec(`
        UPDATE agent_registrations SET cert_order_challenges = '{"not":"array"}'
        WHERE agent_id = 'bad-json'`); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAgentStore(db).FindByAgentID(context.Background(), "bad-json"); err == nil {
		t.Fatal("want decode error for malformed challenge JSON")
	}
}

// TestRenewalStore_LegacyRowSynthesizesChallenges: pre-006 renewal
// rows (bare token columns, NULL challenges JSON) read back as the
// self-issued challenge pair.
func TestRenewalStore_LegacyRowSynthesizesChallenges(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg := seedOrderAgent(t, db, "legacy-renewal-agent", domain.CertificateOrder{})
	renewals := NewRenewalStore(db)
	r := domain.NewBYOCRenewal(reg.AgentID, reg.ID, "LEAF", "CHAIN",
		domain.NewSelfIssuedOrder("dns-tok", "http-tok", time.Now().Add(time.Hour)), time.Now())
	if err := renewals.Save(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	// Strip the JSON column to simulate a pre-006 row; the NOT NULL
	// token columns are already populated by Save.
	if _, err := db.DBX().Exec(
		`UPDATE server_cert_renewals SET challenges = NULL, order_ref = NULL WHERE agent_id = ?`,
		reg.AgentID); err != nil {
		t.Fatal(err)
	}

	got, err := renewals.FindByAgentID(context.Background(), reg.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	dns01, ok := got.Validation.ChallengeOfType(domain.ChallengeTypeDNS01)
	if !ok || dns01.Token != "dns-tok" {
		t.Fatalf("legacy dns01 synthesis: %+v ok=%v", dns01, ok)
	}
	http01, ok := got.Validation.ChallengeOfType(domain.ChallengeTypeHTTP01)
	if !ok || http01.Token != "http-tok" {
		t.Fatalf("legacy http01 synthesis: %+v ok=%v", http01, ok)
	}
}

// TestRenewalStore_OrderRefRoundTrip pins provider order persistence
// on the renewal lane.
func TestRenewalStore_OrderRefRoundTrip(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg := seedOrderAgent(t, db, "renewal-order-agent", domain.CertificateOrder{})
	renewals := NewRenewalStore(db)
	order := domain.CertificateOrder{
		OrderRef: "https://acme.example/order/9",
		State:    domain.OrderStatePending,
		Challenges: []domain.Challenge{
			{Type: domain.ChallengeTypeDNS01, Token: "t", KeyAuthorization: "t.kid", DNSRecordValue: "digest"},
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}
	r := domain.NewCSRRenewal(reg.AgentID, reg.ID, "csr-1", order, time.Now())
	if err := renewals.Save(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	got, err := renewals.FindByAgentID(context.Background(), reg.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Validation.OrderRef != order.OrderRef {
		t.Errorf("orderRef: got %q", got.Validation.OrderRef)
	}
	dns01, ok := got.Validation.ChallengeOfType(domain.ChallengeTypeDNS01)
	if !ok || dns01.DNSRecordValue != "digest" {
		t.Errorf("provider DNS value lost: %+v", dns01)
	}
}
