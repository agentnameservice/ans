package cert

import (
	"os"
	"strings"
	"testing"

	"github.com/godaddy/ans/internal/domain"
)

// TestLive_LetsEncryptStaging_CreateOrder talks to REAL Let's Encrypt
// staging: it registers a throwaway staging account, opens an order,
// and asserts the relayed challenges are LE's own (provider order
// URL, LE-minted token, computed DNS digest, key authorization).
//
// Opt-in via ANS_LE_LIVE_TEST=1 — it needs outbound network and
// consumes (generous) staging rate limits, so it is not part of the
// hermetic suite; the in-process acmetest fake covers the protocol
// there. Order *creation* requires no domain ownership — only
// satisfying a challenge does — which is what makes this smoke test
// runnable from anywhere:
//
//	ANS_LE_LIVE_TEST=1 go test ./internal/adapter/cert/ -run TestLive -v
//
// Completing a full issuance against staging additionally requires a
// public domain you control: run the RA with `ca.server.type: acme`
// pointed at the staging directory and publish the relayed challenge
// for your real FQDN.
func TestLive_LetsEncryptStaging_CreateOrder(t *testing.T) {
	if os.Getenv("ANS_LE_LIVE_TEST") == "" {
		t.Skip("live Let's Encrypt staging test; set ANS_LE_LIVE_TEST=1 to run")
	}
	issuer, err := NewACMEIssuer(
		"https://acme-staging-v02.api.letsencrypt.org/directory",
		"", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	order, err := issuer.CreateOrder(t.Context(), "agent.ans-issuer-smoke-2026.com")
	if err != nil {
		t.Fatalf("create order against real LE staging: %v", err)
	}
	t.Logf("LE staging order ref: %s", order.OrderRef)
	t.Logf("order expires: %s", order.ExpiresAt)
	if !strings.Contains(order.OrderRef, "acme-staging-v02.api.letsencrypt.org") {
		t.Errorf("order ref is not a real LE staging URL: %q", order.OrderRef)
	}
	dns01, ok := order.ChallengeOfType(domain.ChallengeTypeDNS01)
	if !ok {
		t.Fatal("LE did not offer dns-01")
	}
	t.Logf("dns-01 token (LE-minted): %s", dns01.Token)
	t.Logf("TXT value to publish (digest): %s", dns01.EffectiveDNSRecordValue())
	t.Logf("key authorization: %s", dns01.KeyAuthorization)
	if dns01.EffectiveDNSRecordValue() == dns01.Token || dns01.KeyAuthorization == "" {
		t.Error("LE challenges must carry the computed digest + key authorization")
	}
	http01, ok := order.ChallengeOfType(domain.ChallengeTypeHTTP01)
	if !ok {
		t.Fatal("LE did not offer http-01")
	}
	t.Logf("http-01 path: %s", http01.EffectiveHTTPPath())
}
