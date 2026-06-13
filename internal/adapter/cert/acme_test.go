package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/godaddy/ans/internal/adapter/cert/acmetest"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

func newFakeACME(t *testing.T) *acmetest.Server {
	t.Helper()
	f, err := acmetest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if perr := f.Err(); perr != nil {
			t.Errorf("fake acme observed a protocol violation: %v", perr)
		}
		f.Close()
	})
	return f
}

func newTestACMEIssuer(t *testing.T, f *acmetest.Server, opts ...ACMEIssuerOption) *ACMEIssuer {
	t.Helper()
	issuer, err := NewACMEIssuer(f.DirectoryURL(), "ops@example.com", t.TempDir(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func TestACMEIssuer_CreateOrder_RelaysProviderChallenges(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)

	order, err := issuer.CreateOrder(t.Context(), "agent.example.com")
	if err != nil {
		t.Fatalf("create order: %v", err)
	}
	if order.OrderRef != f.OrderURL() {
		t.Errorf("order ref must be the provider order URL, got %q", order.OrderRef)
	}
	if order.State != domain.OrderStatePending || order.ExpiresAt.IsZero() {
		t.Errorf("order shape: %+v", order)
	}

	dns01, ok := order.ChallengeOfType(domain.ChallengeTypeDNS01)
	if !ok {
		t.Fatal("missing dns-01")
	}
	if dns01.Token != f.DNSToken() {
		t.Errorf("dns token: %q", dns01.Token)
	}
	// The TXT value is the digest of the key authorization — never
	// the raw token for an ACME provider.
	if dns01.DNSRecordValue == "" || dns01.DNSRecordValue == dns01.Token {
		t.Errorf("dns record value must be the provider digest, got %q", dns01.DNSRecordValue)
	}
	if !strings.HasPrefix(dns01.KeyAuthorization, f.DNSToken()+".") {
		t.Errorf("key authorization shape: %q", dns01.KeyAuthorization)
	}

	http01, ok := order.ChallengeOfType(domain.ChallengeTypeHTTP01)
	if !ok {
		t.Fatal("missing http-01")
	}
	if http01.EffectiveHTTPPath() != "/.well-known/acme-challenge/"+f.HTTPToken() {
		t.Errorf("http path: %q", http01.EffectiveHTTPPath())
	}
	if !strings.HasPrefix(http01.KeyAuthorization, f.HTTPToken()+".") {
		t.Errorf("http key authorization: %q", http01.KeyAuthorization)
	}
}

func TestACMEIssuer_FinalizeOrder_AnswersOnlyVerifiedChallenge(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)

	order, err := issuer.CreateOrder(t.Context(), "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"})

	issued, err := issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: order.OrderRef,
		CSRPEM:   csrPEM,
		FQDN:     "agent.example.com",
		Verified: []domain.ChallengeType{domain.ChallengeTypeDNS01},
	})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if issued.CertPEM == "" || issued.ChainPEM == "" || issued.SerialNumber == "" {
		t.Errorf("issued cert incomplete: %+v", issued)
	}

	// The Verified contract: only the RA-verified challenge was
	// answered. Answering the unsatisfied http-01 would have
	// invalidated the authorization at a real provider.
	if accepted := f.Accepted(); len(accepted) != 1 || accepted[0] != "dns" {
		t.Errorf("accepted challenges: %v, want exactly [dns]", accepted)
	}

	// Chain root is cached for GetCACertificate after issuance.
	rootPEM, err := issuer.GetCACertificate(t.Context())
	if err != nil || !strings.Contains(rootPEM, "BEGIN CERTIFICATE") {
		t.Errorf("GetCACertificate after issuance: err=%v", err)
	}
}

func TestACMEIssuer_FinalizeOrder_PendingThenRedriven(t *testing.T) {
	f := newFakeACME(t)
	// Tight budget ONLY for the held-pending call: the fake replies
	// Retry-After: 1s, so a sub-second budget forces WaitOrder to
	// time out into ErrOrderPending deterministically.
	pendingIssuer := newTestACMEIssuer(t, f, WithFinalizeBudget(300*time.Millisecond))

	order, err := pendingIssuer.CreateOrder(t.Context(), "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"})

	// Provider-side validation outlives the in-call budget.
	f.SetHoldPending(true)
	_, err = pendingIssuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: order.OrderRef,
		CSRPEM:   csrPEM,
		FQDN:     "agent.example.com",
		Verified: []domain.ChallengeType{domain.ChallengeTypeDNS01},
	})
	if !errors.Is(err, port.ErrOrderPending) {
		t.Fatalf("want ErrOrderPending, got %v", err)
	}

	// Validation completes provider-side; a re-driven call (modeled as
	// a separate verify-acme request, hence its own default-budget
	// issuer — the fake binds orders to no account, so the order URL
	// re-drives cleanly) finishes the order. The default budget means
	// the expected-success finalize is never racing a tight deadline.
	f.SetHoldPending(false)
	f.SetOrderStatus(acme.StatusReady)
	redriveIssuer := newTestACMEIssuer(t, f)
	issued, err := redriveIssuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: order.OrderRef,
		CSRPEM:   csrPEM,
		FQDN:     "agent.example.com",
		Verified: []domain.ChallengeType{domain.ChallengeTypeDNS01},
	})
	if err != nil {
		t.Fatalf("re-driven finalize: %v", err)
	}
	if issued.CertPEM == "" {
		t.Error("re-driven finalize returned no cert")
	}
}

func TestACMEIssuer_FinalizeOrder_ProcessingReportsPending(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)

	order, err := issuer.CreateOrder(t.Context(), "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Provider already validating/issuing when we arrive.
	f.SetOrderStatus(acme.StatusProcessing)
	_, err = issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: order.OrderRef,
		CSRPEM:   buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"}),
		FQDN:     "agent.example.com",
	})
	if !errors.Is(err, port.ErrOrderPending) {
		t.Fatalf("want ErrOrderPending for processing order, got %v", err)
	}
}

func TestACMEIssuer_FinalizeOrder_UnknownStatus(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)

	order, err := issuer.CreateOrder(t.Context(), "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.SetOrderStatus("deactivated")
	_, err = issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: order.OrderRef,
		CSRPEM:   buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"}),
		FQDN:     "agent.example.com",
	})
	if err == nil || errors.Is(err, port.ErrOrderPending) || errors.Is(err, port.ErrOrderFailed) {
		t.Fatalf("unknown status must be a plain error, got %v", err)
	}
}

func TestACMEIssuer_FinalizeOrder_ProviderOutageMidIssuance(t *testing.T) {
	f := newFakeACME(t)
	// Short budget: the client retries 5xx finalize responses until
	// the budget expires.
	issuer := newTestACMEIssuer(t, f, WithFinalizeBudget(300*time.Millisecond))

	order, err := issuer.CreateOrder(t.Context(), "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.SetFailFinalize(true)
	_, err = issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: order.OrderRef,
		CSRPEM:   buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"}),
		FQDN:     "agent.example.com",
		Verified: []domain.ChallengeType{domain.ChallengeTypeDNS01},
	})
	// A 500 on finalize is neither pending nor a terminal order
	// failure — it surfaces as a plain retryable error.
	if err == nil || errors.Is(err, port.ErrOrderPending) || errors.Is(err, port.ErrOrderFailed) {
		t.Fatalf("provider outage must be a plain error, got %v", err)
	}
}

func TestACMEIssuer_FinalizeOrder_ValidOrderFetchesCert(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)

	order, err := issuer.CreateOrder(t.Context(), "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Order already valid (issued while we were away): FetchCert path.
	f.SetOrderStatus(acme.StatusValid)
	issued, err := issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: order.OrderRef,
		CSRPEM:   buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"}),
		FQDN:     "agent.example.com",
	})
	if err != nil || issued.CertPEM == "" {
		t.Fatalf("valid-order fetch: err=%v", err)
	}
}

func TestACMEIssuer_FinalizeOrder_InvalidOrderFails(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)

	order, err := issuer.CreateOrder(t.Context(), "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.SetFailValidation(true)
	_, err = issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: order.OrderRef,
		CSRPEM:   buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"}),
		FQDN:     "agent.example.com",
		Verified: []domain.ChallengeType{domain.ChallengeTypeDNS01},
	})
	if !errors.Is(err, port.ErrOrderFailed) {
		t.Fatalf("want ErrOrderFailed, got %v", err)
	}
}

func TestACMEIssuer_FinalizeOrder_InputValidation(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)

	// Bad CSR shape rejected before any provider call.
	if _, err := issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: "x", CSRPEM: "junk", FQDN: "agent.example.com",
	}); err == nil {
		t.Error("want CSR validation error")
	}
	// Missing order ref rejected.
	if _, err := issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		CSRPEM: buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"}),
		FQDN:   "agent.example.com",
	}); err == nil {
		t.Error("want order-ref error")
	}
}

func TestACMEIssuer_GetCACertificate_BeforeIssuance(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)
	if _, err := issuer.GetCACertificate(t.Context()); err == nil {
		t.Error("want error before first issuance")
	}
}

func TestACMEIssuer_AccountKeyPersists(t *testing.T) {
	f := newFakeACME(t)
	dir := t.TempDir()
	i1, err := NewACMEIssuer(f.DirectoryURL(), "", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i1.CreateOrder(t.Context(), "agent.example.com"); err != nil {
		t.Fatal(err)
	}
	// Second instance reuses the persisted key — same account per
	// RFC 8555 §7.3.1.
	i2, err := NewACMEIssuer(f.DirectoryURL(), "", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i2.CreateOrder(t.Context(), "agent.example.com"); err != nil {
		t.Fatalf("second instance with persisted key: %v", err)
	}
	k1, ok1 := i1.client.Key.(*ecdsa.PrivateKey)
	k2, ok2 := i2.client.Key.(*ecdsa.PrivateKey)
	if !ok1 || !ok2 || !k1.Equal(k2) {
		t.Error("account key must persist across restarts")
	}
}

func TestNewACMEIssuer_InputValidation(t *testing.T) {
	if _, err := NewACMEIssuer("", "", t.TempDir()); err == nil {
		t.Error("want directory-url error")
	}
	if _, err := NewACMEIssuer("https://example.com/dir", "", ""); err == nil {
		t.Error("want data-dir error")
	}
}

func TestACMEIssuer_CreateOrder_RequiresFQDN(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)
	if _, err := issuer.CreateOrder(t.Context(), ""); err == nil {
		t.Error("want fqdn error")
	}
}

func TestACMEIssuer_HTTP01VerifiedChallengeAnswered(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)

	order, err := issuer.CreateOrder(t.Context(), "agent.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: order.OrderRef,
		CSRPEM:   buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"}),
		FQDN:     "agent.example.com",
		Verified: []domain.ChallengeType{domain.ChallengeTypeHTTP01},
	}); err != nil {
		t.Fatalf("finalize via http-01: %v", err)
	}
	if accepted := f.Accepted(); len(accepted) != 1 || accepted[0] != "http" {
		t.Errorf("accepted: %v, want exactly [http]", accepted)
	}
}

func TestACMEIssuer_CreateOrder_BornReady(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)
	// Authorization reuse (RFC 8555 §7.1.3): a new order comes back
	// already 'ready', so there is no challenge for the owner to
	// publish. CreateOrder must relay it as ISSUING with no challenges
	// — NOT error — so the gate skips it and verify-acme finalizes
	// directly. This is routine on real Let's Encrypt within its
	// authorization-reuse window.
	f.SetOrderStatus(acme.StatusReady)
	order, err := issuer.CreateOrder(t.Context(), "agent.example.com")
	if err != nil {
		t.Fatalf("born-ready order must not error: %v", err)
	}
	if order.State != domain.OrderStateIssuing {
		t.Errorf("state: got %s want ISSUING", order.State)
	}
	if len(order.Challenges) != 0 {
		t.Errorf("born-ready order must carry no challenges, got %d", len(order.Challenges))
	}
	if order.OrderRef != f.OrderURL() {
		t.Errorf("order ref: got %q", order.OrderRef)
	}
}

func TestACMEIssuer_CreateOrder_NoSupportedChallenges(t *testing.T) {
	f := newFakeACME(t)
	issuer := newTestACMEIssuer(t, f)
	// A pending order whose only challenge is tls-alpn-01 (which this
	// adapter doesn't implement) must surface a clear error, not an
	// empty challenge set the gate could never satisfy.
	f.SetUnsupportedChallengesOnly(true)
	if _, err := issuer.CreateOrder(t.Context(), "agent.example.com"); err == nil {
		t.Error("want no-supported-challenges error")
	}
}

func TestACMEIssuer_UnreachableProvider(t *testing.T) {
	issuer, err := NewACMEIssuer("http://127.0.0.1:1/dir", "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.CreateOrder(t.Context(), "agent.example.com"); err == nil {
		t.Error("want registration failure against unreachable provider")
	}
	if _, err := issuer.FinalizeOrder(t.Context(), port.FinalizeOrderRequest{
		OrderRef: "http://127.0.0.1:1/order/1",
		CSRPEM:   buildCSR(t, "agent.example.com", nil, []string{"agent.example.com"}),
		FQDN:     "agent.example.com",
	}); err == nil {
		t.Error("want finalize failure against unreachable provider")
	}
}

func TestLoadOrCreateAccountKey_Errors(t *testing.T) {
	dir := t.TempDir()

	// Garbage PEM.
	junk := filepath.Join(dir, "junk.key")
	if err := os.WriteFile(junk, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateAccountKey(junk); err == nil {
		t.Error("want PEM error for junk key file")
	}

	// Wrong PEM block type.
	wrongType := filepath.Join(dir, "wrong-type.key")
	if err := os.WriteFile(wrongType,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateAccountKey(wrongType); err == nil {
		t.Error("want type error for non-private-key PEM")
	}

	// Valid PKCS#8 but not ECDSA.
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	_ = edPub
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	notEC := filepath.Join(dir, "ed25519.key")
	if err := os.WriteFile(notEC,
		pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: edDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateAccountKey(notEC); err == nil {
		t.Error("want ECDSA error for ed25519 key")
	}

	// PEM type right, DER garbage.
	badDER := filepath.Join(dir, "bad-der.key")
	if err := os.WriteFile(badDER,
		pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: []byte{0xff}}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateAccountKey(badDER); err == nil {
		t.Error("want parse error for bad DER")
	}

	// Read failure that isn't not-exist: path is a directory.
	if _, err := loadOrCreateAccountKey(dir); err == nil {
		t.Error("want read error for directory path")
	}
}

func TestNewACMEIssuer_DataDirCreationFails(t *testing.T) {
	// dataDir nested under a regular file cannot be created.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewACMEIssuer("https://acme.example/dir", "", filepath.Join(blocker, "sub")); err == nil {
		t.Error("want mkdir error")
	}
}
