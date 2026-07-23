package crypto_test

import (
	"errors"
	"net/url"
	"testing"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
)

// mustURL panics on parse error, acceptable for test fixtures.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("bad URI fixture %q: %v", raw, err)
	}
	return u
}

// ----- ValidateIdentityCSR -----
//
// Identity CSRs must carry the versioned ANS name as a URI SAN. The
// CN is ignored for identity binding — Go's x509 enforces nothing
// here, so URI-SAN matching is the only proof of the ANS name.

func TestValidateIdentityCSR_OK(t *testing.T) {
	t.Parallel()
	ans := "ans://v1.0.0.example.com"
	csrPEM := issueCSR(t, "ecdsa-p256", "ignored-cn", nil, mustURL(t, ans))

	csr, err := anscrypto.ValidateIdentityCSR(csrPEM, ans)
	if err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if csr == nil {
		t.Fatal("want parsed CSR, got nil")
	}
}

func TestValidateIdentityCSR_RejectsBadPEM(t *testing.T) {
	t.Parallel()
	_, err := anscrypto.ValidateIdentityCSR("not a pem", "ans://v1.0.0.x")
	if !errors.Is(err, anscrypto.ErrPEMParse) {
		t.Errorf("want ErrPEMParse, got %v", err)
	}
}

func TestValidateIdentityCSR_RejectsWeakKey(t *testing.T) {
	t.Parallel()
	// RSA-1024 is below MinRSAKeyBits (2048).
	csrPEM := issueCSR(t, "rsa-1024", "cn", nil, mustURL(t, "ans://v1.0.0.x"))
	_, err := anscrypto.ValidateIdentityCSR(csrPEM, "ans://v1.0.0.x")
	if !errors.Is(err, anscrypto.ErrWeakKey) {
		t.Errorf("want ErrWeakKey, got %v", err)
	}
}

func TestValidateIdentityCSR_RejectsWeakCurve(t *testing.T) {
	t.Parallel()
	// P-224 isn't on the allowed curve list.
	csrPEM := issueCSR(t, "ecdsa-p224", "cn", nil, mustURL(t, "ans://v1.0.0.x"))
	_, err := anscrypto.ValidateIdentityCSR(csrPEM, "ans://v1.0.0.x")
	if !errors.Is(err, anscrypto.ErrWeakKey) {
		t.Errorf("want ErrWeakKey, got %v", err)
	}
}

func TestValidateIdentityCSR_RejectsMismatchedURISAN(t *testing.T) {
	t.Parallel()
	csrPEM := issueCSR(t, "ecdsa-p256", "cn", nil, mustURL(t, "ans://v1.0.0.other.com"))
	_, err := anscrypto.ValidateIdentityCSR(csrPEM, "ans://v1.0.0.expected.com")
	if !errors.Is(err, anscrypto.ErrFQDNMismatch) {
		t.Errorf("want ErrFQDNMismatch, got %v", err)
	}
}

func TestValidateIdentityCSR_RejectsMissingURISAN(t *testing.T) {
	t.Parallel()
	// No URIs attached at all.
	csrPEM := issueCSR(t, "ecdsa-p256", "cn", []string{"example.com"}, nil)
	_, err := anscrypto.ValidateIdentityCSR(csrPEM, "ans://v1.0.0.example.com")
	if !errors.Is(err, anscrypto.ErrFQDNMismatch) {
		t.Errorf("want ErrFQDNMismatch, got %v", err)
	}
}

// ----- ValidateServerCSR -----
//
// Server CSRs must carry the agent FQDN as a DNS SAN. CN fallback is
// allowed for SDK compatibility but the SAN is the primary binding.

func TestValidateServerCSR_OK_DNSSAN(t *testing.T) {
	t.Parallel()
	csrPEM := issueCSR(t, "ecdsa-p256", "ignored", []string{"agent.example.com"}, nil)
	if _, err := anscrypto.ValidateServerCSR(csrPEM, "agent.example.com"); err != nil {
		t.Errorf("want nil, got %v", err)
	}
}

func TestValidateServerCSR_OK_CNFallback(t *testing.T) {
	t.Parallel()
	// No DNS SAN — CN-only CSRs still pass the compatibility path.
	csrPEM := issueCSR(t, "ecdsa-p256", "agent.example.com", nil, nil)
	if _, err := anscrypto.ValidateServerCSR(csrPEM, "agent.example.com"); err != nil {
		t.Errorf("want nil, got %v", err)
	}
}

func TestValidateServerCSR_RejectsBadPEM(t *testing.T) {
	t.Parallel()
	_, err := anscrypto.ValidateServerCSR("not pem", "agent.example.com")
	if !errors.Is(err, anscrypto.ErrPEMParse) {
		t.Errorf("want ErrPEMParse, got %v", err)
	}
}

func TestValidateServerCSR_RejectsWeakKey(t *testing.T) {
	t.Parallel()
	csrPEM := issueCSR(t, "rsa-1024", "agent.example.com", nil, nil)
	_, err := anscrypto.ValidateServerCSR(csrPEM, "agent.example.com")
	if !errors.Is(err, anscrypto.ErrWeakKey) {
		t.Errorf("want ErrWeakKey, got %v", err)
	}
}

func TestValidateServerCSR_RejectsMismatchedFQDN(t *testing.T) {
	t.Parallel()
	csrPEM := issueCSR(t, "ecdsa-p256", "other.example.com", []string{"other.example.com"}, nil)
	_, err := anscrypto.ValidateServerCSR(csrPEM, "agent.example.com")
	if !errors.Is(err, anscrypto.ErrFQDNMismatch) {
		t.Errorf("want ErrFQDNMismatch, got %v", err)
	}
}

// ----- matchDNSSAN (via ValidateServerCSR paths) + empty FQDN path -----

func TestValidateServerCSR_RejectsEmptyExpected(t *testing.T) {
	t.Parallel()
	// A well-formed CSR but the caller passes an empty expected FQDN
	// — this hits the "expected FQDN is empty" branch in matchDNSSAN.
	csrPEM := issueCSR(t, "ecdsa-p256", "agent.example.com", []string{"agent.example.com"}, nil)
	_, err := anscrypto.ValidateServerCSR(csrPEM, "   ")
	if !errors.Is(err, anscrypto.ErrFQDNMismatch) {
		t.Errorf("want ErrFQDNMismatch, got %v", err)
	}
}

// ----- matchURISAN empty-expected path -----

func TestValidateIdentityCSR_RejectsEmptyExpected(t *testing.T) {
	t.Parallel()
	// Identity CSR with a URI SAN, but the caller passes empty. Hits
	// the "expected ANS name is empty" branch in matchURISAN.
	csrPEM := issueCSR(t, "ecdsa-p256", "cn", nil, mustURL(t, "ans://v1.0.0.x"))
	_, err := anscrypto.ValidateIdentityCSR(csrPEM, "")
	if !errors.Is(err, anscrypto.ErrFQDNMismatch) {
		t.Errorf("want ErrFQDNMismatch, got %v", err)
	}
}
