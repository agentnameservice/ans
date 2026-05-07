package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	anscrypto "github.com/godaddy/ans/internal/crypto"
)

// ----- Test helpers -----

// issueSelfSigned mints a self-signed leaf for testing certificate
// parsing, validity windows, fingerprints, and chain verification. The
// returned triple is (certPEM, certDER, parsedCert). The parsed
// certificate is returned separately so tests can avoid round-tripping
// through PEM when they already have the structured form.
func issueSelfSigned(t *testing.T, cn string, dns []string, notBefore, notAfter time.Time) (pemStr string, cert *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dns,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemStr = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return pemStr, parsed
}

// issueCSR mints a PEM-encoded CSR using the given algorithm. keyType
// is "ecdsa-p256", "ecdsa-p224", "rsa-2048", or "rsa-1024" — the last
// two let tests exercise CheckKeyStrength failure paths. If uri is
// non-empty it is parsed and attached as a URI SAN (used by the csr
// package tests to cover matchURISAN).
func issueCSR(t *testing.T, keyType, cn string, dns []string, uri *url.URL) string {
	t.Helper()
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}
	if uri != nil {
		tmpl.URIs = append(tmpl.URIs, uri)
	}
	var priv any
	var sigAlg x509.SignatureAlgorithm
	switch keyType {
	case "ecdsa-p256":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		priv = k
		sigAlg = x509.ECDSAWithSHA256
	case "ecdsa-p224":
		k, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		priv = k
		sigAlg = x509.ECDSAWithSHA256
	case "rsa-2048":
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		priv = k
		sigAlg = x509.SHA256WithRSA
	case "rsa-1024":
		// nosemgrep: go.lang.security.audit.crypto.use_of_weak_rsa_key.use-of-weak-rsa-key
		// Intentional weak key — this test helper exists to produce CSRs
		// that exercise our CheckKeyStrength rejection path. See
		// TestCheckKeyStrength/"rsa 1024 rejected" in this file.
		k, _ := rsa.GenerateKey(rand.Reader, 1024)
		priv = k
		sigAlg = x509.SHA256WithRSA
	default:
		t.Fatalf("unknown keyType %q", keyType)
	}
	tmpl.SignatureAlgorithm = sigAlg
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// ----- ParseCertificatePEM -----

func TestParseCertificatePEM(t *testing.T) {
	t.Parallel()
	pemStr, _ := issueSelfSigned(t, "example.com", []string{"example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	t.Run("ok", func(t *testing.T) {
		cert, err := anscrypto.ParseCertificatePEM(pemStr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cert.Subject.CommonName != "example.com" {
			t.Errorf("CN: got %q, want example.com", cert.Subject.CommonName)
		}
	})

	t.Run("empty pem rejected", func(t *testing.T) {
		_, err := anscrypto.ParseCertificatePEM("")
		if !errors.Is(err, anscrypto.ErrPEMParse) {
			t.Errorf("want ErrPEMParse, got %v", err)
		}
	})

	t.Run("wrong block type rejected", func(t *testing.T) {
		// A valid PEM, but not a CERTIFICATE block.
		other := string(pem.EncodeToMemory(&pem.Block{Type: "FOO", Bytes: []byte("junk")}))
		_, err := anscrypto.ParseCertificatePEM(other)
		if !errors.Is(err, anscrypto.ErrPEMParse) {
			t.Errorf("want ErrPEMParse, got %v", err)
		}
	})

	t.Run("garbled der rejected", func(t *testing.T) {
		bad := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-real-cert")}))
		_, err := anscrypto.ParseCertificatePEM(bad)
		if !errors.Is(err, anscrypto.ErrCertParse) {
			t.Errorf("want ErrCertParse, got %v", err)
		}
	})
}

// ----- ParseCertificateChainPEM -----

func TestParseCertificateChainPEM(t *testing.T) {
	t.Parallel()
	leafPEM, _ := issueSelfSigned(t, "leaf", nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	intPEM, _ := issueSelfSigned(t, "intermediate", nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	t.Run("single cert", func(t *testing.T) {
		certs, err := anscrypto.ParseCertificateChainPEM(leafPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certs) != 1 {
			t.Errorf("got %d certs, want 1", len(certs))
		}
	})

	t.Run("multi cert chain", func(t *testing.T) {
		certs, err := anscrypto.ParseCertificateChainPEM(leafPEM + intPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certs) != 2 {
			t.Errorf("got %d certs, want 2", len(certs))
		}
	})

	t.Run("ignores non-cert blocks", func(t *testing.T) {
		junk := string(pem.EncodeToMemory(&pem.Block{Type: "UNRELATED", Bytes: []byte("ignore me")}))
		certs, err := anscrypto.ParseCertificateChainPEM(junk + leafPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certs) != 1 {
			t.Errorf("got %d certs, want 1 (junk should be skipped)", len(certs))
		}
	})

	t.Run("malformed der aborts", func(t *testing.T) {
		bad := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("wrong")}))
		_, err := anscrypto.ParseCertificateChainPEM(bad)
		if !errors.Is(err, anscrypto.ErrCertParse) {
			t.Errorf("want ErrCertParse, got %v", err)
		}
	})

	t.Run("empty returns empty", func(t *testing.T) {
		certs, err := anscrypto.ParseCertificateChainPEM("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certs) != 0 {
			t.Errorf("want empty slice, got %d", len(certs))
		}
	})
}

// ----- ParseCSRPEM -----

func TestParseCSRPEM(t *testing.T) {
	t.Parallel()
	csrPEM := issueCSR(t, "ecdsa-p256", "example.com", []string{"example.com"}, nil)

	t.Run("ok", func(t *testing.T) {
		csr, err := anscrypto.ParseCSRPEM(csrPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if csr.Subject.CommonName != "example.com" {
			t.Errorf("CN: got %q", csr.Subject.CommonName)
		}
	})

	t.Run("empty", func(t *testing.T) {
		_, err := anscrypto.ParseCSRPEM("")
		if !errors.Is(err, anscrypto.ErrPEMParse) {
			t.Errorf("want ErrPEMParse, got %v", err)
		}
	})

	t.Run("wrong block", func(t *testing.T) {
		wrong := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}))
		_, err := anscrypto.ParseCSRPEM(wrong)
		if !errors.Is(err, anscrypto.ErrPEMParse) {
			t.Errorf("want ErrPEMParse, got %v", err)
		}
	})

	t.Run("malformed der", func(t *testing.T) {
		bad := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("nope")}))
		_, err := anscrypto.ParseCSRPEM(bad)
		if !errors.Is(err, anscrypto.ErrCSRParse) {
			t.Errorf("want ErrCSRParse, got %v", err)
		}
	})

	t.Run("broken self-signature", func(t *testing.T) {
		// Parse a good CSR, flip a bit in the signature, re-encode.
		_, rest := pem.Decode([]byte(csrPEM))
		_ = rest
		block, _ := pem.Decode([]byte(csrPEM))
		// Locate the signature bytes (last ~64 bytes for ECDSA-P256). The
		// robust way is to parse then re-marshal with a mangled signature,
		// but ParseCertificateRequest doesn't expose that. Instead, mangle
		// the last byte of the DER — that lands inside the signature
		// for ECDSA-P256 CSRs. If a future key type changes this, the
		// test will still fail with ErrCSRParse or ErrInvalidSignature
		// (both are the error we want: "signature didn't verify").
		tampered := make([]byte, len(block.Bytes))
		copy(tampered, block.Bytes)
		tampered[len(tampered)-1] ^= 0xFF
		bad := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}))
		_, err := anscrypto.ParseCSRPEM(bad)
		if err == nil {
			t.Fatal("expected error on tampered signature")
		}
		// Either ErrCSRParse (DER structure broken) or ErrInvalidSignature
		// (DER parsed, signature failed) — both are correct rejections.
		if !errors.Is(err, anscrypto.ErrInvalidSignature) && !errors.Is(err, anscrypto.ErrCSRParse) {
			t.Errorf("got %v, want ErrInvalidSignature or ErrCSRParse", err)
		}
	})
}

// ----- CheckSignatureAlgorithm -----

func TestCheckSignatureAlgorithm(t *testing.T) {
	t.Parallel()

	t.Run("allowed alg", func(t *testing.T) {
		if err := anscrypto.CheckSignatureAlgorithm(x509.ECDSAWithSHA256); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})

	t.Run("disallowed alg", func(t *testing.T) {
		err := anscrypto.CheckSignatureAlgorithm(x509.SHA1WithRSA)
		if !errors.Is(err, anscrypto.ErrWeakAlgorithm) {
			t.Errorf("want ErrWeakAlgorithm, got %v", err)
		}
	})
}

// ----- CheckKeyStrength -----

func TestCheckKeyStrength(t *testing.T) {
	t.Parallel()

	t.Run("rsa 2048 ok", func(t *testing.T) {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		if err := anscrypto.CheckKeyStrength(&k.PublicKey); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})

	t.Run("rsa 1024 rejected", func(t *testing.T) {
		// nosemgrep: go.lang.security.audit.crypto.use_of_weak_rsa_key.use-of-weak-rsa-key
		// Intentional weak key — the whole point of this test is to prove
		// CheckKeyStrength returns ErrWeakKey for anything below
		// MinRSAKeyBits (2048). The subtest assertion on the next line
		// IS the security control.
		k, _ := rsa.GenerateKey(rand.Reader, 1024)
		err := anscrypto.CheckKeyStrength(&k.PublicKey)
		if !errors.Is(err, anscrypto.ErrWeakKey) {
			t.Errorf("want ErrWeakKey, got %v", err)
		}
	})

	t.Run("ecdsa p256 ok", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err := anscrypto.CheckKeyStrength(&k.PublicKey); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})

	t.Run("ecdsa p384 ok", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err := anscrypto.CheckKeyStrength(&k.PublicKey); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})

	t.Run("ecdsa p224 rejected", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		err := anscrypto.CheckKeyStrength(&k.PublicKey)
		if !errors.Is(err, anscrypto.ErrWeakKey) {
			t.Errorf("want ErrWeakKey, got %v", err)
		}
	})

	t.Run("unsupported type", func(t *testing.T) {
		err := anscrypto.CheckKeyStrength("not a key")
		if !errors.Is(err, anscrypto.ErrWeakKey) {
			t.Errorf("want ErrWeakKey, got %v", err)
		}
	})
}

// ----- CertificateFingerprint -----

func TestCertificateFingerprint(t *testing.T) {
	t.Parallel()
	_, a := issueSelfSigned(t, "a", nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, b := issueSelfSigned(t, "b", nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	fpA := anscrypto.CertificateFingerprint(a)
	fpB := anscrypto.CertificateFingerprint(b)

	if len(fpA) != 64 {
		t.Errorf("fingerprint length: got %d, want 64 (hex-encoded SHA-256)", len(fpA))
	}
	if fpA == fpB {
		t.Errorf("distinct certs should have distinct fingerprints")
	}
	// Deterministic: fingerprinting the same cert twice returns the same value.
	if fpA != anscrypto.CertificateFingerprint(a) {
		t.Errorf("fingerprint is non-deterministic")
	}
}

// ----- VerifyChain -----

func TestVerifyChain(t *testing.T) {
	t.Parallel()

	t.Run("self-signed fails without custom roots", func(t *testing.T) {
		// No custom root pool + self-signed leaf = system roots don't
		// know about this cert = verification fails.
		_, leaf := issueSelfSigned(t, "self", []string{"self.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		err := anscrypto.VerifyChain(leaf, nil, nil)
		if !errors.Is(err, anscrypto.ErrChainInvalid) {
			t.Errorf("want ErrChainInvalid, got %v", err)
		}
	})

	t.Run("succeeds with self as custom root", func(t *testing.T) {
		// Adding the self-signed cert to a custom root pool is how
		// local-dev sets up the self-CA path.
		_, leaf := issueSelfSigned(t, "self", []string{"self.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		roots := x509.NewCertPool()
		roots.AddCert(leaf)
		if err := anscrypto.VerifyChain(leaf, nil, roots); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})
}

// ----- MatchCertificateToFQDN -----

func TestMatchCertificateToFQDN(t *testing.T) {
	t.Parallel()
	_, cert := issueSelfSigned(t, "primary.example.com", []string{"alt.example.com", "alt2.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	t.Run("cn match", func(t *testing.T) {
		if err := anscrypto.MatchCertificateToFQDN(cert, "primary.example.com"); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})

	t.Run("san match", func(t *testing.T) {
		if err := anscrypto.MatchCertificateToFQDN(cert, "alt.example.com"); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		if err := anscrypto.MatchCertificateToFQDN(cert, "ALT.example.com"); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		err := anscrypto.MatchCertificateToFQDN(cert, "nope.example.com")
		if !errors.Is(err, anscrypto.ErrFQDNMismatch) {
			t.Errorf("want ErrFQDNMismatch, got %v", err)
		}
	})

	t.Run("empty expected", func(t *testing.T) {
		err := anscrypto.MatchCertificateToFQDN(cert, "   ")
		if !errors.Is(err, anscrypto.ErrFQDNMismatch) {
			t.Errorf("want ErrFQDNMismatch, got %v", err)
		}
	})
}

// ----- CheckCertificateValidity -----

func TestCheckCertificateValidity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC)

	t.Run("within window", func(t *testing.T) {
		_, c := issueSelfSigned(t, "a", nil, now.Add(-time.Hour), now.Add(time.Hour))
		if err := anscrypto.CheckCertificateValidity(c, now); err != nil {
			t.Errorf("want nil, got %v", err)
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		_, c := issueSelfSigned(t, "a", nil, now.Add(time.Hour), now.Add(2*time.Hour))
		err := anscrypto.CheckCertificateValidity(c, now)
		if !errors.Is(err, anscrypto.ErrCertNotYetValid) {
			t.Errorf("want ErrCertNotYetValid, got %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		_, c := issueSelfSigned(t, "a", nil, now.Add(-2*time.Hour), now.Add(-time.Hour))
		err := anscrypto.CheckCertificateValidity(c, now)
		if !errors.Is(err, anscrypto.ErrCertExpired) {
			t.Errorf("want ErrCertExpired, got %v", err)
		}
	})
}
