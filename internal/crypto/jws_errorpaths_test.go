package crypto_test

// This file concentrates error-path tests for JWS + chain verification
// that aren't part of the happy-path coverage in jws_test.go. Keeping
// them isolated makes it obvious which branches are intentionally
// exercised with adversarial inputs (malformed base64, tampered
// signatures, wrong key types) vs. the straightforward sign/verify
// flow.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	anscrypto "github.com/godaddy/ans/internal/crypto"
)

// ----- VerifyDetachedJWS: decodeHeader failure -----

func TestVerifyDetachedJWS_BadHeaderBase64(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	// "!@#" is not valid base64url → decodeHeader errors.
	bad := "!@#.." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
	if _, err := anscrypto.VerifyDetachedJWS(context.Background(), km, bad, []byte(`{}`)); !errors.Is(err, anscrypto.ErrJWSDecode) {
		t.Errorf("want ErrJWSDecode, got %v", err)
	}
}

// ----- VerifyWithPublicKey: splitDetachedJWS + decodeHeader failures -----

func TestVerifyWithPublicKey_MalformedJWS(t *testing.T) {
	t.Parallel()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := anscrypto.VerifyWithPublicKey(&k.PublicKey, "not-a-jws", []byte(`{}`)); !errors.Is(err, anscrypto.ErrJWSDecode) {
		t.Errorf("want ErrJWSDecode, got %v", err)
	}
}

func TestVerifyWithPublicKey_BadHeaderBase64(t *testing.T) {
	t.Parallel()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bad := "!!!.." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
	if _, err := anscrypto.VerifyWithPublicKey(&k.PublicKey, bad, []byte(`{}`)); !errors.Is(err, anscrypto.ErrJWSDecode) {
		t.Errorf("want ErrJWSDecode, got %v", err)
	}
}

func TestVerifyWithPublicKey_SignatureMismatch(t *testing.T) {
	t.Parallel()
	// Produce a valid JWS with key A, try to verify with key B's public
	// half — signature rejects.
	km := newMemKM(t, "signer")
	jws, _ := anscrypto.SignDetachedJWS(
		context.Background(), km, "signer",
		anscrypto.JWSProtectedHeader{}, []byte(`{}`),
	)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := anscrypto.VerifyWithPublicKey(&other.PublicKey, jws, []byte(`{}`)); !errors.Is(err, anscrypto.ErrJWSVerify) {
		t.Errorf("want ErrJWSVerify, got %v", err)
	}
}

// ----- VerifyDetachedWithPEM: several error paths -----

func TestVerifyDetachedWithPEM_MalformedJWS(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	pemStr := km.publicPEM(t, "k")
	if _, err := anscrypto.VerifyDetachedWithPEM("abc", []byte(`{}`), pemStr); !errors.Is(err, anscrypto.ErrJWSDecode) {
		t.Errorf("want ErrJWSDecode, got %v", err)
	}
}

func TestVerifyDetachedWithPEM_BadHeaderBase64(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	pemStr := km.publicPEM(t, "k")
	bad := "~~~.." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
	if _, err := anscrypto.VerifyDetachedWithPEM(bad, []byte(`{}`), pemStr); !errors.Is(err, anscrypto.ErrJWSDecode) {
		t.Errorf("want ErrJWSDecode, got %v", err)
	}
}

func TestVerifyDetachedWithPEM_UnknownAlg(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	pemStr := km.publicPEM(t, "k")
	// Build a JWS with a valid header but bogus `alg` value.
	headerJSON := `{"alg":"BOGUS","kid":"k"}`
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	jws := encodedHeader + ".." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
	if _, err := anscrypto.VerifyDetachedWithPEM(jws, []byte(`{}`), pemStr); !errors.Is(err, anscrypto.ErrJWSVerify) {
		t.Errorf("want ErrJWSVerify, got %v", err)
	}
}

func TestVerifyDetachedWithPEM_GarbledSignature(t *testing.T) {
	t.Parallel()
	km := newMemKM(t, "k")
	pemStr := km.publicPEM(t, "k")
	// Correct header + garbage signature.
	headerJSON := `{"alg":"ES256","kid":"k","typ":"JWT"}`
	encodedHeader := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	jws := encodedHeader + ".." + base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))
	if _, err := anscrypto.VerifyDetachedWithPEM(jws, []byte(`{}`), pemStr); !errors.Is(err, anscrypto.ErrJWSVerify) {
		t.Errorf("want ErrJWSVerify, got %v", err)
	}
}

// ----- decodeHeader: bad base64 + bad JSON -----
// decodeHeader is package-internal but exercised via the public DecodeHeader.

func TestDecodeHeader_BadBase64(t *testing.T) {
	t.Parallel()
	// Construct compact-form with invalid base64 header.
	jws := "not-b64.." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
	if _, err := anscrypto.DecodeHeader(jws); !errors.Is(err, anscrypto.ErrJWSDecode) {
		t.Errorf("want ErrJWSDecode, got %v", err)
	}
}

func TestDecodeHeader_BadJSON(t *testing.T) {
	t.Parallel()
	// Valid base64 but decodes to invalid JSON.
	badJSON := base64.RawURLEncoding.EncodeToString([]byte("{not json"))
	jws := badJSON + ".." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
	if _, err := anscrypto.DecodeHeader(jws); !errors.Is(err, anscrypto.ErrJWSDecode) {
		t.Errorf("want ErrJWSDecode, got %v", err)
	}
}

// ----- verifyWithPublicKey: RSA verification failure -----

func TestVerifyWithPublicKey_RSAMismatch(t *testing.T) {
	t.Parallel()
	// Sign with RSA key A, verify with RSA key B → rsa verify fails.
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	km := &fixedRSAKM{key: priv}
	jws, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "k",
		anscrypto.JWSProtectedHeader{Alg: "RS256"}, []byte(`{}`),
	)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	otherPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := anscrypto.VerifyWithPublicKey(&otherPriv.PublicKey, jws, []byte(`{}`)); !errors.Is(err, anscrypto.ErrJWSVerify) {
		t.Errorf("want ErrJWSVerify, got %v", err)
	}
}

// ----- toJWSWireFormat: alg mismatch with key type -----

func TestSignDetachedJWS_AlgOverridesAndMismatch(t *testing.T) {
	t.Parallel()
	// Pre-set an alg in the header that mismatches the key the KM
	// returns → checkAlgMatchesKey rejects before we reach sign.
	km := newMemKM(t, "ec") // EC P-256
	_, err := anscrypto.SignDetachedJWS(
		context.Background(), km, "ec",
		anscrypto.JWSProtectedHeader{Alg: "RS256"}, []byte(`{}`),
	)
	if !errors.Is(err, anscrypto.ErrJWSEncode) {
		t.Errorf("want ErrJWSEncode, got %v", err)
	}
}

// ----- VerifyDetachedWithPEM with a non-ECDSA PEM (mismatch vs alg) -----

func TestVerifyDetachedWithPEM_RSAvsES256Mismatch(t *testing.T) {
	t.Parallel()
	// Sign with an EC key, try to verify with an RSA PEM → go-jose's
	// ParseDetached rejects the key-alg pair.
	km := newMemKM(t, "ec")
	jws, _ := anscrypto.SignDetachedJWS(
		context.Background(), km, "ec",
		anscrypto.JWSProtectedHeader{}, []byte(`{}`),
	)
	// Build an RSA PEM string separately.
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := anscrypto.VerifyDetachedWithPEM(jws, []byte(`{}`), rsaPEM); !errors.Is(err, anscrypto.ErrJWSVerify) {
		t.Errorf("want ErrJWSVerify, got %v", err)
	}
}

// ----- VerifyChain: intermediate-list variant -----

func TestVerifyChain_UsesIntermediates(t *testing.T) {
	t.Parallel()
	// Exercises the `intermediates.AddCert` loop (x509.go:154-156).
	// A single self-signed cert is trivially its own issuer; passing
	// a non-empty intermediates list still exercises the AddCert loop
	// even if verification succeeds via the explicit roots pool.
	_, leaf := issueSelfSigned(t, "s", []string{"s.example.com"}, nowMinus(1), nowPlus(1))
	_, extra := issueSelfSigned(t, "extra", nil, nowMinus(1), nowPlus(1))
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	if err := anscrypto.VerifyChain(leaf, []*x509.Certificate{extra}, roots); err != nil {
		t.Errorf("verify w/ intermediates: got %v, want nil", err)
	}
}

// small helpers used by the chain test above — time-relative to avoid
// dependency on a fixed date across runs.
func nowMinus(hours int) time.Time { return time.Now().Add(-time.Duration(hours) * time.Hour) }
func nowPlus(hours int) time.Time  { return time.Now().Add(time.Duration(hours) * time.Hour) }

// also silence the unused-import warning when all consumers of a given
// symbol were moved around — strings is used in SplitN below.
var _ = strings.SplitN
