package crypto_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/port"
)

func TestDetachedEd25519VerificationInteroperatesWithJose(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"registered":true}`)
	signed, err := signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.DetachedCompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := anscrypto.VerifyWithPublicKey(pub, compact, body); err != nil {
		t.Fatalf("public-key verifier rejected standard EdDSA: %v", err)
	}
	if _, err := anscrypto.VerifyDetachedWithPEM(compact, body, pubPEM); err != nil {
		t.Fatalf("PEM verifier rejected standard EdDSA: %v", err)
	}
	if _, err := anscrypto.VerifyWithPublicKey(pub, compact, []byte(`{"registered":false}`)); err == nil {
		t.Fatal("tampered Ed25519 payload accepted")
	}
	// The note algorithm byte must agree with the DER key algorithm.
	if _, err := anscrypto.ParseVerificationLine("log+00000000+" +
		base64.StdEncoding.EncodeToString(append([]byte{2}, der...))); err == nil {
		t.Fatal("Ed25519 SPKI accepted as an ECDSA checkpoint key")
	}
}

type malformedSignatureKM struct{ port.KeyManager }

func (m malformedSignatureKM) Sign(context.Context, string, []byte) ([]byte, error) {
	return []byte("not a DER signature"), nil
}

func TestJWSSigningRejectsMalformedInputsAndSignerOutput(t *testing.T) {
	km := newMemKM(t, "key")
	pub, err := km.GetPublicKey(t.Context(), "key")
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []anscrypto.JWSProtectedHeader{
		{Alg: anscrypto.AlgRS256},
		{Jwk: json.RawMessage(`{invalid`)},
	} {
		if _, err := anscrypto.SignStandardJWS(t.Context(), km, "key", header, map[string]bool{"ok": true}); err == nil {
			t.Fatal("invalid standard JWS header accepted")
		}
		if _, err := anscrypto.SignDetachedJWS(t.Context(), km, "key", header, []byte(`{}`)); err == nil {
			t.Fatal("invalid detached JWS header accepted")
		}
	}
	if _, err := anscrypto.SignStandardJWS(t.Context(), &dummyKM{pub: "invalid"}, "key",
		anscrypto.JWSProtectedHeader{}, map[string]bool{"ok": true}); err == nil {
		t.Fatal("unsupported signing key accepted")
	}
	if _, err := anscrypto.SignStandardJWS(t.Context(), km, "key", anscrypto.JWSProtectedHeader{},
		json.RawMessage(`{"tooLarge":1e1000}`)); err == nil {
		t.Fatal("noncanonical number accepted")
	}
	badSigner := malformedSignatureKM{KeyManager: km}
	if _, err := anscrypto.SignDetachedJWS(t.Context(), badSigner, "key", anscrypto.JWSProtectedHeader{}, []byte(`{}`)); err == nil {
		t.Fatal("malformed signer output accepted for detached JWS")
	}
	if _, err := anscrypto.SignStandardJWS(t.Context(), badSigner, "key", anscrypto.JWSProtectedHeader{}, map[string]bool{}); err == nil {
		t.Fatal("malformed signer output accepted for standard JWS")
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unsupportedSigner := malformedSignatureKM{KeyManager: &dummyKM{pub: edPub}}
	if _, err := anscrypto.SignStandardJWS(t.Context(), unsupportedSigner, "key",
		anscrypto.JWSProtectedHeader{}, map[string]bool{}); err == nil {
		t.Fatal("digest-signing port incorrectly used for Ed25519")
	}
	compact, err := anscrypto.SignDetachedJWS(t.Context(), km, "key", anscrypto.JWSProtectedHeader{}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anscrypto.VerifyWithPublicKey(pub, compact, []byte("invalid JSON")); err == nil {
		t.Fatal("invalid payload accepted by public-key verifier")
	}
	if _, err := anscrypto.VerifyDetachedWithPEM(compact, []byte("invalid JSON"), km.publicPEM(t, "key")); err == nil {
		t.Fatal("invalid payload accepted by PEM verifier")
	}
	header := strings.Split(compact, ".")[0]
	for _, sig := range []string{"*", base64.RawURLEncoding.EncodeToString(make([]byte, 63))} {
		if _, err := anscrypto.VerifyWithPublicKey(pub, header+".."+sig, []byte(`{}`)); err == nil {
			t.Fatal("malformed detached signature accepted")
		}
		if _, err := anscrypto.VerifyStandardJWSWithPublicKey(pub, header+".e30."+sig); err == nil {
			t.Fatal("malformed standard signature accepted")
		}
	}
	if _, err := anscrypto.VerifyDetachedWithPEM(header+"..*", []byte(`{}`), km.publicPEM(t, "key")); err == nil {
		t.Fatal("malformed compact serialization accepted")
	}
	if _, _, err := anscrypto.DecodeStandardJWS("missing-segments"); err == nil {
		t.Fatal("malformed standard JWS decoded")
	}
	decoded, encodedBody, err := anscrypto.DecodeStandardJWS(header + ".e30.AA")
	if err != nil || decoded.Alg != anscrypto.AlgES256 || encodedBody != "e30" {
		t.Fatalf("valid standard header/payload failed decoding: %v", err)
	}
}

func TestCSRValidationRejectsAlgorithmsOutsideTheCertificatePolicy(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if _, err := anscrypto.ValidateIdentityCSR(csr, "ans://v1.0.0.agent.example.com"); !errors.Is(err, anscrypto.ErrWeakAlgorithm) {
		t.Fatalf("identity CSR algorithm policy: %v", err)
	}
	if _, err := anscrypto.ValidateServerCSR(csr, "agent.example.com"); !errors.Is(err, anscrypto.ErrWeakAlgorithm) {
		t.Fatalf("server CSR algorithm policy: %v", err)
	}
}

func TestKeyEncodingRejectsInvalidCurvePointsAndDIDs(t *testing.T) {
	invalid := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(0), Y: big.NewInt(0)}
	if _, err := anscrypto.PublicKeyToJWK(invalid); err == nil {
		t.Fatal("off-curve point accepted")
	}
	if _, err := anscrypto.EncodeMultibase(invalid); err == nil {
		t.Fatal("off-curve point encoded as did:key")
	}
	if _, _, err := anscrypto.DecodeDIDKey("did:key:z0-invalid"); err == nil {
		t.Fatal("malformed did:key accepted")
	}
}
