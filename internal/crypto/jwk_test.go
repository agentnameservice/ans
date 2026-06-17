package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func genP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func genEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestJWKRoundTrip_AllKinds(t *testing.T) {
	t.Parallel()

	p256 := genP256(t)
	edPub, _ := genEd25519(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		pub  any
	}{
		{"P-256", &p256.PublicKey},
		{"Ed25519", edPub},
		{"RSA", &rsaKey.PublicKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jwk, err := PublicKeyToJWK(tc.pub)
			if err != nil {
				t.Fatalf("PublicKeyToJWK: %v", err)
			}
			back, err := ParseJWK(jwk)
			if err != nil {
				t.Fatalf("ParseJWK: %v", err)
			}
			switch want := tc.pub.(type) {
			case *ecdsa.PublicKey:
				if got, ok := back.(*ecdsa.PublicKey); !ok || !got.Equal(want) {
					t.Fatal("P-256 round trip lost the key")
				}
			case ed25519.PublicKey:
				if got, ok := back.(ed25519.PublicKey); !ok || !got.Equal(want) {
					t.Fatal("Ed25519 round trip lost the key")
				}
			case *rsa.PublicKey:
				if got, ok := back.(*rsa.PublicKey); !ok || !got.Equal(want) {
					t.Fatal("RSA round trip lost the key")
				}
			}
		})
	}
}

func TestParseJWKRejections(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"not json", `{`, "invalid JWK"},
		{"unknown kty", `{"kty":"oct","k":"AA"}`, "unsupported kty"},
		{"EC wrong curve", `{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}`, "no verifier here"},
		{"EC secp256k1", `{"kty":"EC","crv":"secp256k1","x":"AA","y":"AA"}`, "no verifier here"},
		{"EC bad x b64", `{"kty":"EC","crv":"P-256","x":"!!!","y":"AA"}`, "decode x"},
		{"EC bad y b64", `{"kty":"EC","crv":"P-256","x":"AA","y":"!!!"}`, "decode y"},
		{"EC short coords", `{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`, "32 bytes"},
		{"OKP X25519 is key agreement", `{"kty":"OKP","crv":"X25519","x":"9GXjPGGvmRq9F6Ng5dQQ_s31mfhxrcNZxRGONrmH30k"}`, "key-agreement key"},
		{"OKP unknown curve", `{"kty":"OKP","crv":"Ed448","x":"AA"}`, "unsupported OKP curve"},
		{"OKP bad x b64", `{"kty":"OKP","crv":"Ed25519","x":"!!!"}`, "decode x"},
		{"OKP short key", `{"kty":"OKP","crv":"Ed25519","x":"AA"}`, "32 bytes"},
		{"RSA bad n", `{"kty":"RSA","n":"!!!","e":"AQAB"}`, "decode n"},
		{"RSA bad e", `{"kty":"RSA","n":"AQAB","e":"!!!"}`, "decode e"},
		{"RSA missing members", `{"kty":"RSA"}`, "requires n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseJWK(json.RawMessage(tc.raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}

	// Off-curve point: valid lengths, garbage coordinates.
	off := `{"kty":"EC","crv":"P-256","x":"` + strings.Repeat("A", 43) + `","y":"` + strings.Repeat("B", 43) + `"}`
	if _, err := ParseJWK(json.RawMessage(off)); err == nil {
		t.Error("off-curve point should be rejected")
	}
	// Weak RSA key (1024-bit) fails CheckKeyStrength.
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakJWK, err := PublicKeyToJWK(&weak.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJWK(weakJWK); err == nil {
		t.Error("1024-bit RSA should be rejected")
	}
}

func TestPublicKeyToJWKRejectsUnsupported(t *testing.T) {
	t.Parallel()
	if _, err := PublicKeyToJWK(nil); err == nil {
		t.Error("nil key should fail")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublicKeyToJWK(&p384.PublicKey); err == nil {
		t.Error("P-384 key should fail")
	}
}

func TestMultibaseRoundTrip(t *testing.T) {
	t.Parallel()

	p256 := genP256(t)
	edPub, _ := genEd25519(t)

	for _, tc := range []struct {
		name string
		pub  any
	}{
		{"P-256", &p256.PublicKey},
		{"Ed25519", edPub},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodeMultibase(tc.pub)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !strings.HasPrefix(encoded, "z") {
				t.Fatalf("multibase prefix: %s", encoded)
			}
			back, err := DecodeMultibase(encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			switch want := tc.pub.(type) {
			case *ecdsa.PublicKey:
				if got, ok := back.(*ecdsa.PublicKey); !ok || !got.Equal(want) {
					t.Fatal("P-256 round trip lost the key")
				}
			case ed25519.PublicKey:
				if got, ok := back.(ed25519.PublicKey); !ok || !got.Equal(want) {
					t.Fatal("Ed25519 round trip lost the key")
				}
			}
		})
	}

	// The canonical did:key Ed25519 prefix.
	encoded, err := EncodeMultibase(edPub)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "z6Mk") {
		t.Fatalf("ed25519 did:key form should start z6Mk, got %s", encoded[:6])
	}
}

func TestDecodeMultibaseRejections(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no z prefix", "Qabc", "base58btc"},
		{"bad base58", "z0OIl", "invalid base58"},
		{"empty payload", "z", "empty base58"},
		{"too short", "z" + base58Encode([]byte{0xed}), "too short"},
		{"unknown codec", "z" + base58Encode([]byte{0x01, 0x02, 0x03}), "unsupported multicodec"},
		{"wrong p256 length", "z" + base58Encode(append([]byte{0x80, 0x24}, make([]byte, 10)...)), "33 compressed bytes"},
		{"wrong ed25519 length", "z" + base58Encode(append([]byte{0xed, 0x01}, make([]byte, 10)...)), "32 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeMultibase(tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
	// Invalid compressed point: right length, but 0x05 is not a
	// valid SEC1 compression prefix (must be 0x02/0x03).
	garbage := append([]byte{0x80, 0x24, 0x05}, make([]byte, 32)...)
	if _, err := DecodeMultibase("z" + base58Encode(garbage)); err == nil {
		t.Error("invalid compressed point should fail")
	}
}

func TestEncodeMultibaseRejectsUnsupported(t *testing.T) {
	t.Parallel()
	if _, err := EncodeMultibase(nil); err == nil {
		t.Error("nil key should fail")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeMultibase(&rsaKey.PublicKey); err == nil {
		t.Error("RSA has no multicodec form here")
	}
}

func TestDecodeDIDKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		pub  any
	}{
		{"P-256", func() any { k := genP256(t); return &k.PublicKey }()},
		{"Ed25519", func() any { k, _ := genEd25519(t); return k }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msid, err := EncodeMultibase(tc.pub)
			if err != nil {
				t.Fatal(err)
			}
			did := "did:key:" + msid
			pub, kid, err := DecodeDIDKey(did)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if kid != did+"#"+msid {
				t.Fatalf("kid = %s", kid)
			}
			if pub == nil {
				t.Fatal("nil key")
			}
		})
	}

	if _, _, err := DecodeDIDKey("did:web:a.com"); err == nil {
		t.Error("non-did:key should fail")
	}
	if _, _, err := DecodeDIDKey("did:key:"); err == nil {
		t.Error("empty msid should fail")
	}
}

func TestBase58RoundTrip(t *testing.T) {
	t.Parallel()
	cases := [][]byte{
		{},
		{0x00},
		{0x00, 0x00, 0x01},
		{0xff, 0xfe, 0xfd},
		[]byte("hello base58 world"),
	}
	for _, in := range cases {
		enc := base58Encode(in)
		if len(in) == 0 {
			if enc != "" {
				t.Errorf("empty input encoded to %q", enc)
			}
			continue
		}
		got, err := base58Decode(enc)
		if err != nil {
			t.Fatalf("decode %q: %v", enc, err)
		}
		if string(got) != string(in) {
			t.Errorf("round trip %x → %s → %x", in, enc, got)
		}
	}
}

// TestEdDSAJWSVerify pins the EdDSA arm in the standard-JWS verifier:
// an Ed25519 signature over the raw signing input (RFC 8037 — no
// prehash) verifies, and a P-256 key claiming EdDSA is rejected by
// the alg↔key pin.
func TestEdDSAJWSVerify(t *testing.T) {
	t.Parallel()
	pub, priv := genEd25519(t)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"hello":"world"}`))
	signingInput := header + "." + payload
	sig := ed25519.Sign(priv, []byte(signingInput))
	jws := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	if _, err := VerifyStandardJWSWithPublicKey(pub, jws); err != nil {
		t.Fatalf("EdDSA verify: %v", err)
	}

	// Tampered payload fails.
	bad := header + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"hello":"mars"}`)) +
		"." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := VerifyStandardJWSWithPublicKey(pub, bad); err == nil {
		t.Fatal("tampered EdDSA payload must fail")
	}

	// Alg/key confusion: EdDSA header with a P-256 key.
	p256 := genP256(t)
	if _, err := VerifyStandardJWSWithPublicKey(&p256.PublicKey, jws); err == nil {
		t.Fatal("EdDSA header must not verify with an ECDSA key")
	}
}
