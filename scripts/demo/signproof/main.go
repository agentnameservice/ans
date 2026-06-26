// signproof is the demo-side identity-proof tool: it mints keypairs
// and signs identity verify-control proofs (compact JWS over the
// RA-served signingInput).
//
// This is what a registrant's own tooling does in production — the
// private key never touches the RA. Run via `go run`:
//
//	go run ./scripts/demo/signproof keygen -alg ed25519 -out key.pem
//	    → writes the key, prints the did:key identifier on stdout
//
//	go run ./scripts/demo/signproof sign -key key.pem -kid KID -input SIGNING_INPUT
//	    → prints the compact JWS on stdout (alg auto-selected from
//	      the key type: Ed25519 → EdDSA, P-256 → ES256)
//
// The JWS protected header carries kid + the embedded public jwk.
// The jwk header is what lets the RA's noop resolver synthesize a
// DID document for local development; the hardened web resolver
// ignores it and uses the fetched did.json.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	anscrypto "github.com/godaddy/ans/internal/crypto"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "signproof:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: signproof <keygen|sign> [flags]")
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:])
	case "sign":
		return sign(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q (want keygen or sign)", args[0])
	}
}

// keygen mints a keypair, writes it as PKCS#8 PEM, and prints the
// matching did:key identifier — handy both for did:key registrations
// and as the kid fragment for did:web proofs.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "path to write the private key PEM (required)")
	alg := fs.String("alg", "p256", "key algorithm: p256 | ed25519")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("keygen: -out is required")
	}

	var priv any
	var pub any
	switch *alg {
	case "p256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generate p256 key: %w", err)
		}
		priv, pub = key, &key.PublicKey
	case "ed25519":
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate ed25519 key: %w", err)
		}
		priv, pub = privKey, pubKey
	default:
		return fmt.Errorf("keygen: unsupported -alg %q (want p256 or ed25519)", *alg)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(*out, pemBytes, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	multibase, err := anscrypto.EncodeMultibase(pub)
	if err != nil {
		return fmt.Errorf("encode multibase: %w", err)
	}
	// stdout carries exactly the did:key identifier so shell callers
	// can capture it: DID=$(go run ./scripts/demo/signproof keygen ...).
	fmt.Fprintln(os.Stdout, "did:key:"+multibase)
	return nil
}

// sign produces the compact JWS the verify-control endpoint expects:
// the payload segment is the RA-served signingInput VERBATIM (clients
// never canonicalize — the RA checks payload equality first), and the
// algorithm follows the key type: P-256 → ES256 (SHA-256 prehash,
// P1363 signature), Ed25519 → EdDSA (raw signing input, RFC 8037).
func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "path to the private key PEM (required)")
	kid := fs.String("kid", "", "verification method id to claim (required)")
	input := fs.String("input", "", "the RA-served base64url signingInput (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *kid == "" || *input == "" {
		return errors.New("sign: -key, -kid, and -input are all required")
	}

	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("key file is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}

	var alg string
	var pub any
	switch key := parsed.(type) {
	case *ecdsa.PrivateKey:
		if key.Curve != elliptic.P256() {
			return errors.New("ECDSA key must be P-256")
		}
		alg, pub = "ES256", &key.PublicKey
	case ed25519.PrivateKey:
		alg, pub = "EdDSA", key.Public()
	default:
		return fmt.Errorf("unsupported key type %T (want P-256 or Ed25519)", parsed)
	}

	jwk, err := anscrypto.PublicKeyToJWK(pub)
	if err != nil {
		return fmt.Errorf("encode jwk: %w", err)
	}
	headerJSON, err := json.Marshal(map[string]any{
		"alg": alg,
		"kid": *kid,
		"jwk": jwk,
	})
	if err != nil {
		return fmt.Errorf("marshal header: %w", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	toSign := encodedHeader + "." + *input

	var sig []byte
	switch key := parsed.(type) {
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256([]byte(toSign))
		derSig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			return fmt.Errorf("sign: %w", err)
		}
		sig, err = anscrypto.DERToP1363(derSig, 32)
		if err != nil {
			return fmt.Errorf("encode signature: %w", err)
		}
	case ed25519.PrivateKey:
		// EdDSA signs the raw signing input — no prehash.
		sig = ed25519.Sign(key, []byte(toSign))
	}

	fmt.Fprintln(os.Stdout, toSign+"."+base64.RawURLEncoding.EncodeToString(sig))
	return nil
}
