package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/godaddy/ans/internal/tl/receipt"
)

// attestMain implements `ans-verify attest [flags] <agent-id>`.
//
// Flow:
//
//  1. Fetch the bundled attestation from the RA at
//     GET /v2/ans/agents/{id}/attestation.
//  2. Verify the outer COSE_Sign1 signature against the RA producer
//     public key (loaded from -ra-pubkey PEM file).
//  3. Decode the payload, extract the embedded SCITT receipt.
//  4. Verify the embedded receipt against /root-keys served by the
//     TL identified in payload.tl.log_url (or -tl-url override).
//  5. Cross-check: payload.tl.leaf_hash MUST equal
//     RFC 6962 SHA-256(0x00 || receipt-attached-payload). Catches
//     a TL that hands out a real receipt for a different leaf.
//
// Two independent verifications — RA producer key for the outer,
// TL root key for the inner — mirror the two-key topology spelled
// out in the spec.
func attestMain(args []string) {
	fs := flag.NewFlagSet("attest", flag.ExitOnError)
	var (
		raURL       string
		tlURL       string
		agentID     string
		raPubKeyPEM string
	)
	fs.StringVar(&raURL, "ra-url", "http://localhost:18080",
		"Base URL of the Registration Authority")
	fs.StringVar(&tlURL, "tl-url", "",
		"Base URL of the Transparency Log (default: payload's log_url)")
	fs.StringVar(&agentID, "agent", "",
		"Agent ID (UUID) to verify")
	fs.StringVar(&raPubKeyPEM, "ra-pubkey", "",
		"Path to PEM-encoded RA producer public key (required)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if agentID == "" {
		if fs.NArg() > 0 {
			agentID = fs.Arg(0)
		} else {
			fmt.Fprintln(os.Stderr, "usage: ans-verify attest -ra-pubkey <file> [flags] <agent-id>")
			fs.PrintDefaults()
			os.Exit(1)
		}
	}
	if raPubKeyPEM == "" {
		fatalf("-ra-pubkey is required (PEM file with the RA producer public key)")
	}
	raURL = strings.TrimRight(raURL, "/")

	fmt.Println("=== ANS Attestation Verifier ===")
	fmt.Printf("RA URL:   %s\n", raURL)
	fmt.Printf("Agent ID: %s\n\n", agentID)

	// --- Step 1: Load RA producer pubkey ---
	fmt.Println("── Step 1: Load RA producer public key ──")
	raPub, err := loadPublicKeyFromFile(raPubKeyPEM)
	if err != nil {
		fatalf("load %s: %v", raPubKeyPEM, err)
	}
	fmt.Printf("  ✓ Loaded RA producer key from %s\n\n", raPubKeyPEM)

	// --- Step 2: Fetch attestation ---
	fmt.Println("── Step 2: Fetch attestation ──")
	attBytes, ct, err := fetchBinary(context.Background(),
		raURL+"/v2/ans/agents/"+agentID+"/attestation")
	if err != nil {
		fatalf("fetch attestation: %v", err)
	}
	fmt.Printf("  ✓ %d bytes (Content-Type: %s)\n", len(attBytes), ct)
	if len(attBytes) > 0 && attBytes[0] != 0xd2 {
		fmt.Printf("  ⚠ First byte 0x%02x (want 0xd2 for CBOR tag 18)\n", attBytes[0])
	}
	fmt.Println()

	// --- Step 3: Verify outer signature against RA producer key ---
	fmt.Println("── Step 3: Verify outer attestation signature ──")
	payloadBytes, err := verifyAttestationSignature(attBytes, raPub)
	if err != nil {
		fatalf("outer verify: %v", err)
	}
	fmt.Printf("  ✓ VERIFIED (RA producer key)\n\n")

	// --- Step 4: Decode payload ---
	fmt.Println("── Step 4: Decode attestation payload ──")
	payload, err := decodeAttestationPayload(payloadBytes)
	if err != nil {
		fatalf("decode payload: %v", err)
	}
	fmt.Printf("  iss:       %s\n", payload.Issuer)
	fmt.Printf("  sub:       %s\n", payload.Subject)
	fmt.Printf("  did:       %s\n", payload.DID)
	fmt.Printf("  iat:       %s\n", time.Unix(payload.IssuedAt, 0).UTC().Format(time.RFC3339))
	fmt.Printf("  exp:       %s\n", time.Unix(payload.ExpiresAt, 0).UTC().Format(time.RFC3339))
	fmt.Printf("  id-spki:   %s\n", hex.EncodeToString(payload.IDSPKI))
	fmt.Printf("  srv-spki:  %s\n", hex.EncodeToString(payload.ServerSPKI))
	fmt.Printf("  tl.log:    %s\n", payload.TLLogURL)
	fmt.Printf("  tl.size:   %d\n", payload.TLTreeSize)
	fmt.Printf("  tl.leaf:   %s\n", hex.EncodeToString(payload.TLLeafHash))
	fmt.Printf("  tl.recpt:  %d bytes\n\n", len(payload.TLReceipt))

	// --- Step 5: Fetch TL root keys ---
	if tlURL == "" {
		tlURL = payload.TLLogURL
	}
	tlURL = strings.TrimRight(tlURL, "/")
	fmt.Println("── Step 5: Load TL verifier keys ──")
	tlKeys, _, err := fetchRootKeys(tlURL)
	if err != nil {
		fatalf("fetch /root-keys from %s: %v", tlURL, err)
	}
	fmt.Printf("  ✓ Loaded %d TL verifier key(s) from %s/root-keys\n\n", len(tlKeys), tlURL)

	// --- Step 6: Verify embedded receipt ---
	fmt.Println("── Step 6: Verify embedded SCITT receipt ──")
	var lastErr error
	verified := false
	for i, k := range tlKeys {
		err := receipt.Verify(payload.TLReceipt, k)
		if err == nil {
			fmt.Printf("  ✓ VERIFIED (TL key %d/%d)\n", i+1, len(tlKeys))
			verified = true
			break
		}
		lastErr = err
	}
	if !verified {
		fatalf("no TL key verified the embedded receipt (last err: %v)", lastErr)
	}
	fmt.Println()

	// --- Step 7: Cross-check leaf hash ---
	fmt.Println("── Step 7: Cross-check leaf hash ──")
	recPayload, err := receipt.ExtractPayload(payload.TLReceipt)
	if err != nil {
		fatalf("extract receipt payload: %v", err)
	}
	derivedLeaf := receipt.ComputeLeafHash(recPayload)
	if !equalBytes(derivedLeaf, payload.TLLeafHash) {
		fatalf("leaf-hash mismatch — attestation claims %s, receipt payload hashes to %s",
			hex.EncodeToString(payload.TLLeafHash), hex.EncodeToString(derivedLeaf))
	}
	fmt.Printf("  ✓ payload.tl.leaf_hash == SHA-256(0x00 || receipt.payload)\n\n")
	fmt.Println("=== ATTESTATION VERIFIED ===")
}

// attestationPayload is the decoded shape we need from the CBOR
// payload. Keys are string-keyed per spec/api-spec-v2.yaml. Fields
// are intentionally a subset — we only decode what's load-bearing
// for verification.
type attestationPayload struct {
	Issuer     string
	Subject    string
	DID        string
	IssuedAt   int64
	ExpiresAt  int64
	IDSPKI     []byte
	ServerSPKI []byte
	TLLogURL   string
	TLLeafHash []byte
	TLTreeSize uint64
	TLReceipt  []byte
}

func decodeAttestationPayload(b []byte) (*attestationPayload, error) {
	var raw map[string]any
	if err := cbor.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	p := &attestationPayload{}
	if v, ok := raw["iss"].(string); ok {
		p.Issuer = v
	}
	if v, ok := raw["sub"].(string); ok {
		p.Subject = v
	}
	if v, ok := raw["did"].(string); ok {
		p.DID = v
	}
	p.IssuedAt = toInt64(raw["iat"])
	p.ExpiresAt = toInt64(raw["exp"])
	if v, ok := raw["identity_cert_spki_sha256"].([]byte); ok {
		p.IDSPKI = v
	}
	if v, ok := raw["server_cert_spki_sha256"].([]byte); ok {
		p.ServerSPKI = v
	}
	tlAny, ok := raw["tl"]
	if !ok {
		return nil, errors.New("payload missing tl map")
	}
	tlMap, ok := tlAny.(map[any]any)
	if !ok {
		return nil, errors.New("payload.tl is not a map")
	}
	if v, ok := tlMap["log_url"].(string); ok {
		p.TLLogURL = v
	}
	if v, ok := tlMap["leaf_hash"].([]byte); ok {
		p.TLLeafHash = v
	}
	p.TLTreeSize = uint64(toInt64(tlMap["tree_size"])) //nolint:gosec // tree size is non-negative
	if v, ok := tlMap["receipt"].([]byte); ok {
		p.TLReceipt = v
	}
	return p, nil
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case uint64:
		return int64(n) //nolint:gosec // CBOR uint64 range for timestamps/sizes
	case int64:
		return n
	case int:
		return int64(n)
	default:
		return 0
	}
}

// verifyAttestationSignature parses the outer COSE_Sign1, rebuilds
// the Sig_structure exactly as the signer would have built it, and
// verifies the ECDSA P-256 signature against the RA producer key.
// Returns the attached payload bytes on success.
func verifyAttestationSignature(coseBytes []byte, pub *ecdsa.PublicKey) ([]byte, error) {
	var tag cbor.Tag
	if err := cbor.Unmarshal(coseBytes, &tag); err != nil {
		return nil, fmt.Errorf("decode cose tag: %w", err)
	}
	if tag.Number != 18 {
		return nil, fmt.Errorf("not COSE_Sign1: tag = %d", tag.Number)
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return nil, errors.New("cose: top-level not a 4-element array")
	}
	protectedBytes, ok := arr[0].([]byte)
	if !ok {
		return nil, errors.New("cose: protected header not bytes")
	}
	payload, ok := arr[2].([]byte)
	if !ok {
		return nil, errors.New("cose: payload not bytes")
	}
	sig, ok := arr[3].([]byte)
	if !ok {
		return nil, errors.New("cose: signature not bytes")
	}
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	sigStructure := []any{
		"Signature1",
		protectedBytes,
		[]byte{}, // external_aad
		payload,
	}
	sigStructureBytes, err := em.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("encode sig_structure: %w", err)
	}
	digest := sha256.Sum256(sigStructureBytes)
	if len(sig) != 64 {
		return nil, fmt.Errorf("signature length %d, want 64 (P1363 P-256)", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, errors.New("ecdsa.Verify returned false")
	}
	return payload, nil
}

// fileChecker — silences lint complaints about unused symbols imported
// only for documentation purposes elsewhere in the binary.
var _ = http.MethodGet
var _ = pem.Decode
var _ = x509.MarshalPKIXPublicKey

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
