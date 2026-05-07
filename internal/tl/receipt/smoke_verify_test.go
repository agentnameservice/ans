package receipt_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/godaddy/ans/internal/tl/receipt"
)

// TestSmokeVerifyDemoReceipt is a manual-invocation smoke test that
// verifies the receipt + root-keys pair produced by the demo scripts.
// Skipped unless ANS_DEMO_RECEIPT and ANS_DEMO_ROOT_KEYS are set —
// running it asserts the end-to-end round trip: bytes emitted by the
// running TL verify against the verification keys exposed at
// /root-keys.
//
// Usage:
//
//	ANS_DEMO_RECEIPT=data/demo/receipt.cbor \
//	ANS_DEMO_ROOT_KEYS=data/demo/root-keys.pem \
//	  go test ./internal/tl/receipt -run TestSmokeVerifyDemoReceipt -count=1 -v
//
// Accepts either the current sumdb-note verification format served
// by the TL OR legacy PEM blocks (for forward-compat with any
// preserved artefacts from older test runs).
func TestSmokeVerifyDemoReceipt(t *testing.T) {
	receiptPath := os.Getenv("ANS_DEMO_RECEIPT")
	keyPath := os.Getenv("ANS_DEMO_ROOT_KEYS")
	if receiptPath == "" || keyPath == "" {
		t.Skip("ANS_DEMO_RECEIPT / ANS_DEMO_ROOT_KEYS not set")
	}

	rec, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	allBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read keys: %v", err)
	}

	keys, err := extractPublicKeys(string(allBytes))
	if err != nil {
		t.Fatalf("extract keys: %v", err)
	}
	if len(keys) == 0 {
		t.Fatalf("no usable public keys in %s", keyPath)
	}

	var lastErr error
	for i, k := range keys {
		err := receipt.Verify(rec, k)
		if err == nil {
			t.Logf("verified against key %d/%d", i+1, len(keys))
			return
		}
		lastErr = err
	}
	t.Fatalf("no key verified receipt; last err: %v", lastErr)
}

// extractPublicKeys parses the /root-keys response body
// into a slice of ECDSA public keys. Handles both shapes:
//
//   - Sumdb-note verification lines: `<origin>+<keyhash>+<b64(0x02||SPKI)>`
//   - Legacy PEM blocks: `-----BEGIN PUBLIC KEY-----...`
//
// The note format is authoritative going forward; PEM is kept for
// backwards compatibility with fixtures from older runs.
func extractPublicKeys(s string) ([]*ecdsa.PublicKey, error) {
	var keys []*ecdsa.PublicKey
	// Try note format first.
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		parts := strings.SplitN(line, "+", 3)
		if len(parts) != 3 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil || len(raw) < 2 || raw[0] != 0x02 {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(raw[1:])
		if err != nil {
			continue
		}
		if ec, ok := pub.(*ecdsa.PublicKey); ok {
			keys = append(keys, ec)
		}
	}
	if len(keys) > 0 {
		return keys, nil
	}
	// Fallback: PEM blocks.
	rest := []byte(s)
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "PUBLIC KEY" {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		if ec, ok := pub.(*ecdsa.PublicKey); ok {
			keys = append(keys, ec)
		}
	}
	return keys, nil
}
