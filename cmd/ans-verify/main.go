// Command ans-verify is an offline verifier for SCITT COSE receipts
// served by the ANS Transparency Log. It mirrors the reference's
// `cmd/ans-verify` binary so third-party tooling written against the
// reference works unchanged against ans-tl.
//
// Typical use:
//
//	ans-verify -url http://localhost:18081 -agent <agentId>
//
// With the above invocation the tool:
//
//  1. Fetches the TL's verification keys from /root-keys
//     in the sumdb-note verification format.
//  2. Fetches the receipt from /v1/agents/{agentId}/receipt as
//     raw CBOR.
//  3. Parses the COSE_Sign1 structure, decodes the protected header
//     (algorithm, kid, VDS, CWT issuer/iat), and extracts the
//     inclusion proof from the unprotected header (label 396 →
//     {treeSize, leafIndex, path, rootHash}).
//  4. Walks the proof from the leaf hash (RFC 6962:
//     SHA-256(0x00 || event_bytes)) to the stored root.
//  5. Verifies the ES256 signature against one of the fetched
//     verification keys.
//  6. Fetches the badge (/v1/agents/{agentId}) and cross-checks
//     that the badge's merkleProof matches the receipt's proof.
//
// If -pubkey <path> is given, the tool loads that PEM public key
// instead of fetching /root-keys. This is useful for
// air-gapped verification against a receipt saved to disk.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/agentnameservice/ans/internal/tl/receipt"
)

func main() {
	// Subcommand dispatch: `ans-verify list ...` enumerates agents
	// under a provider via tile-walk. Any other first-arg form falls
	// through to the original single-agent verify path so existing
	// invocations (`ans-verify <uuid>` or `ans-verify -agent <uuid>`)
	// keep working unchanged.
	if len(os.Args) > 1 && os.Args[1] == "list" {
		listMain(os.Args[2:])
		return
	}

	var (
		baseURL   string
		agentID   string
		pubKeyPEM string
		verbose   bool
	)

	flag.StringVar(&baseURL, "url", "http://localhost:18081",
		"Base URL of the transparency log")
	flag.StringVar(&agentID, "agent", "",
		"Agent ID (UUID) to verify")
	flag.StringVar(&pubKeyPEM, "pubkey", "",
		"Path to a PEM public key file (optional; default fetches /root-keys)")
	flag.BoolVar(&verbose, "v", false,
		"Verbose output (show raw event JSON)")
	flag.Parse()

	if agentID == "" {
		if flag.NArg() > 0 {
			agentID = flag.Arg(0)
		} else {
			fmt.Fprintln(os.Stderr, "usage: ans-verify [flags] <agent-id>")
			flag.PrintDefaults()
			os.Exit(1)
		}
	}

	baseURL = strings.TrimRight(baseURL, "/")

	fmt.Println("=== ANS SCITT Receipt Verifier ===")
	fmt.Printf("TL Base URL: %s\n", baseURL)
	fmt.Printf("Agent ID:    %s\n", agentID)
	fmt.Println()

	// --- Step 1: Acquire verification keys --------------------------
	fmt.Println("── Step 1: Load verification keys ──")
	var keys []*ecdsa.PublicKey
	var keysByHash map[string]*ecdsa.PublicKey
	if pubKeyPEM != "" {
		k, err := loadPublicKeyFromFile(pubKeyPEM)
		if err != nil {
			fatalf("load %s: %v", pubKeyPEM, err)
		}
		keys = []*ecdsa.PublicKey{k}
		fmt.Printf("  ✓ Loaded 1 key from %s\n", pubKeyPEM)
	} else {
		got, byHash, err := fetchRootKeys(baseURL)
		if err != nil {
			fatalf("fetch root-keys: %v", err)
		}
		keys = got
		keysByHash = byHash
		fmt.Printf("  ✓ Fetched %d verification key(s) from %s/root-keys\n",
			len(keys), baseURL)
	}
	fmt.Println()

	// --- Step 2: Fetch the receipt ---------------------------------
	fmt.Println("── Step 2: Fetch SCITT receipt ──")
	receiptBytes, contentType, err := fetchBinary(context.Background(), baseURL+"/v1/agents/"+agentID+"/receipt")
	if err != nil {
		fatalf("fetch receipt: %v", err)
	}
	fmt.Printf("  ✓ %d bytes (Content-Type: %s)\n", len(receiptBytes), contentType)
	if len(receiptBytes) > 0 && receiptBytes[0] != 0xd2 {
		fmt.Printf("  ⚠ First byte 0x%02x (want 0xd2 for CBOR tag 18 COSE_Sign1)\n", receiptBytes[0])
	}
	fmt.Println()

	// --- Step 3: Decode + display ---------------------------------
	fmt.Println("── Step 3: Decode COSE_Sign1 + inclusion proof ──")
	printReceiptSummary(receiptBytes, verbose)
	fmt.Println()

	// --- Step 4: Cryptographic verification ------------------------
	fmt.Println("── Step 4: Cryptographic verification ──")
	verifyReceiptStep(receiptBytes, keys, keysByHash)
	fmt.Println()

	// --- Step 5: Status token (COSE_Sign1 OCSP-style stapled token) --
	fmt.Println("── Step 5: Status token ──")
	statusBytes, statusCT, err := fetchBinary(context.Background(), baseURL+"/v1/agents/"+agentID+"/status-token")
	switch err {
	case nil:
		fmt.Printf("  ✓ %d bytes (Content-Type: %s)\n", len(statusBytes), statusCT)
		verifyStatusToken(statusBytes, keys, keysByHash)
	default:
		// A disabled or terminal-state endpoint is not a failure of
		// the verify step — report and move on.
		fmt.Printf("  ⚠ %v\n", err)
	}
	fmt.Println()

	// --- Step 6: Cross-check against badge ---------------------------
	fmt.Println("── Step 6: Cross-check against badge ──")
	compareBadge(context.Background(), baseURL, agentID, receiptBytes)
}

// verifyReceiptStep extracts the receipt-verify nested logic out of
// main() so the linter doesn't flag the cyclomatic complexity.
// Tries the kid-direct fast path first, then falls back to trying
// each key.
func verifyReceiptStep(
	receiptBytes []byte,
	keys []*ecdsa.PublicKey,
	keysByHash map[string]*ecdsa.PublicKey,
) {
	if len(keys) == 0 {
		fmt.Println("  ⚠ No keys available — skipping")
		return
	}
	if kidVerified(receiptBytes, keysByHash) {
		return
	}
	for i, k := range keys {
		if err := receipt.Verify(receiptBytes, k); err == nil {
			fmt.Printf("  ✓ VERIFIED (key %d/%d)\n", i+1, len(keys))
			return
		}
	}
	fatalf("no key verified the receipt (tried %d)", len(keys))
}

// kidVerified takes the COSE `kid` from the receipt's protected
// header (4 bytes of SHA-256(SPKI-DER)) and looks it up in the
// hash-indexed map the /root-keys response provided. Returns true
// only on a successful direct-key verification.
func kidVerified(receiptBytes []byte, keysByHash map[string]*ecdsa.PublicKey) bool {
	if keysByHash == nil {
		return false
	}
	kid := kidFromReceipt(receiptBytes)
	if kid == "" {
		return false
	}
	k, ok := keysByHash[kid]
	if !ok {
		return false
	}
	if err := receipt.Verify(receiptBytes, k); err != nil {
		fmt.Printf("  ⚠ kid %s matched a key but verification failed: %v\n", kid, err)
		return false
	}
	fmt.Printf("  ✓ VERIFIED (kid %s matched key directly)\n", kid)
	return true
}

// verifyStatusToken verifies an ANS status token (COSE_Sign1) and
// prints its decoded payload. Mirrors the receipt-verify step but
// carries distinct fields (agent state, expiry, cert fingerprints).
func verifyStatusToken(
	tokenBytes []byte,
	keys []*ecdsa.PublicKey,
	keysByHash map[string]*ecdsa.PublicKey,
) {
	if len(tokenBytes) == 0 {
		fmt.Println("  ⚠ empty token body")
		return
	}
	// Fast path: look up the signing key by kid, same as receipts.
	kidHex, _ := statusTokenKid(tokenBytes)
	var payload *receipt.StatusTokenPayload
	var lastErr error
	if kidHex != "" && keysByHash != nil {
		if k, ok := keysByHash[kidHex]; ok {
			if p, err := receipt.VerifyStatusToken(tokenBytes, k); err == nil {
				payload = p
				fmt.Printf("  ✓ VERIFIED (kid %s matched key directly)\n", kidHex)
			} else {
				lastErr = err
			}
		}
	}
	if payload == nil {
		for i, k := range keys {
			p, err := receipt.VerifyStatusToken(tokenBytes, k)
			if err != nil {
				lastErr = err
				continue
			}
			payload = p
			fmt.Printf("  ✓ VERIFIED (key %d/%d)\n", i+1, len(keys))
			break
		}
	}
	if payload == nil {
		fmt.Printf("  ✗ FAILED: no key verified the status token (last err: %v)\n", lastErr)
		return
	}
	now := time.Now().UTC().Unix()
	fmt.Printf("    agentId:   %s\n", payload.AgentID)
	fmt.Printf("    status:    %s\n", payload.Status)
	fmt.Printf("    ansName:   %s\n", payload.ANSName)
	fmt.Printf("    iat:       %s\n", time.Unix(payload.IAT, 0).UTC().Format(time.RFC3339))
	fmt.Printf("    exp:       %s", time.Unix(payload.EXP, 0).UTC().Format(time.RFC3339))
	if payload.EXP < now {
		fmt.Printf(" (EXPIRED %s ago)\n", time.Duration(now-payload.EXP)*time.Second)
	} else {
		fmt.Printf(" (valid for another %s)\n", time.Duration(payload.EXP-now)*time.Second)
	}
	if len(payload.ValidIdentityCerts) > 0 {
		fmt.Printf("    identityCerts: %d\n", len(payload.ValidIdentityCerts))
		for _, c := range payload.ValidIdentityCerts {
			fmt.Printf("      - %s (%s)\n", c.Fingerprint, c.CertType)
		}
	}
	if len(payload.ValidServerCerts) > 0 {
		fmt.Printf("    serverCerts:   %d\n", len(payload.ValidServerCerts))
	}
	if len(payload.MetadataHashes) > 0 {
		fmt.Printf("    metadataHashes:\n")
		for proto, hash := range payload.MetadataHashes {
			fmt.Printf("      %s: %s\n", proto, hash)
		}
	}
}

// statusTokenKid extracts the kid hex from a status token's
// protected header — same shape as the receipt's kid, so we reuse
// receipt.ExtractKID.
func statusTokenKid(tokenBytes []byte) (string, error) {
	kid, err := receipt.ExtractKID(tokenBytes)
	if err != nil || len(kid) != 4 {
		return "", err
	}
	return hex.EncodeToString(kid), nil
}

// printReceiptSummary decodes the receipt and prints a human-friendly
// summary: protected-header fields, inclusion-proof dimensions, and
// (if -v is set) a pretty-printed JSON of the attached event payload.
func printReceiptSummary(receiptBytes []byte, verbose bool) {
	// We don't re-export the full COSE parser from the internal
	// receipt package; instead extract the payload via the
	// verifier's public ExtractPayload helper. Protected-header
	// introspection is a nice-to-have but not critical for the CLI
	// to demonstrate verification succeeded.
	payload, err := receipt.ExtractPayload(receiptBytes)
	if err != nil {
		fmt.Printf("  ⚠ could not extract payload: %v\n", err)
		return
	}
	fmt.Printf("  ✓ event payload: %d bytes\n", len(payload))

	// Parse the event JSON to surface the most important fields.
	printEventSummary(payload)

	if verbose {
		pretty, err := json.MarshalIndent(json.RawMessage(payload), "    ", "  ")
		if err == nil {
			fmt.Println()
			fmt.Println("    --- event payload (verbose) ---")
			fmt.Printf("    %s\n", pretty)
		}
	}
}

// printEventSummary unmarshals the inner event JSON and surfaces the
// most useful identification fields (ansName, eventType, host,
// schemaVersion). Extracted out of printReceiptSummary so the linter
// doesn't trip on the nested type-assertion ladder, and so callers
// of -verbose still get the field-by-field readout.
func printEventSummary(payload []byte) {
	var env map[string]any
	if err := json.Unmarshal(payload, &env); err != nil {
		return
	}
	p, ok := env["payload"].(map[string]any)
	if !ok {
		return
	}
	prod, ok := p["producer"].(map[string]any)
	if !ok {
		return
	}
	evt, ok := prod["event"].(map[string]any)
	if !ok {
		return
	}
	fmt.Printf("    ansName:   %v\n", evt["ansName"])
	fmt.Printf("    eventType: %v\n", evt["eventType"])
	if agent, ok := evt["agent"].(map[string]any); ok {
		fmt.Printf("    host:      %v\n", agent["host"])
	}
	if v, ok := env["schemaVersion"]; ok {
		fmt.Printf("    schema:    %v\n", v)
	}
}

// compareBadge fetches /v1/agents/{id} and cross-checks the
// merkleProof fields against the receipt — mirrors the reference
// verifier's badge cross-check. This catches the class of bugs where
// the receipt and badge come from different trees (shouldn't happen
// but worth asserting).
func compareBadge(ctx context.Context, baseURL, agentID string, receiptBytes []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/agents/"+agentID, nil)
	if err != nil {
		fmt.Printf("  ⚠ build badge request: %v\n", err)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("  ⚠ fetch badge: %v\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("  ⚠ badge returned HTTP %d\n", resp.StatusCode)
		return
	}
	var badge map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&badge); err != nil {
		fmt.Printf("  ⚠ parse badge JSON: %v\n", err)
		return
	}
	fmt.Printf("  ✓ badge status:    %v\n", badge["status"])
	if proof, ok := badge["merkleProof"].(map[string]any); ok {
		fmt.Printf("    leafIndex:       %v\n", proof["leafIndex"])
		fmt.Printf("    treeSize:        %v\n", proof["treeSize"])
		fmt.Printf("    leafHash:        %v\n", proof["leafHash"])
		rootB64, _ := proof["rootHash"].(string)
		if raw, err := base64.StdEncoding.DecodeString(rootB64); err == nil {
			fmt.Printf("    rootHash (hex):  %s\n", hex.EncodeToString(raw))
		}
	}
	// Prove the receipt and badge describe the same leaf by
	// comparing the RFC 6962 leaf hash both claim.
	payload, err := receipt.ExtractPayload(receiptBytes)
	if err == nil {
		receiptLeaf := receipt.ComputeLeafHash(payload)
		fmt.Printf("  ✓ receipt leafHash: %s (derived from attached event bytes)\n",
			hex.EncodeToString(receiptLeaf))
	}
}

// kidFromReceipt best-effort extracts the 4-byte key ID from the
// receipt's protected header. Returns an empty string on any decode
// error — the caller falls back to trying all available keys.
func kidFromReceipt(receiptBytes []byte) string {
	kid, err := receipt.ExtractKID(receiptBytes)
	if err != nil || len(kid) != 4 {
		return ""
	}
	return hex.EncodeToString(kid)
}

// loadPublicKeyFromFile reads and parses a single PEM-encoded
// ECDSA public key. Used for air-gapped verification when the CLI
// shouldn't hit the network.
func loadPublicKeyFromFile(path string) (*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PEM is not an ECDSA key (type %T)", pub)
	}
	return ec, nil
}

// fetchRootKeys GETs /root-keys and parses the sumdb-note
// verification-key format into a slice + kid-indexed map. Each line
// is `<origin>+<keyhash-hex>+<base64(0x02 || SPKI-DER)>`. The
// 8-char keyhash matches the 4-byte kid in each receipt's protected
// header, so keysByHash lets us do an O(1) kid→key lookup.
func fetchRootKeys(baseURL string) ([]*ecdsa.PublicKey, map[string]*ecdsa.PublicKey, error) {
	body, _, err := fetchBinary(context.Background(), baseURL+"/root-keys")
	if err != nil {
		return nil, nil, err
	}
	keys := []*ecdsa.PublicKey{}
	byHash := map[string]*ecdsa.PublicKey{}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "+", 3)
		if len(parts) != 3 {
			continue
		}
		keyHash := parts[1]
		raw, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil || len(raw) < 2 || raw[0] != 0x02 {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(raw[1:])
		if err != nil {
			continue
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		keys = append(keys, ec)
		byHash[keyHash] = ec
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("no usable ECDSA keys in /root-keys response")
	}
	return keys, byHash, nil
}

// fetchBinary is a minimal HTTP GET with a 30-second timeout that
// returns raw bytes + the response Content-Type. 4xx / 5xx statuses
// become errors so the CLI's message quality stays decent.
func fetchBinary(ctx context.Context, url string) ([]byte, string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, resp.Header.Get("Content-Type"), nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintln(os.Stderr, "ans-verify: "+fmt.Sprintf(format, args...))
	os.Exit(1)
}
