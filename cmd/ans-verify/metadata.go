package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/agentnameservice/ans/internal/tl/receipt"
)

// SVCB SvcParam presentation prefixes the metadata check reads out of an
// attested `dnsRecordsProvisioned[]` row. key65400 / key65402 are the RFC
// 9460 §14.3.1 Private Use presentation of the DNS-AID draft-02 `cap` and
// `bap` params, exactly as internal/adapter/discovery/ans emits them. They
// are restated here rather than imported because the verifier is
// deliberately a leaf that depends only on internal/tl/receipt.
const (
	svcbParamALPN = "alpn="
	svcbParamCap  = "key65400="
	svcbParamBAP  = "key65402="

	// metadataHashPrefix is the algorithm tag the RA validates on every
	// registered metadataHash (domain.metadataHashPattern).
	metadataHashPrefix = "SHA256:"

	// dnsaidHTTPAPIToken is the DNS-AID alpn/bap token for the HTTP_API
	// protocol (protocolToDNSAIDValue); every other protocol is its
	// lowercased name.
	dnsaidHTTPAPIToken = "x-http"
	protocolHTTPAPI    = "HTTP_API"

	rrTypeHTTPS = "HTTPS"
	rrTypeSVCB  = "SVCB"
)

// metadataOutcome classifies one attested-hash check.
type metadataOutcome int

const (
	// metadataMatch: the document at the attested URL hashes to the
	// attested value.
	metadataMatch metadataOutcome = iota
	// metadataMismatch: the document was fetched and its hash differs.
	// The registration asserts something that is not true.
	metadataMismatch
	// metadataUnreachable: the document could not be fetched (network
	// error or non-200). Reported, not failed: it may be a 401.
	metadataUnreachable
	// metadataNoURL: the leaf attests a hash for this protocol but no
	// attested SVCB row carries a descriptor URL for it, so there is
	// nothing to fetch.
	metadataNoURL
)

// metadataCheck is one attested (protocol → hash) pair joined to the
// descriptor URL the attested SVCB row for that protocol carries.
type metadataCheck struct {
	Protocol string // attestation key as registered: "A2A", "MCP", "HTTP_API"
	URL      string // key65400 of the matching attested SVCB row; "" if none
	WantHash string // "SHA256:<64 hex>" as sealed in the leaf
}

// metadataResult is the outcome of fetching and hashing one check.
type metadataResult struct {
	metadataCheck
	Outcome metadataOutcome
	GotHash string // "SHA256:<64 hex>" of the fetched body, when fetched
	Err     error  // fetch error, when Outcome is metadataUnreachable
}

// attestedRecord is the lane-agnostic view of one dnsRecordsProvisioned
// entry: V2 seals a typed {name,data,type} array, V1 a name→data map.
type attestedRecord struct {
	Name string `json:"name"`
	Data string `json:"data"`
	Type string `json:"type"`
}

// metadataChecksFromEvent reads the attested metadataHashes and the
// attested SVCB rows out of a receipt's event payload and pairs them by
// protocol. It returns nil when the leaf attests no metadata hash — the
// registration declared none, so there is nothing to check.
//
// Both inputs come from the same signed leaf, so the check is closed over
// what the log carries: no DNS lookup, no operator input.
func metadataChecksFromEvent(payload []byte) ([]metadataCheck, error) {
	var env struct {
		Payload struct {
			Producer struct {
				Event struct {
					Attestations struct {
						MetadataHashes        map[string]string `json:"metadataHashes"`
						DNSRecordsProvisioned json.RawMessage   `json:"dnsRecordsProvisioned"`
					} `json:"attestations"`
				} `json:"event"`
			} `json:"producer"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("decode event payload: %w", err)
	}
	att := env.Payload.Producer.Event.Attestations
	if len(att.MetadataHashes) == 0 {
		return nil, nil
	}
	urls := descriptorURLsByToken(decodeAttestedRecords(att.DNSRecordsProvisioned))
	checks := make([]metadataCheck, 0, len(att.MetadataHashes))
	for _, proto := range slices.Sorted(maps.Keys(att.MetadataHashes)) {
		checks = append(checks, metadataCheck{
			Protocol: proto,
			URL:      urls[dnsaidTokenForProtocol(proto)],
			WantHash: att.MetadataHashes[proto],
		})
	}
	return checks, nil
}

// decodeAttestedRecords accepts either lane's encoding of
// dnsRecordsProvisioned. Unknown shapes decode to nothing rather than
// failing the whole step: the hash check then reports "no URL", which is
// the honest answer.
func decodeAttestedRecords(raw json.RawMessage) []attestedRecord {
	if len(raw) == 0 {
		return nil
	}
	var typed []attestedRecord
	if err := json.Unmarshal(raw, &typed); err == nil {
		return typed
	}
	var byName map[string]string
	if err := json.Unmarshal(raw, &byName); err != nil {
		return nil
	}
	out := make([]attestedRecord, 0, len(byName))
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		out = append(out, attestedRecord{Name: name, Data: byName[name]})
	}
	return out
}

// descriptorURLsByToken indexes the key65400 descriptor URL of every
// attested SVCB/HTTPS row by the row's alpn and bap tokens. A row without
// key65400 contributes nothing. First row wins per token, matching how
// the RA collapses metadataHashes per protocol.
func descriptorURLsByToken(records []attestedRecord) map[string]string {
	urls := map[string]string{}
	for _, rec := range records {
		if rec.Type != "" && rec.Type != rrTypeHTTPS && rec.Type != rrTypeSVCB {
			continue
		}
		var alpn, bap, capURL string
		for _, field := range strings.Fields(rec.Data) {
			switch {
			case strings.HasPrefix(field, svcbParamALPN):
				alpn = strings.TrimPrefix(field, svcbParamALPN)
			case strings.HasPrefix(field, svcbParamBAP):
				bap = strings.TrimPrefix(field, svcbParamBAP)
			case strings.HasPrefix(field, svcbParamCap):
				capURL = strings.TrimPrefix(field, svcbParamCap)
			}
		}
		if capURL == "" {
			continue
		}
		for _, tok := range []string{alpn, bap} {
			if tok == "" {
				continue
			}
			if _, seen := urls[strings.ToLower(tok)]; !seen {
				urls[strings.ToLower(tok)] = capURL
			}
		}
	}
	return urls
}

// dnsaidTokenForProtocol maps a registered protocol name to the alpn/bap
// token the DNSAID profile emits for it (protocolToDNSAIDValue).
func dnsaidTokenForProtocol(protocol string) string {
	if strings.EqualFold(protocol, protocolHTTPAPI) {
		return dnsaidHTTPAPIToken
	}
	return strings.ToLower(protocol)
}

// verifyMetadata fetches each check's descriptor and compares its SHA-256
// with the attested hash. Bodies are capped at maxResponseBytes like every
// other fetch in this binary.
func verifyMetadata(ctx context.Context, client *http.Client, checks []metadataCheck) []metadataResult {
	results := make([]metadataResult, 0, len(checks))
	for _, c := range checks {
		results = append(results, verifyOneMetadata(ctx, client, c))
	}
	return results
}

func verifyOneMetadata(ctx context.Context, client *http.Client, c metadataCheck) metadataResult {
	res := metadataResult{metadataCheck: c}
	if c.URL == "" {
		res.Outcome = metadataNoURL
		return res
	}
	body, err := fetchDescriptor(ctx, client, c.URL)
	if err != nil {
		res.Outcome = metadataUnreachable
		res.Err = err
		return res
	}
	sum := sha256.Sum256(body)
	res.GotHash = metadataHashPrefix + hex.EncodeToString(sum[:])
	if strings.EqualFold(res.GotHash, c.WantHash) {
		res.Outcome = metadataMatch
	} else {
		res.Outcome = metadataMismatch
	}
	return res
}

// fetchDescriptor GETs the descriptor with the body cap applied. Any
// non-200 is an error so a 401 or 404 reads as "unreachable", not as a
// document that fails to hash.
func fetchDescriptor(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", maxResponseBytes)
	}
	return body, nil
}

// runMetadataStep is Step 7 of the CLI: it verifies every metadata hash
// the leaf attests against the document at the attested descriptor URL.
// It prints one line per protocol and returns true when at least one
// hash MISMATCHES — the only outcome that fails verification. Unreachable
// and no-URL are reported and do not fail. When the leaf attests no
// hash, or the step is disabled, it returns false.
func runMetadataStep(ctx context.Context, receiptBytes []byte, enabled bool, timeout time.Duration) bool {
	if !enabled {
		fmt.Println("  ⚠ skipped (-check-metadata=false)")
		return false
	}
	payload, err := receipt.ExtractPayload(receiptBytes)
	if err != nil {
		fmt.Printf("  ⚠ %v\n", err)
		return false
	}
	return metadataStepForPayload(ctx, payload, &http.Client{Timeout: timeout})
}

// metadataStepForPayload is runMetadataStep after the receipt has been
// opened: the part that reads the leaf, fetches, compares and prints.
// Split out so it can be exercised on a bare event payload.
func metadataStepForPayload(ctx context.Context, payload []byte, client *http.Client) bool {
	checks, err := metadataChecksFromEvent(payload)
	if err != nil {
		fmt.Printf("  ⚠ %v\n", err)
		return false
	}
	if len(checks) == 0 {
		fmt.Println("  ✓ leaf attests no metadata hash — nothing to check")
		return false
	}
	failed := false
	for _, r := range verifyMetadata(ctx, client, checks) {
		printMetadataResult(r)
		if r.Outcome == metadataMismatch {
			failed = true
		}
	}
	return failed
}

func printMetadataResult(r metadataResult) {
	switch r.Outcome {
	case metadataMatch:
		fmt.Printf("  ✓ %s: %s matches attested %s\n", r.Protocol, r.URL, r.WantHash)
	case metadataMismatch:
		fmt.Printf("  ✗ %s: %s hashes to %s, leaf attests %s\n", r.Protocol, r.URL, r.GotHash, r.WantHash)
	case metadataUnreachable:
		fmt.Printf("  ⚠ %s: %s unreachable (%v) — attested %s not checked\n", r.Protocol, r.URL, r.Err, r.WantHash)
	case metadataNoURL:
		fmt.Printf("  ⚠ %s: leaf attests %s but no attested SVCB row carries a descriptor URL\n",
			r.Protocol, r.WantHash)
	}
}
