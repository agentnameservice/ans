package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/tl/logstore"
)

// CheckpointService wraps the checkpoint store to produce the shapes
// the HTTP handler needs. Keeps business logic (parsing checkpoint_raw
// into origin/size/root + signature metadata) out of the handler layer
// so HTTP concerns stay minimal.
//
// Optional verifier material (signingKey, publicKeyPEMBase64) is
// used to populate the `valid` flag on every signature and the
// `publicKeyPem` field on CheckpointView. When unset, `valid` stays
// false — the handler still returns the checkpoint, but without a
// verifier attestation.
type CheckpointService struct {
	store               *sqlitetl.CheckpointStore
	signingKey          *ecdsa.PublicKey // verifies both C2SP and JWS signature lines
	primaryPublicKeyPEM string           // base64-encoded PEM of the signing key's SPKI
}

// NewCheckpointService constructs a CheckpointService without
// signature verifier keys. Callers that want `valid` and the decoded
// JWS fields populated use WithVerifiers.
func NewCheckpointService(store *sqlitetl.CheckpointStore) *CheckpointService {
	return &CheckpointService{store: store}
}

// WithVerifiers registers the single ECDSA P-256 key used to verify
// both C2SP and JWS checkpoint signatures at read time, and records
// the base64-encoded PEM surfaced on CheckpointView.PublicKeyPEM.
//
// Matches the reference TL's single-key topology: one ECDSA key
// drives every outbound signature, so one public key verifies every
// stored signature line.
func (s *CheckpointService) WithVerifiers(
	signingKey *ecdsa.PublicKey,
	publicKeyPEMBase64 string,
) *CheckpointService {
	s.signingKey = signingKey
	s.primaryPublicKeyPEM = publicKeyPEMBase64
	return s
}

// CheckpointView is the service-layer projection of a stored
// checkpoint record — matches the reference TL's CheckpointResponse
// shape (`hack/ans-registry-log/models/checkpoint_response.go`).
// Integer fields stay typed; the handler is responsible for JSON
// encoding.
type CheckpointView struct {
	LogSize          uint64
	TreeHeight       int
	RootHashBase64   string
	OriginName       string
	CheckpointFormat string
	CheckpointText   string // the note body minus signatures, for independent verification
	CreatedAt        time.Time
	PublicKeyPEM     string // base64-encoded PEM of the primary signer's SPKI
	Signatures       []CheckpointSignatureView
}

// CheckpointSignatureView describes one signature attached to a
// checkpoint note. Matches the reference TL's CheckpointSignature
// fields one-to-one
// (`hack/ans-registry-log/models/checkpoint_signature.go`).
//
// JwsHeader, JwsPayload, JwsSignature, Timestamp, and KmsKeyID are
// only populated for "JWS"-type signatures — same conditional the
// reference emits. KmsKeyID stays empty on the file-KeyManager path
// that ships today; future cloud-KMS adapters populate it.
//
// Valid is set when the signature verifies against the configured
// verifier key at read time.
type CheckpointSignatureView struct {
	SignerName    string
	SignatureType string      // "C2SP" (sumdb note) or "JWS" (additional signer)
	Algorithm     string      // "ED25519" for C2SP, "ES256" for JWS
	KeyHash       string      // 4-byte hex, matches the keyhash in /root-keys
	RawSignature  string      // base64-encoded raw signature bytes
	JwsSignature  string      // full compact-JWS "header.payload.signature"
	JwsHeader     interface{} // decoded JWS protected header (JWS signatures only)
	JwsPayload    interface{} // decoded JWS payload (JWS signatures only)
	Timestamp     time.Time   // JWS `timestamp` claim, zero for C2SP
	KmsKeyID      string      // populated by cloud-KMS adapters, empty on file-KeyManager
	Valid         bool        // verified against the configured verifier key at read time
}

// CheckpointPage is the paginated return shape for
// CheckpointService.History.
type CheckpointPage struct {
	Items      []*CheckpointView
	Total      int64
	Limit      int
	Offset     int
	NextOffset *int // nil when this was the last page
}

// Latest returns the service-layer view of the most recent stored
// checkpoint. Returns domain.ErrNotFound (mapped to 404 by the
// handler) when the store is empty.
func (s *CheckpointService) Latest(ctx context.Context) (*CheckpointView, error) {
	rec, err := s.store.Latest(ctx)
	if err != nil {
		return nil, err
	}
	return s.viewFromRecord(rec), nil
}

// HistoryInput bundles the query parameters accepted by
// /v1/log/checkpoint/history. All filters are optional; the
// service supplies sensible defaults (limit=10, offset=0,
// order=DESC) to match the reference swagger defaults.
type HistoryInput struct {
	Limit    int        // 0 → 10
	Offset   int        // 0 → 0
	FromSize *uint64    // nil → no lower bound
	ToSize   *uint64    // nil → no upper bound
	Since    *time.Time // nil → no lower time bound
	Order    string     // "ASC" or "DESC" (default)
}

// History returns a paginated slice of checkpoints matching the
// input filter. Total population comes from a COUNT query so the
// response's `total` field reflects the full filtered set rather
// than just the current page.
func (s *CheckpointService) History(ctx context.Context, in HistoryInput) (*CheckpointPage, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = 10 // reference default
	}
	if limit > 100 {
		limit = 100 // reference maximum
	}
	offset := in.Offset
	if offset < 0 {
		offset = 0
	}
	total, err := s.store.Count(ctx, in.FromSize, in.ToSize, in.Since)
	if err != nil {
		return nil, err
	}
	rows, err := s.store.List(ctx, limit, offset, in.FromSize, in.ToSize, in.Since, in.Order)
	if err != nil {
		return nil, err
	}
	items := make([]*CheckpointView, 0, len(rows))
	for _, r := range rows {
		items = append(items, s.viewFromRecord(r))
	}
	page := &CheckpointPage{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}
	if nextStart := offset + len(items); int64(nextStart) < total {
		next := nextStart
		page.NextOffset = &next
	}
	return page, nil
}

// viewFromRecord parses a stored checkpoint into a wire-ready
// CheckpointView. The stored raw text is the sumdb-note body (origin
// header, tree size, root hash, empty line, one or more signature
// lines). We split it into `checkpointText` (the part before the
// signature block) and a list of CheckpointSignatureView entries so
// the JSON response can surface both.
func (s *CheckpointService) viewFromRecord(rec *sqlitetl.CheckpointRecord) *CheckpointView {
	cv := &CheckpointView{
		LogSize:          rec.TreeSize,
		TreeHeight:       treeHeight(rec.TreeSize),
		OriginName:       rec.Origin,
		CheckpointFormat: "c2sp-tlog/v1", // same value the reference emits
		CreatedAt:        rec.CreatedAt(),
		PublicKeyPEM:     s.primaryPublicKeyPEM,
	}
	// rootHash on the wire is base64; we stored hex. Re-encode.
	if raw, err := hex.DecodeString(rec.TreeHashHex); err == nil {
		cv.RootHashBase64 = base64.StdEncoding.EncodeToString(raw)
	}
	cv.CheckpointText, cv.Signatures = splitNoteBody(rec.CheckpointRaw, rec.Origin)
	s.enrichSignatures(cv.CheckpointText, cv.Signatures)
	return cv
}

// enrichSignatures fills in the per-signature verification state and
// (for JWS signatures) the decoded header + payload + timestamp.
// Runs per-checkpoint, not per-request-per-signature, so the cost is
// amortized at page-render time.
//
// For the primary (sumdb-note) signer: verify the signature block
// against the configured ed25519 verifier over the checkpoint body.
//
// Signature classification labels — match the reference TL wire and
// the production /v1/log/checkpoint response. Lowercase by design.
const (
	sigTypeC2SP = "c2sp"
	sigTypeJWS  = "jws"

	// algES256 is the only algorithm we (or the reference) ever emit
	// on a checkpoint signature line. Hardcoded here so callers don't
	// need to thread it through classifySumdbSig.
	algES256 = "ES256"
)

// For the additional JWS signer: the base64 payload decodes into a
// compact JWS ("header.payload.signature"), which we decode for
// client consumption and re-verify against the configured ECDSA key.
func (s *CheckpointService) enrichSignatures(body string, sigs []CheckpointSignatureView) {
	for i := range sigs {
		switch sigs[i].SignatureType {
		case sigTypeJWS:
			s.enrichJWSSignature(&sigs[i])
		case sigTypeC2SP:
			s.enrichC2SPSignature(body, &sigs[i])
		}
	}
}

// enrichC2SPSignature verifies a raw C2SP ECDSA signature against the
// configured signing key. The signature line's base64 body is
// `<keyhash:4><ecdsa-p1363-sig>`; we hand the signature bytes to
// logstore.VerifyC2SPECDSA which re-hashes the checkpoint body.
func (s *CheckpointService) enrichC2SPSignature(body string, sv *CheckpointSignatureView) {
	if s.signingKey == nil {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(sv.RawSignature)
	if err != nil || len(raw) < 4 {
		return
	}
	sv.Valid = logstore.VerifyC2SPECDSA(s.signingKey, []byte(body), raw[4:])
}

// enrichJWSSignature decodes the additional-signer's compact JWS —
// the sumdb-note line carries a `<keyhash:4><jws-compact-bytes>`
// blob — and surfaces the decoded header, payload, timestamp, and a
// cryptographic-verify result.
//
// Also populates KmsKeyID with the 8-char hex keyhash — matching the
// reference TL's production emit, where every JWS signature carries
// the opaque kid as kmsKeyId regardless of whether the underlying
// signer is KMS-backed. The value is not an AWS ARN; it's the same
// `kid` the JWS protected header advertises.
func (s *CheckpointService) enrichJWSSignature(sv *CheckpointSignatureView) {
	raw, err := base64.StdEncoding.DecodeString(sv.RawSignature)
	if err != nil || len(raw) < 4 {
		return
	}
	jwsCompact := string(raw[4:])
	sv.JwsSignature = jwsCompact
	sv.KmsKeyID = anscrypto.OpaqueKeyIDFromHash(binary.BigEndian.Uint32(raw[:4]))

	parts := strings.Split(jwsCompact, ".")
	if len(parts) != 3 {
		return
	}

	if headerBytes, derr := base64.RawURLEncoding.DecodeString(parts[0]); derr == nil {
		var hdr map[string]any
		if jerr := json.Unmarshal(headerBytes, &hdr); jerr == nil {
			sv.JwsHeader = hdr
		}
	}
	if payloadBytes, derr := base64.RawURLEncoding.DecodeString(parts[1]); derr == nil {
		var p map[string]any
		if jerr := json.Unmarshal(payloadBytes, &p); jerr == nil {
			sv.JwsPayload = p
			// `timestamp` claim is unix-seconds per our signer.
			if ts, ok := p["timestamp"].(float64); ok && ts > 0 {
				sv.Timestamp = time.Unix(int64(ts), 0).UTC()
			}
		}
	}

	// Verify against the configured ECDSA public key. Standard JWS
	// (non-detached) signs the bytes `<b64url(header)>.<b64url(payload)>`
	// — verify those exact bytes without re-canonicalizing the payload,
	// because in standard JWS the embedded payload IS the signed bytes.
	if s.signingKey != nil {
		_, verr := anscrypto.VerifyStandardJWSWithPublicKey(s.signingKey, jwsCompact)
		sv.Valid = verr == nil
	}
}

// treeHeight returns ceil(log2(size)). Reference exposes it so
// verifiers can bound proof walk costs without parsing the note.
func treeHeight(size uint64) int {
	if size <= 1 {
		return 0
	}
	return int(math.Ceil(math.Log2(float64(size))))
}

// splitNoteBody separates the note's data section from its signature
// lines. sumdb-note format: header line(s), empty line, one or more
// `— <name> <base64>` signature lines. We surface:
//
//   - checkpointText: the body up to (and including) the blank line,
//     so a verifier can re-hash it.
//   - signatures: one entry per signature line parsed into
//     {signerName, rawSignature}.
//
// This doesn't re-verify anything — it just decomposes the stored
// text into fields the REST response wants. Consumers that need
// cryptographic verification should use the ed25519 verifier served
// from /root-keys.
func splitNoteBody(raw, origin string) (string, []CheckpointSignatureView) {
	// The sumdb-note separator per golang.org/x/mod/sumdb/note is
	// the LITERAL string "\n\n" — first blank line ends the body.
	sepIdx := strings.Index(raw, "\n\n")
	if sepIdx < 0 {
		return raw, nil
	}
	text := raw[:sepIdx+1] // include trailing newline of last body line
	sigBlock := raw[sepIdx+2:]

	var sigs []CheckpointSignatureView
	for _, line := range strings.Split(strings.TrimRight(sigBlock, "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format per note package: "\u2014 <name> <base64-sig>\n"
		// The Unicode em-dash is U+2014. strings.HasPrefix against it
		// keeps the parser tight without importing the note package.
		const prefix = "\u2014 "
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := line[len(prefix):]
		// rest = "<name> <base64>"
		space := strings.LastIndex(rest, " ")
		if space < 0 {
			continue
		}
		sigs = append(sigs, CheckpointSignatureView{
			SignerName:    rest[:space],
			SignatureType: classifySumdbSig(rest[space+1:]),
			Algorithm:     algES256,
			KeyHash:       keyhashFromSumdbSig(rest[space+1:]),
			RawSignature:  rest[space+1:],
		})
	}
	// If we never parsed a signer name, fall back to the origin.
	for i := range sigs {
		if sigs[i].SignerName == "" {
			sigs[i].SignerName = origin
		}
	}
	return text, sigs
}

// keyhashFromSumdbSig extracts the 4-byte keyhash prefix from a
// sumdb-note signature's base64 blob. The note package prefixes
// every signature with the same 4 bytes advertised in the verifier
// line, so verifiers can match the signature back to the key that
// produced it (O(1) kid lookup, same idea as our COSE receipts).
//
// Returns the `0x`-prefixed 8-char hex form, matching the reference
// TL's production wire format, or "" on any decode error.
func keyhashFromSumdbSig(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < 4 {
		return ""
	}
	return fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(raw[:4]))
}

// classifySumdbSig distinguishes the primary C2SP ECDSA signature
// from the JWS additional-signer signature. Both share the sumdb-note
// `— origin base64` line framing.
//
// Detection: after the 4-byte keyhash prefix, a JWS starts with the
// base64 of `{"alg":` — which in URL-safe base64 is `eyJhbGciOi`.
// The primary C2SP signature is raw P1363 ECDSA (64 bytes), so that
// prefix will not appear. Misclassification risk is ~1 in 2^80.
//
// Labels match the reference TL production wire: lowercase
// "c2sp" / "jws".
func classifySumdbSig(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < 4+10 {
		return sigTypeC2SP
	}
	body := raw[4:] // skip keyhash prefix
	// `{"alg":` base64url = "eyJhbGciOi"
	if bytes.HasPrefix(body, []byte("eyJhbGciOi")) {
		return sigTypeJWS
	}
	return sigTypeC2SP
}
