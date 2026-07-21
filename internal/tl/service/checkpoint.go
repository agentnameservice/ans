package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"time"

	sqlitetl "github.com/godaddy/ans/internal/adapter/store/sqlitetl"
	anscrypto "github.com/godaddy/ans/internal/crypto"
	"github.com/godaddy/ans/internal/lognote"
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
	Algorithm     string      // "ES256" for the single ECDSA checkpoint signing key
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
	cv.CheckpointText, cv.Signatures = checkpointSignatureViews(rec.CheckpointRaw, rec.Origin)
	s.enrichSignatures(cv.CheckpointText, cv.Signatures)
	return cv
}

// checkpointSignatureViews splits a stored checkpoint note into its
// body text and a CheckpointSignatureView per signature line, using the
// canonical parser in internal/lognote. The signer name falls back to
// the note origin when the line carried none; the key hash is the
// production "0x"-prefixed 8-char hex form; the type is the lowercase
// "c2sp"/"jws" label. No cryptographic verification happens here —
// enrichSignatures fills in Valid afterward.
func checkpointSignatureViews(raw, origin string) (string, []CheckpointSignatureView) {
	body, sigs, found := lognote.SplitNote([]byte(raw))
	if !found {
		return raw, nil
	}
	if len(sigs) == 0 {
		return string(body), nil
	}
	views := make([]CheckpointSignatureView, 0, len(sigs))
	for _, sig := range sigs {
		name := sig.Name
		if name == "" {
			name = origin
		}
		keyHash := ""
		if kh := sig.KeyHashHex(); kh != "" {
			keyHash = "0x" + kh
		}
		views = append(views, CheckpointSignatureView{
			SignerName:    name,
			SignatureType: sig.Classify().String(),
			Algorithm:     algES256,
			KeyHash:       keyHash,
			RawSignature:  sig.Raw,
		})
	}
	return string(body), views
}

// algES256 is the only algorithm we (or the reference) ever emit on a
// checkpoint signature line. The signature classification labels
// themselves live in internal/lognote (SigType.String()).
const algES256 = "ES256"

// enrichSignatures fills in the per-signature verification state and
// (for JWS signatures) the decoded header + payload + timestamp.
// Runs per-checkpoint, not per-request-per-signature, so the cost is
// amortized at page-render time.
//
// For the primary (sumdb-note) signer it verifies the signature block
// against the configured ECDSA verifier over the checkpoint body; for
// the additional JWS signer it decodes the compact JWS and verifies
// that. The switch keys off the lognote signature-type labels; the
// default arm leaves any future type un-enriched (Valid stays false)
// rather than misverifying it.
func (s *CheckpointService) enrichSignatures(body string, sigs []CheckpointSignatureView) {
	for i := range sigs {
		switch sigs[i].SignatureType {
		case lognote.SigTypeJWS.String():
			s.enrichJWSSignature(&sigs[i])
		case lognote.SigTypeC2SP.String():
			s.enrichC2SPSignature(body, &sigs[i])
		default:
		}
	}
}

// enrichC2SPSignature verifies a raw C2SP ECDSA signature against the
// configured signing key. The signature line's base64 body is
// `<keyhash:4><ecdsa-der-sig>` for current checkpoints; legacy local
// dev checkpoints may still carry P1363 bytes. We hand the signature
// bytes to lognote.VerifyC2SPECDSA which re-hashes the checkpoint body
// and handles both encodings.
func (s *CheckpointService) enrichC2SPSignature(body string, sv *CheckpointSignatureView) {
	if s.signingKey == nil {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(sv.RawSignature)
	if err != nil || len(raw) < 4 {
		return
	}
	sv.Valid = lognote.VerifyC2SPECDSA(s.signingKey, []byte(body), raw[4:])
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
