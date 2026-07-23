// Package lognote parses and verifies C2SP-shaped transparency-log
// checkpoint signed notes (golang.org/x/mod/sumdb/note framing). It is
// the single home for the checkpoint-note logic that the offline
// verifier (cmd/ans-verify) and the TL checkpoint-read path
// (internal/tl/service) previously duplicated.
//
// The package depends only on internal/crypto and its leaf
// dependencies. It deliberately imports neither internal/tl/logstore,
// the Tessera appender, nor any storage adapter, so cmd/ans-verify can
// link the verification path without pulling the log-writer
// dependency tree.
package lognote

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
)

// keyHashLen is the C2SP signature blob's 4-byte keyhash prefix. The
// note package prepends SHA-256(SPKI-DER)[0:4] (big-endian) ahead of
// the signature bytes so a verifier can match the signature to a key
// advertised at /root-keys in O(1).
const keyHashLen = 4

// jwsMarker is the base64url of the JWS protected-header prefix
// `{"alg":`. An additional-signer JWS line carries it immediately
// after the keyhash; a primary C2SP ECDSA (ASN.1 DER) signature never
// does, so its presence classifies the line as JWS.
const jwsMarker = "eyJhbGciOi"

// jwsClassifyMinLen is the smallest blob that can carry the full JWS
// marker: the 4-byte keyhash plus the 10-byte marker.
const jwsClassifyMinLen = keyHashLen + len(jwsMarker)

// noteSep is the sumdb-note body/signature separator: the literal
// "\n\n" (per golang.org/x/mod/sumdb/note). The first occurrence ends
// the note body; signature lines follow it.
const noteSep = "\n\n"

// sigLinePrefix is the em-dash + space (U+2014 ' ') that opens every
// sumdb-note signature line.
const sigLinePrefix = "— "

// SigType classifies a checkpoint signature line.
type SigType int

const (
	// SigTypeC2SP is the primary sumdb-note ECDSA signature (ASN.1 DER
	// over the checkpoint body). It is the default classification.
	SigTypeC2SP SigType = iota
	// SigTypeJWS is the additional-signer compact-JWS signature.
	SigTypeJWS
)

// String returns the lowercase wire label for the signature type,
// matching the production TL's /v1/log/checkpoint response.
func (t SigType) String() string {
	if t == SigTypeJWS {
		return "jws"
	}
	return "c2sp"
}

// Signature is one parsed signature line from a checkpoint note.
//
//   - Name is the signer name (the token between the em-dash prefix and
//     the trailing base64), or empty when the line carried no name
//     segment. Callers that surface signatures (e.g. the checkpoint
//     view) supply the origin as a fallback.
//   - Raw is the base64 text of the keyhash+signature blob exactly as
//     it appeared on the line.
//   - Blob is the decoded bytes: a 4-byte keyhash prefix followed by the
//     signature (DER ECDSA for C2SP, compact JWS for the additional
//     signer).
type Signature struct {
	Name string
	Raw  string
	Blob []byte
}

// KeyHash returns the 4-byte keyhash prefix as a big-endian uint32 and
// true when the blob is long enough to carry one, else (0, false).
func (s Signature) KeyHash() (uint32, bool) {
	if len(s.Blob) < keyHashLen {
		return 0, false
	}
	return binary.BigEndian.Uint32(s.Blob[:keyHashLen]), true
}

// KeyHashHex returns the keyhash as a plain zero-padded 8-char hex
// string (no "0x" prefix), or "" when the blob has no keyhash. This is
// the form VerifyCheckpointNote looks up in keysByHash; callers that
// need the production "0x"-prefixed wire form add the prefix.
func (s Signature) KeyHashHex() string {
	h, ok := s.KeyHash()
	if !ok {
		return ""
	}
	return fmt.Sprintf("%08x", h)
}

// Body returns the signature bytes after the 4-byte keyhash prefix
// (DER ECDSA or compact JWS), or nil when the blob has no keyhash.
func (s Signature) Body() []byte {
	if len(s.Blob) < keyHashLen {
		return nil
	}
	return s.Blob[keyHashLen:]
}

// Classify reports whether the signature is the additional-signer JWS
// line or the primary C2SP ECDSA line. A JWS blob carries the
// `{"alg":` marker (base64url `eyJhbGciOi`) immediately after the
// keyhash; everything else — including any blob too short to hold the
// marker — classifies as C2SP. Misclassification risk is ~1 in 2^80.
func (s Signature) Classify() SigType {
	if len(s.Blob) >= jwsClassifyMinLen &&
		bytes.HasPrefix(s.Blob[keyHashLen:], []byte(jwsMarker)) {
		return SigTypeJWS
	}
	return SigTypeC2SP
}

// SplitNote splits a C2SP-shaped signed note into its body and its
// parsed signature lines. The body is everything up to and including
// the trailing newline before the first "\n\n" separator; signature
// lines follow it. found reports whether a separator was present:
// found=false means the input had no "\n\n", in which case body is the
// whole input and sigs is nil.
//
// Tokenization is lenient: each signature line is trimmed, must open
// with the em-dash prefix, and is split on its LAST space into a name
// and a base64 blob. Lines that don't match, or whose blob isn't valid
// base64, are skipped. The signer-name fallback to the note origin is
// left to the caller — SplitNote leaves Name empty when the line has
// no name segment.
//
// SAFETY: SplitNote performs NO cryptographic verification. A signature
// that SplitNote returns has only been base64-decoded; its keyhash and
// signature are unvalidated. SplitNote alone proves nothing about
// authenticity. The verification path (VerifyCheckpointNote) is what
// gates trust: it subjects every candidate signature to the
// unconditional gate — the line's keyhash must match a known verifier
// key AND its ECDSA signature must validate against the fixed body
// raw[:sep+1] (the bytes including the trailing newline, hashed once)
// — and accepts the note only when at least one line clears that gate.
// Callers that render signatures without verifying (e.g. checkpoint
// views) must not treat SplitNote output as trusted.
func SplitNote(raw []byte) ([]byte, []Signature, bool) {
	sep := bytes.Index(raw, []byte(noteSep))
	if sep < 0 {
		return raw, nil, false
	}
	// Body INCLUDES the trailing newline of its last line per the
	// signed-note spec; that newline is part of the signed bytes.
	body := raw[:sep+1]
	sigBlock := raw[sep+len(noteSep):]

	var sigs []Signature
	for _, line := range strings.Split(strings.TrimRight(string(sigBlock), "\n"), "\n") {
		sig, ok := parseSignatureLine(line)
		if !ok {
			continue
		}
		sigs = append(sigs, sig)
	}
	return body, sigs, true
}

// parseSignatureLine parses one "— <name> <base64>" signature line.
// It trims surrounding whitespace (which also strips a trailing \r on
// CRLF input), requires the em-dash prefix, splits the remainder on its
// last space, and base64-decodes the trailing token. Returns ok=false
// for any line that isn't a well-formed signature line.
func parseSignatureLine(line string) (Signature, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, sigLinePrefix) {
		return Signature{}, false
	}
	rest := line[len(sigLinePrefix):]
	space := strings.LastIndex(rest, " ")
	if space < 0 {
		return Signature{}, false
	}
	b64 := rest[space+1:]
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return Signature{}, false
	}
	return Signature{Name: rest[:space], Raw: b64, Blob: blob}, true
}

// Checkpoint is a parsed and signature-verified checkpoint.
type Checkpoint struct {
	Origin   string
	Size     uint64
	RootHash []byte
}

// VerifyCheckpointNote parses a C2SP-shaped signed note and verifies it
// against keysByHash (plain 8-char hex keyhash → ECDSA P-256 public
// key). A C2SP-shaped signed note is:
//
//	<origin>\n
//	<size>\n
//	<base64 rootHash>\n
//	\n
//	— <name> <base64(keyhash:4 || sig)>\n
//	[— ...]            (optional additional signature lines)
//
// Verification succeeds when at least one signature line's keyhash
// matches a known verifier key AND its ECDSA P-256 signature validates
// against the body bytes (everything up to and including the blank
// separator line). Without this step, a hostile TL could under-report
// the tree size and hide leaves the verifier would never fetch — a
// textbook omission attack against a transparency log.
//
// Lines with an unknown keyhash are skipped so a later line can match;
// a line with a known keyhash but an invalid signature is rejected and
// the loop continues to subsequent lines.
//
// Verification accepts the note's origin as-is: callers hold keys for a
// single log (this repo's single-key topology), so a keyhash match is a
// sufficient identity check. A future multi-log consumer must pin the
// expected origin here rather than relying on a post-verification check.
func VerifyCheckpointNote(raw []byte, keysByHash map[string]*ecdsa.PublicKey) (*Checkpoint, error) {
	if len(keysByHash) == 0 {
		return nil, errors.New("lognote: no verification keys available")
	}
	body, sigs, found := SplitNote(raw)
	if !found {
		return nil, errors.New("lognote: checkpoint note missing body/signature separator")
	}
	cp, err := parseCheckpointBody(body)
	if err != nil {
		return nil, err
	}

	var lastSigErr error
	for _, sig := range sigs {
		keyhashHex := sig.KeyHashHex()
		if keyhashHex == "" {
			lastSigErr = errors.New("sig line: blob shorter than keyhash")
			continue
		}
		pub, ok := keysByHash[keyhashHex]
		if !ok {
			continue // signature is for an unknown key — try the next line
		}
		if !VerifyC2SPECDSA(pub, body, sig.Body()) {
			lastSigErr = fmt.Errorf("sig for kid %s did not verify", keyhashHex)
			continue
		}
		return cp, nil
	}
	if lastSigErr == nil {
		lastSigErr = errors.New("no signature line matched a known verifier key")
	}
	return nil, fmt.Errorf("lognote: checkpoint note: %w", lastSigErr)
}

// parseCheckpointBody parses the data section of a checkpoint note —
// the bytes SplitNote returns as body — into origin, size, and root
// hash. The body must have at least three lines: origin, decimal size,
// base64 root hash. The trailing newline that the signed-note spec
// keeps on the body is tolerated.
func parseCheckpointBody(body []byte) (*Checkpoint, error) {
	bodyLines := bytes.Split(bytes.TrimRight(body, "\n"), []byte("\n"))
	if len(bodyLines) < 3 {
		return nil, fmt.Errorf("lognote: checkpoint body must have ≥3 lines, got %d", len(bodyLines))
	}
	size, err := strconv.ParseUint(string(bodyLines[1]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("lognote: parse size %q: %w", bodyLines[1], err)
	}
	rootHash, err := base64.StdEncoding.DecodeString(string(bodyLines[2]))
	if err != nil {
		return nil, fmt.Errorf("lognote: decode rootHash: %w", err)
	}
	return &Checkpoint{
		Origin:   string(bodyLines[0]),
		Size:     size,
		RootHash: rootHash,
	}, nil
}

// VerifyC2SPECDSA verifies an ASN.1 DER ECDSA signature over SHA-256 of
// the given checkpoint body. Used by the checkpoint-read path to set
// `valid` on C2SP signature entries and by VerifyCheckpointNote to gate
// each signature line.
//
// Legacy local-dev checkpoints were emitted as IEEE P1363 r||s
// signatures, so verification accepts that form as a compatibility
// fallback. New checkpoint signatures should be DER.
func VerifyC2SPECDSA(pub *ecdsa.PublicKey, body, sig []byte) bool {
	if pub == nil || pub.Curve == nil || len(sig) == 0 {
		return false
	}
	digest := sha256.Sum256(body)
	if ecdsa.VerifyASN1(pub, digest[:], sig) {
		return true
	}
	if len(sig) != 2*anscrypto.CoordinateBytes(pub) {
		return false
	}
	r, s, err := anscrypto.P1363ToScalars(sig)
	if err != nil {
		return false
	}
	return ecdsa.Verify(pub, digest[:], r, s)
}
