package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/godaddy/ans/internal/port"
)

// JWS algorithm identifiers we support. Matches the reference
// producer-key store + JWS verification chain.
const (
	AlgES256 = "ES256" // ECDSA P-256 + SHA-256 (primary)
	AlgRS256 = "RS256" // RSA PKCS#1v1.5 + SHA-256 (interop only)
	AlgEdDSA = "EdDSA" // Ed25519 over the raw signing input (identity proofs)
)

// Sentinel errors.
var (
	ErrJWSEncode = errors.New("crypto/jws: encode")
	ErrJWSDecode = errors.New("crypto/jws: decode")
	ErrJWSVerify = errors.New("crypto/jws: verify")
)

// JWSProtectedHeader is the JWS protected header shape used by the TL
// event envelope and the RA producer attestations. Field names and
// order follow the reference TL's JWS conventions so outputs are
// byte-for-byte compatible with jose-compliant tooling.
//
// We support exactly two signing algorithms, matching the reference:
//
//   - AlgES256 — ECDSA P-256 + SHA-256 (primary; producer + TL attestation)
//   - AlgRS256 — RSA PKCS#1v1.5 + SHA-256 (interop only; never emitted by
//     ans-ra, but a producer-key store may hold RSA keys)
//
// ECDSA signatures are emitted in IEEE P1363 form (raw r || s) per RFC
// 7518 §3.4. This is the format every standards-compliant JWS library
// expects; ASN.1 DER is the format Go's crypto.Signer returns by
// default, so sign paths convert at the boundary.
type JWSProtectedHeader struct {
	// Alg is the JWS algorithm identifier. Required.
	Alg string `json:"alg"`
	// Kid identifies the signing key within the KeyManager. Required.
	Kid string `json:"kid"`
	// Typ is an optional type hint (e.g., "JWT").
	Typ string `json:"typ,omitempty"`
	// Timestamp is the unix-seconds timestamp the signer produced the
	// signature. Matches the reference header's `timestamp` field.
	// Zero means "do not include"; callers set this explicitly so the
	// signing timestamp is observable by verifiers.
	Timestamp int64 `json:"timestamp,omitempty"`
	// RAID identifies the Registration Authority producing the signature.
	// The TL uses this together with Kid to look up the producer key
	// when verifying.
	RAID string `json:"raid,omitempty"`
	// Jwk optionally embeds the signer's public key (RFC 7515 §4.1.3).
	// Identity control proofs set it so the noop DID resolver can
	// synthesize a document from the submitted proofs; the web
	// resolver ignores it — the authoritatively resolved document is
	// always the key source. Never set on producer/TL signatures.
	Jwk json.RawMessage `json:"jwk,omitempty"`
}

// SignDetachedJWS produces a detached JWS — compact-serialization
// `header..signature` with the payload segment empty. The payload
// passed in is JCS-canonicalized before being hashed, so verification
// is stable regardless of JSON whitespace or key ordering.
//
// `keyID` is looked up in the KeyManager and must resolve to an ECDSA
// P-256 key (for ES256) or an RSA key (for RS256). If header.Alg is
// empty, it's auto-selected from the key's public-half type.
func SignDetachedJWS(
	ctx context.Context,
	km port.KeyManager,
	keyID string,
	header JWSProtectedHeader,
	payload []byte,
) (string, error) {
	pub, err := km.GetPublicKey(ctx, keyID)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWSEncode, err)
	}

	if header.Alg == "" {
		header.Alg, err = algForPublicKey(pub)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrJWSEncode, err)
		}
	}
	if err := checkAlgMatchesKey(header.Alg, pub); err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWSEncode, err)
	}
	header.Kid = keyID

	canonicalPayload, err := Canonicalize(payload)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWSEncode, err)
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("%w: marshal header: %w", ErrJWSEncode, err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(canonicalPayload)
	signingInput := encodedHeader + "." + encodedPayload

	digest := sha256.Sum256([]byte(signingInput))
	rawSig, err := km.Sign(ctx, keyID, digest[:])
	if err != nil {
		return "", fmt.Errorf("%w: sign: %w", ErrJWSEncode, err)
	}

	wireSig, err := toJWSWireFormat(header.Alg, pub, rawSig)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWSEncode, err)
	}
	encodedSig := base64.RawURLEncoding.EncodeToString(wireSig)

	return encodedHeader + ".." + encodedSig, nil
}

// SignStandardJWS produces a *standard* JWS — compact-serialization
// `header.payload.signature` with the payload embedded (not detached).
// Used by the TL checkpoint signer where the verifier must know what
// was signed without a separate out-of-band payload channel.
//
// `payload` is any JSON-marshalable value; JCS is applied before
// signing so byte output is stable regardless of Go map iteration
// order. Matches the reference TL's `KMSSigner.SignStandard`.
func SignStandardJWS(
	ctx context.Context,
	km port.KeyManager,
	keyID string,
	header JWSProtectedHeader,
	payload any,
) (string, error) {
	pub, err := km.GetPublicKey(ctx, keyID)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWSEncode, err)
	}
	if header.Alg == "" {
		header.Alg, err = algForPublicKey(pub)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrJWSEncode, err)
		}
	}
	if err := checkAlgMatchesKey(header.Alg, pub); err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWSEncode, err)
	}
	// For standard JWS the reference pins the header's `kid` to
	// the 4-byte keyhash via OpaqueKeyIDFromHash when the caller
	// set it explicitly; otherwise it falls back to the KeyManager's
	// keyID. We leave `Kid` alone if the caller set it (the
	// checkpoint signer passes the opaque hash form); otherwise
	// default to keyID for parity with SignDetachedJWS.
	if header.Kid == "" {
		header.Kid = keyID
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: marshal payload: %w", ErrJWSEncode, err)
	}
	canonicalPayload, err := Canonicalize(payloadBytes)
	if err != nil {
		return "", fmt.Errorf("%w: canonicalize: %w", ErrJWSEncode, err)
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("%w: marshal header: %w", ErrJWSEncode, err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(canonicalPayload)
	signingInput := encodedHeader + "." + encodedPayload

	digest := sha256.Sum256([]byte(signingInput))
	rawSig, err := km.Sign(ctx, keyID, digest[:])
	if err != nil {
		return "", fmt.Errorf("%w: sign: %w", ErrJWSEncode, err)
	}
	wireSig, err := toJWSWireFormat(header.Alg, pub, rawSig)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrJWSEncode, err)
	}
	encodedSig := base64.RawURLEncoding.EncodeToString(wireSig)
	return encodedHeader + "." + encodedPayload + "." + encodedSig, nil
}

// OpaqueKeyIDFromHash returns the 8-char hex rendering of a C2SP-style
// 4-byte keyhash (big-endian uint32) — the exact string the reference
// stamps into the `kid` header of checkpoint JWS signatures so that
// verifiers can link the signature line to the public key advertised
// at `/root-keys`. Mirrors reference
// `internal/key/utils.go:OpaqueKeyIDFromHash`.
func OpaqueKeyIDFromHash(keyhash uint32) string {
	return fmt.Sprintf("%08x", keyhash)
}

// VerifyDetachedJWS validates a detached JWS against the given payload
// using the KeyManager's public key for the header's `kid`. Returns the
// decoded header on success so callers can inspect raid/timestamp/etc.
func VerifyDetachedJWS(
	ctx context.Context,
	km port.KeyManager,
	jwsCompact string,
	payload []byte,
) (*JWSProtectedHeader, error) {
	encodedHeader, encodedSig, err := splitDetachedJWS(jwsCompact)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWSDecode, err)
	}
	header, err := decodeHeader(encodedHeader)
	if err != nil {
		return nil, err
	}
	pub, err := km.GetPublicKey(ctx, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWSVerify, err)
	}
	if err := verifyWithPublicKey(pub, header.Alg, encodedHeader, encodedSig, payload); err != nil {
		return nil, err
	}
	return header, nil
}

// VerifyDetachedWithPEM validates a detached JWS against the given
// payload using a PEM-encoded public key. This is the entry point the
// Transparency Log uses to check producer signatures: the public key
// comes from the producer-key trust store, not from the local
// KeyManager.
//
// Implementation uses go-jose/v4's ParseDetached to guarantee we
// interoperate with every other standards-compliant JWS library — if
// our output parses here, it'll parse anywhere.
func VerifyDetachedWithPEM(jwsCompact string, payload []byte, publicKeyPEM string) (*JWSProtectedHeader, error) {
	encodedHeader, _, err := splitDetachedJWS(jwsCompact)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWSDecode, err)
	}
	header, err := decodeHeader(encodedHeader)
	if err != nil {
		return nil, err
	}
	pub, err := parsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWSVerify, err)
	}
	alg, err := joseAlgorithm(header.Alg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWSVerify, err)
	}

	canonicalPayload, err := Canonicalize(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWSVerify, err)
	}

	sig, err := jose.ParseDetached(jwsCompact, canonicalPayload, []jose.SignatureAlgorithm{alg})
	if err != nil {
		return nil, fmt.Errorf("%w: parse detached: %w", ErrJWSVerify, err)
	}
	if _, err := sig.Verify(pub); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWSVerify, err)
	}
	return header, nil
}

// VerifyWithPublicKey verifies a detached JWS against a payload using
// the given public key directly (no KeyManager, no PEM). Exposed for
// the ans-verify CLI. Accepts *ecdsa.PublicKey or *rsa.PublicKey.
func VerifyWithPublicKey(pub any, jwsCompact string, payload []byte) (*JWSProtectedHeader, error) {
	encodedHeader, encodedSig, err := splitDetachedJWS(jwsCompact)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWSDecode, err)
	}
	header, err := decodeHeader(encodedHeader)
	if err != nil {
		return nil, err
	}
	if err := verifyWithPublicKey(pub, header.Alg, encodedHeader, encodedSig, payload); err != nil {
		return nil, err
	}
	return header, nil
}

// VerifyStandardJWSWithPublicKey verifies a non-detached (standard)
// compact JWS of the form `b64(header).b64(payload).b64(sig)` against
// the given public key. The signing input is the raw
// `b64(header).b64(payload)` prefix — the payload is NOT re-canonicalized
// (unlike the detached-form verifier), because in standard JWS the
// embedded payload bytes are the authoritative signed bytes.
//
// Used by the TL checkpoint-read path to re-verify stored JWS
// signatures and surface a `valid` flag on CheckpointSignature. Mirrors
// the reference TL's `TesseraJWSSigner.VerifyTreeHead`.
func VerifyStandardJWSWithPublicKey(pub any, jwsCompact string) (*JWSProtectedHeader, error) {
	encodedHeader, encodedPayload, encodedSig, err := splitStandardJWS(jwsCompact)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWSDecode, err)
	}
	header, err := decodeHeader(encodedHeader)
	if err != nil {
		return nil, err
	}
	if err := checkAlgMatchesKey(header.Alg, pub); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWSVerify, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(encodedSig)
	if err != nil {
		return nil, fmt.Errorf("%w: decode signature: %w", ErrJWSVerify, err)
	}
	signingInput := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(signingInput))
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		r, s, err := P1363ToScalars(sig)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrJWSVerify, err)
		}
		if !ecdsa.Verify(key, digest[:], r, s) {
			return nil, fmt.Errorf("%w: ecdsa signature mismatch", ErrJWSVerify)
		}
	case *rsa.PublicKey:
		if err := rsaVerifyPKCS1v15(key, digest[:], sig); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrJWSVerify, err)
		}
	case ed25519.PublicKey:
		// EdDSA signs the raw signing input — no prehash (RFC 8037 §3.1).
		if !ed25519.Verify(key, []byte(signingInput), sig) {
			return nil, fmt.Errorf("%w: ed25519 signature mismatch", ErrJWSVerify)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", ErrJWSVerify, pub)
	}
	return header, nil
}

// DecodeStandardJWS splits a standard (non-detached) compact JWS and
// returns its decoded protected header plus the raw base64url payload
// segment, without verifying anything. The identity verify-control
// path uses it to (a) read kid/alg/jwk for key selection and (b)
// enforce payload-equality against the served signingInput BEFORE any
// signature verification — clients sign the served bytes verbatim and
// never canonicalize.
func DecodeStandardJWS(jwsCompact string) (*JWSProtectedHeader, string, error) {
	encodedHeader, encodedPayload, _, err := splitStandardJWS(jwsCompact)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrJWSDecode, err)
	}
	header, err := decodeHeader(encodedHeader)
	if err != nil {
		return nil, "", err
	}
	return header, encodedPayload, nil
}

// splitStandardJWS parses the "header.payload.signature" compact form
// (payload segment non-empty — the non-detached variant).
func splitStandardJWS(jwsCompact string) (string, string, string, error) {
	var first, second int
	first, second = -1, -1
	for i := range len(jwsCompact) {
		if jwsCompact[i] != '.' {
			continue
		}
		switch {
		case first == -1:
			first = i
		case second == -1:
			second = i
		default:
			return "", "", "", errors.New("jws: too many segments")
		}
	}
	if first == -1 || second == -1 {
		return "", "", "", errors.New("jws: not a compact JWS")
	}
	if second == first+1 {
		return "", "", "", errors.New("jws: standard form requires non-empty payload segment")
	}
	encHeader := jwsCompact[:first]
	encPayload := jwsCompact[first+1 : second]
	encSig := jwsCompact[second+1:]
	if encHeader == "" || encSig == "" {
		return "", "", "", errors.New("jws: empty header or signature segment")
	}
	return encHeader, encPayload, encSig, nil
}

// DecodeHeader parses the base64url-encoded header segment of a
// detached JWS and returns the typed header. Useful when a caller
// needs to route on `kid` or `raid` before it has a public key in
// hand (e.g., to look the key up in a trust store).
func DecodeHeader(jwsCompact string) (*JWSProtectedHeader, error) {
	encodedHeader, _, err := splitDetachedJWS(jwsCompact)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWSDecode, err)
	}
	return decodeHeader(encodedHeader)
}

// ----- internal helpers -----

// splitDetachedJWS parses the "header..signature" compact form.
func splitDetachedJWS(jwsCompact string) (string, string, error) {
	var first, second int
	first, second = -1, -1
	for i := range len(jwsCompact) {
		if jwsCompact[i] != '.' {
			continue
		}
		switch {
		case first == -1:
			first = i
		case second == -1:
			second = i
		default:
			return "", "", errors.New("jws: too many segments")
		}
	}
	if first == -1 || second == -1 {
		return "", "", errors.New("jws: not a compact JWS")
	}
	if second != first+1 {
		return "", "", errors.New("jws: payload segment must be empty for detached form")
	}
	encodedHeader := jwsCompact[:first]
	encodedSig := jwsCompact[second+1:]
	if encodedHeader == "" || encodedSig == "" {
		return "", "", errors.New("jws: empty header or signature segment")
	}
	return encodedHeader, encodedSig, nil
}

func decodeHeader(encodedHeader string) (*JWSProtectedHeader, error) {
	headerJSON, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil {
		return nil, fmt.Errorf("%w: decode header: %w", ErrJWSDecode, err)
	}
	var h JWSProtectedHeader
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return nil, fmt.Errorf("%w: parse header: %w", ErrJWSDecode, err)
	}
	return &h, nil
}

// verifyWithPublicKey is the shared ECDSA/RSA verification path. The
// signing input is reconstructed from the encoded header plus the
// canonicalized payload; the signature bytes are decoded from base64url
// and dispatched per algorithm.
func verifyWithPublicKey(pub any, alg, encodedHeader, encodedSig string, payload []byte) error {
	canonicalPayload, err := Canonicalize(payload)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJWSVerify, err)
	}
	signingInput := encodedHeader + "." + base64.RawURLEncoding.EncodeToString(canonicalPayload)
	digest := sha256.Sum256([]byte(signingInput))

	sig, err := base64.RawURLEncoding.DecodeString(encodedSig)
	if err != nil {
		return fmt.Errorf("%w: decode signature: %w", ErrJWSVerify, err)
	}

	if err := checkAlgMatchesKey(alg, pub); err != nil {
		return fmt.Errorf("%w: %w", ErrJWSVerify, err)
	}

	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		r, s, err := P1363ToScalars(sig)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrJWSVerify, err)
		}
		if !ecdsa.Verify(key, digest[:], r, s) {
			return fmt.Errorf("%w: ecdsa signature mismatch", ErrJWSVerify)
		}
	case *rsa.PublicKey:
		if err := rsaVerifyPKCS1v15(key, digest[:], sig); err != nil {
			return fmt.Errorf("%w: %w", ErrJWSVerify, err)
		}
	case ed25519.PublicKey:
		// EdDSA signs the raw signing input — no prehash (RFC 8037 §3.1).
		if !ed25519.Verify(key, []byte(signingInput), sig) {
			return fmt.Errorf("%w: ed25519 signature mismatch", ErrJWSVerify)
		}
	default:
		return fmt.Errorf("%w: unsupported public key type %T", ErrJWSVerify, pub)
	}
	return nil
}

// toJWSWireFormat converts a KeyManager-produced raw signature to the
// wire format JWS expects. For ECDSA, KeyManager returns ASN.1 DER;
// JWS wants P1363. For RSA PKCS#1v1.5, the format is already right.
func toJWSWireFormat(alg string, pub any, rawSig []byte) ([]byte, error) {
	switch alg {
	case AlgES256:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jws: ES256 requires ECDSA public key, got %T", pub)
		}
		return DERToP1363(rawSig, CoordinateBytes(ecPub))
	case AlgRS256:
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("jws: RS256 requires RSA public key, got %T", pub)
		}
		return rawSig, nil
	default:
		return nil, fmt.Errorf("jws: unsupported algorithm %q", alg)
	}
}

func algForPublicKey(pub any) (string, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return AlgES256, nil
	case *rsa.PublicKey:
		return AlgRS256, nil
	case ed25519.PublicKey:
		return AlgEdDSA, nil
	default:
		return "", fmt.Errorf("jws: unsupported public key type %T", pub)
	}
}

func checkAlgMatchesKey(alg string, pub any) error {
	switch alg {
	case AlgES256:
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("jws: alg ES256 requires ECDSA key, got %T", pub)
		}
		return nil
	case AlgRS256:
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return fmt.Errorf("jws: alg RS256 requires RSA key, got %T", pub)
		}
		return nil
	case AlgEdDSA:
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return fmt.Errorf("jws: alg EdDSA requires Ed25519 key, got %T", pub)
		}
		return nil
	default:
		return fmt.Errorf("jws: unsupported algorithm %q", alg)
	}
}

func joseAlgorithm(alg string) (jose.SignatureAlgorithm, error) {
	switch alg {
	case AlgES256:
		return jose.ES256, nil
	case AlgRS256:
		return jose.RS256, nil
	case AlgEdDSA:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("jws: unsupported algorithm %q", alg)
	}
}

func parsePublicKeyPEM(s string) (any, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("jws: invalid PEM")
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("jws: unexpected PEM block type %q", block.Type)
	}
}
