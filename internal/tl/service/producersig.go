package service

import (
	"context"
	"errors"
	"fmt"

	anscrypto "github.com/agentnameservice/ans/internal/crypto"
	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/tl/producerkey"
)

// Error codes surfaced by the producer-signature verifier. They mirror
// the reference TL's producer-signature errors so operators debugging
// an ingest failure see matching identifiers across both
// implementations.
const (
	// CodeNoSignature — X-Signature header absent. 422.
	CodeNoSignature = "NO_PRODUCER_SIGNATURE"
	// CodeInvalidSignatureHeader — JWS could not be parsed at all. 422.
	CodeInvalidSignatureHeader = "INVALID_SIGNATURE_HEADER"
	// CodeNotFoundProducerKey — JWS `kid`/`raid` not in the trust store. 422.
	CodeNotFoundProducerKey = "NOT_FOUND_PRODUCER_KEY"
	// CodeInvalidProducerKey — stored PEM could not be parsed. 500/422 (we use 422).
	CodeInvalidProducerKey = "INVALID_PRODUCER_KEY"
	// CodeMismatchSignature — signature does not verify against the body. 422.
	CodeMismatchSignature = "MISMATCH_SIGNATURE"
)

// ProducerSigVerifier checks the detached-JWS in an event's
// X-Signature header against the PEM stored for its (raId, keyId).
//
// The canonical bytes the signature is verified against are
// JCS(inbound body). This matches the reference flow: the RA signs
// the JCS of the inner Event, the TL re-JCS's the same bytes and
// verifies. If either side deviates from RFC 8785 canonicalization
// the signature silently mismatches — so we use the shared
// anscrypto.Canonicalize on both sides and golden-test the result.
type ProducerSigVerifier struct {
	keys producerkey.Store
}

// NewProducerSigVerifier wires a verifier to the given trust store.
func NewProducerSigVerifier(keys producerkey.Store) *ProducerSigVerifier {
	return &ProducerSigVerifier{keys: keys}
}

// Verify returns the (raID, keyID) extracted from the JWS header on
// success. The `body` argument is the raw (non-canonicalized) inbound
// request body; this function canonicalizes it exactly once.
//
// On failure, returns a *domain.Error with one of the CodeXxx
// values so the HTTP handler can map to the right 4xx/5xx status.
func (v *ProducerSigVerifier) Verify(ctx context.Context, jwsCompact string, body []byte) (string, string, error) {
	if jwsCompact == "" {
		return "", "", domain.NewValidationError(
			CodeNoSignature,
			"X-Signature header is required",
		)
	}

	header, err := anscrypto.DecodeHeader(jwsCompact)
	if err != nil {
		return "", "", domain.NewValidationError(
			CodeInvalidSignatureHeader,
			fmt.Sprintf("cannot parse signature header: %v", err),
		)
	}
	if header.Kid == "" || header.RAID == "" {
		return "", "", domain.NewValidationError(
			CodeInvalidSignatureHeader,
			"signature header missing kid or raid",
		)
	}

	pem, err := v.keys.Get(ctx, header.RAID, header.Kid)
	if err != nil {
		if errors.Is(err, producerkey.ErrNotFound) {
			return "", "", domain.NewValidationError(
				CodeNotFoundProducerKey,
				fmt.Sprintf("no producer key for raid=%q kid=%q", header.RAID, header.Kid),
			)
		}
		return "", "", domain.NewInternalError(
			CodeInvalidProducerKey,
			"producer key lookup failed",
			err,
		)
	}

	if _, err := anscrypto.VerifyDetachedWithPEM(jwsCompact, body, pem); err != nil {
		// Anything from the crypto layer that isn't a lookup-miss we
		// treat as a signature mismatch. The caller gets a 422.
		return "", "", domain.NewValidationError(
			CodeMismatchSignature,
			fmt.Sprintf("signature does not verify for raid=%q kid=%q: %v",
				header.RAID, header.Kid, err),
		)
	}

	return header.RAID, header.Kid, nil
}
