package service

import (
	"encoding/json"
	"fmt"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/tl/event"
	identityevent "github.com/agentnameservice/ans/internal/tl/event/identity"
	eventv1 "github.com/agentnameservice/ans/internal/tl/event/v1"
)

// envelopeCodec bundles the three per-schema-version steps of the
// ingest pipeline: parsing the raw body into a typed inner event,
// JCS-canonicalizing that inner event for dedup hashing, and wrapping
// it in a TL-owned envelope. All other ingest steps (producer sig
// verify, Tessera append, SQLite mirror, checkpoint refresh) are
// version-agnostic and live on `LogService` directly.
//
// Two implementations exist: `v2Codec` produces `event.Envelope` (V2
// shape), `v1Codec` produces `v1.Envelope` (V1 shape). Both return an
// `event.Signable` so the shared ingest code treats them uniformly.
type envelopeCodec interface {
	// ParseAndBuild consumes the raw producer-event body and returns
	// the envelope ready to be signed plus the canonical bytes of
	// the *inner* event (used as the dedup key).
	//
	// verifiedRaID is the raID extracted from the producer's JWS
	// header (already verified upstream). logID is the UUIDv7 the TL
	// assigns at this ingestion.
	ParseAndBuild(
		raw []byte,
		verifiedRaID, producerKeyID, producerSig, logID string,
	) (env event.Signable, innerCanonical []byte, err error)
}

// v2Codec implements envelopeCodec for the V2 schema, matching the
// shape our own `/v2/*` RA routes emit.
type v2Codec struct{}

// ParseAndBuild unmarshals raw into `event.Event` (V2), validates it,
// stamps the verified raID, canonicalizes, and wraps in an envelope.
func (v2Codec) ParseAndBuild(
	raw []byte,
	raID, keyID, sig, logID string,
) (event.Signable, []byte, error) {
	var inner event.Event
	if err := json.Unmarshal(raw, &inner); err != nil {
		return nil, nil, domain.NewValidationError("INVALID_EVENT_BODY", err.Error())
	}
	if err := inner.Validate(); err != nil {
		return nil, nil, domain.NewValidationError("INVALID_EVENT", err.Error())
	}
	// Producers may omit raId in the body; we authoritatively take
	// it from the verified JWS header. A mismatch between the two is
	// a contract violation.
	if inner.RaID == "" {
		inner.RaID = raID
	} else if inner.RaID != raID {
		return nil, nil, domain.NewValidationError(
			"RAID_MISMATCH",
			fmt.Sprintf("inner event raId %q does not match signed raId %q", inner.RaID, raID),
		)
	}
	canonical, err := event.CanonicalizeEvent(&inner)
	if err != nil {
		return nil, nil, fmt.Errorf("service: canonicalize V2 inner: %w", err)
	}
	env := event.BuildEnvelope(logID, &inner, keyID, sig)
	return env, canonical, nil
}

// v1Codec implements envelopeCodec for the V1 schema — the shape the
// reference RA has been emitting since launch and the shape our
// `/v1/*` RA routes will emit to feed the V1 TL ingest lane.
type v1Codec struct{}

// ParseAndBuild unmarshals raw into `v1.Event`, validates it, stamps
// the verified raID, canonicalizes, and wraps in a V1 envelope. The
// returned envelope's outer Signature is empty — the caller signs.
func (v1Codec) ParseAndBuild(
	raw []byte,
	raID, keyID, sig, logID string,
) (event.Signable, []byte, error) {
	var inner eventv1.Event
	if err := json.Unmarshal(raw, &inner); err != nil {
		return nil, nil, domain.NewValidationError("INVALID_EVENT_BODY", err.Error())
	}
	if err := inner.Validate(); err != nil {
		return nil, nil, domain.NewValidationError("INVALID_EVENT", err.Error())
	}
	if inner.RaID == "" {
		inner.RaID = raID
	} else if inner.RaID != raID {
		return nil, nil, domain.NewValidationError(
			"RAID_MISMATCH",
			fmt.Sprintf("inner event raId %q does not match signed raId %q", inner.RaID, raID),
		)
	}
	canonical, err := eventv1.CanonicalizeEvent(&inner)
	if err != nil {
		return nil, nil, fmt.Errorf("service: canonicalize V1 inner: %w", err)
	}
	env := eventv1.BuildEnvelope(logID, &inner, keyID, sig)
	return env, canonical, nil
}

// identityCodec implements envelopeCodec for the identity event
// family — the shape the RA's `/v2/ans/identities/*` routes emit to
// the `/v1/internal/identities/event` ingest lane. Same producer
// lane, same tree; the inner event is keyed by identityId.
//
// The cross-lane guard lives in the closed enums: an AGENT_* body
// fails this codec's `inner.Validate()` (unknown eventType, missing
// identityId) with 422 INVALID_EVENT, exactly as an IDENTITY_* body
// fails the agent codecs.
type identityCodec struct{}

// ParseAndBuild unmarshals raw into `identityevent.Event`, validates
// it, stamps the verified raID, canonicalizes, and wraps in an
// identity envelope.
func (identityCodec) ParseAndBuild(
	raw []byte,
	raID, keyID, sig, logID string,
) (event.Signable, []byte, error) {
	var inner identityevent.Event
	if err := json.Unmarshal(raw, &inner); err != nil {
		return nil, nil, domain.NewValidationError("INVALID_EVENT_BODY", err.Error())
	}
	if err := inner.Validate(); err != nil {
		return nil, nil, domain.NewValidationError("INVALID_EVENT", err.Error())
	}
	if inner.RaID == "" {
		inner.RaID = raID
	} else if inner.RaID != raID {
		return nil, nil, domain.NewValidationError(
			"RAID_MISMATCH",
			fmt.Sprintf("inner event raId %q does not match signed raId %q", inner.RaID, raID),
		)
	}
	canonical, err := identityevent.CanonicalizeEvent(&inner)
	if err != nil {
		return nil, nil, fmt.Errorf("service: canonicalize identity inner: %w", err)
	}
	env := identityevent.BuildEnvelope(logID, &inner, keyID, sig)
	return env, canonical, nil
}
