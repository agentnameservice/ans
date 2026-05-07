package event

// BuildEnvelope is the single chokepoint for envelope construction on
// the TL side of the boundary. The TL receives an Event + producer
// signature + producer keyId; it assigns logId and wraps.
//
// Centralizing this prevents drift — anywhere else in the codebase
// that needs an Envelope goes through this function, so changes to
// the shape happen in exactly one place.
func BuildEnvelope(logID string, inner *Event, producerKeyID, producerSignature string) *Envelope {
	return &Envelope{
		SchemaVersion: SchemaVersion,
		Payload: &Payload{
			LogID: logID,
			Producer: &Producer{
				Event:     inner,
				KeyID:     producerKeyID,
				Signature: producerSignature,
			},
		},
	}
}

// CanonicalizeEvent JCS-canonicalizes a producer Event. This is the
// byte sequence the producer signs (with its own key) before sending
// to the TL, and the byte sequence the TL re-canonicalizes to verify
// that producer signature.
//
// Exposed so both sides of the RA ↔ TL boundary use the exact same
// canonicalization logic; if the RA produces JCS bytes that the TL
// canonicalizes differently, signature verification silently fails.
func CanonicalizeEvent(inner *Event) ([]byte, error) {
	return canonicalize(inner)
}
