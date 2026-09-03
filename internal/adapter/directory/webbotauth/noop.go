package webbotauth

import (
	"context"

	"github.com/agentnameservice/ans/internal/port"
)

// Noop is the quickstart directory resolver. It never dials anywhere:
// the endorsed key set is synthesized from the hints — the kid → JWK
// pairs the service extracted from the submitted proofs' `jwk` protected
// headers.
//
// What this preserves and what it waives (the noop DID resolver
// precedent — real crypto, waived external-world binding):
//
//   - PRESERVED: every JWS still genuinely verifies against the embedded
//     key, the proof input still binds identityId / nonce / purpose, and
//     the sealed event stays self-verifying.
//   - WAIVED: the binding "the live directory at the Signature-Agent URL
//     really endorses this key". Anyone can mint a keypair and claim any
//     Signature-Agent URL.
//
// Strictly for local development and the demo scripts. NOT for
// production.
type Noop struct{}

// NewNoopResolver returns the quickstart directory resolver.
func NewNoopResolver() *Noop { return &Noop{} }

// Resolve synthesizes the endorsed key set from the hints, one
// DirectoryKey per hinted JWK, each with an unbounded validity window.
// With no hints (the register-time advisory fetch) the set is empty —
// the 202 challenge list then carries a single unkeyed entry, and the
// registrant names keys via the JWS `kid` + `jwk` headers at verify
// time. The hint's JWK bytes pass through verbatim, so the sealed
// verification method quotes the registrant's exact key.
func (n *Noop) Resolve(_ context.Context, _ string, hints []port.KeyHint) ([]port.DirectoryKey, error) {
	keys := make([]port.DirectoryKey, 0, len(hints))
	for _, h := range hints {
		if len(h.PublicKeyJWK) == 0 {
			continue
		}
		keys = append(keys, port.DirectoryKey{JWK: h.PublicKeyJWK})
	}
	return keys, nil
}

// compile-time conformance.
var _ port.WebBotAuthDirectoryResolver = (*Noop)(nil)
