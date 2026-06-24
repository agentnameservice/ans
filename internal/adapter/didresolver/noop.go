// Package didresolver provides the two port.DIDResolver adapters:
//
//   - Noop  — zero-I/O quickstart resolver; synthesizes the DID
//     document from the submitted proofs' embedded keys.
//   - Web   — the real thing: hardened HTTPS fetch of did.json with
//     WebPKI validation and SSRF dialer guards.
//
// Selected by `identity.resolver.type` ("noop" | "web") in the RA
// config — the same pattern as the DNS verifier's `dns.type`
// ("noop" | "lookup").
package didresolver

import (
	"context"
	"encoding/json"

	"github.com/godaddy/ans/internal/port"
)

// Noop is the quickstart resolver. It never dials anywhere: the DID
// document is synthesized from the hints — the kid → public-JWK pairs
// the service extracted from the submitted proofs' `jwk` protected
// headers.
//
// What this preserves and what it waives, stated precisely (the noop
// DNS verifier precedent — real crypto, waived external-world
// binding):
//
//   - PRESERVED: every JWS still genuinely verifies against the
//     embedded key, the proof input still binds identityId / nonce /
//     purpose / raId, and the sealed event remains self-verifying.
//   - WAIVED: the binding "the live did.json at the DID's host really
//     lists this key". Anyone can mint a keypair and claim any
//     did:web value.
//
// Strictly for local development and the demo scripts. NOT for
// production.
type Noop struct{}

// NewNoopResolver returns the quickstart resolver.
func NewNoopResolver() *Noop { return &Noop{} }

// Resolve synthesizes a DID document listing exactly the hinted keys
// as assertionMethod entries of the requested DID. With no hints
// (the register-time advisory fetch) the document is valid and empty
// — the 202 challenge list then carries a single unkeyed entry, and
// the registrant names keys via the JWS `kid` + `jwk` headers at
// verify time.
//
// The synthesized Raw entry embeds the registrant's submitted jwk
// VERBATIM (json.RawMessage passes through marshalling untouched), so
// the sealed verification method quotes the registrant's exact key
// bytes — the same no-derived-values rule the web resolver satisfies
// by quoting the live document.
func (n *Noop) Resolve(_ context.Context, did string, hints []port.KeyHint) (*port.DIDDocument, error) {
	doc := &port.DIDDocument{ID: did}
	for _, h := range hints {
		if h.Kid == "" || len(h.PublicKeyJWK) == 0 {
			continue
		}
		raw, err := json.Marshal(map[string]any{
			"id":           h.Kid,
			"type":         "JsonWebKey2020",
			"controller":   did,
			"publicKeyJwk": h.PublicKeyJWK,
		})
		if err != nil {
			continue
		}
		doc.AssertionMethod = append(doc.AssertionMethod, port.VerificationMethod{
			ID:           h.Kid,
			Controller:   did,
			Type:         "JsonWebKey2020",
			PublicKeyJwk: h.PublicKeyJWK,
			Raw:          raw,
		})
	}
	return doc, nil
}

// compile-time conformance.
var _ port.DIDResolver = (*Noop)(nil)
