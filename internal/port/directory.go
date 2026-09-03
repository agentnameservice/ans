package port

import (
	"context"
	"encoding/json"
	"time"
)

// DirectoryKey is one key the web-bot-auth HTTP Message Signatures
// directory endorses, as the RA needs it for the verify-control gate.
//
// JWK is the directory JWKS entry quoted VERBATIM — the exact bytes the
// directory served — so the sealed verification method can carry it
// untouched (the no-derived-values rule the DID resolver also honors).
// The RFC 7638 thumbprint used to match a proof's `kid` is recomputed
// from the required members, so any extra directory metadata inside the
// object (nbf/exp) never perturbs the match.
type DirectoryKey struct {
	// JWK is the directory's key object, verbatim.
	JWK json.RawMessage
	// NotBefore and NotAfter bound the key's validity window. A zero
	// value means unbounded on that side. Keys outside the window are
	// skipped at match time (mid-rotation tolerance) — never fatal.
	NotBefore time.Time
	NotAfter  time.Time
}

// WebBotAuthDirectoryResolver fetches and parses the HTTP Message
// Signatures directory a web-bot-auth Signature-Agent URL serves — the
// authoritative key source for the web-bot-auth control proof, the
// did:web resolver's analog on the web-bot-auth lane:
//
//   - The "http" adapter performs a hardened HTTPS fetch (shared
//     securefetch transport: WebPKI, SSRF dialer guards, DNS-rebind pin,
//     size cap, bounded same-registrable-domain redirects) of the
//     directory at the canonical well-known URL, checks the
//     content-type, and parses the JWKS. Hints are ignored — the
//     resolved directory is always the key source.
//
//   - The "noop" adapter performs no I/O and synthesizes the key set
//     from the hints (the kid → JWK pairs embedded in the submitted
//     proofs' `jwk` headers). Signature verification still genuinely
//     runs against those keys, so sealed events stay self-verifying even
//     from quickstart runs — only the binding "the live directory really
//     endorses this key" is waived. Mirrors the noop DID resolver. NOT
//     for production.
type WebBotAuthDirectoryResolver interface {
	// Resolve returns the endorsed key set for the canonical directory
	// URL. Fetch-layer failures are returned as retryable (503-class)
	// domain errors, never 500 — the request was valid and consumed no
	// state.
	Resolve(ctx context.Context, directoryURL string, hints []KeyHint) ([]DirectoryKey, error)
}
