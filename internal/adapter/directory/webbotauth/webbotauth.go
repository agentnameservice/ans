// Package webbotauth provides the two port.WebBotAuthDirectoryResolver
// adapters behind the web-bot-auth identifier kind:
//
//   - Noop — zero-I/O quickstart resolver; synthesizes the endorsed key
//     set from the submitted proofs' embedded keys.
//   - HTTP — the real thing: a hardened HTTPS fetch of the HTTP Message
//     Signatures directory on the shared securefetch transport (WebPKI,
//     SSRF dialer guards, DNS-rebind pin, size cap, bounded
//     same-registrable-domain redirects), a content-type check, and a
//     JWKS parse with per-key nbf/exp windows.
//
// Selected by `webbotauth.directory.type` ("noop" | "http") in the RA
// config — the same pattern as the DNS verifier's `dns.type` and the
// did:web resolver's `identity.resolver.type`.
package webbotauth
