// Package auth provides AuthProvider implementations.
package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/godaddy/ans/internal/port"
)

type identityCtxKey struct{}

// IdentityFromContext returns the Identity attached by auth middleware.
func IdentityFromContext(ctx context.Context) (*port.Identity, bool) {
	id, ok := ctx.Value(identityCtxKey{}).(*port.Identity)
	return id, ok
}

// WithIdentity returns a child context carrying the given Identity.
// Exported for tests; handler code should rely on middleware.
func WithIdentity(ctx context.Context, id *port.Identity) context.Context {
	return context.WithValue(ctx, identityCtxKey{}, id)
}

// StaticProvider is a quickstart AuthProvider that accepts a single
// static API key configured via the server's YAML config. Supports
// two Authorization header formats so ANS SDKs and simple curl-based
// tooling both work against the same deployment:
//
//  1. `Authorization: Bearer <apiKey>` — simple bearer token. The
//     ans-native format used by the demo scripts. Matched against
//     `apiKey`.
//
//  2. `Authorization: sso-key <apiKey>:<apiSecret>` — the reference
//     RA's format (see the reference `check_api_key` helper). The
//     case-insensitive "sso-key " prefix is optional — a bare
//     `apiKey:apiSecret` pair in the Authorization header is also
//     accepted, matching the reference regex
//     `^(?:sso-key\s+)?([^:]+):(.+)$`. Matched against
//     `apiKey` + `apiSecret` (both must be configured).
//
// All comparisons are constant-time to resist timing side-channels.
//
// Do not use StaticProvider in production. Use OIDCProvider instead.
type StaticProvider struct {
	apiKey    string
	apiSecret string // optional; enables the sso-key format when set
	// anonymousPaths are SUBTREE prefixes under which auth is skipped:
	// a request whose path equals the prefix or extends it past a `/`
	// boundary is anonymous. Used for `/docs` (which also serves
	// `/docs/openapi.yaml`) and `/v2/admin/*`.
	anonymousPaths []string
	// anonymousExactPaths are EXACT paths under which auth is skipped —
	// only an identical path matches, never a child or a same-prefix
	// sibling. Required for leaf routes like `/v1/agents/events` that
	// sit next to authenticated wildcard siblings
	// (`/v1/agents/{agentId}/…`): a subtree exemption there would skip
	// auth for `/v1/agents/events/revoke`, which chi backtracks onto
	// the `{agentId}` route as `agentId="events"`.
	anonymousExactPaths []string
	subject             string // synthetic subject reported on success
}

// StaticOption configures a StaticProvider.
type StaticOption func(*StaticProvider)

// WithAnonymousPath marks a URL-path SUBTREE as unauthenticated: the
// prefix itself and any descendant past a `/` boundary. Handlers can
// still call IdentityFromContext; it will return (nil, false). Use for
// genuinely subtree-shaped exemptions like `/docs` (also serves
// `/docs/openapi.yaml`).
//
// Do NOT use this for a leaf route that sits beside an authenticated
// wildcard sibling — use WithAnonymousExactPath. A subtree exemption on
// `/v1/agents/events` would also exempt `/v1/agents/events/revoke`,
// which chi routes to the authenticated `/v1/agents/{agentId}/revoke`
// handler with `agentId="events"`.
func WithAnonymousPath(prefix string) StaticOption {
	return func(p *StaticProvider) {
		p.anonymousPaths = append(p.anonymousPaths, prefix)
	}
}

// WithAnonymousExactPath marks a single exact URL path as
// unauthenticated. Only a request whose path is byte-identical matches —
// never a child (`/path/child`) and never a same-prefix sibling
// (`/pathfoo`). This is the safe exemption for a public leaf route
// adjacent to authenticated wildcard routes.
func WithAnonymousExactPath(path string) StaticOption {
	return func(p *StaticProvider) {
		p.anonymousExactPaths = append(p.anonymousExactPaths, path)
	}
}

// WithStaticSubject sets the subject reported for authenticated requests.
// Defaults to "static-user".
func WithStaticSubject(s string) StaticOption {
	return func(p *StaticProvider) { p.subject = s }
}

// WithAPISecret enables the reference-compatible
// `Authorization: sso-key <apikey>:<secret>` format. When the secret
// is empty, only the Bearer format is accepted. The SDKs produced
// against the reference RA send `sso-key`; deployments that want
// SDK compatibility must configure a secret here.
func WithAPISecret(secret string) StaticOption {
	return func(p *StaticProvider) { p.apiSecret = secret }
}

// NewStaticProvider creates a StaticProvider with the given key.
func NewStaticProvider(apiKey string, opts ...StaticOption) *StaticProvider {
	p := &StaticProvider{apiKey: apiKey, subject: "static-user"}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Errors returned by Authenticate.
var (
	ErrMissingCredentials = errors.New("auth: missing credentials")
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
)

// Authenticate accepts either format:
//
//   - `Authorization: Bearer <apiKey>` — matched against the
//     configured apiKey.
//   - `Authorization: sso-key <apiKey>:<apiSecret>` (prefix optional,
//     case-insensitive) — matched against apiKey + apiSecret. Only
//     accepted when a non-empty apiSecret is configured.
//
// Missing/malformed header → ErrMissingCredentials.
// Header present but neither format matches → ErrInvalidCredentials.
func (p *StaticProvider) Authenticate(ctx context.Context, r *http.Request) (*port.Identity, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, ErrMissingCredentials
	}

	// Try the sso-key format first when configured. This ordering
	// matters because a string like "apikey:secret" WITHOUT the
	// "sso-key" prefix is also a valid sso-key submission per the
	// reference regex. Falling through to Bearer would then interpret
	// that literal string as a bearer token, producing a confusing
	// ErrInvalidCredentials instead of the proper key/secret match.
	if p.apiSecret != "" {
		if key, secret, ok := parseSSOKey(header); ok {
			if constTimeEqual(key, p.apiKey) && constTimeEqual(secret, p.apiSecret) {
				return p.newIdentity(), nil
			}
			// Mismatch on sso-key format — don't fall through to
			// Bearer. A caller using sso-key intentionally doesn't
			// want their secret silently interpreted as a bearer
			// token, and the mismatch is a real credentials failure.
			return nil, ErrInvalidCredentials
		}
	}

	// Fall back to the Bearer format.
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return nil, ErrMissingCredentials
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return nil, ErrMissingCredentials
	}
	if !constTimeEqual(token, p.apiKey) {
		return nil, ErrInvalidCredentials
	}
	return p.newIdentity(), nil
}

// newIdentity returns the Identity reported on successful auth.
// Centralized so both code paths produce identical results.
func (p *StaticProvider) newIdentity() *port.Identity {
	return &port.Identity{
		Subject: p.subject,
		Scopes:  []string{"ans:read", "ans:write"},
		IsAdmin: true, // quickstart: static key is effectively admin
	}
}

// parseSSOKey extracts (apiKey, apiSecret) from a reference-format
// Authorization header. Returns ok=false when the header doesn't
// match the sso-key shape. The "sso-key" prefix is optional and
// case-insensitive, matching the reference regex exactly.
//
// Reference: the reference RA's `check_api_key` helper.
//
//	match = re.match(r'^(?:sso-key\s+)?([^:]+):(.+)$', auth_header, re.IGNORECASE)
func parseSSOKey(header string) (string, string, bool) {
	// Strip optional "sso-key " prefix (case-insensitive).
	trimmed := strings.TrimSpace(header)
	if len(trimmed) >= len("sso-key ") &&
		strings.EqualFold(trimmed[:len("sso-key ")], "sso-key ") {
		trimmed = strings.TrimSpace(trimmed[len("sso-key "):])
	}
	// Must be <key>:<secret> — single colon separator. The reference
	// regex uses `[^:]+` for the key (one or more non-colon chars)
	// and `.+` for the secret (one or more chars, may contain colons).
	// So we split on the FIRST colon.
	idx := strings.IndexByte(trimmed, ':')
	if idx <= 0 || idx == len(trimmed)-1 {
		return "", "", false
	}
	return trimmed[:idx], trimmed[idx+1:], true
}

// constTimeEqual compares two strings in constant time. Guards against
// timing side-channels when an attacker tries to guess credentials
// character-by-character.
func constTimeEqual(a, b string) bool {
	// Per crypto/subtle docs, ConstantTimeCompare is constant-time
	// ONLY when the inputs are the same length. A length check first
	// leaks length, which is fine for our threat model — guessing
	// the correct length is not the hard part; guessing the bytes is.
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Middleware returns an http.Handler middleware enforcing authentication.
// Requests to anonymous path prefixes pass through without an Identity.
func (p *StaticProvider) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p.isAnonymousPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			id, err := p.Authenticate(r.Context(), r)
			if err != nil {
				writeAuthError(w, err)
				return
			}
			ctx := WithIdentity(r.Context(), id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (p *StaticProvider) isAnonymousPath(path string) bool {
	for _, exact := range p.anonymousExactPaths {
		if path == exact {
			return true
		}
	}
	for _, prefix := range p.anonymousPaths {
		if isSubtreeMatch(path, prefix) {
			return true
		}
	}
	return false
}

// isSubtreeMatch reports whether path is prefix itself or a descendant
// of it past a `/` boundary. Unlike a bare strings.HasPrefix, it does
// NOT treat `/docsfoo` as under `/docs` — a prefix exemption must not
// leak to a same-prefix sibling segment.
//
// A trailing slash on the registered prefix is normalized away first,
// so callers may register either form: `/v1/agents` and `/v1/agents/`
// behave identically. Without this, a registered `/v1/agents/` would
// test HasPrefix(path, "/v1/agents//") — a doubled slash that never
// matches — silently 401ing every descendant. The TL registers its
// public-read prefixes with trailing slashes (`/v1/agents/`, `/v1/log/`,
// `/tile/`), so this tolerance is load-bearing, not cosmetic.
func isSubtreeMatch(path, prefix string) bool {
	prefix = strings.TrimRight(prefix, "/")
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

// extractBearerToken reads the token from an Authorization: Bearer <token>
// header. Returns ErrMissingCredentials if the header is absent or malformed.
func extractBearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", ErrMissingCredentials
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", ErrMissingCredentials
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", ErrMissingCredentials
	}
	return token, nil
}

// writeAuthError writes an RFC 7807 Problem Details response for auth errors.
func writeAuthError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/problem+json")
	status := http.StatusUnauthorized
	w.WriteHeader(status)
	body := map[string]any{
		"type":   "about:blank",
		"title":  "Unauthorized",
		"status": status,
		"detail": err.Error(),
	}
	_ = json.NewEncoder(w).Encode(body)
}
