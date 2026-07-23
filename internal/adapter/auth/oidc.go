package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/agentnameservice/ans/internal/port"
)

// OIDCProvider validates OAuth2 / OpenID Connect Bearer tokens using
// standard OIDC Discovery. It works with any compliant provider: Dex
// (recommended for local dev), Keycloak, Ory Hydra, Okta, Auth0, etc.
//
// On each request the provider:
//  1. extracts the Bearer token
//  2. verifies the signature and issuer via the provider's JWKS
//  3. checks exp/nbf/iat
//  4. validates the audience claim
//  5. maps the token's "sub", "scope", and optional "groups" claims into
//     a port.Identity
//
// Tokens are not cached; go-oidc caches the JWKS internally.
type OIDCProvider struct {
	verifier    *oidc.IDTokenVerifier
	expectedAud string
	// anonymousPaths are SUBTREE prefixes (see the StaticProvider field
	// of the same name); anonymousExactPaths are byte-exact leaf
	// exemptions. Both providers share the same matching semantics so a
	// route's anonymity does not depend on which auth adapter is wired.
	anonymousPaths      []string
	anonymousExactPaths []string
	adminGroups         []string // groups granting admin privileges (optional)
}

// OIDCOption configures an OIDCProvider.
type OIDCOption func(*OIDCProvider)

// WithOIDCAnonymousPath makes a path SUBTREE unauthenticated (the
// prefix itself or any descendant past a `/`). For a leaf route beside
// authenticated wildcard siblings, use WithOIDCAnonymousExactPath — see
// the StaticProvider equivalents for the chi-backtracking rationale.
func WithOIDCAnonymousPath(prefix string) OIDCOption {
	return func(p *OIDCProvider) { p.anonymousPaths = append(p.anonymousPaths, prefix) }
}

// WithOIDCAnonymousExactPath makes a single exact path unauthenticated —
// never a child or a same-prefix sibling.
func WithOIDCAnonymousExactPath(path string) OIDCOption {
	return func(p *OIDCProvider) { p.anonymousExactPaths = append(p.anonymousExactPaths, path) }
}

// WithAdminGroups lists group values that should be treated as admin.
// If empty, tokens are never admin (safe default). Matches against the
// "groups" or "roles" claim.
func WithAdminGroups(groups ...string) OIDCOption {
	return func(p *OIDCProvider) { p.adminGroups = append(p.adminGroups, groups...) }
}

// NewOIDCProvider constructs a provider that validates tokens from the
// given issuer URL and audience. Discovery is performed once at startup;
// a failure here prevents server start.
func NewOIDCProvider(ctx context.Context, issuerURL, audience, clientID string, opts ...OIDCOption) (*OIDCProvider, error) {
	if issuerURL == "" {
		return nil, errors.New("auth/oidc: issuer URL is required")
	}
	if audience == "" {
		return nil, errors.New("auth/oidc: audience is required")
	}
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth/oidc: discover %s: %w", issuerURL, err)
	}
	cfg := &oidc.Config{ClientID: clientID, SkipClientIDCheck: clientID == ""}
	verifier := provider.Verifier(cfg)

	p := &OIDCProvider{verifier: verifier, expectedAud: audience}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// tokenClaims are the minimum set of claims we require from an OIDC token.
type tokenClaims struct {
	Subject  string   `json:"sub"`
	Audience any      `json:"aud"` // string or []string per spec
	Scope    string   `json:"scope"`
	Groups   []string `json:"groups"`
	Roles    []string `json:"roles"`
}

// Authenticate verifies the token in the Authorization header.
func (p *OIDCProvider) Authenticate(ctx context.Context, r *http.Request) (*port.Identity, error) {
	token, err := extractBearerToken(r)
	if err != nil {
		return nil, err
	}
	idToken, err := p.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCredentials, err)
	}
	var claims tokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", ErrInvalidCredentials, err)
	}
	if !audienceMatches(claims.Audience, p.expectedAud) {
		return nil, fmt.Errorf("%w: audience %v does not include %q",
			ErrInvalidCredentials, claims.Audience, p.expectedAud)
	}
	scopes := parseScopeClaim(claims.Scope)

	groups := append([]string{}, claims.Groups...)
	groups = append(groups, claims.Roles...)

	return &port.Identity{
		Subject: claims.Subject,
		Scopes:  scopes,
		IsAdmin: anyGroupMatches(groups, p.adminGroups),
	}, nil
}

// Middleware enforces authentication on all non-anonymous paths.
func (p *OIDCProvider) Middleware() func(http.Handler) http.Handler {
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
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
		})
	}
}

func (p *OIDCProvider) isAnonymousPath(path string) bool {
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

// audienceMatches returns true if the expected audience is in the claim.
// OIDC allows aud to be either a string or a JSON array of strings.
func audienceMatches(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == expected {
				return true
			}
		}
	}
	return false
}

// parseScopeClaim splits a space-separated OAuth2 scope string.
func parseScopeClaim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, " ")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func anyGroupMatches(tokenGroups, adminGroups []string) bool {
	if len(adminGroups) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(adminGroups))
	for _, g := range adminGroups {
		set[g] = struct{}{}
	}
	for _, tg := range tokenGroups {
		if _, ok := set[tg]; ok {
			return true
		}
	}
	return false
}
