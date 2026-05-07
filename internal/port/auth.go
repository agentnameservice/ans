// Package port defines the hexagonal-architecture port interfaces that
// the domain and service layers depend on. Adapters in internal/adapter
// provide concrete implementations. This package has no imports from
// framework, database, or transport libraries.
package port

import (
	"context"
	"net/http"
)

// Identity represents the authenticated principal for a request.
// It is produced by an AuthProvider after successful authentication
// and attached to the request context for downstream handlers.
type Identity struct {
	// Subject uniquely identifies the authenticated principal
	// (e.g., an OIDC "sub" claim, a user ID, or an API key owner).
	Subject string

	// Scopes lists the permissions granted to this identity.
	Scopes []string

	// IsAdmin is true if this identity has administrative privileges.
	IsAdmin bool
}

// AuthProvider authenticates incoming HTTP requests and exposes
// middleware that enforces authentication on protected routes.
// Implementations must be safe for concurrent use.
type AuthProvider interface {
	// Authenticate extracts and validates credentials from the request,
	// returning the authenticated Identity on success. An error is returned
	// if credentials are missing, malformed, or invalid.
	Authenticate(ctx context.Context, r *http.Request) (*Identity, error)

	// Middleware returns an HTTP middleware that authenticates every
	// incoming request and stores the Identity in the request context.
	// On authentication failure the middleware must return 401.
	Middleware() func(http.Handler) http.Handler
}
