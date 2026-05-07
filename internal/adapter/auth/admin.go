package auth

import (
	"encoding/json"
	"net/http"
)

// RequireAdmin returns middleware that rejects any request whose
// authenticated Identity does not carry `IsAdmin = true`. Returns an
// RFC 7807 problem response:
//
//   - 401 if no Identity is attached (auth middleware was skipped).
//     This signals a misconfiguration: admin routes must sit behind
//     the auth middleware, not behind an anonymous-paths exception.
//   - 403 if an Identity is present but not admin.
//
// Design choice: RequireAdmin depends only on the already-attached
// Identity. It does NOT re-authenticate — the auth provider is
// responsible for setting IsAdmin from its own rules (StaticProvider
// always sets true for static-key callers; OIDCProvider matches the
// `groups` claim against a configurable admin-groups list). Keeping
// this middleware ignorant of provider type means admin routes work
// identically under any auth provider.
func RequireAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := IdentityFromContext(r.Context())
			if !ok || id == nil {
				// No Identity in context → the auth middleware let this
				// through (probably via an anonymous-path exception
				// that also matched an admin route). That's always a
				// misconfig; fail closed.
				writeAdminError(w, http.StatusUnauthorized, "UNAUTHORIZED",
					"admin route requires authentication")
				return
			}
			if !id.IsAdmin {
				writeAdminError(w, http.StatusForbidden, "ACCESS_DENIED",
					"admin privileges required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeAdminError emits an RFC 7807 Problem Details response.
// Intentionally duplicated (not shared with writeAuthError) because
// that helper only emits 401s; this emits either 401 or 403 with
// an explicit code per problem.
func writeAdminError(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{
		"type":   "about:blank",
		"title":  http.StatusText(status),
		"status": status,
		"code":   code,
		"detail": detail,
	}
	_ = json.NewEncoder(w).Encode(body)
}
