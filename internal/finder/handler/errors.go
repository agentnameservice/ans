// Package handler is the HTTP adapter for the ANS Finder's discovery
// surface: POST /v1/search and POST /v1/explore, plus operator
// health/readiness. It maps between the frozen OpenAPI request/response
// DTOs (spec/api-spec-finder-v1.yaml) and the index.Catalog port. All
// failures are RFC 7807 Problem Details whose `code` carries an ARD
// standard error code (ARDS Appendix B).
package handler

import (
	"encoding/json"
	"net/http"
)

// ARD standard error codes (ARDS Appendix B) carried in Problem.code.
const (
	codeInvalidArgument   = "INVALID_ARGUMENT"
	codeUnauthenticated   = "UNAUTHENTICATED"
	codeNotFound          = "NOT_FOUND"
	codeRateLimitExceeded = "RATE_LIMIT_EXCEEDED"
	codeInternalError     = "INTERNAL_ERROR"
)

// Problem is the RFC 7807 problem-details body. Its shape matches the ANS
// TL spec and the RA handler's Problem struct byte-for-byte (type, title,
// status, detail, code), so a client that already speaks ANS errors needs
// no Finder-specific handling. `code` is the programmatic key; `detail`
// is the human-readable explanation.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code,omitempty"`
}

// writeProblem writes p as application/problem+json with its status.
func writeProblem(w http.ResponseWriter, p Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// writeOK writes value as a 200 application/json response. The Finder's
// successful responses are always 200; error paths use writeProblem with
// the appropriate status, so this helper takes no status parameter. The
// nosniff header keeps a browser from MIME-sniffing the JSON body into
// something executable.
func writeOK(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

// problemInvalidArgument builds a 400 INVALID_ARGUMENT problem.
func problemInvalidArgument(detail string) Problem {
	return Problem{
		Type:   "about:blank",
		Title:  "Invalid Argument",
		Status: http.StatusBadRequest,
		Detail: detail,
		Code:   codeInvalidArgument,
	}
}

// problemRateLimited builds a 429 RATE_LIMIT_EXCEEDED problem.
func problemRateLimited() Problem {
	return Problem{
		Type:   "about:blank",
		Title:  "Rate Limit Exceeded",
		Status: http.StatusTooManyRequests,
		Detail: "request rate limit exceeded on the unauthenticated discovery surface",
		Code:   codeRateLimitExceeded,
	}
}

// problemInternal builds a 500 INTERNAL_ERROR problem. The detail is a
// fixed, non-leaking string — the underlying error is logged, not
// returned, so an index/store failure never exposes internals to an
// anonymous caller.
func problemInternal() Problem {
	return Problem{
		Type:   "about:blank",
		Title:  "Internal Server Error",
		Status: http.StatusInternalServerError,
		Detail: "the finder encountered an internal error",
		Code:   codeInternalError,
	}
}
