package leiverifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// Verifier is the production vLEI control verifier: a hardened HTTP
// client for an internal GLEIF vlei-verifier service. The RA is the
// single touchpoint for the verifier — it never parses KERI key state
// itself; the verifier is the authoritative key-state oracle.
//
// It speaks three vlei-verifier endpoints (the real reference API):
//
//   - PUT  /presentations/{said}  (application/json+cesr) — submit the
//     full-chain CESR export; the verifier validates it cryptographically
//     and reports the holder AID + credential SAID. The {said} is read
//     out of the (registrant-supplied) CESR, so it is qb64-validated
//     before it is interpolated into the path (see isQB64); the verifier
//     then re-derives and re-validates it, and the SUBJECT AID we pin
//     comes from the verifier's response, never from the caller.
//   - GET  /authorizations/{aid}  — the LIVE authorization for the AID:
//     200 with {aid, said, lei, role} while authorized, 401 when not,
//     404 before the presentation has been processed.
//   - POST /signature/verify       — verify a CESR signature: the
//     verifier resolves the AID's current key from its KEL and checks
//     the signature over the supplied bytes verbatim.
//
// The base URL is operator-configured (a trusted internal service), so
// the host can never be attacker-chosen the way the did:web resolver's
// can; the controls are a hard timeout, a response-size cap, error
// details that never echo the configured host, and qb64 validation of
// every identifier interpolated into a request path (the {said} read
// from registrant-supplied CESR, the subject AID) so it cannot re-target
// the path or inject a query against that host.
type Verifier struct {
	baseURL      string
	client       *http.Client
	maxBodyBytes int64
}

// VerifierOption customizes the Verifier.
type VerifierOption func(*Verifier)

// WithTimeout overrides the per-request HTTP timeout (default 5s).
func WithTimeout(d time.Duration) VerifierOption {
	return func(v *Verifier) {
		if d > 0 {
			v.client.Timeout = d
		}
	}
}

// WithHTTPClient injects an HTTP client (tests). Its Timeout is
// preserved unless WithTimeout follows.
func WithHTTPClient(c *http.Client) VerifierOption {
	return func(v *Verifier) {
		if c != nil {
			v.client = c
		}
	}
}

// WithMaxBodyBytes overrides the response-size cap (default 1 MiB).
func WithMaxBodyBytes(n int64) VerifierOption {
	return func(v *Verifier) {
		if n > 0 {
			v.maxBodyBytes = n
		}
	}
}

// NewVerifier constructs the production verifier against baseURL (e.g.
// "http://vlei-verifier:7676"), with the trailing slash trimmed.
func NewVerifier(baseURL string, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		baseURL:      strings.TrimRight(baseURL, "/"),
		client:       &http.Client{Timeout: 5 * time.Second},
		maxBodyBytes: 1 << 20,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// presentationResponse is the PUT /presentations/{said} body.
type presentationResponse struct {
	AID  string `json:"aid"`
	SAID string `json:"said"`
	Msg  string `json:"msg"`
}

// authorizationResponse is the GET /authorizations/{aid} body.
type authorizationResponse struct {
	AID  string `json:"aid"`
	SAID string `json:"said"`
	LEI  string `json:"lei"`
	Role string `json:"role"`
	Msg  string `json:"msg"`
}

// Present submits the full-chain CESR export and returns the verifier's
// view of the holder. The subject AID is read from the verifier's
// response — never extracted by us, never caller-asserted. The {said}
// path segment is the only thing we read out of the CESR (a content
// address the verifier re-derives), routing the submission to the
// presented credential.
func (v *Verifier) Present(ctx context.Context, cesr string) (port.PresentationResult, error) {
	said := presentedCredentialSAID(cesr)
	if said == "" {
		return port.PresentationResult{}, domain.NewValidationError("LEI_PRESENTATION_INVALID",
			"vlei presentation carries no ACDC credential")
	}
	// said is read from registrant-supplied CESR and interpolated into the
	// path below — reject anything outside the qb64 alphabet so it cannot
	// re-target the path ('/', '..') or inject a query ('?', '#', '%').
	if !isQB64(said) {
		return port.PresentationResult{}, domain.NewValidationError("LEI_PRESENTATION_INVALID",
			"the presented credential SAID is not a valid qb64 identifier")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		v.baseURL+"/presentations/"+said, strings.NewReader(cesr))
	if err != nil {
		return port.PresentationResult{}, v.unavailable("present")
	}
	req.Header.Set("Content-Type", "application/json+cesr")

	var pres presentationResponse
	status, err := v.do(req, &pres)
	if err != nil {
		return port.PresentationResult{}, err
	}
	switch {
	case status == http.StatusAccepted || status == http.StatusOK:
		// processed below
	case status >= 400 && status < 500:
		return port.PresentationResult{}, domain.NewValidationError("LEI_PRESENTATION_INVALID",
			"the vlei verifier rejected the presented credential")
	default:
		return port.PresentationResult{}, v.unavailable("present")
	}
	if pres.AID == "" {
		return port.PresentationResult{}, v.unavailable("present")
	}

	// The presentation is accepted; authorization is processed
	// asynchronously, so the holder may still be PENDING. A live
	// authorization check resolves the status + LEI.
	auth, err := v.Authorization(ctx, pres.AID)
	if err != nil {
		return port.PresentationResult{}, err
	}
	status0 := "PENDING"
	if auth.Authorized {
		status0 = "AUTHORIZED"
	}
	return port.PresentationResult{
		SubjectAID: pres.AID,
		LEI:        auth.LEI,
		Status:     status0,
	}, nil
}

// Authorization reports the verifier's live authorization for the AID.
func (v *Verifier) Authorization(ctx context.Context, subjectAID string) (port.AuthorizationResult, error) {
	// On the real path subjectAID is verifier-derived, but it is
	// interpolated into the path below all the same — qb64-validate it for
	// the same reason as the {said} in Present (defense in depth).
	if !isQB64(subjectAID) {
		return port.AuthorizationResult{}, domain.NewValidationError("LEI_SUBJECT_AID_INVALID",
			"subject AID is not a valid qb64 identifier")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		v.baseURL+"/authorizations/"+subjectAID, nil)
	if err != nil {
		return port.AuthorizationResult{}, v.unavailable("authorize")
	}
	var auth authorizationResponse
	status, err := v.do(req, &auth)
	if err != nil {
		return port.AuthorizationResult{}, err
	}
	switch status {
	case http.StatusOK:
		return port.AuthorizationResult{Authorized: true, LEI: auth.LEI}, nil
	case http.StatusUnauthorized, http.StatusNotFound:
		// 401: presented but not authorized; 404: not yet processed.
		return port.AuthorizationResult{Authorized: false}, nil
	default:
		return port.AuthorizationResult{}, v.unavailable("authorize")
	}
}

// signatureVerifyRequest is the POST /signature/verify body. The
// verifier resolves the AID's current key from its KEL and checks the
// signature over the UTF-8 bytes of non_prefixed_digest verbatim — so
// non_prefixed_digest carries the served signingInput, the exact bytes
// the registrant signed (the same payload the JWS kinds sign).
type signatureVerifyRequest struct {
	SignerAID         string `json:"signer_aid"`
	Signature         string `json:"signature"`
	NonPrefixedDigest string `json:"non_prefixed_digest"`
}

// VerifySignature checks the CESR signature over the signing input via
// the verifier's KEL-backed key state. A well-formed but non-verifying
// signature is a false; an I/O or protocol failure reaching the
// verifier is an error.
func (v *Verifier) VerifySignature(ctx context.Context, subjectAID, signingInput, signature string) (bool, error) {
	body, err := json.Marshal(signatureVerifyRequest{
		SignerAID:         subjectAID,
		Signature:         signature,
		NonPrefixedDigest: signingInput,
	})
	if err != nil {
		return false, v.unavailable("verify-signature")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		v.baseURL+"/signature/verify", bytes.NewReader(body))
	if err != nil {
		return false, v.unavailable("verify-signature")
	}
	req.Header.Set("Content-Type", "application/json")

	status, err := v.do(req, nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusAccepted, http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusBadRequest, http.StatusNotFound:
		// 401: signature does not verify against the AID's current key.
		// 400: malformed input (a non-verifying signature, not an outage).
		// 404: AID is unknown to the verifier's KEL — also a non-verifying
		// proof from the registrant's perspective, not a verifier outage.
		return false, nil
	default:
		return false, v.unavailable("verify-signature")
	}
}

// do executes the request, enforces the response-size cap, and (when
// out is non-nil and the status carries a JSON body) decodes it.
// Returns the status code so callers map it to domain semantics.
func (v *Verifier) do(req *http.Request, out any) (int, error) {
	// The request URL is built only from the operator-configured baseURL
	// (a trusted internal vlei-verifier) plus verifier-controlled path
	// segments — never from registrant input — so the SSRF posture the
	// did:web resolver needs does not apply here. (See the type doc.)
	resp, err := v.client.Do(req) //nolint:gosec // baseURL is operator-configured; no caller-controlled host

	if err != nil {
		return 0, v.unavailable(req.Method)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, v.maxBodyBytes+1))
	if err != nil {
		return resp.StatusCode, v.unavailable(req.Method)
	}
	if int64(len(body)) > v.maxBodyBytes {
		return resp.StatusCode, v.unavailable(req.Method)
	}
	// Decode strictly on a 2xx success — the contract callers rely on.
	// A 200 with malformed JSON would otherwise leave `out` zero-valued
	// (e.g. auth.LEI == ""), and the service treats an empty LEI as the
	// noop waiver of the AID↔LEI binding — silently degrading the
	// production verifier to noop semantics. Fail-closed instead.
	// Non-2xx bodies are caller-mapped status text (plain or JSON) and
	// are not consumed by callers, so we leave them undecoded.
	if out != nil && len(body) > 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(body, out); err != nil {
			return resp.StatusCode, v.unavailable("decode")
		}
	}
	return resp.StatusCode, nil
}

// unavailable builds the operator-facing error for a verifier I/O or
// protocol failure. The detail names the operation but never the
// configured host (no internal-topology leak).
func (v *Verifier) unavailable(op string) error {
	return domain.NewInternalError("LEI_VERIFIER_UNAVAILABLE",
		fmt.Sprintf("the vlei verifier is unavailable (%s)", op), nil)
}

// isQB64 reports whether s is a non-empty CESR qb64 token — the
// base64url alphabet ([A-Za-z0-9_-]) and nothing else. KERI SAIDs and
// AIDs are qb64, so this is the guard that lets us safely interpolate a
// verifier SAID / subject AID into a request path: it rejects '/', '.',
// '?', '#', '%', and every other character that could re-target the path
// or inject a query against the operator-configured verifier host. The
// fixed baseURL bounds the host; this bounds the path.
func isQB64(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// presentedCredentialSAID extracts the SAID of the *presented* (leaf)
// credential from a full-chain CESR export — the minimal, targeted read
// the real verifier path needs to route PUT /presentations/{said}. It is
// NOT a CESR codec: KERI/ACDC serializations are version-string-first, so
// an ACDC credential message is always a JSON object whose first member
// is `"v":"ACDC…"`; we locate those frames by brace-balancing (respecting
// JSON string escaping), read each frame's self-addressing `d`, and
// collect the edge node SAIDs (the `n` of each edge) from each frame's
// `e` block.
//
// The presented credential is the most-derived one — the ECR/role
// credential at the bottom of the ECR→LE→QVI chain — identified
// structurally as the lone credential whose SAID is NOT referenced by any
// other credential's edge. This is position-independent: KERIA's
// `credentials().get(said, true)` exporter emits the chain in topological
// (issuer-first) order, so the leaf is serialized LAST, but we never rely
// on frame order. A single-credential export (no chain) has no references,
// so its one frame is the leaf. The end-to-end demo (scripts/demo/vlei)
// exercises this against the live verifier.
func presentedCredentialSAID(cesr string) string {
	const marker = `{"v":"ACDC`
	type acdcFrame struct {
		D string          `json:"d"`
		E json.RawMessage `json:"e"`
	}
	var saids []string
	referenced := make(map[string]struct{})
	offset := 0
	for {
		rel := strings.Index(cesr[offset:], marker)
		if rel < 0 {
			break
		}
		start := offset + rel
		obj, end := balancedJSONObject(cesr, start)
		if obj == "" {
			offset = start + 1
			continue
		}
		offset = end
		var frame acdcFrame
		if err := json.Unmarshal([]byte(obj), &frame); err != nil || frame.D == "" {
			continue
		}
		saids = append(saids, frame.D)
		if len(frame.E) > 0 {
			collectEdgeNodes(frame.E, referenced)
		}
	}
	// The leaf is the credential no other credential chains to. A
	// well-formed linear chain has exactly one such SAID.
	for _, d := range saids {
		if _, ok := referenced[d]; !ok {
			return d
		}
	}
	return ""
}

// collectEdgeNodes walks an ACDC `e` (edge) block and records every edge
// node SAID — the `n` field of each edge — into seen. Edge group names
// are arbitrary (le, qvi, auth, …) and the block may nest, so it
// recurses; the edge block's own `d` (a SAID of the edge block itself,
// not a referenced credential) is ignored because only `n` values are
// collected.
func collectEdgeNodes(raw json.RawMessage, seen map[string]struct{}) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return
	}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, val := range t {
				if k == "n" {
					if s, ok := val.(string); ok && s != "" {
						seen[s] = struct{}{}
					}
				}
				walk(val)
			}
		case []any:
			for _, el := range t {
				walk(el)
			}
		}
	}
	walk(doc)
}

// balancedJSONObject returns the JSON object beginning at start
// (cesr[start] must be '{') and the index just past it, balancing
// braces while respecting strings and escapes. Returns "" if the object
// does not close.
func balancedJSONObject(s string, start int) (string, int) {
	depth := 0
	inStr := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inStr:
			escaped = true
		case c == '"':
			inStr = !inStr
		case inStr:
			// skip
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[start : i+1], i + 1
			}
		}
	}
	return "", len(s)
}

// compile-time conformance.
var _ port.LEIControlVerifier = (*Verifier)(nil)
