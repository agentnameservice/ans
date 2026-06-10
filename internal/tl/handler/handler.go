// Package handler wires HTTP routes for the Transparency Log API.
//
// Paths match the reference TL swagger byte-for-byte.
// Operator/infra-only endpoints (health, ready, docs) are ans
// conventions with no reference counterpart.
//
// Reference routes (mirrored exactly):
//
//	POST   /v1/internal/agents/event          — append a signed event (RA only)
//	GET    /v1/agents/{agentId}               — badge (real-time status)
//	GET    /v1/agents/{agentId}/audit         — paginated event history
//	GET    /v1/agents/{agentId}/receipt       — SCITT COSE_Sign1 receipt
//	GET    /v1/agents/{agentId}/status-token  — COSE_Sign1 status token
//	GET    /v1/log/checkpoint                 — JSON CheckpointResponse
//	GET    /v1/log/checkpoint/history         — paginated checkpoint history
//	GET    /v1/log/schema/{version}           — JSON-Schema for TL events
//	GET    /checkpoint                        — raw sumdb note (tlog-tiles)
//	GET    /root-keys                         — verifier keys (sumdb-note fmt)
//	GET    /tile/{level}/{index}              — complete Merkle tile
//	GET    /tile/{level}/{index}.p/{width}    — partial Merkle tile
//	GET    /tile/entries/{index}              — complete entry tile
//	GET    /tile/entries/{index}.p/{width}    — partial entry tile
//
// Operator-only (ans additions, not in reference swagger):
//
//	GET    /v2/admin/health                   — liveness
//	GET    /v2/admin/ready                    — readiness
//	GET    /docs                              — Swagger UI
//	GET    /docs/openapi.yaml                 — raw spec
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/tl/service"
)

// Handlers groups the TL HTTP handlers.
type Handlers struct {
	log           *service.LogService
	badge         *service.BadgeService
	identityBadge *service.IdentityBadgeService
	receipt       *service.ReceiptService
	statusToken   *service.StatusTokenService // nil if status tokens are disabled
	checkpoint    *service.CheckpointService
	schema        *service.SchemaService
	// rootKeysBody is the pre-rendered text/plain body for the
	// /root-keys endpoint — one verification-line per
	// active TL verifier, in the order the operator wired them.
	// Pre-rendering at startup keeps the handler allocation-free on
	// the hot path and avoids exposing the raw key material to a
	// request-scoped encoder.
	rootKeysBody []byte
}

// NewHandlers constructs a Handlers group.
//
// rootKeysBody is the text/plain response body served at
// /root-keys — typically one sumdb-note verification line
// per verifier key concatenated with '\n'.
//
// statusToken may be nil; when it is, the /status-token route
// returns 501 Not Implemented (mirroring reference swagger §305).
func NewHandlers(
	log *service.LogService,
	badge *service.BadgeService,
	identityBadge *service.IdentityBadgeService,
	receipt *service.ReceiptService,
	statusToken *service.StatusTokenService,
	checkpoint *service.CheckpointService,
	schema *service.SchemaService,
	rootKeysBody []byte,
) *Handlers {
	return &Handlers{
		log:           log,
		badge:         badge,
		identityBadge: identityBadge,
		receipt:       receipt,
		statusToken:   statusToken,
		checkpoint:    checkpoint,
		schema:        schema,
		rootKeysBody:  rootKeysBody,
	}
}

// Mount registers every route on r. The static tile/checkpoint file
// server is mounted at /checkpoint + /tile/* and points at Tessera's POSIX
// data directory so the files Tessera writes are served as-is.
//
// /root-keys is registered before the tile catch-all so
// chi routes the specific path to our handler instead of attempting
// to serve a (non-existent) `root-keys` file from the tile root.
func (h *Handlers) Mount(r chi.Router, tileRoot string) {
	// Ingest — two lanes for the two envelope schemas. V1 matches
	// the reference TL byte-for-byte (swagger §13
	// `/v1/internal/agents/event`); V2 is the ans-only lane the
	// RA's `/v2/*` routes feed. Each handler rejects the wrong
	// schema at parse time inside the codec.
	r.Post("/v1/internal/agents/event", h.AppendEventV1)
	r.Post("/v2/internal/agents/event", h.AppendEventV2)

	// Identity ingest — the IDENTITY_* event family rides the same
	// producer-signature lane into the same Merkle tree; the
	// dedicated route exists because the payload schema differs
	// (keyed by identityId) and the closed enums are the cross-lane
	// guard.
	r.Post("/v1/internal/identities/event", h.AppendEventIdentity)

	// Agent-scoped reads. Reference swagger §78-308.
	r.Get("/v1/agents/{agentId}", h.GetBadge)
	r.Get("/v1/agents/{agentId}/audit", h.GetAudit)
	r.Get("/v1/agents/{agentId}/receipt", h.GetReceipt)
	r.Get("/v1/agents/{agentId}/status-token", h.GetStatusToken)

	// Agent-side computed identity views — read-time joins through
	// the link events' agent index. Never stored on the agent; the
	// agent's own audit stays purely AGENT_*.
	r.Get("/v1/agents/{agentId}/identities", h.GetAgentIdentities)
	r.Get("/v1/agents/{agentId}/identities/history", h.GetAgentIdentityHistory)

	// Identity-stream reads — same response shapes as the agent
	// reads (badge / audit envelope / COSE receipt), keyed by
	// identityId, plus the reverse join to currently-linked agents.
	r.Get("/v1/identities/{identityId}", h.GetIdentityBadge)
	r.Get("/v1/identities/{identityId}/audit", h.GetIdentityAudit)
	r.Get("/v1/identities/{identityId}/receipt", h.GetIdentityReceipt)
	r.Get("/v1/identities/{identityId}/agents", h.GetIdentityAgents)

	// Log metadata (JSON variants). Reference swagger §310-461.
	r.Get("/v1/log/checkpoint", h.GetCheckpointJSON)
	r.Get("/v1/log/checkpoint/history", h.GetCheckpointHistory)
	r.Get("/v1/log/schema/{version}", h.GetSchema)

	// C2SP tlog-tiles routes at root. Reference swagger §470-716.
	// Tessera's POSIX layout places `checkpoint` + `tile/` directly
	// under tileRoot, so an http.Dir file server at that root serves
	// all four route families transparently:
	//
	//   /checkpoint                    → <tileRoot>/checkpoint
	//   /tile/<level>/<index>          → <tileRoot>/tile/<level>/<index>
	//   /tile/<level>/<index>.p/<w>    → <tileRoot>/tile/<level>/<index>.p/<w>
	//   /tile/entries/<index>[.p/<w>]  → <tileRoot>/tile/entries/<index>[.p/<w>]
	//
	// /root-keys is a handler (not a file) because it's rendered
	// fresh at startup from the KeyManager's public keys.
	r.Get("/root-keys", h.GetRootKeys)
	tileFS := http.FileServer(http.Dir(tileRoot))
	r.Method(http.MethodGet, "/checkpoint", tileFS)
	r.Method(http.MethodGet, "/tile/*", tileFS)
}

// AppendEventV1 handles POST /v1/internal/agents/event — ingest for
// V1-schema producer events. Exact path match with the reference TL.
//
// AppendEventV2 handles POST /v2/internal/agents/event — ingest for
// V2-schema producer events (ans-only, emitted by the RA's `/v2/*`
// routes).
//
// Contract (both):
//
//   - Body is the JCS-canonicalized producer-event JSON — not an
//     envelope; the TL wraps. Max 256 KiB.
//   - X-Signature header is a detached JWS over the body, signed by
//     the producer (RA). Missing → 422 NO_PRODUCER_SIGNATURE.
//
// The handler does no JSON decoding — the raw bytes go straight to the
// service so canonicalization happens exactly once, at the sig-verify
// boundary. The version guard lives one layer down, inside the
// codec's ParseAndBuild (a body whose `eventType` can't be parsed as
// the target schema's enum fails validation and returns 422).

// AppendEventV1 is the V1 ingest entrypoint.
func (h *Handlers) AppendEventV1(w http.ResponseWriter, r *http.Request) {
	h.appendEvent(w, r, h.log.AppendV1)
}

// AppendEventV2 is the V2 ingest entrypoint.
func (h *Handlers) AppendEventV2(w http.ResponseWriter, r *http.Request) {
	h.appendEvent(w, r, h.log.AppendV2)
}

// AppendEventIdentity is the identity-family ingest entrypoint —
// POST /v1/internal/identities/event. Same contract as the agent
// lanes (raw inner-event body + X-Signature detached JWS, 256 KiB
// cap); the identity codec enforces the IDENTITY_* enum and the
// identityId keyspace.
func (h *Handlers) AppendEventIdentity(w http.ResponseWriter, r *http.Request) {
	h.appendEvent(w, r, h.log.AppendIdentity)
}

// appendEvent is the shared body-read / response-shape glue; the
// passed-in `appendFn` picks which LogService path runs.
func (h *Handlers) appendEvent(
	w http.ResponseWriter, r *http.Request,
	appendFn func(ctx context.Context, in service.AppendInput) (*service.AppendResult, error),
) {
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024) // 256 KiB
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// http.MaxBytesReader surfaces oversize reads as
		// *http.MaxBytesError; map that to 413 Payload Too Large
		// per RFC 9110. Other I/O errors stay 422.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writePayloadTooLarge(w, maxErr.Limit)
			return
		}
		writeError(w, domain.NewValidationError("BAD_BODY", "failed to read request body: "+err.Error()))
		return
	}
	producerSig := r.Header.Get("X-Signature")

	res, err := appendFn(r.Context(), service.AppendInput{
		RawBody:           body,
		ProducerSignature: producerSig,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	message := "Event logged successfully"
	if res.Duplicate {
		message = "Event already logged"
	}
	writeJSON(w, http.StatusOK, appendResponse{
		LogID:     res.LogID,
		Message:   message,
		Success:   true,
		LeafIndex: res.LeafIndex,
		LeafHash:  encodeHex(res.LeafHash[:]),
		Duplicate: res.Duplicate,
		TreeSize:  res.TreeSize,
	})
}

// GetBadge handles GET /v1/agents/{agentId}. Returns the
// reference-shaped TransparencyLog JSON: merkleProof, payload (the
// V1 envelope's payload piece), schemaVersion, signature (TL
// attestation), status — plus the computed identities[] join (the
// agent's currently-linked verified identities, decorated with each
// identity's current stream state). The join is read-time: rotation
// and revocation on the identity stream are visible here immediately
// with zero agent-stream writes.
func (h *Handlers) GetBadge(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		writeError(w, domain.NewValidationError("MISSING_AGENT_ID", "agentId is required"))
		return
	}
	tl, err := h.badge.Get(r.Context(), agentID)
	if err != nil {
		writeError(w, err)
		return
	}
	if h.identityBadge != nil {
		identities, jerr := h.identityBadge.LinkedIdentitiesForAgent(r.Context(), agentID)
		if jerr != nil {
			writeError(w, jerr)
			return
		}
		tl.Identities = identities
	}
	writeJSON(w, http.StatusOK, tl)
}

// GetAgentIdentities handles GET /v1/agents/{agentId}/identities —
// the computed list of identities currently linked to the agent.
// Identical entries to the badge's identities[] field, served alone
// for callers who don't need the full badge.
func (h *Handlers) GetAgentIdentities(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		writeError(w, domain.NewValidationError("MISSING_AGENT_ID", "agentId is required"))
		return
	}
	identities, err := h.identityBadge.LinkedIdentitiesForAgent(r.Context(), agentID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"identities": identities})
}

// GetAgentIdentityHistory handles
// GET /v1/agents/{agentId}/identities/history — the link/unlink
// events that ever named this agent, in the standard audit envelope
// (each record a TransparencyLog), filtered through the agent index.
// Past and present associations fall out of reading those events;
// current state is the computed identities[] join.
func (h *Handlers) GetAgentIdentityHistory(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		writeError(w, domain.NewValidationError("MISSING_AGENT_ID", "agentId is required"))
		return
	}
	limit, offset := parsePagination(r)
	records, err := h.identityBadge.LinkHistoryForAgent(r.Context(), agentID, limit, offset)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

// GetIdentityBadge handles GET /v1/identities/{identityId} — the
// identity badge: latest sealed identity event + inclusion proof +
// computed status (VERIFIED | REVOKED).
func (h *Handlers) GetIdentityBadge(w http.ResponseWriter, r *http.Request) {
	identityID := chi.URLParam(r, "identityId")
	if identityID == "" {
		writeError(w, domain.NewValidationError("MISSING_IDENTITY_ID", "identityId is required"))
		return
	}
	tl, err := h.identityBadge.Get(r.Context(), identityID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tl)
}

// GetIdentityAudit handles GET /v1/identities/{identityId}/audit —
// the identity's full event chain in the same audit envelope as the
// agent audit ({ records: [TransparencyLog, ...] }).
func (h *Handlers) GetIdentityAudit(w http.ResponseWriter, r *http.Request) {
	identityID := chi.URLParam(r, "identityId")
	if identityID == "" {
		writeError(w, domain.NewValidationError("MISSING_IDENTITY_ID", "identityId is required"))
		return
	}
	limit, offset := parsePagination(r)
	records, err := h.identityBadge.Audit(r.Context(), identityID, limit, offset)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

// GetIdentityReceipt handles GET /v1/identities/{identityId}/receipt
// — a SCITT COSE_Sign1 receipt for the identity's latest sealed
// event. Same machinery, content type, and 503 retry semantics as
// the agent receipt.
func (h *Handlers) GetIdentityReceipt(w http.ResponseWriter, r *http.Request) {
	identityID := chi.URLParam(r, "identityId")
	if identityID == "" {
		writeError(w, domain.NewValidationError("MISSING_IDENTITY_ID", "identityId is required"))
		return
	}
	rec, err := h.receipt.ForIdentity(r.Context(), identityID)
	if err != nil {
		if errors.Is(err, service.ErrLeafNotYetCovered) {
			w.Header().Set("Retry-After", "2")
			writeJSON(w, http.StatusServiceUnavailable, problem{
				Type:   "about:blank",
				Title:  "Receipt Not Yet Available",
				Status: http.StatusServiceUnavailable,
				Code:   "TL_LEAF_UNCOMMITTED",
				Detail: "leaf committed but no signed checkpoint yet covers it; retry after the Retry-After delay",
			})
			return
		}
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", rec.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(rec.Bytes)))
	w.WriteHeader(http.StatusOK)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	// Binary COSE_Sign1 receipt (application/scitt-receipt+cose); not HTML, no user-controlled input.
	_, _ = w.Write(rec.Bytes) //nolint:gosec // G705: binary receipt body, no XSS surface
}

// GetIdentityAgents handles GET /v1/identities/{identityId}/agents —
// the reverse join: the agents this identity currently links to,
// each decorated with its own computed badge status so a reader
// checks both ends of the link in one response.
func (h *Handlers) GetIdentityAgents(w http.ResponseWriter, r *http.Request) {
	identityID := chi.URLParam(r, "identityId")
	if identityID == "" {
		writeError(w, domain.NewValidationError("MISSING_IDENTITY_ID", "identityId is required"))
		return
	}
	agents, err := h.identityBadge.LinkedAgentsForIdentity(r.Context(), identityID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

// GetAudit handles GET /v1/agents/{agentId}/audit. Matches the
// reference TransparencyLogAudit shape — { records: [TransparencyLog, ...] }.
func (h *Handlers) GetAudit(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		writeError(w, domain.NewValidationError("MISSING_AGENT_ID", "agentId is required"))
		return
	}
	limit, offset := parsePagination(r)
	records, err := h.badge.Audit(r.Context(), agentID, limit, offset)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records": records,
	})
}

// GetReceipt handles GET /v1/agents/{agentId}/receipt.
//
// Returns a SCITT COSE_Sign1 receipt as binary CBOR bytes with
// Content-Type `application/scitt-receipt+cose`. The body is not
// JSON — it is the CBOR-encoded COSE_Sign1 tagged structure (tag
// 18) containing the inclusion proof and ES256 signature over the
// event's canonical bytes.
//
// When the event has been appended but no checkpoint yet covers it, the
// handler returns 503 Service Unavailable with a Retry-After header.
// This matches RFC 7231 guidance and gives clients a cheap retry loop.
func (h *Handlers) GetReceipt(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		writeError(w, domain.NewValidationError("MISSING_AGENT_ID", "agentId is required"))
		return
	}
	rec, err := h.receipt.ForAgent(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, service.ErrLeafNotYetCovered) {
			w.Header().Set("Retry-After", "2")
			writeJSON(w, http.StatusServiceUnavailable, problem{
				Type:   "about:blank",
				Title:  "Receipt Not Yet Available",
				Status: http.StatusServiceUnavailable,
				Code:   "TL_LEAF_UNCOMMITTED",
				Detail: "leaf committed but no signed checkpoint yet covers it; retry after the Retry-After delay",
			})
			return
		}
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", rec.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(rec.Bytes)))
	w.WriteHeader(http.StatusOK)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	// Binary COSE_Sign1 receipt (application/scitt-receipt+cose); not HTML, no user-controlled input.
	_, _ = w.Write(rec.Bytes) //nolint:gosec // G705: binary receipt body, no XSS surface
}

// GetStatusToken handles GET /v1/agents/{agentId}/status-token.
//
// Returns a signed COSE_Sign1 status token (CBOR tag 18) carrying
// the agent's current lifecycle state plus enough identity data
// (cert fingerprints, metadata hashes) for verifiers to check a
// connection without hitting the badge endpoint. Behaves like OCSP
// stapling for agents.
//
// Response codes mirror reference swagger §283-308:
//
//	200 OK                         — binary CBOR, application/ans-status-token+cbor
//	404 Not Found                  — no events exist for the agent
//	410 Gone                       — agent in a terminal state (EXPIRED / REVOKED)
//	501 Not Implemented            — status tokens disabled on this instance
//
// A "disabled" deployment is one where the operator did not wire a
// StatusTokenService (e.g., they don't want to hold a third signing
// key). 501 tells clients to stop trying and fall back to the badge.
func (h *Handlers) GetStatusToken(w http.ResponseWriter, r *http.Request) {
	if h.statusToken == nil {
		// 501 — feature flag off. The reference uses this code
		// (swagger §305) to distinguish "your deployment intentionally
		// disabled this" from "the server failed".
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"type":"about:blank","title":"Not Implemented","status":501,"code":"STATUS_TOKENS_DISABLED","detail":"status tokens not enabled on this instance"}`))
		return
	}
	agentID := chi.URLParam(r, "agentId")
	if agentID == "" {
		writeError(w, domain.NewValidationError("MISSING_AGENT_ID", "agentId is required"))
		return
	}
	tok, err := h.statusToken.ForAgent(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, service.ErrStatusTokenNotIssued) {
			// 410 Gone — terminal state, stop asking.
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"type":"about:blank","title":"Gone","status":410,"code":"AGENT_TERMINAL","detail":"status tokens are not issued for terminal-state agents"}`))
			return
		}
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", tok.ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(tok.Bytes)))
	w.WriteHeader(http.StatusOK)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	// Binary COSE_Sign1 status token (application/ans-status-token+cbor); not HTML.
	_, _ = w.Write(tok.Bytes) //nolint:gosec // G705: binary token body, no XSS surface
}

// GetRootKeys handles GET /root-keys.
//
// Returns the active TL verifier public keys in sumdb-note
// verification-line format — one line per key:
//
//	<origin>+<keyhash-hex>+<base64(0x02 || SPKI-DER)>\n
//
// served as text/plain. Matches the reference TL's
// `GetRootVerificationKeys` controller shape. Verifiers call this
// once at session start and cache the result; rotation is expressed
// by adding a new line while the old one is still trusted, not by
// mutating the response. The 4-byte keyhash embedded in each line
// gives verifiers an O(1) `kid`-to-key lookup against COSE receipts
// and checkpoint signatures. (See cmd/ans-tl/main.go where the body
// is pre-rendered at startup.)
func (h *Handlers) GetRootKeys(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(h.rootKeysBody)))
	w.WriteHeader(http.StatusOK)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	// Operator-owned PEM-encoded root public keys, served as text/plain; no user input, not HTML.
	_, _ = w.Write(h.rootKeysBody)
}

// GetCheckpointJSON handles GET /v1/log/checkpoint — the
// JSON-encoded view of the current checkpoint.
//
// The raw sumdb-note bytes are served at /checkpoint via the
// file-server mount (matches C2SP tlog-tiles conventions + the
// reference TL's root-level `/checkpoint` path). This endpoint
// is the reference's `/v1/log/checkpoint` JSON shape byte-for-byte.
func (h *Handlers) GetCheckpointJSON(w http.ResponseWriter, r *http.Request) {
	if h.checkpoint == nil {
		writeError(w, domain.NewInternalError("CHECKPOINT_DISABLED",
			"checkpoint service not configured", nil))
		return
	}
	cv, err := h.checkpoint.Latest(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, mapCheckpoint(cv))
}

// GetCheckpointHistory handles GET /v1/log/checkpoint/history.
// Accepts reference filter params (limit, offset, fromSize, toSize,
// since, order); returns CheckpointHistoryResponse shape (§1335).
func (h *Handlers) GetCheckpointHistory(w http.ResponseWriter, r *http.Request) {
	if h.checkpoint == nil {
		writeError(w, domain.NewInternalError("CHECKPOINT_DISABLED",
			"checkpoint service not configured", nil))
		return
	}
	in, err := parseHistoryInput(r)
	if err != nil {
		writeError(w, err)
		return
	}
	page, err := h.checkpoint.History(r.Context(), *in)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, mapCheckpointHistory(page))
}

// GetSchema handles GET /v1/log/schema/{version}.
//
// Returns the embedded JSON schema describing the V{n} envelope
// shape, byte-for-byte, with Content-Type: application/json. 404
// if the version string isn't one we bundle.
func (h *Handlers) GetSchema(w http.ResponseWriter, r *http.Request) {
	if h.schema == nil {
		writeError(w, domain.NewInternalError("SCHEMA_DISABLED",
			"schema service not configured", nil))
		return
	}
	version := chi.URLParam(r, "version")
	if version == "" {
		writeError(w, domain.NewValidationError("MISSING_VERSION", "version is required"))
		return
	}
	body, err := h.schema.Get(r.Context(), version)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	// Embedded JSON schema bytes (application/json) keyed by a validated version param; not HTML.
	_, _ = w.Write(body) //nolint:gosec // G705: embedded JSON, no XSS surface
}

// ----- DTOs & helpers -----

// appendResponse is the JSON returned on successful ingest. The first
// three fields (logId, message, success) match the reference TL's
// AgentEventResponse byte-for-byte so reference-built clients decode
// ours unchanged. The remaining fields (leafIndex, leafHashHex,
// duplicate, treeSize) are ans-specific additions that expose the
// Merkle-tree position to callers who want to fetch a receipt without
// a second round-trip; reference clients ignore unknown JSON fields.
type appendResponse struct {
	LogID     string `json:"logId,omitempty"`
	Message   string `json:"message,omitempty"`
	Success   bool   `json:"success,omitempty"`
	LeafIndex uint64 `json:"leafIndex"`
	LeafHash  string `json:"leafHashHex"`
	Duplicate bool   `json:"duplicate"`
	TreeSize  uint64 `json:"treeSize"`
}

// parsePagination extracts safe limit/offset from query params.
func parsePagination(r *http.Request) (int, int) {
	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

// writeJSON / writeError mirror the RA handler helpers; duplicated here
// to keep the TL package dependency-free on the RA handler.

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code,omitempty"`
}

func writeError(w http.ResponseWriter, err error) {
	p := mapError(err)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// writePayloadTooLarge emits a 413 RFC-7807 problem response. Used
// for the oversize-body case so we don't dilute 422 (validation) with
// what's really a transport-layer failure.
func writePayloadTooLarge(w http.ResponseWriter, limitBytes int64) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_ = json.NewEncoder(w).Encode(problem{
		Type:   "about:blank",
		Title:  "Payload Too Large",
		Status: http.StatusRequestEntityTooLarge,
		Code:   "BODY_TOO_LARGE",
		Detail: fmt.Sprintf("request body exceeds %d-byte limit", limitBytes),
	})
}

func mapError(err error) problem {
	var de *domain.Error
	if errors.As(err, &de) {
		return problem{
			Type:   "about:blank",
			Title:  titleForCause(de.Cause),
			Status: statusForCause(de.Cause),
			Detail: de.Message,
			Code:   de.Code,
		}
	}
	return problem{Type: "about:blank", Title: "Internal Server Error", Status: 500, Detail: err.Error()}
}

func statusForCause(cause error) int {
	switch {
	case errors.Is(cause, domain.ErrValidation):
		return http.StatusUnprocessableEntity
	case errors.Is(cause, domain.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(cause, domain.ErrConflict):
		return http.StatusConflict
	case errors.Is(cause, domain.ErrInvalidState):
		return http.StatusConflict
	case errors.Is(cause, domain.ErrUnauthorized):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

func titleForCause(cause error) string {
	switch {
	case errors.Is(cause, domain.ErrValidation):
		return "Validation Failed"
	case errors.Is(cause, domain.ErrNotFound):
		return "Not Found"
	case errors.Is(cause, domain.ErrConflict):
		return "Conflict"
	case errors.Is(cause, domain.ErrInvalidState):
		return "Invalid State"
	case errors.Is(cause, domain.ErrUnauthorized):
		return "Forbidden"
	default:
		return "Internal Server Error"
	}
}

func encodeHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}
