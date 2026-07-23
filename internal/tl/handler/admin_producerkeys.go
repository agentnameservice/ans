package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/agentnameservice/ans/internal/domain"
	"github.com/agentnameservice/ans/internal/tl/producerkey"
)

// AdminHandlers holds the admin-route HTTP handlers for the TL.
// Currently wraps only the producer-key CRUD surface; as more admin
// routes land they'll hang off this same type so the wiring in main.go
// has a single injection point for "everything that needs admin".
type AdminHandlers struct {
	keys producerkey.AdminStore
}

// NewAdminHandlers constructs an AdminHandlers group over the given
// admin store. Passing the interface (not the concrete SQLite type)
// keeps the handler swappable — a future in-memory admin store for
// e2e tests, or a remote-API-proxy store, slots in without handler
// changes.
func NewAdminHandlers(keys producerkey.AdminStore) *AdminHandlers {
	return &AdminHandlers{keys: keys}
}

// Mount registers the admin producer-key routes under
// /internal/v1/producer-keys — matching the reference TL's
// swagger.yaml §720 byte-for-byte. Admin routes are intentionally not
// in the V2 RA spec (they're internal plumbing, not the client-facing
// API), so they keep the reference's shape. Callers are responsible
// for wrapping the router with the RequireAdmin middleware before or
// during Mount — this handler does no authentication/authorization
// itself.
//
// Routes:
//
//	POST   /internal/v1/producer-keys                      — register a new key
//	DELETE /internal/v1/producer-keys/{key_id}             — revoke
//	GET    /internal/v1/producer-keys/ra/{ra_id}           — list keys for an RA
//	GET    /internal/v1/producer-keys/{key_id}             — fetch one by key_id (ans extension)
//
// The last route is an ans-only addition used by admin tooling for
// single-record lookups; the reference does not expose it. Callers
// can achieve the same by listing by ra_id and filtering, but a
// direct-lookup route is cheaper when the caller already has the
// key_id in hand (e.g., after a CREATE).
func (h *AdminHandlers) Mount(r chi.Router) {
	r.Post("/internal/v1/producer-keys", h.CreateKey)
	r.Delete("/internal/v1/producer-keys/{key_id}", h.RevokeKey)
	r.Get("/internal/v1/producer-keys/ra/{ra_id}", h.ListByRAID)
	r.Get("/internal/v1/producer-keys/{key_id}", h.GetByKeyID)
}

// ----- DTOs -----
//
// Field names are snake_case — byte-for-byte match with the reference
// TL's swagger.yaml §1371-1513 (ProducerKeyRequest, ProducerKeyResponse,
// ProducerKeyMetadata, ProducerKeysListResponse). Admin routes are
// not part of the V2 RA spec, so there's no camelCase obligation; the
// reference shape is authoritative.

type createKeyRequest struct {
	KeyID        string    `json:"key_id"`
	PublicKeyPEM string    `json:"public_key_pem"`
	Algorithm    string    `json:"algorithm"`
	RaID         string    `json:"ra_id"`
	ValidFrom    time.Time `json:"valid_from"`
	ExpiresAt    time.Time `json:"expires_at"`
	// Metadata accepts the reference's ProducerKeyMetadata shape
	// verbatim; we stash the raw bytes so the SQLite CHECK json_valid
	// enforces shape. The reference makes environment + region
	// required but since we only persist the blob (never read it)
	// those are soft requirements here.
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// keyResponse matches the reference ProducerKeyResponse (§1411) plus
// the ProducerKeysListResponse.keys-item expansion (§1481-1508) which
// includes the write-side fields (public_key_pem, algorithm, ra_id,
// valid_from, expires_at, metadata). Using the expanded shape on both
// GET single and GET list keeps the two response bodies symmetric.
type keyResponse struct {
	KeyID        string          `json:"key_id"`
	KeyIDOpaque  string          `json:"key_id_opaque,omitempty"`
	RaIDOpaque   string          `json:"ra_id_opaque,omitempty"`
	Status       string          `json:"status"`
	Fingerprint  string          `json:"fingerprint"`
	CreatedAt    time.Time       `json:"created_at"`
	PublicKeyPEM string          `json:"public_key_pem,omitempty"`
	Algorithm    string          `json:"algorithm,omitempty"`
	RaID         string          `json:"ra_id,omitempty"`
	ValidFrom    time.Time       `json:"valid_from,omitzero"`
	ExpiresAt    time.Time       `json:"expires_at,omitzero"`
	RevokedAt    *time.Time      `json:"revoked_at,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
}

// keyListResponse matches reference ProducerKeysListResponse (§1471).
type keyListResponse struct {
	Keys       []keyResponse `json:"keys"`
	TotalCount int64         `json:"total_count"`
}

// recordToDTO is the single point where database records turn into
// wire bytes — kept in one place so future fields (opaque IDs,
// rotation_of pointers, …) only need one edit.
func recordToDTO(r *producerkey.Record) keyResponse {
	dto := keyResponse{
		KeyID:        r.KeyID,
		KeyIDOpaque:  r.KeyIDOpaque,
		RaIDOpaque:   r.RaIDOpaque,
		Status:       r.Status,
		Fingerprint:  r.Fingerprint,
		CreatedAt:    r.CreatedAt,
		PublicKeyPEM: r.PublicKeyPEM,
		Algorithm:    r.Algorithm,
		RaID:         r.RaID,
		ValidFrom:    r.ValidFrom,
		ExpiresAt:    r.ExpiresAt,
	}
	if !r.RevokedAt.IsZero() {
		rev := r.RevokedAt
		dto.RevokedAt = &rev
	}
	if len(r.Metadata) > 0 {
		dto.Metadata = json.RawMessage(r.Metadata)
	}
	return dto
}

// ----- handlers -----

// CreateKey handles POST /internal/v1/producer-keys.
//
// Response codes mirror the reference swagger §742-776:
//
//	200 OK             — key registered, body is ProducerKeyResponse
//	409 Conflict       — key_id already exists
//	422 Unprocessable  — malformed body, invalid PEM, invalid date range
//
// The reference spec uses 200 (not 201) on create; we follow.
func (h *AdminHandlers) CreateKey(w http.ResponseWriter, r *http.Request) {
	// 32 KiB is more than enough for a PEM + a small metadata blob.
	// Larger bodies are almost certainly either confused clients or
	// attempts to exhaust memory.
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, domain.NewValidationError("BAD_BODY", "failed to read body: "+err.Error()))
		return
	}
	var req createKeyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, domain.NewValidationError("BAD_JSON", "invalid JSON body: "+err.Error()))
		return
	}

	entry := producerkey.Entry{
		KeyID:        req.KeyID,
		RaID:         req.RaID,
		Algorithm:    req.Algorithm,
		PublicKeyPEM: req.PublicKeyPEM,
		ValidFrom:    req.ValidFrom,
		ExpiresAt:    req.ExpiresAt,
		Metadata:     []byte(req.Metadata),
	}

	rec, err := h.keys.Register(r.Context(), entry)
	if err != nil {
		if errors.Is(err, producerkey.ErrDuplicateKey) {
			writeError(w, domain.NewConflictError("PRODUCER_KEY_EXISTS",
				"Producer key already exists"))
			return
		}
		if errors.Is(err, producerkey.ErrInvalidRange) {
			writeError(w, domain.NewValidationError("INVALID_DATE_RANGE",
				err.Error()))
			return
		}
		// Fingerprint-parse failure (bad PEM / private key pasted)
		// bubbles up as a plain error from the store. Map to 422 so
		// the admin sees the actionable message.
		writeError(w, domain.NewValidationError("INVALID_PUBLIC_KEY_PEM", err.Error()))
		return
	}

	writeJSON(w, http.StatusOK, recordToDTO(rec))
}

// ListByRAID handles GET /internal/v1/producer-keys/ra/{ra_id}.
//
// Reference returns 404 when no keys exist for the ra_id (§874); we
// match that behavior. An empty list suggests a typo; returning 200
// with an empty array would make such typos silent.
func (h *AdminHandlers) ListByRAID(w http.ResponseWriter, r *http.Request) {
	raID := chi.URLParam(r, "ra_id")
	if raID == "" {
		writeError(w, domain.NewValidationError("MISSING_RA_ID",
			"ra_id is required"))
		return
	}
	records, err := h.keys.ListByRAID(r.Context(), raID)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(records) == 0 {
		writeError(w, domain.NewNotFoundError("NOT_FOUND",
			"No producer keys found for this RA ID"))
		return
	}
	keys := make([]keyResponse, len(records))
	for i, rec := range records {
		keys[i] = recordToDTO(rec)
	}
	writeJSON(w, http.StatusOK, keyListResponse{
		Keys:       keys,
		TotalCount: int64(len(keys)),
	})
}

// GetByKeyID handles GET /internal/v1/producer-keys/{key_id} — an
// ans-only extension not in the reference swagger (admins typically
// list-by-ra then filter client-side). We keep it because it makes
// the demo script and admin CLIs cheaper, and maps naturally to the
// existing store method.
func (h *AdminHandlers) GetByKeyID(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "key_id")
	if keyID == "" {
		writeError(w, domain.NewValidationError("MISSING_KEY_ID", "key_id is required"))
		return
	}
	rec, err := h.keys.GetByKeyID(r.Context(), keyID)
	if err != nil {
		if errors.Is(err, producerkey.ErrNotFound) {
			writeError(w, domain.NewNotFoundError("NOT_FOUND", "producer key not found"))
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, recordToDTO(rec))
}

// RevokeKey handles DELETE /internal/v1/producer-keys/{key_id}.
//
// Returns 204 No Content on success, 404 if the key doesn't exist or
// is already revoked — matching the reference's behavior (swagger
// §800-820). Repeat DELETEs returning 404 (rather than idempotent
// 204) is intentional: the typo guardrail is worth the slight
// inconvenience.
func (h *AdminHandlers) RevokeKey(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "key_id")
	if keyID == "" {
		writeError(w, domain.NewValidationError("MISSING_KEY_ID", "key_id is required"))
		return
	}
	if err := h.keys.Revoke(r.Context(), keyID); err != nil {
		if errors.Is(err, producerkey.ErrNotFound) {
			writeError(w, domain.NewNotFoundError("NOT_FOUND",
				"Key not found or already revoked"))
			return
		}
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
