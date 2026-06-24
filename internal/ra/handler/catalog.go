package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/godaddy/ans/internal/catalog"
	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/ra/service"
)

// catalogDocumentMediaType is the AI Catalog document content type. A
// bare CatalogEntry is plain application/json; a catalog *document*
// (host-complete per-host file, and later the export) is this type.
const catalogDocumentMediaType = "application/ai-catalog+json"

// CatalogHandler serves the per-agent AI Catalog artifact (IMPL §6). Its
// routes are owner-scoped (ReadOwnership middleware), not public: the bare
// CatalogEntry is the registrant's own view of how their agent will appear
// in a catalog. The public, crawlable surface is the population export
// (a later slice) and the well-known per-host document an AHP publishes —
// not these agent-keyed routes.
type CatalogHandler struct {
	svc *service.RegistrationService
}

// NewCatalogHandler constructs a CatalogHandler.
func NewCatalogHandler(svc *service.RegistrationService) *CatalogHandler {
	return &CatalogHandler{svc: svc}
}

// CatalogEntry handles GET /v2/ans/agents/{agentId}/catalog-entry. It
// returns the agent's CatalogEntry (§3) as application/json, or 422
// NOT_CATALOG_ELIGIBLE when the registration is versionless or carries no
// A2A/MCP endpoint with a policy-passing metaDataUrl (§3.6). Ownership is
// enforced by the ReadOwnership middleware, which 404s a registration the
// caller does not own.
func (h *CatalogHandler) CatalogEntry(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	res, err := h.svc.GetByAgentID(r.Context(), agentID)
	if err != nil {
		WriteError(w, err)
		return
	}
	// GetByAgentID returns endpoints as a sibling slice; the catalog
	// generator reads them off the aggregate.
	res.Registration.Endpoints = res.Endpoints

	entry, err := catalog.BuildEntry(res.Registration, catalog.Options{
		TLPublicBaseURL: h.svc.TLPublicBaseURL(),
	})
	if err != nil {
		var notEligible *catalog.NotEligibleError
		if errors.As(err, &notEligible) {
			WriteError(w, domain.NewValidationError("NOT_CATALOG_ELIGIBLE", notEligible.Error()))
			return
		}
		WriteError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, entry)
}

// HostCatalog handles GET /v2/ans/agents/{agentId}/ai-catalog. It returns
// the per-host AI Catalog document (§4) for the agent's host — the file an
// AHP publishes verbatim at /.well-known/ai-catalog.json. Owner-scoped
// (ReadOwnership middleware): the caller proves ownership of the keying
// agent, and the document then lists that owner's ACTIVE catalog-eligible
// agents on the host. Scoping the body to the owner — not just the route
// key — is what keeps one owner from seeing another owner's agents on a
// shared host (HostRegistrations §). The response is
// application/ai-catalog+json with an ETag, and honors If-None-Match with
// 304 (§6.3).
func (h *CatalogHandler) HostCatalog(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	res, err := h.svc.GetByAgentID(r.Context(), agentID)
	if err != nil {
		WriteError(w, err)
		return
	}
	host := res.Registration.AnsName.AgentHost()

	// ReadOwnership has verified the caller owns the keying agent, so its
	// OwnerID is the authenticated owner — use it to scope the document.
	regs, err := h.svc.HostRegistrations(r.Context(), res.Registration.OwnerID, host)
	if err != nil {
		WriteError(w, err)
		return
	}
	doc := catalog.BuildHostDocument(host, regs, catalog.Options{
		TLPublicBaseURL: h.svc.TLPublicBaseURL(),
	})
	writeCatalogDocument(w, r, doc)
}

// writeCatalogDocument serializes a catalog document once, derives a
// strong ETag (SHA-256 of the exact bytes), and writes it as
// application/ai-catalog+json. A matching If-None-Match short-circuits to
// 304 Not Modified with no body (§6.3). The body is marshalled with the
// standard library (HTML-escaping on, §3.8) — never the JCS marshaller.
func writeCatalogDocument(w http.ResponseWriter, r *http.Request, doc catalog.Document) {
	body, err := json.Marshal(doc)
	if err != nil {
		WriteError(w, domain.NewInternalError("CATALOG_MARSHAL", "marshal catalog document", err))
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`

	w.Header().Set("ETag", etag)
	// Owner-scoped response: revalidate every time, never store in a
	// shared cache. The ETag makes revalidation a cheap 304.
	w.Header().Set("Cache-Control", "private, no-cache")

	if ifNoneMatch(r, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", catalogDocumentMediaType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// ifNoneMatch reports whether the request's If-None-Match header matches
// etag (RFC 9110 §13.1.2): "*" matches anything, otherwise any of the
// comma-separated entity tags equal to etag (weak comparison — the W/
// prefix is ignored, which is correct for the cache-validation use here).
func ifNoneMatch(r *http.Request, etag string) bool {
	header := r.Header.Get("If-None-Match")
	if header == "" {
		return false
	}
	if strings.TrimSpace(header) == "*" {
		return true
	}
	target := strings.TrimPrefix(etag, "W/")
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if strings.TrimPrefix(candidate, "W/") == target {
			return true
		}
	}
	return false
}
