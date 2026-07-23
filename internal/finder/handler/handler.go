package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/finder/index"
	"github.com/agentnameservice/ans/internal/finder/project"
)

// rateLimitRetryAfterSeconds is the Retry-After hint (seconds) returned
// with a 429 so a well-behaved client backs off rather than hot-retrying.
const rateLimitRetryAfterSeconds = 1

// maxRequestBytes caps the JSON body the discovery routes will read, so a
// hostile client cannot push an unbounded body at an anonymous endpoint.
const maxRequestBytes = 1 << 20 // 1 MiB

// defaultFacetLimit is the spec default for a facet's bucket cap when the
// request omits limit (ARDS §7.3).
const defaultFacetLimit = 20

// Config tunes the handler.
type Config struct {
	// SourceURL is the Finder's own base URL, echoed as a result's
	// `source` (ARDS §7.2). For a locally-indexed entry this is always the
	// Finder itself.
	SourceURL string
	// MaxPageSize caps the per-page result count (spec default 10, max
	// 100); a request asking for more is clamped to this.
	MaxPageSize int
	// DefaultPageSize is used when a search omits pageSize (spec default 10).
	DefaultPageSize int
	// StaleBound is how far behind the last successful poll the index may
	// fall before responses carry staleSince. Zero disables the signal.
	StaleBound time.Duration
	// Referrals are catalog entries describing other registries, returned
	// in `referrals` federation mode. Config-only; the Finder never
	// auto-follows them.
	Referrals []project.Entry
}

// Handler serves the Finder's discovery routes.
type Handler struct {
	idx index.Catalog
	cfg Config
	rl  *RateLimiter
	log zerolog.Logger
	now func() time.Time
}

// New constructs a Handler. rl guards the unauthenticated routes; now is
// injected for deterministic tests (nil → time.Now).
func New(idx index.Catalog, cfg Config, rl *RateLimiter, log zerolog.Logger, now func() time.Time) *Handler {
	if now == nil {
		now = time.Now
	}
	if cfg.MaxPageSize <= 0 {
		cfg.MaxPageSize = 100
	}
	if cfg.DefaultPageSize <= 0 {
		cfg.DefaultPageSize = 10
	}
	return &Handler{idx: idx, cfg: cfg, rl: rl, log: log, now: now}
}

// NewRateLimiter exposes the package's token-bucket limiter to the
// binary's wiring without leaking the type. rate/burst <= 0 disables it.
func NewRateLimiter(rate, burst float64) *RateLimiter {
	return newRateLimiter(rate, burst, nil)
}

// Mount registers the discovery and operator routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/v1/search", h.Search)
	r.Post("/v1/explore", h.Explore)
	r.Get("/v1/admin/health", h.health)
	r.Get("/v1/admin/ready", h.ready)
}

// health is liveness: the process is up and serving. It says nothing
// about whether the index has any data — it stays 200 even before the
// first poll, so an orchestrator does not kill a still-bootstrapping
// replica.
func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeOK(w, map[string]string{"status": "ok"})
}

// ready is readiness: the replica has completed at least one successful
// poll round and is serving a populated (or legitimately empty) index.
// A never-polled replica reports 503 so a load balancer does not route
// discovery traffic to it while it would only return empty results. The
// check is one cheap singleton cursor read.
func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	c, err := h.idx.Cursor(r.Context())
	if err != nil {
		h.log.Error().Err(err).Msg("finder handler: cursor read for readiness")
		writeProblem(w, Problem{
			Type:   "about:blank",
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "the finder index is not yet readable",
			Code:   codeInternalError,
		})
		return
	}
	if c.LastPollOK.IsZero() {
		writeProblem(w, Problem{
			Type:   "about:blank",
			Title:  "Service Unavailable",
			Status: http.StatusServiceUnavailable,
			Detail: "the finder has not yet completed a feed poll",
			Code:   codeInternalError,
		})
		return
	}
	writeOK(w, map[string]string{"status": "ready"})
}

// rejectRateLimited writes the 429 Problem with a Retry-After hint and
// logs a WARN so rate-limit rejections — otherwise invisible server-side
// — are observable (a sustained climb signals abuse or an undersized
// bucket). The header is set before writeProblem writes the status.
func (h *Handler) rejectRateLimited(w http.ResponseWriter, r *http.Request, route string) {
	w.Header().Set("Retry-After", strconv.Itoa(rateLimitRetryAfterSeconds))
	h.log.Warn().
		Str("route", route).
		Str("reqId", middleware.GetReqID(r.Context())).
		Msg("finder handler: request rate-limited")
	writeProblem(w, problemRateLimited())
}

// Search handles POST /v1/search.
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	if !h.rl.Allow() {
		h.rejectRateLimited(w, r, "search")
		return
	}

	var req searchRequest
	if err := decodeBody(r, &req); err != nil {
		writeProblem(w, problemInvalidArgument(err.Error()))
		return
	}

	q, federation, pageSize, err := h.validateSearch(req)
	if err != nil {
		writeProblem(w, problemInvalidArgument(err.Error()))
		return
	}

	filter := q.asIndexFilter()

	// Resolve the page offset from the token (bound to this query).
	hash := queryHash(q.Text, filter)
	offset := 0
	if req.PageToken != "" {
		tok, err := decodePageToken(req.PageToken, hash)
		if err != nil {
			writeProblem(w, problemInvalidArgument(err.Error()))
			return
		}
		// decodePageToken bounds Offset to MaxInt32, so this fits int on
		// every platform.
		//nolint:gosec // bounded to MaxInt32 by decodePageToken above
		offset = int(tok.Offset)
	}

	results, err := h.idx.Search(r.Context(), index.SearchQuery{
		Text:   q.Text,
		Filter: filter,
		Limit:  pageSize,
		Offset: offset,
	}, h.now())
	if err != nil {
		h.log.Error().Err(err).Str("reqId", middleware.GetReqID(r.Context())).
			Msg("finder handler: search")
		writeProblem(w, problemInternal())
		return
	}

	resp := h.buildSearchResponse(results, federation, hash, h.staleSince(r.Context()))
	writeOK(w, resp)
}

// Explore handles POST /v1/explore.
func (h *Handler) Explore(w http.ResponseWriter, r *http.Request) {
	if !h.rl.Allow() {
		h.rejectRateLimited(w, r, "explore")
		return
	}

	var req exploreRequest
	if err := decodeBody(r, &req); err != nil {
		writeProblem(w, problemInvalidArgument(err.Error()))
		return
	}

	q, facets, err := h.validateExplore(req)
	if err != nil {
		writeProblem(w, problemInvalidArgument(err.Error()))
		return
	}

	res, err := h.idx.Explore(r.Context(), index.ExploreQuery{
		Text:   q.Text,
		Filter: q.asIndexFilter(),
		Facets: facets,
	}, h.now())
	if err != nil {
		h.log.Error().Err(err).Str("reqId", middleware.GetReqID(r.Context())).
			Msg("finder handler: explore")
		writeProblem(w, problemInternal())
		return
	}

	writeOK(w, h.buildExploreResponse(res, h.staleSince(r.Context())))
}

// buildSearchResponse maps index results into the wire response, attaches
// the pagination token (when more pages exist), the configured referrals
// (in referrals mode), and the staleSince signal.
func (h *Handler) buildSearchResponse(results index.SearchResults, federation string, hash uint64, staleSince string) searchResponse {
	out := make([]searchResult, 0, len(results.Results))
	for _, r := range results.Results {
		out = append(out, searchResult{
			Entry:  r.Entry,
			Score:  r.Score,
			Source: h.cfg.SourceURL,
		})
	}
	resp := searchResponse{Results: out}
	if results.HasMore {
		// NextOffset is a non-negative result-set index (start+limit over a
		// counted slice), so widening to uint64 cannot overflow.
		//nolint:gosec // NextOffset is always >= 0 by construction
		resp.NextPageToken = encodePageToken(pageToken{Offset: uint64(results.NextOffset), QueryHash: hash})
	}
	// referrals mode returns local results plus the configured registry
	// entries; auto/none merge a zero-upstream set (no upstreams wired),
	// so they return only local results.
	if federation == federationReferrals && len(h.cfg.Referrals) > 0 {
		resp.Referrals = h.cfg.Referrals
	}
	resp.StaleSince = staleSince
	return resp
}

// buildExploreResponse maps index facets into the wire response.
func (h *Handler) buildExploreResponse(res index.ExploreResults, staleSince string) exploreResponse {
	facets := make(map[string]facetDTO, len(res.Facets))
	for field, f := range res.Facets {
		buckets := make([]facetBucketDTO, 0, len(f.Buckets))
		for _, b := range f.Buckets {
			buckets = append(buckets, facetBucketDTO{Value: b.Value, Count: b.Count})
		}
		facets[field] = facetDTO{Buckets: buckets, OtherCount: f.OtherCount}
	}
	return exploreResponse{
		ResultType: "facets",
		Facets:     facets,
		StaleSince: staleSince,
	}
}

// staleSince returns an RFC 3339 timestamp of the last successful poll
// when the index has fallen behind the configured StaleBound, or "" when
// the index is fresh (or the signal is disabled). A never-polled index
// reports the zero time so a client can detect "no successful ingestion
// yet". A cursor-read failure omits the signal rather than failing the
// response — the discovery answer is still useful without it.
func (h *Handler) staleSince(ctx context.Context) string {
	if h.cfg.StaleBound <= 0 {
		return ""
	}
	c, err := h.idx.Cursor(ctx)
	if err != nil {
		h.log.Warn().Err(err).Msg("finder handler: cursor read for staleness")
		return ""
	}
	if c.LastPollOK.IsZero() {
		return time.Time{}.UTC().Format(time.RFC3339)
	}
	if h.now().Sub(c.LastPollOK) > h.cfg.StaleBound {
		return c.LastPollOK.UTC().Format(time.RFC3339)
	}
	return ""
}

// decodeBody reads and strictly decodes the JSON request body. Unknown
// fields are rejected so a typo'd field name surfaces as INVALID_ARGUMENT
// rather than being silently ignored. The decoder's own error message is
// surfaced to the caller — it describes only the client's own malformed
// input (a bad type, an unknown field, a syntax position) and carries
// nothing sensitive, so it is more useful than a generic string.
func decodeBody(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("request body is not valid JSON for this operation: %w", err)
	}
	return nil
}
