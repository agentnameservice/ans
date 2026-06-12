package poller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/finder/feed"
)

// eventsPath is the feed route the Finder consumes (production contract
// GET /v1/agents/events).
const eventsPath = "/v1/agents/events"

// maxResponseBytes caps how much of a feed response the client reads, so
// a misbehaving or hostile feed cannot exhaust memory. 16 MiB is far
// above any realistic page.
const maxResponseBytes = 16 << 20

// HTTPFeedClient fetches feed pages over HTTP(S). It is the production
// FeedClient; tests use a fake or an httptest server behind this same
// type.
type HTTPFeedClient struct {
	baseURL string
	http    *http.Client
}

// NewHTTPFeedClient validates baseURL against the feed transport policy
// and returns a client. TLS-verified https is the sole ingestion
// integrity control, so plaintext http is permitted only when allowHTTP
// is set (a dev override); verification is never skipped. timeout bounds
// each request.
func NewHTTPFeedClient(baseURL string, allowHTTP bool, timeout time.Duration) (*HTTPFeedClient, error) {
	if err := validateFeedBaseURL(baseURL, allowHTTP); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &HTTPFeedClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		http: &http.Client{
			Timeout: timeout,
			// Refuse redirects. The feed base URL is operator-configured and
			// validated (https unless AllowHTTP); a feed that 30x-redirects is
			// a misconfiguration or an attempt to downgrade the transport
			// (https→http) or point ingestion elsewhere, so a redirect is a
			// hard error rather than something to follow.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("poller: feed redirect refused (base URL must be the final endpoint)")
			},
		},
	}, nil
}

// FetchEvents GETs one page of the feed after afterLogID with the given
// limit. A non-2xx response is an error; the body is decoded as a
// feed.EventPageResponse.
func (c *HTTPFeedClient) FetchEvents(ctx context.Context, afterLogID string, limit int) (feed.EventPageResponse, error) {
	endpoint := c.baseURL + eventsPath
	q := url.Values{}
	if afterLogID != "" {
		q.Set("lastLogId", afterLogID)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if encoded := q.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return feed.EventPageResponse{}, fmt.Errorf("poller: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return feed.EventPageResponse{}, fmt.Errorf("poller: fetch %s: %w", eventsPath, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read one byte past the cap so an over-cap body is detected explicitly
	// (rather than silently truncated into a confusing JSON-decode error).
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return feed.EventPageResponse{}, fmt.Errorf("poller: read response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return feed.EventPageResponse{}, fmt.Errorf(
			"poller: feed response exceeds the %d-byte cap", maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return feed.EventPageResponse{}, fmt.Errorf(
			"poller: feed returned %d: %s", resp.StatusCode, snippet(body))
	}

	var page feed.EventPageResponse
	if err := json.Unmarshal(body, &page); err != nil {
		return feed.EventPageResponse{}, fmt.Errorf("poller: decode response: %w", err)
	}
	return page, nil
}

// validateFeedBaseURL enforces the feed transport policy: absolute URL,
// https (or http only under the dev allowHTTP override), no userinfo,
// query, or fragment. TLS verification is always on — this client never
// configures an InsecureSkipVerify transport, so https here means a
// verified chain.
func validateFeedBaseURL(raw string, allowHTTP bool) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("poller: feed base URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("poller: feed base URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("poller: feed base URL %q is not absolute", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return fmt.Errorf("poller: feed base URL %q uses http but AllowHTTP is off", raw)
		}
	default:
		return fmt.Errorf("poller: feed base URL %q scheme %q not permitted", raw, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("poller: feed base URL %q carries userinfo", raw)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("poller: feed base URL %q carries a query string", raw)
	}
	if u.Fragment != "" {
		return fmt.Errorf("poller: feed base URL %q carries a fragment", raw)
	}
	return nil
}

// snippet returns a short, single-line prefix of a response body for
// error messages, so a large or multi-line error page does not flood the
// log.
func snippet(b []byte) string {
	const maxLen = 200
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}
