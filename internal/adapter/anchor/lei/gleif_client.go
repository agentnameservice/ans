// gleif_client.go ships a GLEIFClient that talks to the GLEIF
// Public API at api.gleif.org. The endpoint is free, public, and
// unauthenticated; production deployments may wrap it with caching,
// rate limiting, or LOU-mirror selection per anchor-0c-lei.md §3.3.
//
// The client populates the entity-status fields of GLEIFRecord
// (status, name, jurisdiction, updatedAt) from the Level 1 record
// the API returns. AttestationJWK is left empty: the GLEIF Level 1
// record does not carry an attestation key. Deployments that need
// the AttestationJWK populate it through a separate
// AttestationJWKSource composed with the Resolver (see
// attestation_source.go).
//
// vLEI Option A (self-attestation through GLEIF vLEI infrastructure)
// and Option B (LOU custom field) both ride above this client; both
// add the AttestationJWK without changing the entity-verification
// pipeline this file implements.
package lei

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// gleifAPIBaseURL is the production GLEIF Public API base. Tests
// override it via WithGLEIFBaseURL(httptest.Server.URL).
const gleifAPIBaseURL = "https://api.gleif.org/api/v1"

// GLEIFHTTPClient is the concrete GLEIFClient implementation.
type GLEIFHTTPClient struct {
	baseURL string
	http    *http.Client
}

// NewGLEIFHTTPClient returns a client pointing at the production
// GLEIF API with sensible HTTP timeouts. Production callers SHOULD
// wrap this with a caching layer (the GLEIF API rate-limits free
// callers) and a retry policy keyed on transient 5xx responses.
func NewGLEIFHTTPClient() *GLEIFHTTPClient {
	return &GLEIFHTTPClient{
		baseURL: gleifAPIBaseURL,
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// WithBaseURL returns a copy with a different base URL. Tests use
// this to point at httptest.Server.URL.
func (c *GLEIFHTTPClient) WithBaseURL(url string) *GLEIFHTTPClient {
	cp := *c
	cp.baseURL = strings.TrimRight(url, "/")
	return &cp
}

// WithHTTPClient returns a copy with a different *http.Client.
// Production callers inject a client carrying their preferred
// transport (proxy, mTLS to a corporate egress, HTTP/2 connection
// pool, observability hooks).
func (c *GLEIFHTTPClient) WithHTTPClient(h *http.Client) *GLEIFHTTPClient {
	cp := *c
	cp.http = h
	return &cp
}

// gleifLevel1Response is the subset of the GLEIF Level 1 response
// the resolver consumes. The GLEIF API returns a JSON:API envelope
// (https://jsonapi.org); fields the resolver does not need are
// ignored. See https://documenter.getpostman.com/view/7679680/SVYrrxuU
// for the full schema.
type gleifLevel1Response struct {
	Data struct {
		Type       string `json:"type"`
		ID         string `json:"id"`
		Attributes struct {
			LEI    string `json:"lei"`
			Entity struct {
				LegalName struct {
					Name     string `json:"name"`
					Language string `json:"language"`
				} `json:"legalName"`
				Status         string `json:"status"`
				LegalAddress   struct {
					Country string `json:"country"`
				} `json:"legalAddress"`
				Jurisdiction string `json:"jurisdiction"`
			} `json:"entity"`
			Registration struct {
				Status         string `json:"status"`
				LastUpdateDate string `json:"lastUpdateDate"`
			} `json:"registration"`
		} `json:"attributes"`
	} `json:"data"`
}

// LookupRecord fetches the Level 1 record for an LEI from
// api.gleif.org. Returns nil with no error when the API responds
// 404 (record not found); any other error path returns a non-nil
// error so the resolver can surface a typed failure to its caller.
func (c *GLEIFHTTPClient) LookupRecord(ctx context.Context, lei string) (*GLEIFRecord, error) {
	url := fmt.Sprintf("%s/lei-records/%s", c.baseURL, lei)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.api+json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gleif http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return nil, fmt.Errorf("gleif http %d: %s", resp.StatusCode, preview)
	}

	var decoded gleifLevel1Response
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode gleif response: %w", err)
	}
	if decoded.Data.Attributes.LEI == "" {
		return nil, errors.New("gleif response missing data.attributes.lei")
	}

	updatedAt, _ := time.Parse(time.RFC3339, decoded.Data.Attributes.Registration.LastUpdateDate)

	return &GLEIFRecord{
		LEI:          decoded.Data.Attributes.LEI,
		EntityName:   decoded.Data.Attributes.Entity.LegalName.Name,
		EntityStatus: decoded.Data.Attributes.Entity.Status,
		Jurisdiction: decoded.Data.Attributes.Entity.Jurisdiction,
		// AttestationJWK intentionally left empty; populated by a
		// separate AttestationJWKSource composed with the Resolver.
		UpdatedAt: updatedAt,
	}, nil
}
