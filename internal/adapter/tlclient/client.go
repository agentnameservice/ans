// Package tlclient is the HTTP client the RA uses to POST signed
// events to the Transparency Log. It's the client half of the
// outbox-delivery path; the TL's ingest handlers are the server half.
//
// The TL exposes two ingest lanes with identical wire contracts but
// different envelope schemas:
//
//   - `POST /v1/internal/agents/event` — V1 schema (reference parity)
//   - `POST /v2/internal/agents/event` — V2 schema (ans extension)
//
// The worker (internal/ra/outbox) calls Append once per claimed
// outbox row, passing the row's recorded `schemaVersion`; this
// package picks the matching URL. All other wire details (headers,
// response-code classification, timeouts, error typing) are
// version-agnostic.
//
// Error typing is deliberately structured because the worker's
// retry logic depends on it:
//
//   - TransientError — transport failure, 5xx, 429. Worker retries
//     with capped exponential backoff.
//   - PermanentError — 4xx (except 429). Worker marks the row failed
//     with long backoff and logs at ERROR so operators see it.
//   - nil (on success) — 200 OK (reference shape; `duplicate: true`
//     on idempotent retry). Legacy 201 Created is also accepted so
//     clients continue to work against older-build TLs.
package tlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/domain"
)

// AppendResult is the parsed success response from the TL's ingest
// endpoint — same JSON shape on both V1 and V2 lanes. `LogID`,
// `Message`, and `Success` mirror the reference TL's
// AgentEventResponse; the remaining fields are ans-specific
// additions carrying the Merkle-tree position.
type AppendResult struct {
	LogID     string `json:"logId"`
	Message   string `json:"message"`
	Success   bool   `json:"success"`
	LeafIndex uint64 `json:"leafIndex"`
	LeafHash  string `json:"leafHashHex"`
	Duplicate bool   `json:"duplicate"`
	TreeSize  uint64 `json:"treeSize"`
}

// ingestPathForVersion returns the URL path the TL exposes for the
// given envelope schema version. Allow-listed: unrecognized
// versions error rather than defaulting silently, because a wrong
// lane means the TL will reject the body with a 422 that looks like
// a signature failure — very hard to debug.
//
// "IDENTITY" is the third lane: the IDENTITY_* event family, keyed
// by identityId, riding the same producer-signature discipline into
// the same Merkle tree via its own ingest route.
func ingestPathForVersion(schemaVersion string) (string, error) {
	switch schemaVersion {
	case "V1":
		return "/v1/internal/agents/event", nil
	case "V2":
		return "/v2/internal/agents/event", nil
	case "IDENTITY":
		return "/v1/internal/identities/event", nil
	default:
		return "", fmt.Errorf("tlclient: unknown schemaVersion %q (want V1, V2, or IDENTITY)", schemaVersion)
	}
}

// Client POSTs signed events to the TL.
//
// One Client serves the whole outbox worker; its underlying
// *http.Client is safe for concurrent use.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
	logger  zerolog.Logger
}

// New constructs a Client. baseURL is the TL's listen URL (no
// trailing slash); apiKey is the static bearer token the TL accepts.
func New(baseURL, apiKey string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: timeout},
		logger:  zerolog.Nop(),
	}
}

// Append POSTs the given inner-event canonical bytes to the TL's
// ingest lane for the named schema version, with the producer's
// detached-JWS signature in the X-Signature header.
//
// schemaVersion must be "V1" or "V2" — it selects the URL path
// (`/v1/internal/agents/event` vs `/v2/internal/agents/event`).
//
// The caller is responsible for the outbox-replay invariant: `body`
// and `producerSig` must be the exact bytes that were originally
// signed and persisted. Regenerating either on retry would break TL
// dedup (which hashes `body`) and invalidate `producerSig`.
func (c *Client) Append(ctx context.Context, schemaVersion string, body []byte, producerSig string) (*AppendResult, error) {
	if len(body) == 0 {
		return nil, errors.New("tlclient: body is empty")
	}
	if producerSig == "" {
		return nil, errors.New("tlclient: producer signature is empty")
	}
	path, err := ingestPathForVersion(schemaVersion)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("tlclient: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("X-Signature", producerSig)

	resp, err := c.http.Do(req)
	if err != nil {
		// Network / DNS / timeout — always retryable.
		return nil, &TransientError{
			Status:  0,
			Message: fmt.Sprintf("transport: %v", err),
			Cause:   err,
		}
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	switch {
	case resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK:
		// Both are success: 201 = new leaf, 200 = idempotent retry
		// the TL already saw. In either case the event is durable
		// in the log and we can mark the outbox row sent.
		var out AppendResult
		if err := json.Unmarshal(rawBody, &out); err != nil {
			return nil, fmt.Errorf("tlclient: parse %d response: %w", resp.StatusCode, err)
		}
		return &out, nil

	case resp.StatusCode == http.StatusTooManyRequests:
		// Rate-limited — retryable with backoff.
		return nil, &TransientError{
			Status:  resp.StatusCode,
			Message: "rate limited",
			Body:    string(rawBody),
		}

	case resp.StatusCode >= 500:
		// Server error — retryable.
		return nil, &TransientError{
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("server error %d", resp.StatusCode),
			Body:    string(rawBody),
		}

	case resp.StatusCode >= 400:
		// Client error — permanent. Most commonly 422 from producer-
		// signature verification failure, RAID mismatch, invalid
		// event, etc. Retrying won't help until the TL's trust
		// store or the outbox row itself is fixed.
		return nil, &PermanentError{
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("client error %d", resp.StatusCode),
			Body:    string(rawBody),
		}

	default:
		// 1xx / 3xx are unexpected from this endpoint. Treat as
		// transient so we retry; an operator investigating logs
		// will see the oddity.
		return nil, &TransientError{
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("unexpected status %d", resp.StatusCode),
			Body:    string(rawBody),
		}
	}
}

// TransientError indicates the request should be retried later.
type TransientError struct {
	Status  int
	Message string
	Body    string
	Cause   error
}

// Error implements error.
func (e *TransientError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("tlclient: transient %s (status %d): %s", e.Message, e.Status, e.Body)
	}
	return fmt.Sprintf("tlclient: transient %s", e.Message)
}

// Unwrap returns the cause so errors.Is(err, net.ErrClosed) etc. works.
func (e *TransientError) Unwrap() error { return e.Cause }

// PermanentError indicates the request will never succeed in its
// current form. The worker marks the outbox row failed with long
// backoff and logs at ERROR.
type PermanentError struct {
	Status  int
	Message string
	Body    string
}

// Error implements error.
func (e *PermanentError) Error() string {
	return fmt.Sprintf("tlclient: permanent %s (status %d): %s", e.Message, e.Status, e.Body)
}

// IsTransient reports whether an error returned by Append is
// retryable. Convenience wrapper over errors.As for the worker.
func IsTransient(err error) bool {
	var t *TransientError
	return errors.As(err, &t)
}

// IsPermanent reports whether an error returned by Append is a
// permanent client error.
func IsPermanent(err error) bool {
	var p *PermanentError
	return errors.As(err, &p)
}

// WithLogger attaches the structured logger used to record the raw
// transport cause of a failed seal BEFORE the domain mapping strips it —
// the RA-side line that distinguishes a timeout from connection-refused
// from a 429 during a TL incident. Defaults to zerolog.Nop().
func (c *Client) WithLogger(logger zerolog.Logger) *Client {
	c.logger = logger.With().Str("component", "tl-client").Logger()
	return c
}

// logSealFailure records the unmapped transport error for a failed seal.
// WARN for transient faults (retryable; expected during a TL incident),
// ERROR for permanent rejections (the RA produced an event the TL
// refuses). The domain error the caller receives carries only the
// sanitized category, so this line is where the cause survives.
func (c *Client) logSealFailure(lane string, err error) {
	ev := c.logger.Error()
	if IsTransient(err) {
		ev = c.logger.Warn()
	}
	ev.Err(err).Str("lane", lane).Msg("TL seal failed")
}

// SealIdentityEvent submits a producer-signed identity event on the
// IDENTITY lane and returns only after the TL acknowledges the seal —
// the client half of seal-before-success (design §5.6.1). Identity
// events never ride the outbox: delivery precedes success, and a
// failed delivery IS a failed operation, so errors are mapped to
// domain kinds the service layer can return directly:
//
//   - transient (transport, 5xx, 429) → ErrUnavailable / 503
//     TL_UNAVAILABLE: retryable, the caller consumed nothing;
//   - permanent (other 4xx)           → ErrInternal /
//     TL_REJECTED_EVENT: the RA produced an event the TL refuses —
//     a pipeline bug, not weather; operators must see it.
func (c *Client) SealIdentityEvent(ctx context.Context, innerCanonical []byte, producerSig string) error {
	_, err := c.Append(ctx, "IDENTITY", innerCanonical, producerSig)
	if err != nil {
		c.logSealFailure("IDENTITY", err)
	}
	switch {
	case err == nil:
		return nil
	case IsTransient(err):
		return domain.NewUnavailableError("TL_UNAVAILABLE",
			"the transparency log did not confirm the seal; the operation is retryable and nothing was consumed")
	default:
		return domain.NewInternalError("TL_REJECTED_EVENT",
			"the transparency log rejected the identity event", err)
	}
}

// SealAgentEvent submits a producer-signed AGENT event on the V1 or V2
// ingest lane and returns only after the TL acknowledges the seal — the
// client half of seal-before-success for agent ACTIVATION (ANS-1 §12.3:
// "the RA MUST NOT activate without a sealed event"). Used by the
// registration service to seal AGENT_REGISTERED inline at verify-dns,
// before the agent is reported ACTIVE. On success it returns the
// TL-assigned logId from the ack — the activation path persists it on a
// pre-delivered outbox row so the sealed event surfaces on the
// agent-events feed (which gates on log_id) without riding the worker.
// Error mapping mirrors SealIdentityEvent: transient → TL_UNAVAILABLE
// (retryable, nothing consumed — the activation can be retried),
// permanent → TL_REJECTED_EVENT (the RA produced an event the TL refuses
// — a pipeline bug operators must see). schemaVersion selects the lane
// ("V1" or "V2").
func (c *Client) SealAgentEvent(ctx context.Context, schemaVersion string, innerCanonical []byte, producerSig string) (string, error) {
	res, err := c.Append(ctx, schemaVersion, innerCanonical, producerSig)
	if err != nil {
		c.logSealFailure(schemaVersion, err)
	}
	switch {
	case err == nil:
		return res.LogID, nil
	case IsTransient(err):
		return "", domain.NewUnavailableError("TL_UNAVAILABLE",
			"the transparency log did not confirm the seal; activation is retryable and nothing was consumed")
	default:
		return "", domain.NewInternalError("TL_REJECTED_EVENT",
			"the transparency log rejected the agent event", err)
	}
}
