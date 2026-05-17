// Package opentimestamps implements the ANS-4.C witness profile —
// Bitcoin-anchored timestamps produced by the public OpenTimestamps
// calendars.
//
// Producer flow:
//
//  1. Hash the TL checkpoint with SHA-256.
//  2. POST the digest to a calendar (default
//     https://alice.btc.calendar.opentimestamps.org/digest). The
//     calendar returns a binary OTS proof file containing pending
//     Bitcoin attestations.
//  3. Wrap the bytes in a port.WitnessAttestation with profile
//     "4.C-opentimestamps".
//
// Verifier flow (out of scope for this package): pass the ExternalProof
// bytes to the OpenTimestamps reference CLI or to an SPV-aware
// verifier; both validate the proof against a Bitcoin block header
// and report an attestation timestamp accurate to the block time.
//
// Pending vs upgraded proofs: a calendar's immediate response carries
// a *pending* attestation. After the next Bitcoin block (typically
// 10 minutes), an Upgrade fetch replaces the pending bytes with
// final Bitcoin attestations. Production deployments call Attest at
// checkpoint time to get the pending proof, persist it, and run a
// background Upgrade pass on a schedule until the proof finalizes.
// The WithUpgradeAfter helper exposes the upgrade endpoint so
// operators can build that loop.
//
// References:
//   - OpenTimestamps protocol: https://opentimestamps.org/
//   - Calendar API: https://github.com/opentimestamps/opentimestamps-server
//   - Reference CLI: https://github.com/opentimestamps/opentimestamps-client
package opentimestamps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/godaddy/ans/internal/port"
)

// ProfileID is the canonical profile identifier this witness reports
// from Profile(). Matches the ANS_SPEC.md §4.11 enumeration.
const ProfileID = "4.C-opentimestamps"

// DefaultCalendarURL is one of the public OpenTimestamps calendars
// maintained by the OTS project (alice). Bob (bob.btc.calendar.opentimestamps.org)
// and finney (finney.calendar.eternitywall.com) are alternates a
// production deployment may rotate to via WithCalendarURL. The OTS
// reference client aggregates across all three; a future amendment
// may admit a multi-calendar variant. The default targets one
// because a single calendar is enough for a TL deployment whose own
// state is already replicated, and multi-calendar dispatch belongs
// in a wrapper rather than in the base adapter.
const DefaultCalendarURL = "https://alice.btc.calendar.opentimestamps.org"

// Witness implements port.Witness against an OTS calendar.
type Witness struct {
	calendarURL string
	httpClient  *http.Client
	clock       func() time.Time
}

// New returns a Witness pointed at the default public calendar with
// a 30-second HTTP timeout. Production deployments wrap the returned
// httpClient with a retry policy and observability hooks.
func New() *Witness {
	return &Witness{
		calendarURL: DefaultCalendarURL,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		clock:       time.Now,
	}
}

// WithCalendarURL returns a copy of the witness pointed at a different
// calendar. Tests use this to point at httptest.Server.URL.
func (w *Witness) WithCalendarURL(url string) *Witness {
	cp := *w
	cp.calendarURL = strings.TrimRight(url, "/")
	return &cp
}

// WithHTTPClient returns a copy with a different *http.Client.
func (w *Witness) WithHTTPClient(h *http.Client) *Witness {
	cp := *w
	cp.httpClient = h
	return &cp
}

// WithClock returns a copy with a deterministic clock. Tests use
// this for reproducible AttestedAt values.
func (w *Witness) WithClock(clock func() time.Time) *Witness {
	cp := *w
	cp.clock = clock
	return &cp
}

// Profile reports the witness profile identifier.
func (w *Witness) Profile() string { return ProfileID }

// Attest implements port.Witness. Hashes the checkpoint, POSTs the
// digest to the calendar, wraps the calendar's response bytes in a
// WitnessAttestation.
func (w *Witness) Attest(ctx context.Context, checkpoint []byte) (*port.WitnessAttestation, error) {
	if len(checkpoint) == 0 {
		return nil, errors.New("opentimestamps: empty checkpoint")
	}
	digest := sha256.Sum256(checkpoint)

	url := w.calendarURL + "/digest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(digest[:]))
	if err != nil {
		return nil, fmt.Errorf("opentimestamps: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/octet-stream")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opentimestamps: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return nil, fmt.Errorf("opentimestamps: calendar http %d: %s", resp.StatusCode, preview)
	}

	otsBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("opentimestamps: read body: %w", err)
	}
	if len(otsBytes) == 0 {
		return nil, errors.New("opentimestamps: calendar returned empty body")
	}

	digestCopy := make([]byte, len(digest))
	copy(digestCopy, digest[:])

	return &port.WitnessAttestation{
		Profile:          ProfileID,
		CheckpointDigest: digestCopy,
		AttestedAt:       w.clock().UTC().Format(time.RFC3339),
		ExternalProof:    otsBytes,
	}, nil
}

// Upgrade fetches a finalized version of a pending OTS proof from
// the calendar. Pending proofs reference a calendar commitment that
// will eventually be sealed into a Bitcoin block; Upgrade replaces
// the calendar commitment with a Bitcoin block-header reference.
//
// Operational pattern: producers call Attest at checkpoint time and
// persist the pending proof. A background loop calls Upgrade against
// each pending proof on a schedule (e.g., hourly) until Upgrade
// returns a finalized proof, at which point the persisted bytes are
// replaced with the upgraded form.
//
// The pending input is the bytes from a prior Attest call's
// ExternalProof. Returns the upgraded bytes when finalization is
// available; returns the input bytes unchanged with no error when
// the calendar still has no Bitcoin attestation (the typical case
// in the first ~10 minutes after Attest).
func (w *Witness) Upgrade(ctx context.Context, pending []byte) ([]byte, error) {
	if len(pending) == 0 {
		return nil, errors.New("opentimestamps: empty pending proof")
	}

	url := w.calendarURL + "/timestamp"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(pending))
	if err != nil {
		return nil, fmt.Errorf("opentimestamps: build upgrade request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/octet-stream")

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opentimestamps: upgrade http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		// Calendar has no Bitcoin attestation yet; return the input
		// unchanged so callers can retry later.
		return pending, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return nil, fmt.Errorf("opentimestamps: upgrade http %d: %s", resp.StatusCode, preview)
	}

	upgraded, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("opentimestamps: read upgrade body: %w", err)
	}
	if len(upgraded) == 0 {
		return nil, errors.New("opentimestamps: calendar returned empty upgrade body")
	}
	return upgraded, nil
}
