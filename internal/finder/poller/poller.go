// Package poller is the Finder's ingestion loop. It polls the ANS agent
// events feed, projects each event into catalog entries, and applies them
// to the index, advancing a durable cursor as it goes.
//
// The poller is the Finder's only writer. It runs as a single goroutine,
// so the index never sees concurrent writes; search and explore read
// concurrently under WAL. The loop is fail-soft: a transient feed or
// projection problem is logged and retried on the next tick rather than
// crashing the process, because the discovery surface should keep serving
// its last-known index while ingestion recovers.
package poller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/finder/feed"
	"github.com/agentnameservice/ans/internal/finder/index"
	"github.com/agentnameservice/ans/internal/finder/project"
)

// FeedClient fetches one page of the agent-events feed. The poller
// depends on this narrow port, not on net/http, so it can be driven by a
// fake in tests. afterLogID is the cursor to resume from (empty for the
// first page); limit caps the page size.
type FeedClient interface {
	FetchEvents(ctx context.Context, afterLogID string, limit int) (feed.EventPageResponse, error)
}

// Clock returns the current time. Injected so the poller's lastPollOK
// timestamps are deterministic in tests.
type Clock func() time.Time

// Config tunes the poll loop.
type Config struct {
	// Interval is the delay between poll rounds. A round drains as many
	// pages as the feed offers (until a page returns no cursor), then
	// sleeps Interval before the next round.
	Interval time.Duration
	// PageSize is the per-request limit passed to the feed.
	PageSize int
	// ProjectOptions configures the pure projection (TL base URL for
	// attestation URIs, AllowHTTP for dev URL policy).
	ProjectOptions project.Options
}

// wedgeThreshold is the number of consecutive failed rounds at the SAME
// cursor after which the poller emits a distinct escalation line. The
// feed-only design deliberately wedges at the cursor on a structural
// error (rather than skipping a malformed event), so this is the operator
// signal that ingestion has stopped making progress and needs manual
// intervention (see the cmd/ans-finder package comment for the runbook).
const wedgeThreshold = 5

// Poller drives feed ingestion into the index.
type Poller struct {
	client FeedClient
	idx    index.Catalog
	cfg    Config
	log    zerolog.Logger
	now    Clock

	// Wedge tracking across rounds: consecutive failures stuck at the same
	// cursor. Reset on any forward progress. Single-goroutine (Run), so no
	// synchronization is needed.
	failCursor string
	failStreak int
}

// New constructs a Poller. now may be nil (defaults to time.Now); a
// non-positive Interval defaults to 5s and a non-positive PageSize to 100
// so a partially-filled Config from a caller cannot produce a zero-tick
// ticker panic or a zero-limit fetch.
func New(client FeedClient, idx index.Catalog, cfg Config, log zerolog.Logger, now Clock) *Poller {
	if now == nil {
		now = time.Now
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = 100
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	return &Poller{client: client, idx: idx, cfg: cfg, log: log, now: now}
}

// Run blocks polling on Config.Interval until ctx is cancelled. It runs
// one round immediately on entry so a freshly-started Finder ingests
// without waiting a full interval, then ticks. Run returns nil on
// ctx.Done (graceful stop); it never returns an ingestion error, because
// a poll failure is logged and retried, not fatal.
func (p *Poller) Run(ctx context.Context) error {
	p.RunOnce(ctx)

	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.RunOnce(ctx)
		}
	}
}

// RunOnce executes one poll round: drain pages from the current cursor
// until the feed reports no more, applying each and advancing the cursor.
// A failure mid-round leaves the cursor at the last fully-applied page so
// the next round resumes cleanly; the error is logged, not propagated. A
// failure that recurs at the same cursor for wedgeThreshold rounds emits
// an escalation line for the operator. Run drives RunOnce on the
// configured interval; callers that schedule polling themselves
// (one-shot ingestion, tests) may invoke it directly.
func (p *Poller) RunOnce(ctx context.Context) {
	cursor, err := p.idx.Cursor(ctx)
	if err != nil {
		p.log.Error().Err(err).Msg("finder poller: read cursor")
		p.recordFailure(cursor.LastLogID)
		return
	}

	pagesApplied := 0
	itemsApplied := 0
	for {
		if ctx.Err() != nil {
			return
		}
		page, err := p.client.FetchEvents(ctx, cursor.LastLogID, p.cfg.PageSize)
		if err != nil {
			// A cancelled context during a fetch is a graceful stop, not a
			// failure worth logging at error level or counting as a wedge.
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return
			}
			p.log.Error().Err(err).
				Str("afterLogId", cursor.LastLogID).
				Msg("finder poller: fetch events")
			p.recordFailure(cursor.LastLogID)
			return
		}

		applied, report, err := p.applyPage(ctx, page)
		if err != nil {
			p.log.Error().Err(err).
				Str("afterLogId", cursor.LastLogID).
				Msg("finder poller: apply page")
			p.recordFailure(cursor.LastLogID)
			return
		}
		p.logTombstoneNoOps(report)

		lastLogID := nextCursorLogID(cursor.LastLogID, page)

		// Progress guard: if the feed reports more pages (LastLogID set)
		// but the cursor does not advance, draining again would re-fetch
		// the same page forever, hammering the RA. Stop the round and
		// surface it; the next interval retries from the same point.
		if page.LastLogID != "" && lastLogID == cursor.LastLogID {
			p.log.Error().
				Str("cursor", cursor.LastLogID).
				Int("items", len(page.Items)).
				Msg("finder poller: feed returned no progress (same cursor, more claimed); stopping round")
			p.recordFailure(cursor.LastLogID)
			return
		}

		// Advance and persist the cursor. The successful-poll timestamp is
		// recorded on every applied page so the staleness signal stays
		// fresh even on a quiet feed (a page with zero items still counts
		// as a successful round-trip).
		next := index.Cursor{LastLogID: lastLogID, LastPollOK: p.now().UTC()}
		if err := p.idx.SaveCursor(ctx, next); err != nil {
			p.log.Error().Err(err).Msg("finder poller: save cursor")
			p.recordFailure(cursor.LastLogID)
			return
		}
		cursor = next
		pagesApplied++
		itemsApplied += applied

		p.log.Debug().
			Int("items", len(page.Items)).
			Int("applied", applied).
			Str("lastLogId", lastLogID).
			Msg("finder poller: page applied")

		// No cursor on the page → we have reached the tail; stop draining
		// and wait for the next interval.
		if page.LastLogID == "" {
			break
		}
	}

	// A completed round clears the wedge counter.
	p.clearFailure()

	// Only an ingesting round is worth an INFO line. An idle round (a feed
	// that returned no new items) would otherwise emit a content-free INFO
	// every interval, drowning the log; those go to DEBUG.
	if itemsApplied > 0 {
		p.log.Info().
			Int("items", itemsApplied).
			Int("pages", pagesApplied).
			Str("lastLogId", cursor.LastLogID).
			Msg("finder poller: ingested")
	} else {
		p.log.Debug().Int("pages", pagesApplied).Msg("finder poller: idle round complete")
	}
}

// recordFailure tracks consecutive failed rounds stuck at the same
// cursor and emits a distinct escalation line once the streak crosses
// wedgeThreshold, so an operator can detect ingestion that has stopped
// making progress (the feed-only design wedges at the cursor on a
// structural error rather than skipping it).
func (p *Poller) recordFailure(cursor string) {
	if cursor == p.failCursor {
		p.failStreak++
	} else {
		p.failCursor = cursor
		p.failStreak = 1
	}
	if p.failStreak == wedgeThreshold {
		p.log.Error().
			Str("logId", cursor).
			Int("consecutiveFailures", p.failStreak).
			Msg("finder poller: ingestion wedged at logId; manual intervention required (see runbook)")
	}
}

// clearFailure resets the wedge counter after a round makes progress.
func (p *Poller) clearFailure() {
	p.failCursor = ""
	p.failStreak = 0
}

// logTombstoneNoOps surfaces revocations that suppressed nothing while
// Active rows remain — the agent stays discoverable, so each is a WARN.
// Two causes produce this: a producer clock step-back (the revoke's
// created_at is older than the active registration it should bury), or a
// duplicate/replayed older revoke arriving after the agent was
// re-registered. Either way the operator should reconcile against the TL.
func (p *Poller) logTombstoneNoOps(report index.ApplyReport) {
	for _, t := range report.TombstoneNoOps {
		p.log.Warn().
			Str("ansName", t.AnsName).
			Str("logId", t.LogID).
			Str("createdAt", t.CreatedAt).
			Msg("finder poller: revocation suppressed no rows but the agent is still active (stale/replayed revoke or clock step-back)")
	}
}

// applyPage projects every event in a page and applies the resulting
// entries to the index in one batch. It returns the number of projected
// entries applied and the cursor to persist.
//
// Projection errors are handled per the lifecycle safety rule:
//   - A structural feed error (FromEvent returns a non-nil error) on one
//     event aborts the page so the cursor does NOT advance past a
//     malformed event — the operator must see and fix it rather than have
//     it silently skipped. This is the one place ingestion intentionally
//     stops.
//   - A Skip (unknown eventType, missing label, bad URL) is logged at the
//     appropriate level and the event simply contributes no entry; the
//     page still applies and the cursor advances. UnknownEventType /
//     UnknownProtocol are logged at WARN (a producer-contract surprise
//     worth alerting on); routine publisher-data skips at DEBUG.
func (p *Poller) applyPage(ctx context.Context, page feed.EventPageResponse) (int, index.ApplyReport, error) {
	var entries []project.ProjectedEntry
	for i := range page.Items {
		item := page.Items[i]
		proj, err := project.FromEvent(item, p.cfg.ProjectOptions)
		if err != nil {
			return 0, index.ApplyReport{}, fmt.Errorf("project event logId=%q: %w", item.LogID, err)
		}
		p.logSkips(item, proj.Skipped)
		entries = append(entries, proj.Entries...)
	}

	report, err := p.idx.Apply(ctx, entries)
	if err != nil {
		return 0, index.ApplyReport{}, fmt.Errorf("apply %d entries: %w", len(entries), err)
	}
	return len(entries), report, nil
}

// nextCursorLogID computes the cursor to persist after a page applies:
//   - the page's explicit LastLogID when present (the feed's own cursor);
//   - else, when the page carried items but no cursor (a tail page), the
//     last item's logId, so progress through the tail is still recorded;
//   - else (no cursor, no items — an empty tail) the prior cursor,
//     unchanged. Returning the prior value here is what stops an empty
//     tail page from rewinding the cursor to empty.
func nextCursorLogID(prior string, page feed.EventPageResponse) string {
	if page.LastLogID != "" {
		return page.LastLogID
	}
	if len(page.Items) > 0 {
		return page.Items[len(page.Items)-1].LogID
	}
	return prior
}

// logSkips emits one log line per Skip at a level chosen by kind:
// producer-contract surprises (unknown eventType / protocol) at WARN so
// they can be alerted on; routine publisher-data skips at DEBUG.
func (p *Poller) logSkips(item feed.EventItem, skips []project.Skip) {
	for _, s := range skips {
		ev := p.log.Debug()
		if s.Kind == project.SkipUnknownEventType || s.Kind == project.SkipUnknownProtocol {
			ev = p.log.Warn()
		}
		ev.Str("logId", item.LogID).
			Str("agentId", item.AgentID).
			Str("kind", string(s.Kind)).
			Str("detail", s.Detail).
			Msg("finder poller: event skipped")
	}
}
