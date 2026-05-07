package service

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/godaddy/ans/internal/domain"
	"github.com/godaddy/ans/internal/port"
)

// ExpireRenewalsOnce fails and closes out any pending renewals whose
// validation window has elapsed without VERIFIED status. Returns the
// number of renewals processed.
//
// Mirrors the reference RA's `RenewalExpiryCheckJob`. Our build runs
// it on a ticker instead of the reference's scheduler; otherwise the
// semantics are identical:
//
//   - Scan `server_cert_renewals` for rows with
//     completed_at_ms IS NULL AND validation_status = 'PENDING' AND
//     validation_expires_ms <= now.
//   - Mark each with failure_reason = "Renewal validation expired".
//   - If the renewal originated from a CSR, flip the CSR status to
//     REJECTED with the same reason so GET /csrs/{id}/status reflects
//     the outcome.
//   - Persist.
//
// This is idempotent — running twice on the same state produces the
// same result, which matches the reference's scheduler-semantics.
func ExpireRenewalsOnce(
	ctx context.Context,
	renewals port.RenewalStore,
	certs port.CertificateStore,
	now time.Time,
) (int, error) {
	expired, err := renewals.ListPendingExpired(ctx)
	if err != nil {
		return 0, fmt.Errorf("list expired renewals: %w", err)
	}
	const reason = "Renewal validation expired"
	for _, r := range expired {
		// Mark the validation failed + mark the renewal failed in
		// one Save. The domain methods guard against double-fail,
		// so this is safe on retry.
		failedValidation, err := r.Validation.MarkFailed(now)
		if err == nil {
			r.UpdateValidationStatus(failedValidation)
		}
		if ferr := r.MarkFailed(reason, now); ferr != nil {
			// Renewal is already completed (e.g. raced with a
			// verify-acme call). Skip without failing the whole
			// sweep.
			continue
		}
		if err := renewals.Save(ctx, r); err != nil {
			return 0, fmt.Errorf("save expired renewal %d: %w", r.ID, err)
		}
		// For CSR renewals, flip the linked CSR to REJECTED so the
		// status endpoint reflects the outcome.
		if r.RenewalType == domain.RenewalTypeCSR && r.ServerCsrID != "" {
			csr, cerr := certs.FindCSRByID(ctx, r.AgentID, r.ServerCsrID)
			if cerr == nil && csr != nil && csr.Status == domain.CSRStatusPending {
				rejected, rerr := csr.MarkRejected(reason, now)
				if rerr == nil {
					_ = certs.SaveCSR(ctx, r.AgentID, &rejected)
				}
			}
		}
	}
	return len(expired), nil
}

// ExpiryCheckerOptions configures the background expiry checker.
type ExpiryCheckerOptions struct {
	// Interval between sweeps. Default is 5 minutes; shorter
	// intervals tighten the "how long is a failed renewal listed as
	// PENDING" window at the cost of extra DB activity.
	Interval time.Duration
}

// RunExpiryChecker blocks until ctx is cancelled, calling
// ExpireRenewalsOnce on a fixed interval. The first sweep happens
// one Interval after Start (not immediately) — matches the reference
// RA's scheduler cadence which ticks on fixed wall-clock boundaries.
//
// Errors during a sweep are logged and not returned; a single bad
// sweep shouldn't tear down the whole worker. A real error is usually
// a database-connectivity issue that will self-resolve once the DB
// is back.
func RunExpiryChecker(
	ctx context.Context,
	renewals port.RenewalStore,
	certs port.CertificateStore,
	logger zerolog.Logger,
	opts ExpiryCheckerOptions,
) {
	interval := opts.Interval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	logger.Info().Dur("interval", interval).Msg("renewal expiry checker started")
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("renewal expiry checker stopped")
			return
		case now := <-ticker.C:
			n, err := ExpireRenewalsOnce(ctx, renewals, certs, now)
			if err != nil {
				logger.Warn().Err(err).Msg("renewal expiry sweep failed")
				continue
			}
			if n > 0 {
				logger.Info().Int("expired", n).Msg("renewal expiry sweep completed")
			}
		}
	}
}
