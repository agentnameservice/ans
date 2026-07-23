package service

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/agentnameservice/ans/internal/port"
)

// ExpireAgentsOnce transitions lapsed PENDING_VALIDATION registrations
// to EXPIRED via a single guarded store write, honoring the spec's
// revoke-route contract: "PENDING_VALIDATION registrations are not
// cancellable and will auto-expire". Returns the number transitioned.
//
// The guard (status still PENDING_VALIDATION, order still PENDING,
// window lapsed) lives in the store's UPDATE WHERE clause, so the
// sweep cannot clobber a row that a concurrent verify-acme advanced
// between scans — see port.AgentStore.ExpireLapsedPendingValidation.
//
// No certificate cleanup is needed by construction: identity
// certificates are signed only when the certificate order completes —
// the same transaction that advances the agent to PENDING_DNS — so a
// still-PENDING_VALIDATION row with a PENDING order has never had
// anything issued. Registrations whose order failed terminally or is
// mid-issuance are excluded by the guard and leave PENDING_VALIDATION
// through the cancel path instead (see RegistrationService.Revoke).
//
// No TL emit: under the terminal-only event model no leaf exists for
// an agent that never reached ACTIVE. Idempotent — an already-EXPIRED
// row no longer matches the guard.
func ExpireAgentsOnce(
	ctx context.Context,
	agents port.AgentStore,
	now time.Time,
) (int, error) {
	n, err := agents.ExpireLapsedPendingValidation(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("expire lapsed registrations: %w", err)
	}
	return int(n), nil
}

// RunAgentExpiryChecker blocks until ctx is cancelled, calling
// ExpireAgentsOnce on a fixed interval — the registration-side twin
// of RunExpiryChecker for renewals. Sweep errors are logged, not
// returned: a single bad sweep (usually transient DB trouble)
// shouldn't tear down the worker.
func RunAgentExpiryChecker(
	ctx context.Context,
	agents port.AgentStore,
	logger zerolog.Logger,
	opts ExpiryCheckerOptions,
) {
	interval := opts.Interval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	logger.Info().Dur("interval", interval).Msg("agent expiry checker started")
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("agent expiry checker stopped")
			return
		case now := <-ticker.C:
			n, err := ExpireAgentsOnce(ctx, agents, now)
			if err != nil {
				logger.Warn().Err(err).Msg("agent expiry sweep failed")
				continue
			}
			if n > 0 {
				logger.Info().Int("expired", n).Msg("agent expiry sweep completed")
			}
		}
	}
}
