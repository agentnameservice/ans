# Revocation delivery and pending-work cancellation

The existing `AgentRevocationResponse` in `spec/api-spec-v2.yaml` requires
`agentId`, `ansName`, `status`, `revokedAt`, `reason`, and `links`, and optionally
returns `dnsRecordsToRemove`. These fields and both V1/V2 event shapes remain
unchanged. A successful revoke still reports committed local state with durable
TL delivery pending; it does not promise synchronous TL confirmation.

Migration 015 adds delivery claims, cancellation and dead-letter state to the
outbox. Stop all old RA workers before upgrading: they do not understand these
columns or token fencing. Back up the RA database, deploy one version across
workers, then restart them. Keep #127's terminal-aware TL reads and revocation
clock-rollback exemption with this change.

Revocation re-reads registration/certificate state inside its transaction,
cancels pending renewal/CSR work, fences undelivered modifications, revokes
stored identity certificates, and enqueues the signed revocation atomically.
If identity rotation committed while external CA revocation was underway,
`409 CERTIFICATES_CHANGED` asks the caller to retry, so the new certificate is
also revoked at its CA before completion. Repeated revoke calls do not enqueue
another event. A stale aggregate cannot restore ACTIVE over REVOKED.

Workers select eligible events, then acquire a one-minute durable claim before
a bounded 30-second send. Unique tokens fence stale acknowledgements. Crashed
workers' claims expire; retries replay the original bytes and signature. A
request already in flight may reach the TL after cancellation, so TL terminal
state remains the final safety boundary. If it arrives first, revocation follows;
if revocation arrives first, the modification is rejected.

Revocation bypasses earlier pending events and never automatically dead-letters.
Malformed modifications are parked immediately; other modifications are parked
after five consecutive permanent rejections. Transient errors reset that count.
ERROR logs identify parked rows; backlog WARN logs report pending/dead counts
and the oldest pending creation time. Alert on these independently of readiness.

Investigate a dead row's `last_error`, schema lane and TL producer trust before
repairing it. Preserve `payload_json`: changing or re-signing it breaks replay.
To retry a repaired nonterminal agent's dead row during an operator maintenance
window, stop workers and reset only that row, guarded against revocation:

```sql
UPDATE outbox_events
SET dead_at_ms = NULL, permanent_attempts = 0, next_attempt_at_ms = 0,
    claim_token = NULL, claimed_until_ms = NULL
WHERE id = :reviewed_row_id AND dead_at_ms IS NOT NULL
  AND cancelled_at_ms IS NULL AND sent_at_ms IS NULL
  AND EXISTS (SELECT 1 FROM agent_registrations a
              WHERE a.agent_id = outbox_events.agent_id AND a.status = 'ACTIVE');
```

Cancelled rows are retained as audit evidence and must not be requeued. Never
mark a row sent manually; only a TL acknowledgement provides its receipt log ID.

Claims coordinate processes that share the same transactional database. The
provided SQLite adapter remains a single-host deployment; copying a database
per pod or placing SQLite WAL on an unsupported network filesystem does not
create a distributed RA. A future multi-host store must preserve atomic
cancellation, claim comparison, and state checks at the database boundary.
