# Upgrading RA/TL certificate lifecycle and recovery support

Back up the RA database, signer keys, identity CA state, and complete ACME data
directory. Back up the TL SQLite database, Merkle tile directory, and signing
key together. Stop the old writer before replacing binaries. Run exactly one
writer per SQLite/POSIX tile directory; this is not a multi-pod storage backend.

## Owner-scoped ACME orders

The RA stores persistent ACME accounts under `owners/<SHA256(ownerID)>`. Account
selection is separate from the single-account ACME client. Create and finalize
both require the authenticated owner; middleware/decorators must preserve it.
Account private keys remain on the RA, separate from user certificate keys.

Before upgrading, finish or cancel outstanding legacy shared-account orders.
An order without the owner-bound reference cannot be resumed after upgrade.
A registration with no persisted challenges/proof returns
`CERT_ORDER_UPGRADE_REQUIRED`; cancel it where supported or allow expiry, then
register a new version. Cancel/recreate an affected pending renewal. These
conflicts do not mark an order as a CA-reported terminal failure.

Let's Encrypt production permits 10 new accounts per source IP per 3 hours,
with one replenished every 18 minutes and no override. Separate accounts do
not avoid registered-domain or exact-identifier-set certificate limits. See
https://letsencrypt.org/docs/rate-limits/. This can constrain onboarding from
a shared egress IP even though existing owner accounts continue working.

Provider HTTP 429/503 responses become 503 `CERT_PROVIDER_THROTTLED` with a
validated `Retry-After` header when available. Honor that hint, preserve account
keys and pending orders, and do not retry in a tight loop. Provider throttling
is retryable, not a terminal certificate-order failure. A shared-account
provider design or BYOC policy is a separate deployment decision.

## Activation retries

Migration 014 adds `activation_seals`, keyed by agent ID. It stores the API
lane, canonical producer event and signature before the first synchronous TL
submission. Concurrent attempts use the first persisted candidate; retry uses
those same signed bytes even if timestamps or DNS observations later change.
These records are not asynchronous outbox work. ACTIVE still requires TL
confirmation. A retry through another API lane returns a conflict; retry the
original lane. Keep this table in backups along with the ordinary outbox.

## TL migration, recovery, and readiness

Migration 006 rebuilds the event index to preserve historical duplicate leaves.
Allow disk space for both the existing index and its replacement, plus SQLite
journal/WAL overhead. Estimate from the deployed database rather than the tile
size alone. Never delete old log leaves or recreate signing keys to resolve
an index error.

Recovery runs before the listener opens. Large logs can exceed the example
Compose healthcheck startup allowance; increase `start_period` and deployment
startup deadlines for the log size and storage performance. Wait for readiness
before routing traffic. The process logs recovery start, completion/failure,
restored-leaf count, and duration.

"Index extends beyond the integrated log" means the SQLite mirror refers to
leaves unavailable in this tile snapshot. Restore a consistent backup or
investigate the storage mismatch. Do not truncate signed history to make the
sizes match.

Healthy current-state reads share a read lock. Signing does not fence readers;
a submitted append does, until its outcome and mirror write are known. A caller
timeout does not cancel a potentially committed leaf. The single writer keeps
that operation fenced until completion, and runtime readiness returns 503 when
it cannot inspect a healthy index within its deadline. This deliberately
preserves fail-closed status behavior during an uncertain append.

Malformed supplied certificate-expiry timestamps are rejected at ingest.
Historical malformed evidence fails consistently when serving badges/status
rather than falling back to ACTIVE for one endpoint and erroring in another.
Absent dates in legacy records remain supported.

## Renewal evidence and diagnostics

Server renewal observes DNS before finalizing with the CA. Identity rotation
also observes DNS, but observation is not fresh domain-control proof. DNS
lookup outages produce an explicit warning and no DNS attestation for the
unobserved records; an authenticated mismatch is logged at ERROR and the
mismatching record is omitted. It does not prevent rotation from repairing the
configuration. Required ACME owner proof remains a separate gate.

Certificate, CSR/renewal state, and signed publication intent still commit
atomically. Success is logged only after transaction commit. V1 HTTP renewal
and rotation handlers are pinned to V1 outbox events by handler regressions.

Post-renewal DNS re-verification/resealing remains a separate protocol change.
Current TL lifecycle rejection and RA outbox ordering are not changed by these
follow-ups while the multi-pod revocation-cancellation contract is being decided.
