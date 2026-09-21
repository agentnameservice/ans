# TL recovery and activation replay upgrade

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

