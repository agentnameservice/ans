# TL lifecycle acceptance and recovery boundaries

Canonical source: `spec/api-spec-tl-v2.yaml`, V1/V2 agent-ingest responses and
`components.schemas.Problem`:

```yaml
properties:
  type: {type: string}
  title: {type: string}
  status: {type: integer}
  detail: {type: string}
  code: {type: string}
required: [type, title, status]
```

Problem fields and signed event shapes are unchanged. Agent state/timestamp
conflicts return 409 with `AGENT_STATE_CONFLICT` or `STALE_AGENT_EVENT`;
structural/signature validation remains 422. Revocation ignores timestamp
ordering after producer/name ownership checks. Identity events do not run
agent lifecycle policy. Deduplication uses only the canonical producer-event
hash, including signed timestamps; activation retries use persisted bytes.

A versioned name, agent ID and original RA remain bound. Revocation is terminal;
deprecation permits only revocation. Transition checks project onto
`domain.RegistrationStatus.CanTransitionTo`, with renewal retaining ACTIVE.
These acceptance checks are implementation policy pending ANS-4 clarification,
not a requirement of its published content-hash deduplication text.

Recovery preserves every raw leaf, including historical duplicates; current
state uses distinct event hashes and gives terminal states precedence. A
checkpoint-bounded read considers only leaves within that checkpoint.

The V0 schema endpoint provides historical schema lookup. This implementation
has no V0 ingest/writer codec or supported V0 tile-import workflow. V0 data from
another implementation must not be copied into its tile directory: its outer
leaf encoding, signer topology, and read semantics require a separately
validated migration. Unknown leaf schemas fail recovery/readiness closed and
are never silently skipped or re-signed. V1, V2 and identity leaves produced by
this implementation are the supported recovery inputs.
