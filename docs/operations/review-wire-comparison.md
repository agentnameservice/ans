# Contract comparison for certificate-provider and readiness fixes

Canonical RA source: spec/api-spec-v2.yaml, components.schemas.Problem:

```yaml
properties:
  type: {type: string}
  title: {type: string}
  status: {type: integer}
  detail: {type: string}
  code: {type: string}
required: [type, title, status]
```

Those JSON fields are unchanged. New documented outcomes on registration and
server-renewal creation/finalization are 503 CERT_PROVIDER_THROTTLED with an
optional Retry-After header, and owner/legacy-order 409 conflicts. Existing
conflict responses retain their existing codes. The API versions share the
same RFC 7807 handler mapping. Domain retry metadata is not serialized into
an additional body field.

The existing private TL readiness route retains {"status":"ready"} for
success and returns 503 {"status":"not_ready"} when its index is unavailable.
No public route is added. Signed event fields, algorithms, and receipt/checkpoint
shapes are unchanged. Durable activation evidence is an internal storage change.

The current agent lifecycle acceptance policy is retained while its revocation
and cancellation contract is explicitly deferred. Agent state/timestamp errors
are validation errors (422), not the generic domain conflict mapping (409).
Identity ingest does not run those agent-state rules. Both V1 and V2 agent
ingest routes are now documented explicitly.
