# ACME owner isolation and upgrade

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

