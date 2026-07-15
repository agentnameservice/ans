# vlei-verifier 0.1.5 contract fixtures

Recorded response bodies for the three vlei-verifier endpoints the
`leiverifier.Verifier` adapter speaks. They are the SINGLE SOURCE OF TRUTH
for the verifier's response shapes: the `vleiServer` harness in
`leiverifier_test.go` serves these bytes verbatim on every happy path
(via the `fixture()` loader), so the whole suite is a CI-runnable
stand-in verified against the real 0.1.5 contract rather than against
what we assume the service returns. A field-name / structural drift on a
version bump changes the re-derived fixture and fails the matching test
**loudly** instead of silently. (Only deliberately-malformed or
edge-shaped bodies — missing fields, junk JSON — stay inline in the test;
those are synthetic by design and have no real counterpart to record.)

## Provenance

Derived from the vlei-verifier source at the exact commit the demo
docker-compose builds (`scripts/demo/vlei/docker-compose.yml`,
SHA-pinned build context):

- Repo: `github.com/GLEIF-IT/vlei-verifier`
- Commit: `e742b65b085bb41b9fa25e9ef04dc3cf0644b297` (the `0.1.5` tag)
- File: `src/verifier/core/verifying.py`

These are **derived from source**, not captured from live traffic. They
reproduce the JSON shapes the handlers emit (`json.dumps(dict(...))`), so
they catch field-name / structural drift. They do NOT capture runtime-only
quirks (field ordering, incidental extra keys, header casing) — a live
capture would be strictly stronger. Re-derive (or re-capture) on every
version bump; the diff in this directory is the loud signal.

## Fixtures

| File | Endpoint | Status | Source (`verifying.py`) |
|---|---|---|---|
| `present-202.json` | `PUT /presentations/{said}` (CREDENTIAL) | 202 | `on_put` L500–506: `dict(creds=json.dumps(creds), aid=aid, msg=info)` |
| `authorizations-200-credential.json` | `GET /authorizations/{aid}` (cred login) | 200 | `_process_cred_auth` L659–665: `dict(aid, said, lei, role, msg)` |
| `authorizations-200-aid-only.json` | `GET /authorizations/{aid}` (AID-only login) | 200 | `_process_aid_auth` L631–637: `lei=None, role=None` |
| `authorizations-401-unknown.json` | `GET /authorizations/{aid}` (unknown AID) | 401 | `on_get` L720: `dict(msg=f"unknown AID: {aid}")` |
| `signature-verify-202.json` | `POST /signature/verify` (valid) | 202 | `on_post` L939: `dict(msg="Signature Valid", code=3)` |
| `signature-verify-401.json` | `POST /signature/verify` (bad sig) | 401 | `on_post` L916–918: `dict(msg=..., code=1)` |

Notes:

- `present-202.json` `creds` is abbreviated to `"[]"`. The real value is
  `json.dumps(creds)` — a large cloned-credential array serialized to a
  JSON *string*. The adapter reads only `aid`, so the abbreviation does
  not affect the contract under test; it keeps the fixture legible.
- `authorizations-200-aid-only.json` carries `lei: null`. This is the
  AID-only login path (a valid AID account with no bound credential). The
  adapter must fail closed on an empty LEI — an authorized-but-LEI-less
  200 must NOT be mistaken for a credential-bound authorization — so this
  fixture pins that fail-closed behavior against the real shape that
  triggers it.
- The request the adapter *sends* (`signer_aid` / `signature` /
  `non_prefixed_digest`, the `application/json+cesr` content type, the
  path composition) is pinned separately by `TestVerifierRequestShapes`;
  `verifying.py` `on_post` L878–880 is the upstream side of that contract.
