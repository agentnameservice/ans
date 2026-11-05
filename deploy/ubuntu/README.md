# Native Ubuntu deployment

Install and startup verified on Ubuntu **24.04.5 LTS arm64**, with Go **1.26.8**
and Caddy **2.11.6**, on 2026-10-02. Verification covered package installation,
binary builds, config permissions/overwrite refusal, systemd readiness, API
producer-key bootstrap, and proxy routes. Proxy HTTPS used a temporary local
CA; public DNS, Let's Encrypt issuance and authenticated registration remain
deployment-specific acceptance steps.

Run RA, TL, and Caddy directly on Ubuntu under systemd. No Docker, external
SQL server, or Node.js runtime is required for RA/TL. These instructions assume
a recent systemd-based Ubuntu server on amd64 or arm64, sudo access, and the
reviewed source release containing these deployment files. Build on a separate
Ubuntu machine of the same architecture if you do not want build tools on
the service host.

Caddy terminates RA/TL HTTPS with Let's Encrypt production certificates. The
RA independently uses Let's Encrypt staging for agent server certificates.
The identity CA remains the local persistent issuer for initial staging.

## Before starting

Replace the example values in these templates before installing them:

| File | Values to replace |
| --- | --- |
| `Caddyfile` | `ra.ans.example.com` and `tl.ans.example.com` with your service hostnames |
| `ra.yaml` | OIDC issuer and audience; `tl-client.public-base-url` with the same public TL URL |
| `tl.yaml` | `merkle.origin` with the same public TL hostname |

Choose stable signer key IDs and RA IDs before first startup. Preserve them
and their keys on upgrades. The `__TL_SERVICE_KEY__` marker is replaced by the
installation command below; do not substitute a real secret into the repository.

Configure an OIDC provider with a discoverable issuer, JWKS, and tokens whose
`aud` matches `auth.oidc.audience`. As one example, with Clerk create a JWT template named `ans-ra` with an `aud` claim matching
`auth.oidc.audience` (the example uses `ans-ra`). Send the resulting template
JWT as `Authorization: Bearer <token>` to the RA. Use your own issuer; a Clerk
development instance is not a production identity deployment. Other OIDC
providers work when their discovery/JWKS and token claims match the config.
OIDC protects RA operations, independently of agents' ANS identity certificates.

The example uses the persistent local identity CA. A managed private CA
requires its own adapter; selecting ACME does not replace the identity CA.

## 1. Install packages

From the repository root:

```sh
sudo bash deploy/ubuntu/install-packages.sh
```

The script installs `ca-certificates`, `curl`, `gnupg`, `debian-keyring`,
`debian-archive-keyring`, `apt-transport-https`, `git`, `build-essential`, `jq`,
`openssl`, `dnsutils`, `python3`, and `python3-yaml` from Ubuntu; Caddy from
its official stable APT repository; and the latest stable Go patch on the
release line declared by the `go` directive in this checkout's `go.mod`,
checking its published SHA-256. The complete upstream release index is used
so the installer still finds that line after newer Go releases appear.
The package installer requires outbound network access and sudo; it changes
APT sources and `/usr/local/bin/go` and `/usr/local/bin/gofmt`.
Go is installed in `/opt/ans-toolchains/<version>` with `go` and `gofmt`
symlinks under `/usr/local/bin`. Existing toolchains are retained.
Caddy's package may start its default site; our hostnames are enabled below.

Sources: [Caddy packages](https://caddyserver.com/docs/install#debian-ubuntu-raspbian),
[Go downloads](https://go.dev/dl/),
[Let's Encrypt staging roots](https://letsencrypt.org/docs/staging-environment/).

## 2. Build the reviewed source

As your ordinary user, from the repository root:

```sh
export PATH="/usr/local/bin:$PATH"
go version
make check
make test-race
make build
sudo install -o root -g root -m 0755 bin/ans-ra bin/ans-tl bin/ans-verify /usr/local/bin/
```

`make check` installs the repository's pinned golangci-lint when needed.
Do not continue past failed checks. These are build-time tools; Go and the
compiler are not needed by the installed running binaries.

## 3. Create accounts and install configuration

```sh
id ans-ra >/dev/null 2>&1 || sudo useradd --system --user-group --home-dir /var/lib/ans-ra --no-create-home --shell /usr/sbin/nologin ans-ra
id ans-tl >/dev/null 2>&1 || sudo useradd --system --user-group --home-dir /var/lib/ans-tl --no-create-home --shell /usr/sbin/nologin ans-tl
sudo install -d -o root -g root -m 0755 /etc/ans
```

Install first-time configurations with one shared random TL service secret.
This refuses to overwrite existing configurations. Secrets remain in files
readable by root and the corresponding service group, not in shell history:

```sh
sudo bash deploy/ubuntu/install-config.sh
```

The templates bind both services to `127.0.0.1`, configure OIDC for RA users,
use DNS lookup and real did:web resolution, and disable vLEI (`off`) until a
real verifier is deployed. The TL accepts its service secret only on localhost;
Caddy publishes only read/verification routes.

**Trust boundary:** the TL's static service key grants administrator privileges,
including producer-key changes, as well as ingestion. The RA holds that key.
Compromise of the RA process therefore permits changes to the TL producer trust
store over loopback. Separate Unix users and Caddy's public allowlist do not
remove this authority. This single-host profile assumes RA and TL share an
administrative trust boundary. Deployments requiring separation must provide a
least-privileged ingest authorization path before using this profile.

Do not use the checked-in secret
markers directly. Add your ACME contact email under `ca.server.acme.email` if
desired. ACME account creation accepts the issuer's terms as documented by the
adapter.

Install staging roots **only into the RA-specific trust file**, not Ubuntu's
system/browser trust store:

```sh
(
  set -eu
  ans_roots_work=$(mktemp -d)
  trap 'rm -rf "$ans_roots_work"' EXIT
  curl -fsSL https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem -o "$ans_roots_work/x1.pem"
  curl -fsSL https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem -o "$ans_roots_work/x2.pem"
  openssl x509 -in "$ans_roots_work/x1.pem" -noout -subject
  openssl x509 -in "$ans_roots_work/x2.pem" -noout -subject
  cat "$ans_roots_work/x1.pem" "$ans_roots_work/x2.pem" > "$ans_roots_work/roots.pem"
  sudo install -o root -g ans-ra -m 0640 "$ans_roots_work/roots.pem" /etc/ans/le-staging-roots.pem
)
```

## 4. Start RA/TL and bootstrap signing trust

```sh
sudo install -o root -g root -m 0644 deploy/ubuntu/ans-ra.service deploy/ubuntu/ans-tl.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ans-tl ans-ra
sudo journalctl -u ans-tl -u ans-ra -n 80 --no-pager
curl --fail http://127.0.0.1:18080/v2/admin/ready
curl --fail http://127.0.0.1:18081/v2/admin/ready
```

Wait for both readiness checks to pass. Then seed the RA public key into the
TL through its loopback producer-key admin API. No private signing key is
copied and no YAML rewrite or TL restart is needed. The initial key uses a
ten-year validity interval; plan rotations before expiry. Re-running the script
verifies an existing identical, active key and refuses conflicting/revoked keys.

```sh
sudo bash deploy/ubuntu/bootstrap-trust.sh
```

The script reads the administrator credential from root-controlled config; it
does not place it in command arguments, output, or shell history. A successful
bootstrap confirms trust-store configuration; health alone does not prove
end-to-end event delivery.

## 5. DNS, firewall, and HTTPS

Point `ra.ans.example.com` and `tl.ans.example.com` A records at the server.
Add AAAA only with working public IPv6. Any CAA records must permit
`letsencrypt.org`. Allow inbound TCP 80/443 in the host/cloud firewall while
preserving the existing SSH rule. Never expose 18080/18081/18082. No DNS API
credentials are required for Caddy's normal HTTP/TLS challenges. Agent
registration still requires publishing its challenge and ANS DNS records.

Use DNS-only records during initial setup. If you later enable a proxy, its
edge certificate must cover the exact hostnames; a wildcard for example.com
does not cover ra.ans.example.com. Agent certificate/TLSA checks must see the
certificate authorized by the agent registration.

The example RA queries `1.1.1.1:53` for DNS verification. Choose a reachable
recursive resolver for your environment, or omit `dns.server` to use the
system resolver. An old answer from a recursive cache is not evidence that
an authoritative update failed; compare authoritative answers and TTLs.

After DNS is ready, from the repository root:

```sh
sudo install -o root -g caddy -m 0640 deploy/ubuntu/Caddyfile /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl enable --now caddy
sudo systemctl reload caddy
sudo journalctl -u caddy -n 80 --no-pager
curl --fail https://ra.ans.example.com/docs
curl --fail https://tl.ans.example.com/root-keys
curl -o /dev/null -w '%{http_code}\n' https://tl.ans.example.com/internal/v1/producer-keys
```

Also open `https://tl.ans.example.com/docs`;
the proxy explicitly allows both `/docs` and its static assets. Swagger uses
the public service origin for requests. Deploy with the Swagger fix in #135,
which pins the CDN JavaScript and CSS with Subresource Integrity. An SSH tunnel
alone does not protect bearer tokens from a tampered CDN script.

The last request must return 404. Caddy obtains/renews RA/TL certificates and
redirects HTTP to HTTPS; no Certbot is needed. Its administration API remains
loopback-only. Check backend ports are unreachable from another machine.

Back up `/etc/ans`, `/etc/caddy`, `/var/lib/ans-ra`, `/var/lib/ans-tl`, and
`/var/lib/caddy`, protecting keys/secrets. For a simple consistent backup,
stop RA and TL while copying their complete state directories, then restart
them. Run only one TL writer per tile directory. On upgrades stop a service
before replacing its binary, then start it again.

When moving agent issuance to Let's Encrypt production, change the RA ACME
directory URL, use a separate production ACME data directory, and remove the
staging-only `ca.validation.roots-file` setting. Reissue/register suitable
trusted agent certificates. Caddy's RA/TL certificates already use production.

## Verify a registration and maintain the deployment

Use the RA Swagger UI with an OIDC bearer token to register an agent, publish
one returned ACME challenge, and call `verify-acme`. Retrieve the issued
certificates, publish the returned permanent DNS records, and call `verify-dns`.
Wait for ACTIVE and verify the TL receipt/status before serving the agent with
its registered certificate. Registration version and metadata hashes must
match the exact metadata documents the agent serves. RA/TL readiness alone
does not prove this full lifecycle.

Run ordinary setup validation with a registration owned by your account. A
controlled renewal/revocation exercise and backup restoration are separate
acceptance steps; do not revoke a live user's agent merely to check setup.

Caddy automatically renews the RA/TL service certificates. It does not rotate
agent certificates issued through the RA or install them into an agent. Plan
agent renewal, TL publication, DNS updates, and certificate installation
before expiry. Post-renewal DNS resealing remains tracked in
[ans-registry#66](https://github.com/agentnameservice/ans-registry/issues/66):
`verify-dns` on an ACTIVE registration does not refresh its sealed snapshot.

Use external monitoring for `GET https://tl.ans.example.com/root-keys` and
`GET https://ra.ans.example.com/docs`. These check public routing/availability;
run `/v2/admin/ready` checks locally because Caddy intentionally returns 404
for them. Alert separately on private readiness and public endpoint failures.

Inspect unit confinement after installation with
`sudo systemd-analyze security ans-ra.service ans-tl.service`.

Configure off-host encrypted backups and monitoring for service readiness,
outbox delivery failures, disk space, and certificate expiry. The units do not
install a backup schedule or certificate-installation automation.

This guide covers RA/TL only. An A2A/MCP agent, its ANS authentication,
metadata, and any application frontend are separate deployments.

For existing installations, follow the [certificate lifecycle and TL recovery upgrade notes](../../docs/operations/deployment-fix-upgrade.md) before replacing binaries.

## Source and merge sequence

The source release must include #125, #126, #127, and #128 in that dependency
order, plus #135 for Swagger. After each parent merges, rebase its dependent
branch onto the merged `main` and retarget the PR before merging it. For a
squash merge, drop the old parent commits during that rebase; do not merge a
child whose diff still contains a second copy of the parent changes. Merge
this deployment PR onto `main` last so `Fixes #133` closes against the default
branch. Check the resulting diff before deleting the old stack branches.
