#!/usr/bin/env bash
# Install native-host build/runtime dependencies. Run with sudo on Ubuntu.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo bash deploy/ubuntu/install-packages.sh" >&2
  exit 1
fi
. /etc/os-release
if [[ ${ID} != ubuntu ]]; then
  echo "This installer targets Ubuntu." >&2
  exit 1
fi

apt-get update
apt-get install -y \
  ca-certificates curl gnupg debian-keyring debian-archive-keyring \
  apt-transport-https git build-essential jq openssl dnsutils \
  python3 python3-yaml

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Official Caddy stable APT repository.
curl -fsSL --retry 3 https://dl.cloudsmith.io/public/caddy/stable/gpg.key -o "$work/caddy.asc"
gpg --batch --yes --dearmor -o "$work/caddy.gpg" "$work/caddy.asc"
install -m 0644 "$work/caddy.gpg" /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -fsSL --retry 3 https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt -o "$work/caddy.list"
install -m 0644 "$work/caddy.list" /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y caddy

# Ubuntu's golang-go may be older than the project's Go 1.26 minimum.
# Stay on the project's Go 1.26 line: the pinned linter must understand
# the compiler's export format. Verify the selected patch release SHA-256.
case "$(dpkg --print-architecture)" in
  amd64) ans_arch=amd64 ;;
  arm64) ans_arch=arm64 ;;
  *) echo "Supported server architectures: amd64 and arm64" >&2; exit 1 ;;
esac
curl -fsSL --retry 3 'https://go.dev/dl/?mode=json' -o "$work/releases.json"
ans_version=$(jq -er '[.[] | select(.stable == true and (.version | startswith("go1.26.")))][0].version' "$work/releases.json")
if [[ ! $ans_version =~ ^go1\.26\.[0-9]+$ ]]; then
  echo "No supported Go 1.26 patch release found in the upstream release index." >&2
  exit 1
fi
ans_archive=$(jq -er --arg v "$ans_version" --arg a "$ans_arch" \
  '.[] | select(.version == $v) | .files[] | select(.os == "linux" and .arch == $a and .kind == "archive") | .filename' "$work/releases.json")
ans_sha=$(jq -er --arg v "$ans_version" --arg f "$ans_archive" \
  '.[] | select(.version == $v) | .files[] | select(.filename == $f) | .sha256' "$work/releases.json")
curl -fsSL --retry 3 "https://go.dev/dl/$ans_archive" -o "$work/$ans_archive"
(cd "$work" && printf '%s  %s\n' "$ans_sha" "$ans_archive" | sha256sum --check --status)
tar -C "$work" -xzf "$work/$ans_archive"
install -d -m 0755 /opt/ans-toolchains
if [[ ! -e /opt/ans-toolchains/$ans_version ]]; then
  mv "$work/go" "/opt/ans-toolchains/$ans_version"
fi
ln -sfn "/opt/ans-toolchains/$ans_version/bin/go" /usr/local/bin/go
ln -sfn "/opt/ans-toolchains/$ans_version/bin/gofmt" /usr/local/bin/gofmt
/usr/local/bin/go version
caddy version

echo "Packages installed. Follow deploy/ubuntu/README.md to build and configure RA/TL."
