#!/usr/bin/env bash
# Install first-time configuration; existing secrets/configuration are never replaced.
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo bash deploy/ubuntu/install-config.sh" >&2
  exit 1
fi
ans_templates=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python3 - "$ans_templates" <<'PY'
import grp
import os
from pathlib import Path
import secrets
import sys

key = secrets.token_hex(32)
prepared = []
for name, group in [('ra', 'ans-ra'), ('tl', 'ans-tl')]:
    dest = Path('/etc/ans') / (name + '.yaml')
    if dest.exists() or dest.is_symlink():
        raise SystemExit(f'{dest} exists; preserve its secret and edit deliberately')
    text = (Path(sys.argv[1]) / (name + '.yaml')).read_text()
    if text.count('__TL_SERVICE_KEY__') != 1:
        raise SystemExit(f'{name}.yaml must contain exactly one service-secret marker')
    prepared.append((dest, grp.getgrnam(group).gr_gid, text.replace('__TL_SERVICE_KEY__', key)))
created = []
try:
    for dest, gid, text in prepared:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        created.append(dest)
        with os.fdopen(fd, 'w') as stream:
            os.fchown(stream.fileno(), 0, gid)
            os.fchmod(stream.fileno(), 0o640)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
except BaseException:
    for dest in created:
        dest.unlink()
    raise
print('Installed RA/TL configurations with one generated service secret.')
PY
