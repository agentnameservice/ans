#!/usr/bin/env bash
# Read only the RA public signer key; register it through the private TL admin API.
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo bash deploy/ubuntu/bootstrap-trust.sh" >&2
  exit 1
fi
python3 - <<'PY'
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
import yaml

ra = yaml.safe_load(Path('/etc/ans/ra.yaml').read_text())
tl = yaml.safe_load(Path('/etc/ans/tl.yaml').read_text())
kid = ra['signer']['keyId']
if not kid or Path(kid).name != kid or kid in ('.', '..'):
    raise SystemExit('RA signer keyId is not a safe key filename')
entry = {
    'key_id': kid,
    'ra_id': ra['signer']['raId'],
    'algorithm': 'ES256',
    'public_key_pem': (Path(ra['keys']['file']['path']) / (kid + '.pub')).read_text(),
}
if tl['server']['host'] != '127.0.0.1':
    raise SystemExit('Bootstrap requires the documented loopback TL listener')
base = f"http://127.0.0.1:{int(tl['server']['port'])}/internal/v1/producer-keys"
# Neither environment proxies nor redirects may receive the administrator key.
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
def request(method, url, body=None):
    req = urllib.request.Request(url, method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={'Authorization': 'Bearer ' + tl['auth']['static']['api-key'],
                 'Content-Type': 'application/json'})
    try:
        with opener.open(req, timeout=15) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        with error:
            # Do not echo arbitrary server bodies or credential-bearing requests.
            return error.code, None
    except urllib.error.URLError:
        raise SystemExit('Cannot reach the loopback TL; check readiness and its journal') from None
url = base + '/' + urllib.parse.quote(kid, safe='')
status, existing = request('GET', url)
if status == 404:
    now = datetime.now(timezone.utc)
    body = dict(entry, valid_from=now.isoformat(), expires_at=(now + timedelta(days=3650)).isoformat())
    status, _ = request('POST', base, body)
    if status not in (200, 409):
        raise SystemExit(f'TL producer-key creation failed with HTTP {status}')
    status, existing = request('GET', url)
if status != 200:
    raise SystemExit(f'TL producer-key lookup failed with HTTP {status}')
for field, expected in entry.items():
    if str(existing.get(field, '')).strip() != expected.strip():
        raise SystemExit(f'Existing producer key differs in {field}; investigate before changing trust')
now = datetime.now(timezone.utc)
if existing.get('status') != 'active' or not (
        datetime.fromisoformat(existing['valid_from'].replace('Z', '+00:00')) <= now <
        datetime.fromisoformat(existing['expires_at'].replace('Z', '+00:00'))):
    raise SystemExit('Existing producer key is revoked or outside its validity interval; rotate deliberately')
print('RA public signer key is active in the TL trust store. No TL restart required.')
PY
