"""Bootstrap for the public demo web tier VX1.

The web tier serves site/live.html over self-signed HTTPS on 443, and proxies
/api/* to the control VM over NetBird (the web-tier group is only granted TCP
8000 to cerberus-control). No Vultr keys live on this host -- only the demo
password, the web cookie secret, the control bearer and its NetBird setup key.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import shlex
import zlib


def web_tier_user_data(repo_sha, netbird_setup_key, control_token, demo_password, web_secret=None, progress_form=None):
    if progress_form is not None:
        from instance_lifecycle import validated_presigned_nic_post

        validated_presigned_nic_post(progress_form)
    reporter = _progress_reporter(progress_form) if progress_form is not None else ""
    if web_secret is None:
        web_secret = secrets.token_urlsafe(48)
    if not isinstance(repo_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", repo_sha):
        raise ValueError("A pinned 40-hex commit is required")
    for name, value in (("setup key", netbird_setup_key), ("control token", control_token), ("demo password", demo_password), ("web secret", web_secret)):
        if not isinstance(value, str) or not value or len(value) > 512 or not value.isprintable() or any(c in value for c in "'\"\\$\n"):
            raise ValueError(f"{name} cannot be embedded safely")
    env_body = "\n".join([
        "CERBERUS_CONTROL_URL=http://100.124.55.15:8000",
        f"CERBERUS_CONTROL_TOKEN={control_token}",
        f"CERBERUS_DEMO_PASSWORD={demo_password}",
        f"CERBERUS_WEB_SECRET={web_secret}",
    ])
    return f"""#!/bin/sh
set -eu
systemctl stop ssh.socket ssh.service || :
systemctl mask ssh.socket ssh.service || :
export DEBIAN_FRONTEND=noninteractive HOME=/root
{reporter}apt-get update -q && apt-get install -y -q python3-venv curl ca-certificates openssl git-core 2>&1 | tail -1
cerberus_progress packages_ready || :
curl -fsSL https://install.netbird.io | sh >/root/netbird-install.log 2>&1
netbird up --setup-key {shlex.quote(netbird_setup_key)} >>/root/netbird-install.log 2>&1
for i in $(seq 1 20); do netbird status --check ready >/dev/null 2>&1 && break; sleep 3; done
netbird status --check ready
cerberus_progress netbird_ready || :
mkdir -p /etc/cerberus-web /opt/cerberus-web
umask 077
cat > /etc/cerberus-web/web.env <<'WEBENV'
{env_body}
WEBENV
chmod 600 /etc/cerberus-web/web.env
git clone --quiet --depth 50 https://github.com/Preet37/VultrHack /opt/cerberus-web/app
cd /opt/cerberus-web/app && git checkout -q {repo_sha}
python3 -m venv /opt/cerberus-web/venv
/opt/cerberus-web/venv/bin/pip install -q fastapi==0.136.3 uvicorn==0.38.0 httpx==0.28.1 python-dotenv==1.2.1
cerberus_progress code_ready || :
openssl req -x509 -newkey rsa:2048 -keyout /etc/cerberus-web/tls.key -out /etc/cerberus-web/tls.crt -days 365 -nodes -subj '/CN=cerberus-demo' >/dev/null 2>&1
cat > /etc/systemd/system/cerberus-web.service <<'UNIT'
[Unit]
Description=Cerberus demo web tier
After=network-online.target netbird.service

[Service]
WorkingDirectory=/opt/cerberus-web/app
EnvironmentFile=/etc/cerberus-web/web.env
ExecStart=/opt/cerberus-web/venv/bin/uvicorn web_proxy:app --host 0.0.0.0 --port 443 --ssl-keyfile /etc/cerberus-web/tls.key --ssl-certfile /etc/cerberus-web/tls.crt
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now cerberus-web
cerberus_progress service_started || :
if command -v ufw >/dev/null 2>&1; then
  ufw default deny incoming || :
  ufw allow in on wt0 || :
  ufw allow 443/tcp || :
  yes | ufw enable || :
fi
cerberus_progress firewall_done || :
"""


def _progress_reporter(form):
    encoded = base64.b64encode(json.dumps(form, separators=(",", ":")).encode()).decode()
    return f"""cerberus_progress() {{
  python3 - {shlex.quote("-")} "$1" {shlex.quote(encoded)} <<'PPY'
import base64,json,secrets,sys,urllib.request as u
form=json.loads(base64.b64decode(sys.argv[2]))
boundary='cerberus'+secrets.token_hex(8)
parts=[]
for name,value in form['fields'].items():
    parts.append((f'--{{boundary}}\\r\\nContent-Disposition: form-data; name="{{name}}"\\r\\n\\r\\n{{value}}\\r\\n').encode())
parts.append((f'--{{boundary}}\\r\\nContent-Disposition: form-data; name="file"; filename="progress.json"\\r\\nContent-Type: application/json\\r\\n\\r\\n').encode())
parts.append(json.dumps({{"probe":sys.argv[1],"vpc_ip":None}}).encode())
parts.append((f'\\r\\n--{{boundary}}--\\r\\n').encode())
body=b''.join(parts)
try:
    if len(body)<=4096:u.urlopen(u.Request(form['url'],body,{{'Content-Type':'multipart/form-data; boundary='+boundary}}),timeout=5).close()
except Exception:pass
PPY
}}
cerberus_progress bootstrap_started || :
"""


def build_create_web_tier_payload(user_data, region, plan):
    if not re.fullmatch(r"[a-z]{3}", region):
        raise ValueError("region must be a short code")
    if not isinstance(plan, str) or not re.fullmatch(r"[a-z0-9-]{2,48}", plan) or not plan.endswith("gb"):
        raise ValueError("plan must be a small cloud compute plan")
    return {
        "region": region,
        "plan": plan,
        "os_id": 2284,
        "label": "cerberus-web",
        "tags": ["cerberus-web"],
        "user_data": base64.b64encode(user_data.encode()).decode(),
    }
