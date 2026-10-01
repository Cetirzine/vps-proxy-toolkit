#!/usr/bin/env python3
"""Publish private, HTTPS-only client subscriptions on the user's own VPS."""
import base64
import gzip
import json
import os
import secrets
import re
import subprocess
from pathlib import Path
from common import load_settings, remote

ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / "private"
STATE = PRIVATE / "subscriptions.json"

def private_write(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)

def main():
    settings = load_settings()
    host = settings["server_ipv4"]
    token = json.loads(STATE.read_text())["token"] if STATE.exists() else secrets.token_urlsafe(32)
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
        raise ValueError("Invalid subscription token")
    prefix = f"https://{host}/s/{token}"
    links = {"Surge":prefix+"/Surge.conf", "Shadowrocket_nodes":prefix+"/Shadowrocket.txt",
        "Shadowrocket_rules":prefix+"/Shadowrocket.conf", "Clash_Mihomo":prefix+"/Clash.yaml", "Clash_Legacy":prefix+"/Clash-Legacy.yaml"}
    files = {
        "Surge.conf": f"#!MANAGED-CONFIG {links['Surge']} interval=86400 strict=false\n"+(PRIVATE/"VPS-Surge.conf").read_text(),
        "Shadowrocket.conf":(PRIVATE/"VPS-Shadowrocket.conf").read_text(),
        "Clash.yaml":(PRIVATE/"VPS-Clash-Mihomo.yaml").read_text(),
        "Clash-Legacy.yaml":(PRIVATE/"VPS-Clash-Legacy.yaml").read_text(),
    }
    node_list=(PRIVATE/"Shadowrocket-nodes.txt").read_text().strip()+"\n"
    files["Shadowrocket.txt"] = base64.b64encode(node_list.encode()).decode()+"\n"
    private_write(STATE,json.dumps({"token":token,"links":links},indent=2)+"\n")
    payload=base64.b64encode(gzip.compress(json.dumps({"token":token,"files":files}).encode())).decode()
    remote_code = r'''
import base64,gzip,json,subprocess
from pathlib import Path
from common import load_settings, remote
payload=json.loads(gzip.decompress(base64.b64decode(PAYLOAD)))
root=Path("/var/lib/vps-proxy-subscriptions");root.mkdir(exist_ok=True);root.chmod(0o750)
subprocess.run(["chown","root:www-data",str(root)],check=True)
for name,content in payload["files"].items():
    p=root/name;p.write_text(content);p.chmod(0o640)
    subprocess.run(["chown","root:www-data",str(p)],check=True)
nginx="""# Managed by vps-proxy-toolkit
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ { root /var/www/html; }
    location ^~ /s/TOKEN/ {
        allow 127.0.0.1;
        allow ::1;
        deny all;
        alias /var/lib/vps-proxy-subscriptions/;
        autoindex off;
        default_type text/plain;
        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options "nosniff" always;
    }
    location / { default_type text/plain; return 200 "Service available\\n"; }
}
""".replace("TOKEN",payload["token"])
p=Path("/etc/nginx/sites-available/default");original=p.read_text()
if not Path("/root/vps-proxy-toolkit/credentials.json").exists(): raise SystemExit("Run toolkit deployment first")
p.write_text(nginx)
if subprocess.run(["nginx","-t"]).returncode:
    p.write_text(original);raise SystemExit("Nginx validation failed; previous config restored")
subprocess.run(["systemctl","reload","nginx"],check=True)
Path("/root/vps-proxy-subscriptions-token").write_text(payload["token"]+"\n")
Path("/root/vps-proxy-subscriptions-token").chmod(0o600)
validator=Path("/root/proxy-config-validation/mihomo")
if validator.exists():
    for name in ["Clash.yaml","Clash-Legacy.yaml"]:
        subprocess.run([str(validator),"-t","-d","/root/proxy-config-validation","-f",str(root/name)],check=True)
print("HTTPS subscriptions published; plaintext access denied")
'''.replace("PAYLOAD",repr(payload))
    remote(remote_code)
    private_write(STATE,json.dumps({"token":token,"links":links},indent=2)+"\n")
    private_write(PRIVATE/"Surge-managed.conf",files["Surge.conf"])
    print("Subscription URLs saved in private/subscriptions.json (not printed)")

if __name__ == "__main__":
    main()
