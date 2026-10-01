#!/usr/bin/env python3
"""Install a verified Xray Trojan endpoint on a fresh Ubuntu 24.04 VPS."""
import argparse
import json

from common import ROOT, PRIVATE, fetch_private_file, load_settings, remote


REMOTE = r'''
import hashlib, io, json, os, platform, re, secrets, shutil, subprocess, urllib.request, zipfile
from datetime import datetime, timezone
from pathlib import Path

settings = json.loads(__SETTINGS__)
allow_existing = settings.get("allow_existing", False)
host4 = settings["server_ipv4"]
host6 = settings.get("server_ipv6")

def run(*args):
    subprocess.run(args, check=True)

def write(path, content, mode=0o644):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    p.chmod(mode)

if os.geteuid() != 0:
    raise RuntimeError("Run this deployment as root")
release_info = Path("/etc/os-release").read_text()
if 'VERSION_ID="24.04"' not in release_info or platform.machine() not in ("x86_64", "amd64"):
    raise RuntimeError("This installer supports Ubuntu 24.04 amd64 only")

toolkit = Path("/root/vps-proxy-toolkit")
toolkit.mkdir(mode=0o700, parents=True, exist_ok=True)
toolkit.chmod(0o700)
managed_marker = toolkit / "xray-managed"
config_dir = Path("/usr/local/etc/xray")
config_path = config_dir / "config.json"
xray_unit = Path("/etc/systemd/system/xray.service")
xray_existing = [p for p in (config_path, xray_unit) if p.exists()]
if xray_existing and not managed_marker.exists() and not allow_existing:
    raise RuntimeError("An unmanaged Xray config or service exists; set allow_existing=true after reviewing it")
if xray_existing and not managed_marker.exists() and allow_existing:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for path in xray_existing:
        shutil.copy2(path, path.with_name(f"{path.name}.pre-toolkit-{stamp}"))

nginx_default = Path("/etc/nginx/sites-available/default")
nginx_custom = []
if nginx_default.exists():
    content = nginx_default.read_text()
    stock_tokens = ("listen 80 default_server;", "listen [::]:80 default_server;", "root /var/www/html;",
        "server_name _;", "try_files $uri $uri/ =404;")
    is_stock = all(token in content for token in stock_tokens) and not any(token in content for token in ("proxy_pass", "upstream "))
    if "vps-proxy-toolkit" not in content and not is_stock:
        nginx_custom.append(nginx_default)
for path in list(Path("/etc/nginx/sites-enabled").glob("*")) if Path("/etc/nginx/sites-enabled").exists() else []:
    if path.name == "default":
        continue
    try:
        if "vps-proxy-toolkit" not in path.read_text():
            nginx_custom.append(path)
    except OSError:
        nginx_custom.append(path)
for path in Path("/etc/nginx/conf.d").glob("*.conf") if Path("/etc/nginx/conf.d").exists() else []:
    try:
        if "vps-proxy-toolkit" not in path.read_text():
            nginx_custom.append(path)
    except OSError:
        nginx_custom.append(path)
if nginx_custom and not allow_existing:
    raise RuntimeError("Custom nginx configuration exists; set allow_existing=true after reviewing it")

run("apt-get", "update")
run("apt-get", "install", "-y", "nginx", "python3-venv", "ca-certificates")
certbot_venv = Path("/opt/certbot")
if not certbot_venv.exists():
    run("python3", "-m", "venv", str(certbot_venv))
run(str(certbot_venv / "bin/pip"), "install", "--upgrade", "pip", "certbot>=5.4")
version_text = subprocess.check_output([str(certbot_venv / "bin/certbot"), "--version"], text=True)
match = re.search(r"(\d+)\.(\d+)", version_text)
if not match or tuple(map(int, match.groups())) < (5, 4):
    raise RuntimeError("Certbot 5.4 or newer is required")

if nginx_default.exists():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = nginx_default.with_name(f"default.pre-vps-proxy-toolkit-{stamp}")
    shutil.copy2(nginx_default, backup)
write(str(nginx_default), """# Managed by vps-proxy-toolkit.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ { root /var/www/html; }
    location / { default_type text/plain; return 200 \"Service available\\n\"; }
}
""")
run("nginx", "-t")
run("systemctl", "enable", "--now", "nginx")
run("systemctl", "reload", "nginx")

cert_args = [str(certbot_venv / "bin/certbot"), "certonly", "--non-interactive", "--agree-tos",
    "--register-unsafely-without-email", "--preferred-profile", "shortlived", "--webroot", "--webroot-path", "/var/www/html",
    "--cert-name", "vps-proxy-ip", "--key-type", "ecdsa", "--ip-address", host4]
if host6:
    cert_args.extend(["--ip-address", host6])
run(*cert_args)

if subprocess.run(["id", "xray"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
    run("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "xray")
req = urllib.request.Request("https://api.github.com/repos/XTLS/Xray-core/releases/latest", headers={"User-Agent":"vps-proxy-toolkit"})
release = json.load(urllib.request.urlopen(req, timeout=30))
asset = next(a for a in release["assets"] if a["name"] == "Xray-linux-64.zip")
digest = asset.get("digest", "")
if not digest.startswith("sha256:"):
    raise RuntimeError("Xray release has no SHA256 digest; installation stopped")
blob = urllib.request.urlopen(asset["browser_download_url"], timeout=120).read()
if hashlib.sha256(blob).hexdigest() != digest.split(":", 1)[1]:
    raise RuntimeError("Xray release SHA256 mismatch")
binary = Path("/usr/local/bin/xray")
candidate = binary.with_name(".xray.download")
candidate.write_bytes(zipfile.ZipFile(io.BytesIO(blob)).read("xray"))
candidate.chmod(0o755)
candidate.replace(binary)

credentials_path = toolkit / "credentials.json"
if credentials_path.exists():
    credentials = json.loads(credentials_path.read_text())
    if credentials.get("server_ipv4") != host4 or credentials.get("server_ipv6") != host6:
        raise RuntimeError("Existing toolkit credentials target different server IPs")
else:
    credentials = {"server_ipv4":host4, "server_ipv6":host6, "port":443,
        "protocol":"trojan", "password":secrets.token_urlsafe(32)}
    write(str(credentials_path), json.dumps(credentials, indent=2)+"\n", 0o600)
credentials_path.chmod(0o600)

config_dir.mkdir(parents=True, exist_ok=True)
config_dir.chmod(0o750)
run("chown", "root:xray", str(config_dir))
write("/usr/local/sbin/vps-proxy-renew-certificate", """#!/bin/sh
set -eu
install -o root -g xray -m 0640 /etc/letsencrypt/live/vps-proxy-ip/fullchain.pem /usr/local/etc/xray/fullchain.pem.new
install -o root -g xray -m 0640 /etc/letsencrypt/live/vps-proxy-ip/privkey.pem /usr/local/etc/xray/privkey.pem.new
mv /usr/local/etc/xray/fullchain.pem.new /usr/local/etc/xray/fullchain.pem
mv /usr/local/etc/xray/privkey.pem.new /usr/local/etc/xray/privkey.pem
if systemctl is-active --quiet xray; then systemctl restart xray; fi
""", 0o750)
run("/usr/local/sbin/vps-proxy-renew-certificate")

config = {
    "log":{"loglevel":"warning"},
    "dns":{"servers":["https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query"], "queryStrategy":"UseIPv4"},
    "inbounds":[{"tag":"trojan-in", "listen":"::", "port":443, "protocol":"trojan",
        "settings":{"clients":[{"password":credentials["password"], "email":"vps-proxy-toolkit"}], "fallbacks":[{"dest":80}]},
        "streamSettings":{"network":"tcp", "security":"tls", "tlsSettings":{
            "minVersion":"1.2", "alpn":["http/1.1"], "certificates":[{
                "certificateFile":"/usr/local/etc/xray/fullchain.pem", "keyFile":"/usr/local/etc/xray/privkey.pem"}]}}}],
    "outbounds":[{"tag":"direct", "protocol":"freedom", "streamSettings":{"sockopt":{"domainStrategy":"ForceIPv4"}}},
        {"tag":"block", "protocol":"blackhole"}],
    "routing":{"rules":[{"type":"field", "ip":["0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"],
        "outboundTag":"block"}]}}
write(str(config_path), json.dumps(config, indent=2)+"\n", 0o640)
run("chown", "root:xray", str(config_path))
run("/usr/local/bin/xray", "run", "-test", "-config", str(config_path))
write(str(managed_marker), "Managed by vps-proxy-toolkit.\n", 0o600)

write("/etc/systemd/system/xray.service", """[Unit]
Description=vps-proxy-toolkit Trojan TLS proxy
After=network-online.target nginx.service
Wants=network-online.target

[Service]
User=xray
Group=xray
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
LimitNOFILE=65536
MemoryMax=512M

[Install]
WantedBy=multi-user.target
""")
write("/etc/systemd/system/vps-proxy-cert-renew.service", """[Unit]
Description=Renew vps-proxy-toolkit IP TLS certificate
After=network-online.target nginx.service

[Service]
Type=oneshot
ExecStart=/opt/certbot/bin/certbot renew --quiet --deploy-hook /usr/local/sbin/vps-proxy-renew-certificate
""")
write("/etc/systemd/system/vps-proxy-cert-renew.timer", """[Unit]
Description=Check vps-proxy-toolkit certificate renewal every six hours

[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
""")
run("systemctl", "daemon-reload")
run("systemctl", "enable", "--now", "xray", "vps-proxy-cert-renew.timer")
run("systemctl", "restart", "xray")
manifest = {"xray_version":release["tag_name"], "asset_sha256":digest, "download_url":asset["browser_download_url"],
    "server_ipv4":host4, "server_ipv6":host6, "port":443, "certificate_name":"vps-proxy-ip",
    "certificate_renewal":"every six hours"}
write(str(toolkit / "deployment.json"), json.dumps(manifest, indent=2)+"\n", 0o600)
print("Trojan deployment completed; credentials are stored in /root/vps-proxy-toolkit/credentials.json")
'''


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    settings = load_settings()
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    code = REMOTE.replace("__SETTINGS__", repr(json.dumps(settings)))
    remote(code)
    raw = fetch_private_file("/root/vps-proxy-toolkit/credentials.json", PRIVATE / "credentials.json")
    credentials = json.loads(raw)
    credentials["server"] = credentials["server_ipv4"]
    credentials.setdefault("port", 443)
    credentials.setdefault("protocol", "trojan")
    path = PRIVATE / "credentials.json"
    path.write_text(json.dumps(credentials, indent=2) + "\n")
    path.chmod(0o600)
    fetch_private_file("/root/vps-proxy-toolkit/deployment.json", PRIVATE / "deployment.json")


if __name__ == "__main__":
    main()
