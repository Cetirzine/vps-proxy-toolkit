#!/usr/bin/env python3
"""Install verified Hysteria 2 QUIC services alongside the toolkit's Xray endpoint."""
import argparse
import json
import math

from common import PRIVATE, fetch_private_file, load_settings, remote


REMOTE = r'''
import hashlib, json, os, platform, subprocess, urllib.request
from datetime import datetime, timezone
from pathlib import Path

settings = json.loads(__SETTINGS__)
mode = __MODE__
obfs_password = __OBFS_PASSWORD__
host4 = settings["server_ipv4"]
host6 = settings.get("server_ipv6")
allow_existing = settings.get("allow_existing", False)
limits = settings.get("hysteria", {})

def run(*args):
    subprocess.run(args, check=True)

def write(path, content, mode_bits=0o644):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    p.chmod(mode_bits)

if os.geteuid() != 0:
    raise RuntimeError("Run this deployment as root")
release_info = Path("/etc/os-release").read_text()
if 'VERSION_ID="24.04"' not in release_info or platform.machine() not in ("x86_64", "amd64"):
    raise RuntimeError("This installer supports Ubuntu 24.04 amd64 only")
toolkit = Path("/root/vps-proxy-toolkit")
credentials_path = toolkit / "credentials.json"
if not credentials_path.exists():
    raise RuntimeError("Deploy the toolkit Trojan endpoint first to create its shared credentials and certificate")
credentials = json.loads(credentials_path.read_text())
if credentials.get("server_ipv4") != host4 or credentials.get("server_ipv6") != host6:
    raise RuntimeError("Toolkit credentials target different server IPs")
if not Path("/etc/letsencrypt/live/vps-proxy-ip/fullchain.pem").exists():
    raise RuntimeError("The toolkit IP certificate is missing")

services = []
if mode in ("primary", "both"):
    services.append({"name":"primary", "unit":"hysteria", "config":"config.json", "port":443,
        "listen":":443", "limit":limits.get("primary", {})})
if mode in ("fast", "both"):
    if not host6:
        raise RuntimeError("Fast IPv6 mode requires server_ipv6 in project.json")
    services.append({"name":"fast", "unit":"hysteria-fast", "config":"fast.json", "port":8443,
        "listen":"[::]:8443", "limit":limits.get("fast", {})})

for item in services:
    for key in ("upload_mbps", "download_mbps"):
        value = item["limit"].get(key)
        if not isinstance(value, (int, float)) or value <= 0 or value > 10000:
            raise RuntimeError(f"Configure a valid positive {key} value for hysteria.{item['name']}")
    config_path = Path("/usr/local/etc/hysteria") / item["config"]
    marker = Path(f"/root/vps-proxy-toolkit/hysteria-{item['name']}-managed")
    unit_path = Path(f"/etc/systemd/system/{item['unit']}.service")
    unmanaged = [p for p in (config_path, unit_path) if p.exists()]
    if unmanaged and not marker.exists() and not allow_existing:
        raise RuntimeError(f"An unmanaged Hysteria config or service exists for mode {item['name']}; set allow_existing=true after reviewing it")
    if unmanaged and not marker.exists() and allow_existing:
        import shutil
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        for path in unmanaged:
            shutil.copy2(path, path.with_name(f"{path.name}.pre-toolkit-{stamp}"))

req = urllib.request.Request("https://api.github.com/repos/apernet/hysteria/releases/latest", headers={"User-Agent":"vps-proxy-toolkit"})
release = json.load(urllib.request.urlopen(req, timeout=30))
asset = next(a for a in release["assets"] if a["name"] == "hysteria-linux-amd64")
digest = asset.get("digest", "")
if not digest.startswith("sha256:"):
    raise RuntimeError("Hysteria release has no SHA256 digest; installation stopped")
data = urllib.request.urlopen(asset["browser_download_url"], timeout=120).read()
if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
    raise RuntimeError("Hysteria release SHA256 mismatch")
binary = Path("/usr/local/bin/hysteria")
candidate = binary.with_name(".hysteria.download")
candidate.write_bytes(data)
candidate.chmod(0o755)
candidate.replace(binary)
run("id", "xray")
directory = Path("/usr/local/etc/hysteria")
directory.mkdir(exist_ok=True, parents=True)
directory.chmod(0o750)
run("chown", "root:xray", str(directory))

for item in services:
    config = {
        "listen":item["listen"],
        "tls":{"cert":"/usr/local/etc/xray/fullchain.pem", "key":"/usr/local/etc/xray/privkey.pem"},
        "bandwidth":{"up":f"{item['limit']['upload_mbps']} mbps", "down":f"{item['limit']['download_mbps']} mbps"},
        "auth":{"type":"password", "password":credentials["password"]},
        "resolver":{"type":"https", "https":{"addr":"1.1.1.1:443", "sni":"cloudflare-dns.com", "insecure":False, "timeout":"5s"}},
        "outbounds":[{"name":"direct", "type":"direct", "direct":{"mode":"4", "bindIPv4":host4}}],
        "acl":{"inline":["reject(0.0.0.0/8)", "reject(10.0.0.0/8)", "reject(127.0.0.0/8)", "reject(169.254.0.0/16)",
            "reject(172.16.0.0/12)", "reject(192.168.0.0/16)", "reject(::/128)", "reject(::1/128)", "reject(fc00::/7)",
            "reject(fe80::/10)", "reject(ff00::/8)"]},
        "masquerade":{"type":"string", "string":{"content":"Service available\n", "statusCode":200,
            "headers":{"content-type":"text/plain"}}}}
    if item["name"] == "fast" and obfs_password:
        config["obfs"] = {"type":"salamander", "salamander":{"password":obfs_password}}
    config_path = directory / item["config"]
    write(str(config_path), json.dumps(config, indent=2)+"\n", 0o640)
    run("chown", "root:xray", str(config_path))
    marker = Path(f"/root/vps-proxy-toolkit/hysteria-{item['name']}-managed")
    write(str(marker), "Managed by vps-proxy-toolkit.\n", 0o600)
    unit = item["unit"]
    write(f"/etc/systemd/system/{unit}.service", f"""[Unit]
Description=vps-proxy-toolkit Hysteria 2 {item['name']} endpoint
After=network-online.target xray.service
Wants=network-online.target

[Service]
User=xray
Group=xray
ExecStart=/usr/local/bin/hysteria server -c /usr/local/etc/hysteria/{item['config']}
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

write("/etc/sysctl.d/90-vps-proxy-toolkit-network.conf", """# Preserve BBR/fq; allow path-MTU recovery and larger QUIC socket buffers.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv6.bindv6only = 0
""")
run("sysctl", "-p", "/etc/sysctl.d/90-vps-proxy-toolkit-network.conf")
run("systemctl", "daemon-reload")
for item in services:
    run("systemctl", "enable", "--now", item["unit"])
    run("systemctl", "restart", item["unit"])
run("/usr/local/bin/hysteria", "version")
manifest = {"version":release["tag_name"], "sha256":digest, "download_url":asset["browser_download_url"],
    "modes":[{"name":x["name"], "unit":x["unit"], "port":x["port"], "listen":x["listen"], "upload_mbps":x["limit"]["upload_mbps"],
        "download_mbps":x["limit"]["download_mbps"], "salamander":bool(x["name"] == "fast" and obfs_password)} for x in services]}
write(str(toolkit / "hysteria-deployment.json"), json.dumps(manifest, indent=2)+"\n", 0o600)
print("Hysteria deployment completed; no credentials were printed")
'''


def positive_rate(settings, mode, key):
    value = settings.get("hysteria", {}).get(mode, {}).get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 or value > 10000:
        raise ValueError(f"Set hysteria.{mode}.{key} to a number from 0 to 10000")


def write_optimized_nodes(settings, credentials, mode, obfs_password):
    blueprint_path = PRIVATE / "optimized-nodes.json"
    previous = json.loads(blueprint_path.read_text()) if blueprint_path.exists() else {"nodes": []}
    prior_nodes = previous.get("nodes", [])
    ipv4, ipv6 = credentials["server_ipv4"], credentials.get("server_ipv6")

    def has_endpoint(kind, address, port):
        return any(n.get("type") == kind and n.get("server") == address and int(n.get("port", -1)) == port
            for n in prior_nodes if isinstance(n, dict))

    keep_primary = mode in ("primary", "both") or has_endpoint("hysteria2", ipv4, 443)
    keep_fast = bool(ipv6) and (mode in ("fast", "both") or has_endpoint("hysteria2", ipv6, 8443))
    nodes = []
    if keep_fast:
        fast = {"name":"VPS-IPv6-Fast-Hysteria2", "type":"hysteria2", "server":ipv6, "port":8443,
            "sni":ipv6,
            # Client download maps to server upload; client upload maps to server download.
            "download_mbps":settings["hysteria"]["fast"]["upload_mbps"],
            "upload_mbps":settings["hysteria"]["fast"]["download_mbps"]}
        if mode in ("fast", "both"):
            if obfs_password:
                fast["obfs_password"] = obfs_password
        else:
            old = next((n for n in prior_nodes if n.get("type") == "hysteria2" and n.get("server") == ipv6
                and int(n.get("port", -1)) == 8443), {})
            if old.get("obfs_password"):
                fast["obfs_password"] = old["obfs_password"]
        nodes.append(fast)
    if ipv6:
        nodes.append({"name":"VPS-Trojan-IPv6", "type":"trojan", "server":ipv6, "port":443, "sni":ipv6})
    if keep_primary:
        nodes.append({"name":"VPS-Primary-Hysteria2", "type":"hysteria2", "server":ipv4, "port":443,
            "sni":ipv4, "download_mbps":settings["hysteria"]["primary"]["upload_mbps"],
            "upload_mbps":settings["hysteria"]["primary"]["download_mbps"]})
    nodes.append({"name":"VPS-Trojan-IPv4", "type":"trojan", "server":ipv4, "port":443, "sni":ipv4})

    known = {("hysteria2", ipv4, 443), ("trojan", ipv4, 443)}
    if ipv6:
        known.update({("hysteria2", ipv6, 8443), ("trojan", ipv6, 443)})
    extras = [n for n in prior_nodes if isinstance(n, dict)
        and (n.get("type"), n.get("server"), int(n.get("port", -1))) not in known]
    nodes.extend(extras)
    payload = dict(previous)
    payload["nodes"] = nodes
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    blueprint_path.write_text(json.dumps(payload, indent=2) + "\n")
    blueprint_path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", nargs="?", choices=("primary", "fast", "both"), default="primary",
        help="primary: IPv4/dual-stack UDP 443; fast: IPv6 dual-stack UDP 8443; both: install both modes")
    args = parser.parse_args()
    settings = load_settings()
    if args.mode in ("fast", "both") and not settings.get("server_ipv6"):
        parser.error("fast and both modes require server_ipv6 in project.json")
    modes = ("primary", "fast") if args.mode == "both" else (args.mode,)
    for mode in modes:
        positive_rate(settings, mode, "upload_mbps")
        positive_rate(settings, mode, "download_mbps")
    obfs_password = ""
    if "fast" in modes:
        path = PRIVATE / "hysteria-fast-obfs-password.txt"
        if path.exists():
            obfs_password = path.read_text().strip()
            if len(obfs_password) < 4 or "\n" in obfs_password or "\r" in obfs_password:
                raise ValueError("private/hysteria-fast-obfs-password.txt must contain one Salamander password of at least 4 characters")
    code = REMOTE.replace("__SETTINGS__", repr(json.dumps(settings)))
    code = code.replace("__MODE__", repr(args.mode)).replace("__OBFS_PASSWORD__", repr(obfs_password))
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    remote(code)
    raw = fetch_private_file("/root/vps-proxy-toolkit/credentials.json", PRIVATE / "credentials.json")
    credentials = json.loads(raw)
    credentials["server"] = credentials["server_ipv4"]
    credentials.setdefault("port", 443)
    credentials.setdefault("protocol", "trojan")
    local_credentials = PRIVATE / "credentials.json"
    local_credentials.write_text(json.dumps(credentials, indent=2) + "\n")
    local_credentials.chmod(0o600)
    write_optimized_nodes(settings, credentials, args.mode, obfs_password)


if __name__ == "__main__":
    main()
