#!/usr/bin/env python3
"""Shared configuration and SSH helpers for vps-proxy-toolkit."""
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / "private"


def load_settings():
    """Load local project.json (or VPS_PROXY_CONFIG) and validate its endpoints."""
    configured = os.environ.get("VPS_PROXY_CONFIG")
    path = Path(configured).expanduser() if configured else ROOT / "project.json"
    if not path.is_absolute():
        path = ROOT / path
    try:
        settings = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"Configuration not found: {path}. Copy project.example.json to project.json and edit it."
        ) from exc
    if not isinstance(settings, dict):
        raise ValueError("Project configuration must be a JSON object")
    for key in ("server_ipv4", "ssh_target"):
        if not isinstance(settings.get(key), str) or not settings[key].strip():
            raise ValueError(f"Missing required project setting: {key}")
    try:
        ipv4 = ipaddress.ip_address(settings["server_ipv4"])
    except ValueError as exc:
        raise ValueError("server_ipv4 must be an IPv4 address") from exc
    if ipv4.version != 4:
        raise ValueError("server_ipv4 must be an IPv4 address")
    if settings.get("server_ipv6"):
        try:
            ipv6 = ipaddress.ip_address(settings["server_ipv6"])
        except ValueError as exc:
            raise ValueError("server_ipv6 must be an IPv6 address") from exc
        if ipv6.version != 6:
            raise ValueError("server_ipv6 must be an IPv6 address")
        settings["server_ipv6"] = str(ipv6)
    settings["server_ipv4"] = str(ipv4)
    target = settings["ssh_target"].strip()
    if re.search(r"[\s\x00-\x1f]", target) or target.startswith("-"):
        raise ValueError("ssh_target must be a single OpenSSH destination (for example root@203.0.113.10)")
    settings["ssh_target"] = target
    if "allow_existing" in settings and not isinstance(settings["allow_existing"], bool):
        raise ValueError("allow_existing must be true or false")
    return settings


def remote(code):
    """Run a Python deployment program on the configured host over existing SSH access."""
    settings = load_settings()
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", settings["ssh_target"], "python3", "-"],
        input=code,
        text=True,
        check=True,
    )


def fetch_private_file(remote_path, local_path):
    """Copy one toolkit-owned root-only file over SSH without sending it to stdout."""
    settings = load_settings()
    if not re.fullmatch(r"/root/vps-proxy-toolkit/[A-Za-z0-9_.-]+", remote_path):
        raise ValueError("Only a file directly under /root/vps-proxy-toolkit can be fetched")
    data = subprocess.check_output(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", settings["ssh_target"], "cat", "--", remote_path]
    )
    target = Path(local_path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.parent.chmod(0o700)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    target.chmod(0o600)
    return data
