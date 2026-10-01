#!/usr/bin/env python3
"""Small, dependency-free network diagnostics for VPS and proxy paths.

Examples:
  python diagnostics.py minecraft mc.hypixel.net --samples 3
  python diagnostics.py minecraft mc.hypixel.net --proxy http://127.0.0.1:6152
  python diagnostics.py network example.net --count 10 --family ipv6

Output is compact JSON on stdout. The tool does not save results, log in to
Minecraft, or modify system/proxy settings.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import re
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit


def _safe_target(value: str) -> str:
    """Do not echo literal IP addresses into reports by default."""
    try:
        addr = ip_address(value.split("%", 1)[0])
    except ValueError:
        return value
    return f"<{addr.version}-address>"


def _failure(exc: BaseException) -> str:
    if isinstance(exc, (TimeoutError, socket.timeout, subprocess.TimeoutExpired)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(exc, socket.gaierror):
        return "name_resolution_failed"
    if isinstance(exc, PermissionError):
        return "permission_denied"
    if isinstance(exc, ValueError):
        return "invalid_response_or_argument"
    return "connection_or_protocol_error"


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        part = value & 0x7F
        value >>= 7
        if value:
            part |= 0x80
        out.append(part)
        if not value:
            return bytes(out)


def _read_varint(sock: socket.socket) -> int:
    result = 0
    for shift in range(0, 35, 7):
        data = sock.recv(1)
        if not data:
            raise ConnectionError("eof")
        byte = data[0]
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result
    raise ValueError("long_varint")


def _read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError("eof")
        data.extend(part)
    return bytes(data)


def _read_packet(sock: socket.socket) -> bytes:
    length = _read_varint(sock)
    if length <= 0 or length > 1_048_576:
        raise ValueError("packet_size")
    return _read_exact(sock, length)


def _send_packet(sock: socket.socket, packet_id: int, payload: bytes = b"") -> None:
    body = _varint(packet_id) + payload
    sock.sendall(_varint(len(body)) + body)


def _parse_proxy(value: str | None) -> tuple[str, int] | None:
    if value is None:
        return None
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "http" or not parsed.hostname or parsed.port is None:
        raise ValueError("proxy must be an HTTP URL with host and port")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("proxy URL user-info is not supported; do not put credentials on the command line")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("proxy URL must not contain a path, query, or fragment")
    return parsed.hostname, parsed.port


def _open_tunnel(host: str, port: int, timeout: float,
                 proxy: tuple[str, int] | None) -> tuple[socket.socket, float]:
    started = time.perf_counter()
    connect_host, connect_port = proxy if proxy else (host, port)
    sock = socket.create_connection((connect_host, connect_port), timeout=timeout)
    sock.settimeout(timeout)
    if proxy is not None:
        authority_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        request = (
            f"CONNECT {authority_host}:{port} HTTP/1.1\r\n"
            f"Host: {authority_host}:{port}\r\n"
            "Proxy-Connection: keep-alive\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        headers = bytearray()
        while b"\r\n\r\n" not in headers:
            part = sock.recv(1)
            if not part:
                sock.close()
                raise ConnectionError("proxy_closed")
            headers.extend(part)
            if len(headers) > 16_384:
                sock.close()
                raise ValueError("proxy_header_size")
        status_line = bytes(headers).split(b"\r\n", 1)[0]
        try:
            status_code = int(status_line.split()[1])
        except (IndexError, ValueError) as exc:
            sock.close()
            raise ValueError("proxy_response") from exc
        if status_code != 200:
            sock.close()
            raise ConnectionError("proxy_connect_rejected")
    return sock, (time.perf_counter() - started) * 1000


def _minecraft_probe(host: str, port: int, timeout: float,
                     proxy: tuple[str, int] | None) -> dict[str, Any]:
    row: dict[str, Any] = {"ok": False}
    sock: socket.socket | None = None
    try:
        sock, connect_ms = _open_tunnel(host, port, timeout, proxy)
        row["connect_ms"] = round(connect_ms, 2)

        # Java STATUS uses a handshake to state 1, followed by packet 0.
        # Protocol 47 works as a broadly accepted status handshake; no login or
        # play-state packets are sent.
        host_bytes = host.encode("utf-8")
        handshake = (
            _varint(47)
            + _varint(len(host_bytes))
            + host_bytes
            + struct.pack(">H", port)
            + _varint(1)
        )
        _send_packet(sock, 0, handshake)
        started = time.perf_counter()
        _send_packet(sock, 0)  # Status Request
        response = _read_packet(sock)
        if response[0] != 0 or len(response) < 2:
            raise ValueError("status_packet")
        # Parse, then discard, the JSON response. Server metadata is not stored.
        json_length = _read_varint_from_bytes(response, 1)
        payload_start = 1 + _varint_length(json_length)
        if payload_start + json_length > len(response):
            raise ValueError("status_json_length")
        json.loads(response[payload_start:payload_start + json_length].decode("utf-8"))
        row["status_ms"] = round((time.perf_counter() - started) * 1000, 2)

        nonce = time.time_ns() & 0x7FFFFFFFFFFFFFFF
        started = time.perf_counter()
        _send_packet(sock, 1, struct.pack(">q", nonce))  # Ping Request
        pong = _read_packet(sock)
        row["pong_ms"] = round((time.perf_counter() - started) * 1000, 2)
        if len(pong) != 9 or pong[0] != 1:
            raise ValueError("pong_packet")
        if struct.unpack(">q", pong[1:])[0] != nonce:
            raise ValueError("pong_nonce")
        row["ok"] = True
    except Exception as exc:
        row["failure"] = _failure(exc)
    finally:
        if sock is not None:
            sock.close()
    return row


def _varint_length(value: int) -> int:
    return len(_varint(value))


def _read_varint_from_bytes(data: bytes, offset: int) -> int:
    value = 0
    for i in range(5):
        if offset + i >= len(data):
            raise ValueError("truncated_varint")
        byte = data[offset + i]
        value |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            return value
    raise ValueError("long_varint")


def _summary(rows: list[dict[str, Any]], key: str) -> dict[str, float | int] | None:
    values = [row[key] for row in rows if row.get("ok") and isinstance(row.get(key), (int, float))]
    if not values:
        return None
    return {
        "samples": len(values),
        "min_ms": round(min(values), 2),
        "median_ms": round(statistics.median(values), 2),
        "mean_ms": round(statistics.mean(values), 2),
        "max_ms": round(max(values), 2),
    }


def command_minecraft(args: argparse.Namespace) -> int:
    started_wall = datetime.now(timezone.utc)
    started = time.perf_counter()
    host = args.hostname.rstrip(".")
    proxy = _parse_proxy(args.proxy)
    rows = [_minecraft_probe(host, args.port, args.timeout, proxy) for _ in range(args.samples)]
    result = {
        "kind": "minecraft_java_status_ping",
        "target": _safe_target(host),
        "port": args.port,
        "proxy_used": proxy is not None,
        "samples_requested": args.samples,
        "started_utc": started_wall.isoformat(),
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "connect": _summary(rows, "connect_ms"),
        "status": _summary(rows, "status_ms"),
        "pong": _summary(rows, "pong_ms"),
        "probes": rows,
        "warnings": [
            "STATUS/PONG probes are endpoint diagnostics; they do not measure real-match gameplay, rendering, or server tick delay.",
            "A small sample can miss route variation. Compare routes to the same hostname and port over longer ordinary sessions.",
        ],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if any(row.get("ok") for row in rows) else 2


def _resolve_target(target: str, family: str) -> tuple[str, int]:
    try:
        address = ip_address(target.split("%", 1)[0])
        if family == "ipv4" and address.version != 4:
            raise ValueError("target_family_mismatch")
        if family == "ipv6" and address.version != 6:
            raise ValueError("target_family_mismatch")
        return (socket.AF_INET6 if address.version == 6 else socket.AF_INET), address.version
    except ValueError as e:
        if str(e) == "target_family_mismatch":
            raise
    requested = socket.AF_INET if family == "ipv4" else socket.AF_INET6 if family == "ipv6" else socket.AF_UNSPEC
    infos = socket.getaddrinfo(target, None, requested, socket.SOCK_DGRAM)
    if not infos:
        raise socket.gaierror("no_address")
    # Prefer IPv6 in auto mode only when DNS actually provides an IPv6 answer.
    if family == "auto":
        infos.sort(key=lambda item: 0 if item[0] == socket.AF_INET6 else 1)
    af = infos[0][0]
    return af, 6 if af == socket.AF_INET6 else 4


def _ping_command(target: str, count: int, timeout: float, family: int,
                  interface: str | None) -> list[str]:
    system = platform.system().lower()
    ping = shutil.which("ping6" if system == "darwin" and family == 6 else "ping")
    if not ping:
        raise FileNotFoundError("ping utility not found")
    if system == "linux":
        cmd = [ping, "-n", "-c", str(count), "-W", str(max(1, math.ceil(timeout))), "-6" if family == 6 else "-4"]
        if interface:
            cmd.extend(["-I", interface])
    elif system == "darwin":
        cmd = [ping, "-n", "-c", str(count), "-W", str(max(1, round(timeout * 1000)))]
        if interface:
            cmd.extend(["-b", interface])
    elif system == "windows":
        if interface:
            raise ValueError("--interface is not supported by this Windows ping backend")
        cmd = [ping, "-n", str(count), "-w", str(max(1000, round(timeout * 1000))), "-6" if family == 6 else "-4"]
    else:
        raise ValueError("unsupported operating system for system ping")
    cmd.append(target)
    return cmd


def _parse_ping(output: str) -> dict[str, Any]:
    sent = received = None
    loss = None
    m = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets )?received,\s*([\d.]+)%\s*packet loss", output, re.I)
    if m:
        sent, received, loss = int(m.group(1)), int(m.group(2)), float(m.group(3))
    else:
        m = re.search(r"Packets:\s*Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*\d+\s*\(([\d.]+)%\s*loss\)", output, re.I)
        if m:
            sent, received, loss = int(m.group(1)), int(m.group(2)), float(m.group(3))
    rtt: dict[str, float] | None = None
    m = re.search(r"(?:rtt|round-trip)\s+min/avg/max(?:/mdev|/stddev)?\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)", output, re.I)
    if m:
        rtt = {"min_ms": float(m.group(1)), "mean_ms": float(m.group(2)), "max_ms": float(m.group(3))}
    else:
        m = re.search(r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms", output, re.I)
        if m:
            rtt = {"min_ms": float(m.group(1)), "mean_ms": float(m.group(3)), "max_ms": float(m.group(2))}
    parsed: dict[str, Any] = {}
    if sent is not None:
        parsed.update({"sent": sent, "received": received, "loss_pct": loss})
    if rtt is not None:
        parsed["rtt"] = rtt
    return parsed


def command_network(args: argparse.Namespace) -> int:
    started_wall = datetime.now(timezone.utc)
    started = time.perf_counter()
    target = args.target.rstrip(".")
    result: dict[str, Any] = {
        "kind": "icmp_echo_diagnostic",
        "target": _safe_target(target),
        "count_requested": args.count,
        "interface_requested": bool(args.interface),
        "started_utc": started_wall.isoformat(),
    }
    try:
        af, version = _resolve_target(target, args.family)
        cmd = _ping_command(target, args.count, args.timeout, version, args.interface)
        env = dict(os.environ, LC_ALL="C", LANG="C")
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=args.count * args.timeout + 8, env=env, check=False)
        parsed = _parse_ping(p.stdout + "\n" + p.stderr)
        result.update({"family": f"IPv{version}", "exit_code": p.returncode, "measurements": parsed})
        if not parsed:
            result["failure"] = "ping_output_unrecognized_or_no_replies"
        result["warnings"] = [
            "ICMP echo results may be filtered or deprioritized; they are not the same as application or game traffic.",
            "The resolved destination address is intentionally omitted from this report.",
        ]
    except Exception as exc:
        result["failure"] = _failure(exc)
        if isinstance(exc, ValueError) and str(exc).startswith("--interface"):
            result["failure"] = "interface_not_supported_on_platform"
        result["warnings"] = ["No raw command output or resolved address is included."]
    result["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "failure" not in result else 2


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0 or parsed > 100:
        raise argparse.ArgumentTypeError("must be between 1 and 100")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0 or parsed > 120:
        raise argparse.ArgumentTypeError("must be greater than 0 and at most 120 seconds")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Low-volume network path diagnostics (standard library only).")
    sub = parser.add_subparsers(dest="command", required=True)

    mc = sub.add_parser("minecraft", help="Minecraft Java STATUS and PING/PONG diagnostic")
    mc.add_argument("hostname", nargs="?", default="mc.hypixel.net", help="server hostname (default: mc.hypixel.net)")
    mc.add_argument("--port", type=int, default=25565)
    mc.add_argument("--proxy", help="optional HTTP proxy URL, e.g. http://127.0.0.1:6152")
    mc.add_argument("--samples", type=_positive_int, default=3)
    mc.add_argument("--timeout", type=_positive_float, default=8.0)
    mc.set_defaults(func=command_minecraft)

    net = sub.add_parser("network", help="ICMP echo diagnostic using the platform ping utility")
    net.add_argument("target", help="hostname or address; a literal address is masked in JSON output")
    net.add_argument("--count", type=_positive_int, default=10)
    net.add_argument("--timeout", type=_positive_float, default=2.0, help="per-reply timeout in seconds")
    net.add_argument("--interface", help="outgoing interface where supported (Linux/macOS)")
    net.add_argument("--family", choices=("auto", "ipv4", "ipv6"), default="auto")
    net.set_defaults(func=command_network)

    args = parser.parse_args()
    if getattr(args, "port", 1) < 1 or getattr(args, "port", 65535) > 65535:
        parser.error("--port must be between 1 and 65535")
    if getattr(args, "hostname", "") and any(c.isspace() for c in args.hostname):
        parser.error("hostname must not contain whitespace")
    try:
        return args.func(args)
    except (ValueError, OSError) as exc:
        print(json.dumps({"failure": _failure(exc)}, indent=2), file=sys.stdout)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
