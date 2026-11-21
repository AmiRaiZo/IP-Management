#!/usr/bin/env python3
"""Safe helpers for recovering an existing IP Management HTTPS hostname."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path


DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}\Z"
)


def normalize_domain(value: str) -> str:
    """Return a strict lowercase FQDN; URLs, ports, IPs and single labels fail."""
    domain = value.strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Enter a valid hostname such as panel.example.com (without https:// or a port).")
    return domain


def _server_blocks(source: str):
    source = re.sub(r"(?m)^\s*#.*$", "", source)
    for match in re.finditer(r"\bserver\s*\{", source):
        opening = match.end() - 1
        depth = 1
        quote = ""
        escaped = False
        comment = False
        index = opening + 1
        while index < len(source) and depth:
            char = source[index]
            if comment:
                if char == "\n":
                    comment = False
            elif quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
            elif char == "#":
                comment = True
            elif char in "'\"":
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            index += 1
        if depth == 0:
            yield source[opening + 1:index - 1]


def find_usable_https_port(domain: str, app_port: int, roots: tuple[Path, ...]) -> int | None:
    """Find a matching enabled HTTPS proxy whose certificate covers the hostname."""
    for root in roots:
        if not root.is_dir():
            continue
        for candidate in sorted(root.iterdir()):
            if not candidate.is_file():
                continue
            try:
                source = candidate.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for block in _server_blocks(source):
                names = re.search(r"(?m)^\s*server_name\s+([^;]+);", block)
                proxy = re.search(r"proxy_pass\s+http://127\.0\.0\.1:(\d+)\b", block)
                listen = re.search(
                    r"(?m)^\s*listen\s+(?:(?:\d{1,3}\.){3}\d{1,3}:)?"
                    r"(?:\[::\]:)?(\d+)\s+ssl\b", block
                )
                cert = re.search(r"(?m)^\s*ssl_certificate\s+([^;]+);", block)
                if not (names and proxy and listen and cert):
                    continue
                if domain not in names.group(1).split() or int(proxy.group(1)) != app_port:
                    continue
                cert_path = Path(cert.group(1).strip().strip("\"'"))
                if not cert_path.is_file():
                    continue
                checked = subprocess.run(
                    ["openssl", "x509", "-in", str(cert_path), "-noout", "-checkhost", domain, "-checkend", "86400"],
                    capture_output=True, text=True, check=False,
                )
                if checked.returncode == 0:
                    return int(listen.group(1))
    return None


def render_nginx_site(domain: str, public_ip: str, https_port: int, app_port: int,
                      webroot: str = "/var/www/station-archive-acme") -> str:
    domain = normalize_domain(domain)
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", public_ip):
        raise ValueError("Invalid public IPv4 address.")
    if not (1 <= https_port <= 65535 and 1 <= app_port <= 65535) or https_port == 80:
        raise ValueError("Invalid HTTPS or application port.")
    return f'''server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    location ^~ /.well-known/acme-challenge/ {{ root {webroot}; default_type "text/plain"; }}
    location / {{ return 301 https://$host:{https_port}$request_uri; }}
}}

server {{
    listen {public_ip}:{https_port} ssl;
    server_name {domain};
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    client_max_body_size 512m;
    client_body_timeout 900s;
    location / {{
        proxy_pass http://127.0.0.1:{app_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_read_timeout 900s;
        proxy_send_timeout 900s;
    }}
}}
'''


def atomic_write_text(path: Path, content: str, mode: int = 0o644) -> None:
    """Atomically replace a generated Nginx site file in its destination directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_update_env(path: Path, values: dict[str, str]) -> None:
    """Atomically update selected KEY=value entries and preserve other settings."""
    original = path.read_text(encoding="utf-8")
    mode = stat.S_IMODE(path.stat().st_mode)
    seen: set[str] = set()
    output: list[str] = []
    for line in original.splitlines():
        key = line.split("=", 1)[0] if "=" in line else ""
        if key in values:
            if key not in seen:
                output.append(f"{key}={values[key]}")
                seen.add(key)
        else:
            output.append(line)
    output.extend(f"{key}={value}" for key, value in values.items() if key not in seen)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write("\n".join(output) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
