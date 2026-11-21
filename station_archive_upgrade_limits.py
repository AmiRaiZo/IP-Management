#!/usr/bin/env python3
"""Raise the existing Nginx/Gunicorn limits needed by large in-panel restores."""

from __future__ import annotations

import argparse
import os
import re
import stat
import tempfile
from pathlib import Path


def _matching_brace(source: str, opening: int) -> int:
    depth = 1
    quote = ""
    escaped = False
    comment = False
    for index in range(opening + 1, len(source)):
        character = source[index]
        if comment:
            if character == "\n":
                comment = False
            continue
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character == "#":
            comment = True
        elif character in ("'", '"'):
            quote = character
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("Nginx configuration contains an unclosed block.")


def _replace_directive(block: str, name: str, value: str, indent: str) -> str:
    pattern = re.compile(rf"(?m)^([ \t]*){re.escape(name)}\s+[^;]+;")
    if pattern.search(block):
        return pattern.sub(lambda match: f"{match.group(1)}{name} {value};", block, count=1)
    opening = block.find("{")
    if opening < 0:
        raise ValueError(f"Cannot add {name}: Nginx block has no opening brace.")
    return block[:opening + 1] + f"\n{indent}{name} {value};" + block[opening + 1:]


def update_nginx_source(source: str, domain: str, https_port: int, app_port: int) -> tuple[str, int]:
    matches = list(re.finditer(r"(?m)^\s*server\s*\{", source))
    output = source
    changed_blocks = 0
    offset = 0
    for match in matches:
        opening = source.find("{", match.start(), match.end())
        closing = _matching_brace(source, opening)
        block = source[match.start():closing + 1]
        server_name = re.search(r"(?m)^\s*server_name\s+([^;]+);", block)
        listen_ports = re.findall(r"(?m)^\s*listen\s+(?:(?:\d{1,3}\.){3}\d{1,3}:)?(?:\[::\]:)?(\d+)\s+ssl\b", block)
        proxy_target = re.search(r"proxy_pass\s+http://127\.0\.0\.1:(\d+)\b", block)
        names = server_name.group(1).split() if server_name else []
        if domain not in names or str(https_port) not in listen_ports or not proxy_target or int(proxy_target.group(1)) != app_port:
            continue

        block = _replace_directive(block, "client_max_body_size", "512m", "    ")
        block = _replace_directive(block, "client_body_timeout", "900s", "    ")
        location_match = re.search(r"(?m)^([ \t]*)location\s+/\s*\{", block)
        if not location_match:
            raise ValueError("The matching HTTPS server block has no location / proxy block.")
        location_open = block.find("{", location_match.start(), location_match.end())
        location_close = _matching_brace(block, location_open)
        location_block = block[location_match.start():location_close + 1]
        location_indent = location_match.group(1) + "    "
        location_block = _replace_directive(location_block, "proxy_read_timeout", "900s", location_indent)
        location_block = _replace_directive(location_block, "proxy_send_timeout", "900s", location_indent)
        block = block[:location_match.start()] + location_block + block[location_close + 1:]

        start = match.start() + offset
        end = closing + 1 + offset
        output = output[:start] + block + output[end:]
        offset += len(block) - (closing + 1 - match.start())
        changed_blocks += 1

    if not changed_blocks:
        raise ValueError("Could not find the existing HTTPS proxy block for the configured domain and ports.")
    return output, changed_blocks


def _atomic_write(path: Path, content: str) -> None:
    resolved = path.resolve()
    mode = stat.S_IMODE(resolved.stat().st_mode)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{resolved.name}.", dir=str(resolved.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, resolved)
    finally:
        temporary.unlink(missing_ok=True)


def update_nginx_file(path: Path, domain: str, https_port: int, app_port: int) -> int:
    source = path.read_text(encoding="utf-8")
    updated, count = update_nginx_source(source, domain, https_port, app_port)
    if updated != source:
        _atomic_write(path, updated)
    return count


def update_gunicorn_timeout(path: Path, timeout_seconds: int = 900) -> bool:
    source = path.read_text(encoding="utf-8")
    updated, count = re.subn(r"--timeout(?:=|\s+)\d+", f"--timeout {timeout_seconds}", source)
    if not count:
        updated, count = re.subn(r"(?m)^(ExecStart=.*?gunicorn)(.*)$", rf"\1 --timeout {timeout_seconds}\2", source, count=1)
    if not count:
        raise ValueError("Could not find the Gunicorn ExecStart command in the systemd unit.")
    if updated != source:
        _atomic_write(path, updated)
    return updated != source


def update_existing_limits(domain: str, https_port: int, app_port: int,
                           nginx_roots: tuple[Path, ...] = (Path("/etc/nginx/sites-enabled"), Path("/etc/nginx/conf.d")),
                           service_unit: Path = Path("/etc/systemd/system/station-archive.service")) -> int:
    updated_files = 0
    visited: set[Path] = set()
    for root in nginx_roots:
        if not root.exists():
            continue
        for candidate in sorted(root.iterdir()):
            if not candidate.is_file() and not candidate.is_symlink():
                continue
            resolved = candidate.resolve()
            if resolved in visited:
                continue
            visited.add(resolved)
            try:
                count = update_nginx_file(candidate, domain, https_port, app_port)
            except ValueError as exc:
                if "Could not find the existing HTTPS proxy block" in str(exc):
                    continue
                raise
            if count:
                updated_files += 1
    if not updated_files:
        raise ValueError("No matching Nginx site configuration was updated.")
    update_gunicorn_timeout(service_unit)
    return updated_files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--https-port", required=True, type=int)
    parser.add_argument("--app-port", required=True, type=int)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9.-]+", args.domain):
        parser.error("invalid domain")
    if not (1 <= args.https_port <= 65535 and 1 <= args.app_port <= 65535):
        parser.error("ports must be between 1 and 65535")
    try:
        count = update_existing_limits(args.domain, args.https_port, args.app_port)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"station-archive-upgrade-limits: {exc}\n")
    print(f"Updated {count} Nginx site file(s) and the Gunicorn timeout for full backup restore.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

