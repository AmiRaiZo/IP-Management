#!/usr/bin/env python3
"""Keep the IP Management Nginx HTTPS listener aligned with the current public IPv4."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

ENV_FILE = Path("/etc/station-archive/env")
NGINX_SITES = Path("/etc/nginx/sites-available")
BACKUP_DIR = Path("/var/backups/station-archive-ip-refresh")


class NoPublicIPv4(RuntimeError):
    """Raised when the current public IPv4 address cannot be determined safely."""


def choose_public_ipv4(route_info: str, addresses: Iterable[tuple[str, str]]) -> str:
    """Choose a globally routable address, avoiding private VPN/tunnel interfaces."""
    fields = route_info.split()
    route_source = ""
    route_device = ""
    for index, field in enumerate(fields[:-1]):
        if field == "src":
            route_source = fields[index + 1]
        elif field == "dev":
            route_device = fields[index + 1]

    public_addresses: list[tuple[str, str]] = []
    for device, value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4 and address.is_global:
            public_addresses.append((device.split("@", 1)[0], str(address)))

    if route_source:
        try:
            parsed_source = ipaddress.ip_address(route_source)
        except ValueError:
            parsed_source = None
        if parsed_source and parsed_source.version == 4 and parsed_source.is_global:
            if any(address == str(parsed_source) for _, address in public_addresses):
                return str(parsed_source)

    interface_addresses = [address for device, address in public_addresses if device == route_device]
    if len(interface_addresses) == 1:
        return interface_addresses[0]
    if len(public_addresses) == 1:
        return public_addresses[0][1]
    if not public_addresses:
        raise NoPublicIPv4("No globally routable IPv4 address is assigned to a local interface.")
    raise NoPublicIPv4(
        "More than one public IPv4 address is assigned and the outbound route does not select one unambiguously."
    )


def detect_public_ipv4() -> str:
    """Detect the public IPv4 currently assigned to this VPS, not an IP cached in Nginx."""
    try:
        route = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            text=True,
            capture_output=True,
            check=False,
        )
        addresses_result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise NoPublicIPv4(f"Could not run the ip utility: {exc}") from exc

    if addresses_result.returncode != 0:
        raise NoPublicIPv4("Could not read local IPv4 interface addresses.")

    addresses: list[tuple[str, str]] = []
    for line in addresses_result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4 or "inet" not in fields:
            continue
        try:
            value = fields[fields.index("inet") + 1].split("/", 1)[0]
        except (ValueError, IndexError):
            continue
        addresses.append((fields[1], value))

    return choose_public_ipv4(route.stdout if route.returncode == 0 else "", addresses)


def read_env(path: Path = ENV_FILE) -> dict[str, str]:
    """Read the simple KEY=value deployment file without evaluating shell code."""
    if not path.is_file():
        raise RuntimeError(f"Deployment environment file is missing: {path}")
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def iter_server_blocks(source: str) -> Iterable[tuple[int, int, str]]:
    """Yield top-level Nginx server blocks and their offsets."""
    offset = 0
    start: int | None = None
    depth = 0
    for line in source.splitlines(keepends=True):
        visible = line.split("#", 1)[0]
        if start is None:
            if re.match(r"^[ \t]*server[ \t]*\{", visible):
                start = offset
                depth = visible.count("{") - visible.count("}")
        else:
            depth += visible.count("{") - visible.count("}")
        offset += len(line)
        if start is not None and depth == 0:
            yield start, offset, source[start:offset]
            start = None


def atomic_write(path: Path, content: str) -> None:
    """Replace an Nginx config atomically while preserving its metadata."""
    original = path.stat()
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.ip-refresh-", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if hasattr(os, "chown"):
            try:
                os.chown(temporary, original.st_uid, original.st_gid)
            except (PermissionError, NotImplementedError):
                pass
        os.chmod(temporary, stat.S_IMODE(original.st_mode))
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def rewrite_listener(
    config_path: Path,
    domain: str,
    public_port: int,
    app_port: int,
    public_ip: str,
    backup_dir: Path = BACKUP_DIR,
) -> tuple[bool, Path | None]:
    """Update only the HTTPS listen address of this app's Nginx proxy server."""
    source = config_path.read_text(encoding="utf-8")
    matching_blocks: list[tuple[int, int, str]] = []
    for start, end, block in iter_server_blocks(source):
        names_match = re.search(r"(?m)^[ \t]*server_name[ \t]+([^;]+);", block)
        proxy_match = re.search(
            rf"(?m)^[ \t]*proxy_pass[ \t]+http://127\.0\.0\.1:{app_port}(?:/[^;]*)?;",
            block,
        )
        if names_match and domain in names_match.group(1).split() and proxy_match:
            matching_blocks.append((start, end, block))

    if len(matching_blocks) != 1:
        raise RuntimeError(
            f"Expected one HTTPS proxy server block for {domain} and 127.0.0.1:{app_port}; found {len(matching_blocks)}."
        )

    start, end, target_block = matching_blocks[0]
    listen_pattern = re.compile(
        rf"(?m)^([ \t]*listen[ \t]+)(?:(?:[0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}):{public_port}"
        rf"([ \t]+[^;\r\n]*\bssl\b[^;\r\n]*;)"
    )
    rewritten_block, count = listen_pattern.subn(
        lambda match: f"{match.group(1)}{public_ip}:{public_port}{match.group(2)}",
        target_block,
    )
    if count == 0:
        raise RuntimeError(
            f"Could not find an IP-specific SSL listen directive on port {public_port} in the {domain} proxy server."
        )

    updated_source = source[:start] + rewritten_block + source[end:]
    if updated_source == source:
        return False, None

    backup_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = backup_dir / f"{config_path.name}-{stamp}.bak"
    shutil.copy2(config_path, backup_path)
    try:
        atomic_write(config_path, updated_source)
    except Exception:
        try:
            backup_path.unlink()
        except OSError:
            pass
        raise
    return True, backup_path


def command_result(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, text=True, capture_output=True, check=False)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments not in ([], ["--preflight"]):
        print("Usage: station-archive-refresh-ip [--preflight]", file=sys.stderr)
        return 2
    preflight = arguments == ["--preflight"]
    if os.geteuid() != 0:
        print("station-archive-ip-refresh: must run as root.", file=sys.stderr)
        return 1

    try:
        settings = read_env()
        domain = settings.get("APP_DOMAIN", "").strip().lower()
        public_port_text = settings.get("PUBLIC_PORT") or settings.get("APP_HTTPS_PORT", "")
        app_port_text = settings.get("APP_INTERNAL_PORT") or public_port_text
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", domain):
            raise RuntimeError("APP_DOMAIN is missing or invalid in /etc/station-archive/env.")
        if not public_port_text.isdigit() or not app_port_text.isdigit():
            raise RuntimeError("PUBLIC_PORT or APP_INTERNAL_PORT is missing or invalid.")
        public_port = int(public_port_text)
        app_port = int(app_port_text)
        if not 1 <= public_port <= 65535 or not 1 <= app_port <= 65535:
            raise RuntimeError("Configured port is outside the valid TCP port range.")

        try:
            public_ip = detect_public_ipv4()
        except NoPublicIPv4 as exc:
            # The timer retries periodically while the VPS network comes up or changes.
            print(f"station-archive-ip-refresh: {exc} Will retry automatically.", flush=True)
            return 1 if preflight else 0

        config_path = NGINX_SITES / f"station-archive-{domain}"
        if not config_path.is_file():
            raise RuntimeError(f"Nginx site configuration was not found: {config_path}")

        changed, backup_path = rewrite_listener(
            config_path, domain, public_port, app_port, public_ip
        )
        nginx_active = command_result(["systemctl", "is-active", "--quiet", "nginx"]).returncode == 0
        if not changed and nginx_active and not preflight:
            return 0

        test = command_result(["nginx", "-t"])
        if test.returncode != 0:
            if changed and backup_path is not None:
                shutil.copy2(backup_path, config_path)
                print(
                    f"station-archive-ip-refresh: nginx -t failed; restored the previous site config from {backup_path}.",
                    file=sys.stderr,
                )
            details = (test.stdout + "\n" + test.stderr).strip()
            raise RuntimeError(f"Nginx configuration validation failed: {details}")

        if preflight:
            print(
                f"station-archive-ip-refresh: verified {domain} HTTPS listener for {public_ip}:{public_port} before Nginx start.",
                flush=True,
            )
            return 0

        if nginx_active:
            if changed:
                reload_result = command_result(["systemctl", "reload", "nginx"])
                if reload_result.returncode != 0:
                    restart_result = command_result(["systemctl", "restart", "nginx"])
                    if restart_result.returncode != 0:
                        details = (restart_result.stdout + "\n" + restart_result.stderr).strip()
                        raise RuntimeError(f"Nginx reload and restart both failed: {details}")
        else:
            command_result(["systemctl", "reset-failed", "nginx"])
            start_result = command_result(["systemctl", "start", "nginx"])
            if start_result.returncode != 0:
                details = (start_result.stdout + "\n" + start_result.stderr).strip()
                raise RuntimeError(f"Nginx failed to start after IP refresh: {details}")

        if changed:
            print(
                f"station-archive-ip-refresh: updated {domain} HTTPS listener to {public_ip}:{public_port}; "
                f"backup: {backup_path}",
                flush=True,
            )
        else:
            print("station-archive-ip-refresh: Nginx was started successfully.", flush=True)
        return 0
    except Exception as exc:
        print(f"station-archive-ip-refresh: ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
