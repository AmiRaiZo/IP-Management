#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this upgrade as root, for example: curl -fsSL https://raw.githubusercontent.com/OWNER/REPOSITORY/main/upgrade_existing.sh | sudo bash" >&2
  exit 1
fi

APP_DIR=/opt/station-archive
DATA_DIR=/var/lib/station-archive
ENV_FILE=/etc/station-archive/env
SERVICE_FILE=/etc/systemd/system/station-archive.service
[[ -d "$APP_DIR" && -f "$APP_DIR/app.py" ]] || { echo "Existing application not found at $APP_DIR." >&2; exit 1; }
[[ -f "$ENV_FILE" && -f "$SERVICE_FILE" ]] || { echo "Expected existing environment file or systemd service is missing." >&2; exit 1; }
command -v python3 >/dev/null && command -v systemctl >/dev/null && command -v nginx >/dev/null || { echo "Required tools (Python 3, systemctl, Nginx) are missing." >&2; exit 1; }

prompt() { local name="$1" label="$2" value=""; read -r -p "$label: " value < /dev/tty; printf -v "$name" '%s' "$value"; }
# Keep the upgrader aligned with the repository used by the installer.
REPO_URL="https://github.com/AmiRaiZo/IP-Management"

APP_PORT="$(systemctl show station-archive.service -p ExecStart --value | grep -oE -- '--bind[= ]+127\.0\.0\.1:[0-9]+' | grep -oE '[0-9]+$' | tail -n1 || true)"
if [[ -z "$APP_PORT" ]]; then
  APP_PORT="$(grep -RhoE 'proxy_pass[[:space:]]+http://127\.0\.0\.1:[0-9]+' /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null | grep -oE '[0-9]+$' | head -n1 || true)"
fi
[[ "$APP_PORT" =~ ^[0-9]{1,5}$ ]] && (( APP_PORT >= 1 && APP_PORT <= 65535 )) || { echo "Could not detect the existing internal application port from systemd or Nginx." >&2; exit 1; }

NGINX_INFO="$(python3 - <<'PY'
from pathlib import Path
import re
roots = [Path('/etc/nginx/sites-enabled'), Path('/etc/nginx/conf.d')]
for root in roots:
    if not root.exists():
        continue
    for path in sorted(root.iterdir()):
        if not path.is_file() and not path.is_symlink():
            continue
        try:
            source = path.read_text(errors='ignore')
        except OSError:
            continue
        # Strip comments, then split top-level server blocks by brace depth.
        source = re.sub(r'(?m)^\s*#.*$', '', source)
        for match in re.finditer(r'\bserver\s*\{', source):
            start = match.end()
            depth = 1
            i = start
            while i < len(source) and depth:
                if source[i] == '{': depth += 1
                elif source[i] == '}': depth -= 1
                i += 1
            block = source[start:i-1]
            proxy = re.search(r'proxy_pass\s+http://127\.0\.0\.1:(\d+)', block)
            ssl_listen = re.search(r'listen\s+(?:(?:\d{1,3}\.){3}\d{1,3}:)?(?:\[::\]:)?(\d+)\s+ssl\b', block)
            domain = re.search(r'(?m)^\s*server_name\s+([^;]+);', block)
            if proxy and ssl_listen and domain:
                names = domain.group(1).split()
                name = next((n for n in names if n != '_' and not n.startswith('~')), '')
                if name:
                    print(name)
                    print(ssl_listen.group(1))
                    raise SystemExit(0)
raise SystemExit('Unable to detect an HTTPS server block with a localhost proxy_pass.')
PY
)" || { echo "Could not detect the existing domain and public HTTPS port from Nginx." >&2; exit 1; }
DOMAIN="$(printf '%s\n' "$NGINX_INFO" | sed -n '1p')"
HTTPS_PORT="$(printf '%s\n' "$NGINX_INFO" | sed -n '2p')"
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ && "$HTTPS_PORT" =~ ^[0-9]{1,5}$ ]] || { echo "Detected invalid domain or HTTPS port." >&2; exit 1; }

echo "Existing deployment detected: https://$DOMAIN:$HTTPS_PORT, internal port $APP_PORT."
echo "Nginx configuration and SSL certificates will be kept as they are."
read -r -p "Type UPGRADE to continue: " CONFIRM < /dev/tty
[[ "$CONFIRM" == UPGRADE ]] || { echo "Cancelled."; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl git rsync python3-venv python3-pip
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/var/backups/station-archive-upgrade-$STAMP"
install -d -o root -g root -m 0700 "$BACKUP_DIR"
mkdir -p "$BACKUP_DIR/app"
cp -a "$ENV_FILE" "$BACKUP_DIR/env"
if [[ -f "$DATA_DIR/archive.sqlite3" ]]; then
  python3 - "$DATA_DIR/archive.sqlite3" "$BACKUP_DIR/archive.sqlite3" <<'PY'
import sqlite3, sys
with sqlite3.connect(f'file:{sys.argv[1]}?mode=ro', uri=True, timeout=30) as source:
    with sqlite3.connect(sys.argv[2]) as target:
        source.backup(target)
PY
  chmod 0600 "$BACKUP_DIR/archive.sqlite3"
fi
rsync -a --exclude='.git/' --exclude='.venv/' "$APP_DIR/" "$BACKUP_DIR/app/"
echo "Backup created at $BACKUP_DIR"

# Source code remains root-owned and readable by the service group. Runtime
# data belongs to www-data; avoid world-readable or world-writable permissions.
install -d -o www-data -g www-data -m 0750 "$DATA_DIR"

WORK_DIR="$(mktemp -d /tmp/station-archive-existing-upgrade.XXXXXX)"
DEPLOYED=0
SUCCESS=0
cleanup() {
  if (( DEPLOYED == 1 && SUCCESS == 0 )); then
    echo "Upgrade failed; restoring the application files and environment from $BACKUP_DIR." >&2
    rsync -a --delete --exclude='.venv/' "$BACKUP_DIR/app/" "$APP_DIR/" || true
    cp -a "$BACKUP_DIR/env" "$ENV_FILE" || true
    chown -R root:www-data "$APP_DIR"
    chown root:www-data "$APP_DIR" || true
    find "$APP_DIR" -path "$APP_DIR/.venv" -prune -o -type d -exec chmod 0750 {} + || true
    find "$APP_DIR" -path "$APP_DIR/.venv" -prune -o -type f -exec chmod 0640 {} + || true
    chown -R www-data:www-data "$DATA_DIR" || true
    find "$DATA_DIR" -type d -exec chmod 0750 {} + || true
    find "$DATA_DIR" -type f -exec chmod 0640 {} + || true
    if [[ -d "$APP_DIR/.venv" ]]; then
      if [[ ! -x "$APP_DIR/.venv/bin/python" || ! -x "$APP_DIR/.venv/bin/pip" ]]; then python3 -m venv --clear "$APP_DIR/.venv" || true; fi
      chown -R root:www-data "$APP_DIR/.venv" || true
      find "$APP_DIR/.venv" -type d -exec chmod 0750 {} + || true
      find "$APP_DIR/.venv" -type f -perm /u=r -exec chmod g+r {} + || true
      find "$APP_DIR/.venv" -type f -perm /u=x -exec chmod g+x {} + || true
    fi
    chown root:www-data /etc/station-archive || true
    chmod 0750 /etc/station-archive || true
    systemctl restart station-archive.service || true
  fi
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT
RELEASE_API="https://api.github.com/repos/AmiRaiZo/IP-Management/releases/latest"
curl -fsSL -H 'Accept: application/vnd.github+json' -H 'User-Agent: IP-Archive-Upgrader' "$RELEASE_API" -o "$WORK_DIR/release.json"
mapfile -t RELEASE_INFO < <(python3 - "$WORK_DIR/release.json" <<'PY'
import json, sys
release=json.load(open(sys.argv[1], encoding="utf-8"))
assets=[a for a in release.get("assets", []) if a.get("name", "").startswith("station-archive-v") and a.get("name", "").endswith(".zip")]
if not release.get("tag_name") or not assets:
    raise SystemExit("Latest GitHub Release has no IP Archive ZIP package.")
url=assets[0].get("browser_download_url", "")
if not url.startswith("https://github.com/AmiRaiZo/IP-Management/releases/download/"):
    raise SystemExit("Release package URL failed validation.")
print(release["tag_name"])
print(url)
PY
)
[[ ${#RELEASE_INFO[@]} -eq 2 ]] || { echo "Could not read GitHub Release metadata." >&2; exit 1; }
curl -fsSL --retry 3 --retry-delay 1 "${RELEASE_INFO[1]}" -o "$WORK_DIR/release.zip"
python3 - "$WORK_DIR/release.zip" "$WORK_DIR/source" <<'PY'
import sys, zipfile
archive, destination=sys.argv[1:]
with zipfile.ZipFile(archive) as z:
    bad=z.testzip()
    if bad: raise SystemExit("Corrupt release package: "+bad)
    for item in z.infolist():
        name=item.filename.replace("\\\\", "/")
        if name.startswith("/") or ".." in name.split("/"):
            raise SystemExit("Unsafe path in release package.")
    z.extractall(destination)
PY
for required in app.py requirements.txt VERSION templates static update.sh; do
  [[ -e "$WORK_DIR/source/$required" ]] || { echo "Release package is missing required path: $required" >&2; exit 1; }
done
echo "Preparing in-place upgrade to ${RELEASE_INFO[0]} from GitHub Releases."

# Keep the currently installed virtual environment and all data outside APP_DIR.
DEPLOYED=1
systemctl stop station-archive.service
rsync -a --delete --exclude='.git/' --exclude='.venv/' "$WORK_DIR/source/" "$APP_DIR/"
chown -R root:www-data "$APP_DIR"
chown root:www-data "$APP_DIR"
find "$APP_DIR" -path "$APP_DIR/.venv" -prune -o -type d -exec chmod 0750 {} +
find "$APP_DIR" -path "$APP_DIR/.venv" -prune -o -type f -exec chmod 0640 {} +
# Recreate the virtual environment on every in-place upgrade. This avoids stale
# or damaged pip launchers and preserves all application data outside the venv.
python3 -m venv --clear "$APP_DIR/.venv"
chown -R root:www-data "$APP_DIR/.venv"
find "$APP_DIR/.venv" -type d -exec chmod 0750 {} +
find "$APP_DIR/.venv" -type f -perm /u=r -exec chmod g+r {} +
find "$APP_DIR/.venv" -type f -perm /u=x -exec chmod g+x {} +
chown -R www-data:www-data "$DATA_DIR"
find "$DATA_DIR" -type d -exec chmod 0750 {} +
find "$DATA_DIR" -type f -exec chmod 0640 {} +
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/.venv/bin/python" -m pip install -r "$APP_DIR/requirements.txt"

# Update only deployment metadata; retain existing secret values and unrelated settings.
python3 - "$ENV_FILE" "$REPO_URL" "$DOMAIN" "$HTTPS_PORT" "$APP_PORT" <<'PY'
from pathlib import Path
import re, sys
path = Path(sys.argv[1])
values = {
    'APP_REPO_URL': sys.argv[2], 'GITHUB_REPO': sys.argv[2],
    'APP_DOMAIN': sys.argv[3], 'APP_HTTPS_PORT': sys.argv[4],
    'PUBLIC_PORT': sys.argv[4], 'APP_INTERNAL_PORT': sys.argv[5],
    'STATION_ARCHIVE_DATA': '/var/lib/station-archive',
}
lines = path.read_text().splitlines()
seen = set()
updated = []
for line in lines:
    key = line.split('=', 1)[0] if '=' in line else ''
    if key in values:
        if key not in seen:
            updated.append(f'{key}={values[key]}')
            seen.add(key)
    else:
        updated.append(line)
for key, value in values.items():
    if key not in seen:
        updated.append(f'{key}={value}')
path.write_text('\n'.join(updated) + '\n')
PY
chown root:www-data "$ENV_FILE"
chmod 0640 "$ENV_FILE"
chown root:www-data /etc/station-archive
chmod 0750 /etc/station-archive

cat > /usr/local/sbin/station-archive-update <<'UPDATER'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "This updater must run as root." >&2; exit 1; }
exec /bin/bash /opt/station-archive/update.sh
UPDATER
chown root:root /usr/local/sbin/station-archive-update
chmod 0750 /usr/local/sbin/station-archive-update
cat > /etc/sudoers.d/station-archive-update <<'SUDOERS'
www-data ALL=(root) NOPASSWD: /usr/local/sbin/station-archive-update
SUDOERS
chmod 0440 /etc/sudoers.d/station-archive-update
visudo -cf /etc/sudoers.d/station-archive-update

nginx -t
systemctl daemon-reload
systemctl restart station-archive.service
systemctl is-active --quiet station-archive.service
SUCCESS=1
echo "Upgrade completed. Existing domain, public HTTPS port, Nginx configuration, SSL certificates, secrets, and database were preserved."
echo "Backups: $BACKUP_DIR"
echo "Application URL: https://$DOMAIN:$HTTPS_PORT"
echo "Updater: sudo /usr/local/sbin/station-archive-update"
