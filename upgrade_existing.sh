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
apt-get install -y git rsync python3-venv python3-pip
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

# Runtime data is private to the application account; source code stays
# root-owned and readable by the service's www-data group (never world-writable).
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
    if [[ -d "$APP_DIR/.venv" ]]; then
      chown -R root:www-data "$APP_DIR/.venv" || true
    chmod -R g+rX "$APP_DIR/.venv" || true
    fi
    chown -R www-data:www-data "$DATA_DIR" || true
    find "$DATA_DIR" -type d -exec chmod 0750 {} + || true
    find "$DATA_DIR" -type f -exec chmod 0640 {} + || true
    chown root:www-data /etc/station-archive || true
    chmod 0750 /etc/station-archive || true
    systemctl restart station-archive.service || true
  fi
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT
git clone --depth 1 "$REPO_URL" "$WORK_DIR/source"
for required in app.py requirements.txt templates static; do
  [[ -e "$WORK_DIR/source/$required" ]] || { echo "Repository is missing required path: $required" >&2; exit 1; }
done

# Keep the currently installed virtual environment and all data outside APP_DIR.
DEPLOYED=1
systemctl stop station-archive.service
rsync -a --delete --exclude='.git/' --exclude='.venv/' "$WORK_DIR/source/" "$APP_DIR/"
chown -R root:www-data "$APP_DIR"
chown root:www-data "$APP_DIR"
find "$APP_DIR" -path "$APP_DIR/.venv" -prune -o -type d -exec chmod 0750 {} +
find "$APP_DIR" -path "$APP_DIR/.venv" -prune -o -type f -exec chmod 0640 {} +
chown -R root:www-data "$APP_DIR/.venv"
chmod -R g+rX "$APP_DIR/.venv"
chown -R www-data:www-data "$DATA_DIR"
find "$DATA_DIR" -type d -exec chmod 0750 {} +
find "$DATA_DIR" -type f -exec chmod 0640 {} +
# Detect an incomplete/corrupt virtualenv before attempting an in-place pip repair.
if [[ ! -x "$APP_DIR/.venv/bin/python" ]] || ! "$APP_DIR/.venv/bin/python" -c 'from gunicorn.app.wsgiapp import run' >/dev/null 2>&1; then
  if [[ -d "$APP_DIR/.venv" ]]; then mv "$APP_DIR/.venv" "$BACKUP_DIR/venv-before-rebuild"; fi
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/.venv/bin/python" -m pip install -r "$APP_DIR/requirements.txt"
"$APP_DIR/.venv/bin/python" -m pip install --no-cache-dir --force-reinstall 'gunicorn>=23,<24'
chown -R root:www-data "$APP_DIR/.venv"
chmod -R g+rX "$APP_DIR/.venv"
chown root:www-data "$APP_DIR/.venv/bin/gunicorn"
chmod 0750 "$APP_DIR/.venv/bin/gunicorn"
"$APP_DIR/.venv/bin/python" -c 'from gunicorn.app.wsgiapp import run; import gunicorn; print("Gunicorn verified:", gunicorn.__version__)'
sudo -u www-data "$APP_DIR/.venv/bin/python" -c 'from gunicorn.app.wsgiapp import run; import gunicorn; print("Gunicorn service-account check OK:", gunicorn.__version__)'

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
umask 077
[[ ${EUID} -eq 0 ]] || { echo "This updater must run as root." >&2; exit 1; }
ENV_FILE=/etc/station-archive/env
[[ -r "$ENV_FILE" ]] || { echo "Missing deployment configuration." >&2; exit 1; }
set -a; . "$ENV_FILE"; set +a
UPDATE_REPO="${GITHUB_REPO:-${APP_REPO_URL:-}}"
[[ "$UPDATE_REPO" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$ ]] || { echo "Configured repository URL is invalid." >&2; exit 1; }
[[ -d /opt/station-archive && -f /opt/station-archive/app.py ]] || { echo "Application installation not found." >&2; exit 1; }
VERSION_FILE=/var/lib/station-archive/version
TARGET_FILE=/var/lib/station-archive/update-target
TARGET_SHA="$(cat "$TARGET_FILE" 2>/dev/null || true)"
[[ "$TARGET_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "Update failed: no verified target commit was provided. Check for updates in the web interface first." >&2; exit 1; }
echo "PROGRESS:5:Preparing update"
TMP="$(mktemp -d /tmp/station-archive-update.XXXXXX)"
DEPLOYED=0; SUCCESS=0
cleanup() {
  if (( DEPLOYED == 1 && SUCCESS == 0 )); then
    if rsync -a --delete --exclude='.git/' --exclude='.venv/' "$TMP/backup/" /opt/station-archive/; then
      chown -R root:www-data /opt/station-archive
      chown root:www-data /opt/station-archive
      find /opt/station-archive -path /opt/station-archive/.venv -prune -o -type d -exec chmod 0750 {} +
      find /opt/station-archive -path /opt/station-archive/.venv -prune -o -type f -exec chmod 0640 {} +
      chown -R root:www-data /opt/station-archive/.venv || true
      chmod -R g+rX /opt/station-archive/.venv || true
      /opt/station-archive/.venv/bin/python -m pip install -r /opt/station-archive/requirements.txt >/dev/null 2>&1 || true
      /opt/station-archive/.venv/bin/python -m pip install --no-cache-dir --force-reinstall 'gunicorn>=23,<24' >/dev/null 2>&1 || true
      systemctl restart station-archive.service >/dev/null 2>&1 || true
      echo "Update failed; previous application files were restored." >&2
    else
      echo "Update failed and automatic rollback could not restore previous files." >&2
    fi
  fi
  if (( SUCCESS == 0 && DEPLOYED == 0 )); then echo "Update process failed before deployment." >&2; fi
  rm -rf -- "$TMP"
}
trap cleanup EXIT
echo "PROGRESS:12:Downloading repository and checking target version"
git clone --depth 1 "${UPDATE_REPO%/}" "$TMP/source"
SOURCE_SHA="$(git -C "$TMP/source" rev-parse HEAD)"
[[ "$SOURCE_SHA" == "$TARGET_SHA" ]] || { echo "Update failed: GitHub changed after the version check; please check again." >&2; exit 1; }
for required in app.py requirements.txt templates static; do [[ -e "$TMP/source/$required" ]] || { echo "Repository is missing required path: $required" >&2; exit 1; }; done
echo "PROGRESS:25:Backing up the current application"
mkdir -p "$TMP/backup"
rsync -a --exclude='.git/' --exclude='.venv/' /opt/station-archive/ "$TMP/backup/"
DEPLOYED=1
echo "PROGRESS:35:Stopping the application service"
systemctl stop station-archive.service
echo "PROGRESS:48:Installing application files"
rsync -a --delete --exclude='.git/' --exclude='.venv/' "$TMP/source/" /opt/station-archive/
chown -R root:www-data /opt/station-archive
chown root:www-data /opt/station-archive
find /opt/station-archive -path /opt/station-archive/.venv -prune -o -type d -exec chmod 0750 {} +
find /opt/station-archive -path /opt/station-archive/.venv -prune -o -type f -exec chmod 0640 {} +
chown -R root:www-data /opt/station-archive/.venv
chmod -R g+rX /opt/station-archive/.venv
echo "PROGRESS:62:Installing Python dependencies"
/opt/station-archive/.venv/bin/python -m pip install -r /opt/station-archive/requirements.txt
/opt/station-archive/.venv/bin/python -m pip install --no-cache-dir --force-reinstall 'gunicorn>=23,<24'
# Ensure the systemd service account can execute Gunicorn (pip-created files are root-owned).
chown root:www-data /opt/station-archive/.venv/bin/gunicorn
chmod 0750 /opt/station-archive/.venv/bin/gunicorn
/opt/station-archive/.venv/bin/python -c 'from gunicorn.app.wsgiapp import run; import gunicorn; print("Gunicorn verified:", gunicorn.__version__)'
echo "PROGRESS:80:Validating server configuration"
nginx -t
echo "PROGRESS:88:Restarting application and web server"
systemctl restart station-archive.service
systemctl is-active --quiet station-archive.service
printf '%s\n' "$SOURCE_SHA" > "$VERSION_FILE"
chown www-data:www-data "$VERSION_FILE"
chmod 0640 "$VERSION_FILE"
SUCCESS=1
echo "PROGRESS:100:Update completed successfully"
echo "IP Archive updated successfully."
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
HTTP_CODE="$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$APP_PORT/" || true)"
[[ "$HTTP_CODE" =~ ^[0-9]{3}$ && "$HTTP_CODE" != 000 && "$HTTP_CODE" -lt 500 ]] || { echo "Application health check failed (HTTP $HTTP_CODE)." >&2; exit 1; }
git -C "$WORK_DIR/source" rev-parse HEAD > "$DATA_DIR/version"
chown www-data:www-data "$DATA_DIR/version"
chmod 0640 "$DATA_DIR/version"
SUCCESS=1
echo "Upgrade completed. Existing domain, public HTTPS port, Nginx configuration, SSL certificates, secrets, and database were preserved."
echo "Backups: $BACKUP_DIR"
echo "Application URL: https://$DOMAIN:$HTTPS_PORT"
echo "Updater: sudo /usr/local/sbin/station-archive-update"
