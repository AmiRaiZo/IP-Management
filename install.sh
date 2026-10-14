#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root, for example: curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/install.sh | sudo bash" >&2
  exit 1
fi

prompt() { local name="$1" label="$2" default="${3:-}" value=""; if [[ -n "$default" ]]; then read -r -p "$label [$default]: " value < /dev/tty; value="${value:-$default}"; else read -r -p "$label: " value < /dev/tty; fi; printf -v "$name" '%s' "$value"; }
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

# If an installation already exists, route the same install command into the
# dedicated in-place upgrader before asking for fresh-install credentials.
REPO_URL="https://github.com/AmiRaiZo/IP-Management"
UPGRADE_URL="https://raw.githubusercontent.com/AmiRaiZo/IP-Management/main/upgrade_existing.sh"
if [[ -e /opt/station-archive ]]; then
  if [[ ! -d /opt/station-archive || ! -f /opt/station-archive/app.py ]]; then
    echo "/opt/station-archive exists but does not look like an IP Management installation. Refusing to overwrite it." >&2
    exit 1
  fi
  command -v curl >/dev/null 2>&1 || { echo "curl is required to download the upgrade script." >&2; exit 1; }
  UPGRADE_SCRIPT="$(mktemp /tmp/station-archive-upgrade.XXXXXX.sh)"
  trap 'rm -f -- "$UPGRADE_SCRIPT"' EXIT
  echo "Existing IP Management installation detected. Starting the in-place upgrade workflow..."
  if ! curl -fsSL "$UPGRADE_URL" -o "$UPGRADE_SCRIPT"; then
    echo "Could not download the upgrade script. No existing files were changed." >&2
    exit 1
  fi
  bash "$UPGRADE_SCRIPT"
  exit $?
fi

prompt DOMAIN "Domain name (DNS must point to this server)"
DOMAIN="${DOMAIN,,}"
[[ "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || { echo "Invalid domain name." >&2; exit 1; }
prompt HTTPS_PORT "HTTPS port (public and application use the same port number)" "443"
valid_port "$HTTPS_PORT" || { echo "HTTPS port must be between 1 and 65535." >&2; exit 1; }
HTTPS_PORT=$((10#$HTTPS_PORT))
[[ "$HTTPS_PORT" != 80 ]] || { echo "HTTPS cannot use port 80." >&2; exit 1; }
# Nginx binds the server's public IPv4 address while Gunicorn binds loopback.
# They can therefore share the same TCP port number without socket conflict.
PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i ~ /src/) {print $(i+1); exit}}')"
[[ "$PUBLIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Could not detect the server's outbound IPv4 address. A single shared port requires the public IPv4 address to be assigned directly to this VPS." >&2; exit 1; }
ip -o -4 addr show | grep -Fq " $PUBLIC_IP/" || { echo "Detected IPv4 $PUBLIC_IP is not assigned to a local interface. This VPS may be behind NAT; same-number public and loopback ports cannot be used with this Nginx setup." >&2; exit 1; }
prompt ADMIN_USER "Superadmin username"
[[ "$ADMIN_USER" =~ ^[A-Za-z0-9_.@-]{3,80}$ ]] || { echo "Username must be 3–80 characters using English letters, numbers, dot, underscore, @, and hyphen." >&2; exit 1; }
read -r -s -p "Superadmin password: " ADMIN_PASSWORD < /dev/tty; printf '\n' > /dev/tty
read -r -s -p "Confirm superadmin password: " ADMIN_PASSWORD_CONFIRM < /dev/tty; printf '\n' > /dev/tty
[[ "$ADMIN_PASSWORD" == "$ADMIN_PASSWORD_CONFIRM" ]] || { echo "Passwords do not match." >&2; exit 1; }
[[ -n "$ADMIN_PASSWORD" ]] || { echo "Password must not be empty." >&2; exit 1; }

echo "Install target: https://$DOMAIN:$HTTPS_PORT (single port $HTTPS_PORT; public bind $PUBLIC_IP, app bind 127.0.0.1)"
echo "Make sure DNS points to this server and inbound TCP ports 80 and $HTTPS_PORT are allowed by both the VPS provider and the server firewall."
read -r -p "Type YES to continue: " CONFIRM < /dev/tty
[[ "$CONFIRM" == YES ]] || { echo "Cancelled."; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git rsync ca-certificates python3 python3-venv python3-pip nginx certbot openssl

WORK_DIR="$(mktemp -d /tmp/station-archive-install.XXXXXX)"
cleanup() { rm -rf -- "$WORK_DIR"; [[ -z "${ADMIN_CREDENTIALS:-}" ]] || rm -f -- "$ADMIN_CREDENTIALS"; unset ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM; }
trap cleanup EXIT
git clone --depth 1 "$REPO_URL" "$WORK_DIR/source"
SOURCE_DIR="$WORK_DIR/source"
for required in app.py setup_admin.py requirements.txt templates static reconfigure_server.sh; do
  [[ -e "$SOURCE_DIR/$required" ]] || { echo "Repository is missing required path: $required" >&2; exit 1; }
done

install -d -o root -g root -m 0750 /opt/station-archive
rsync -a --delete --exclude='.git/' "$SOURCE_DIR/" /opt/station-archive/
chown -R root:www-data /opt/station-archive
chown root:www-data /opt/station-archive
find /opt/station-archive -type d -exec chmod 0750 {} +
find /opt/station-archive -type f -exec chmod 0640 {} +
python3 -m venv /opt/station-archive/.venv
/opt/station-archive/.venv/bin/pip install --upgrade pip
/opt/station-archive/.venv/bin/pip install -r /opt/station-archive/requirements.txt
/opt/station-archive/.venv/bin/python -m pip install --no-cache-dir --force-reinstall 'gunicorn>=23,<24'
# Ensure the systemd service account can execute Gunicorn (pip-created files are root-owned).
chown root:www-data /opt/station-archive/.venv/bin/gunicorn
chmod 0750 /opt/station-archive/.venv/bin/gunicorn
/opt/station-archive/.venv/bin/python -c 'from gunicorn.app.wsgiapp import run; import gunicorn; print("Gunicorn verified:", gunicorn.__version__)'
chown -R root:www-data /opt/station-archive/.venv
chmod -R g+rX /opt/station-archive/.venv

install -d -o root -g root -m 0750 /etc/station-archive
install -d -o www-data -g www-data -m 0750 /var/lib/station-archive
if [[ ! -e /etc/station-archive/env ]]; then
  SECRET_KEY="$(openssl rand -hex 48)"
  FERNET_KEY="$(/opt/station-archive/.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
  cat > /etc/station-archive/env <<EOF
SECRET_KEY=$SECRET_KEY
FERNET_KEY=$FERNET_KEY
STATION_ARCHIVE_DATA=/var/lib/station-archive
COOKIE_SECURE=1
APP_REPO_URL=$REPO_URL
GITHUB_REPO=$REPO_URL
APP_DOMAIN=$DOMAIN
APP_HTTPS_PORT=$HTTPS_PORT
PUBLIC_PORT=$HTTPS_PORT
APP_INTERNAL_PORT=$HTTPS_PORT
EOF
  chmod 0640 /etc/station-archive/env
  chown root:www-data /etc/station-archive/env
fi
for setting in "APP_REPO_URL=$REPO_URL" "GITHUB_REPO=$REPO_URL" "APP_DOMAIN=$DOMAIN" "APP_HTTPS_PORT=$HTTPS_PORT" "PUBLIC_PORT=$HTTPS_PORT" "APP_INTERNAL_PORT=$HTTPS_PORT"; do
  key="${setting%%=*}"
  if ! grep -qE "^${key}=" /etc/station-archive/env; then
    printf '%s\n' "$setting" >> /etc/station-archive/env
  fi
done
chown root:www-data /etc/station-archive/env
chmod 0640 /etc/station-archive/env
chown root:www-data /etc/station-archive
chmod 0750 /etc/station-archive
chown -R www-data:www-data /var/lib/station-archive
find /var/lib/station-archive -type d -exec chmod 0750 {} +
find /var/lib/station-archive -type f -exec chmod 0640 {} +
SOURCE_SHA="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
printf '%s\n' "$SOURCE_SHA" > /var/lib/station-archive/commit
python3 - "$SOURCE_SHA" /var/lib/station-archive/version "$SOURCE_DIR/VERSION" <<'PY'
import json, re, sys
from pathlib import Path
from urllib.request import Request, urlopen
source_sha, output, version_path = sys.argv[1:]
version = Path(version_path).read_text(encoding="utf-8").strip()
try:
    req = Request("https://api.github.com/repos/AmiRaiZo/IP-Management/releases/latest",
                  headers={"Accept":"application/vnd.github+json", "User-Agent":"IP-Archive-Installer"})
    with urlopen(req, timeout=8) as response:
        release = json.loads(response.read(256_000).decode("utf-8"))
    if release.get("target_commitish") == source_sha:
        candidate = str(release.get("tag_name", "")).strip().lstrip("v")
        if re.fullmatch(r"\d+\.\d+\.\d+", candidate):
            version = candidate
except Exception:
    pass
Path(output).write_text(version + "\n", encoding="utf-8")
PY
chown www-data:www-data /var/lib/station-archive/version
chmod 0640 /var/lib/station-archive/version

cat > /etc/systemd/system/station-archive.service <<EOF
[Unit]
Description=IP Management Web Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/station-archive
EnvironmentFile=/etc/station-archive/env
ExecStart=/opt/station-archive/.venv/bin/gunicorn --workers 2 --bind 127.0.0.1:$HTTPS_PORT --timeout 60 app:app
Restart=on-failure
RestartSec=3
NoNewPrivileges=false
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/station-archive
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

WEBROOT=/var/www/station-archive-acme
install -d -o www-data -g www-data -m 0755 "$WEBROOT/.well-known/acme-challenge"
NGINX_FILE="/etc/nginx/sites-available/station-archive-$DOMAIN"
cat > "$NGINX_FILE" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location ^~ /.well-known/acme-challenge/ { root $WEBROOT; default_type "text/plain"; }
    location / { return 301 https://\$host:$HTTPS_PORT\$request_uri; }
}
EOF
ln -sfn "$NGINX_FILE" "/etc/nginx/sites-enabled/station-archive-$DOMAIN"
(more lines follow — continue from line 161)
nginx -t
systemctl enable --now nginx
if ! certbot certonly --webroot -w "$WEBROOT" --non-interactive --agree-tos --register-unsafely-without-email -d "$DOMAIN"; then
  echo "TLS certificate issuance failed. Check DNS and inbound TCP port 80, then run: certbot certonly --webroot -w $WEBROOT -d $DOMAIN" >&2
  exit 2
fi

cat >> "$NGINX_FILE" <<EOF

server {
    listen $PUBLIC_IP:$HTTPS_PORT ssl;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    client_max_body_size 2m;
    location / {
        proxy_pass http://127.0.0.1:$HTTPS_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
    }
}
EOF

cat > /usr/local/sbin/station-archive-update <<'UPDATER'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ ${EUID} -eq 0 ]] || { echo "This updater must run as root." >&2; exit 1; }
ENV_FILE=/etc/station-archive/env
[[ -r "$ENV_FILE" ]] || { echo "Missing deployment configuration." >&2; exit 1; }
set -a
. "$ENV_FILE"
set +a
APP_PORT="${APP_INTERNAL_PORT:-${APP_PORT:-}}"
[[ "$APP_PORT" =~ ^[0-9]{1,5}$ ]] && (( APP_PORT >= 1 && APP_PORT <= 65535 )) || { echo "Configured internal application port is missing or invalid." >&2; exit 1; }
UPDATE_REPO="${GITHUB_REPO:-${APP_REPO_URL:-}}"
if [[ -f /var/lib/station-archive/update-repository ]]; then
  UPDATE_REPO="$(cat /var/lib/station-archive/update-repository)"
fi
[[ "$UPDATE_REPO" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$ ]] || { echo "Configured repository URL is invalid." >&2; exit 1; }
[[ -d /opt/station-archive && -f /opt/station-archive/app.py ]] || { echo "Application installation not found." >&2; exit 1; }
[[ "${APP_INTERNAL_PORT:-}" =~ ^[0-9]{1,5}$ ]] && (( APP_INTERNAL_PORT >= 1 && APP_INTERNAL_PORT <= 65535 )) || { echo "Configured application port is invalid." >&2; exit 1; }
VERSION_FILE=/var/lib/station-archive/version
TARGET_FILE=/var/lib/station-archive/update-target
TARGET_SHA="$(cat "$TARGET_FILE" 2>/dev/null || true)"
[[ "$TARGET_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "Update failed: no verified target commit was provided. Check for updates in the web interface first." >&2; exit 1; }
echo "PROGRESS:5:Preparing update"
TMP="$(mktemp -d /tmp/station-archive-update.XXXXXX)"
DEPLOYED=0
SUCCESS=0
cleanup() {
  if (( DEPLOYED == 1 && SUCCESS == 0 )); then
    if rsync -a --delete --exclude='.git/' --exclude='.venv/' "$TMP/backup/" /opt/station-archive/; then
      chown -R root:www-data /opt/station-archive
      chown root:www-data /opt/station-archive
      find /opt/station-archive -type d -exec chmod 0750 {} +
      find /opt/station-archive -type f -exec chmod 0640 {} +
      chown -R root:www-data /opt/station-archive/.venv || true
      chmod -R g+rX /opt/station-archive/.venv || true
      /opt/station-archive/.venv/bin/python -m pip install -r /opt/station-archive/requirements.txt >/dev/null 2>&1 || true
	      /opt/station-archive/.venv/bin/python -m pip install --no-cache-dir --force-reinstall 'gunicorn>=23,<24' >/dev/null 2>&1 || true
	      if ! (cd /opt/station-archive && /opt/station-archive/.venv/bin/python -c 'from gunicorn.app.wsgiapp import run') >/dev/null 2>&1; then
	        mv /opt/station-archive/.venv "$TMP/venv-rollback-broken" || true
	        python3 -m venv /opt/station-archive/.venv || true
	        /opt/station-archive/.venv/bin/python -m pip install -r /opt/station-archive/requirements.txt || true
	        /opt/station-archive/.venv/bin/python -m pip install --no-cache-dir --force-reinstall 'gunicorn>=23,<24' || true
	        chown -R root:www-data /opt/station-archive/.venv || true
	        chmod -R g+rX /opt/station-archive/.venv || true
	      fi
      systemctl restart station-archive >/dev/null 2>&1 || true
      echo "Update failed; previous application files were restored." >&2
    else
      echo "Update failed and automatic rollback could not restore the previous files. Inspect /opt/station-archive and the service logs." >&2
    fi
  fi
  if (( SUCCESS == 0 && DEPLOYED == 0 )); then echo "Update process failed before deployment." >&2; fi
  rm -rf -- "$TMP"
}
trap cleanup EXIT
echo "PROGRESS:12:Downloading repository and checking target version"
git init -q "$TMP/source"
git -C "$TMP/source" remote add origin "${UPDATE_REPO%/}"
git -C "$TMP/source" fetch --depth 1 origin "$TARGET_SHA"
git -C "$TMP/source" checkout --quiet --detach FETCH_HEAD
SOURCE_SHA="$(git -C "$TMP/source" rev-parse HEAD)"
[[ "$SOURCE_SHA" == "$TARGET_SHA" ]] || { echo "Update failed: downloaded commit does not match the verified target." >&2; exit 1; }
for required in app.py requirements.txt templates static reconfigure_server.sh; do [[ -e "$TMP/source/$required" ]] || { echo "Repository is missing required path: $required" >&2; exit 1; }; done
echo "PROGRESS:25:Backing up the current application"
mkdir -p "$TMP/backup"
rsync -a --exclude='.git/' --exclude='.venv/' /opt/station-archive/ "$TMP/backup/"
DEPLOYED=1
	echo "PROGRESS:32:Preparing the application backup"
	echo "PROGRESS:35:Installing application files while the current worker stays online"
	rsync -a --delete --exclude='.git/' --exclude='.venv/' "$TMP/source/" /opt/station-archive/
	echo "PROGRESS:50:Installing privileged helper and server service configuration"
install -o root -g root -m 0750 "$TMP/source/reconfigure_server.sh" /usr/local/sbin/station-archive-reconfigure
cat > /etc/sudoers.d/station-archive-update <<'SUDOERS'
www-data ALL=(root) NOPASSWD: /usr/bin/systemctl start station-archive-update.service, /usr/bin/systemctl --no-block start station-archive-reconfigure.service
SUDOERS
chmod 0440 /etc/sudoers.d/station-archive-update
visudo -cf /etc/sudoers.d/station-archive-update
cat > /etc/systemd/system/station-archive-reconfigure.service <<'RECONFIGUNIT'
[Unit]
Description=IP Management server address reconfiguration
After=network-online.target nginx.service
Wants=network-online.target
[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/sbin/station-archive-reconfigure
StandardOutput=journal
StandardError=journal
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=false
ReadWritePaths=/etc/nginx /etc/letsencrypt /etc/systemd/system /etc/station-archive /var/lib/station-archive /var/backups /usr/local/sbin -/etc/ufw
TimeoutStartSec=300
UMask=0077
RECONFIGUNIT
chmod 0644 /etc/systemd/system/station-archive-reconfigure.service
systemctl daemon-reload
chown -R root:www-data /opt/station-archive
chown root:www-data /opt/station-archive
find /opt/station-archive -type d -exec chmod 0750 {} +
find /opt/station-archive -type f -exec chmod 0640 {} +
chown -R root:www-data /opt/station-archive/.venv
chmod -R g+rX /opt/station-archive/.venv
	echo "PROGRESS:58:Checking the Python virtual environment from the application directory"
	# Check from the exact working directory used by systemd; the updater itself runs from /.
	if ! (cd /opt/station-archive && /opt/station-archive/.venv/bin/python -c 'from gunicorn.app.wsgiapp import run; import gunicorn; print("Gunicorn import path:", gunicorn.__file__)') >/dev/null 2>&1; then
	  echo "PROGRESS:60:Rebuilding the damaged Python virtual environment"
	  mv /opt/station-archive/.venv "$TMP/venv-before-rebuild"
	  python3 -m venv /opt/station-archive/.venv
	fi
	echo "PROGRESS:62:Installing Python dependencies"
	/opt/station-archive/.venv/bin/python -m pip install --upgrade pip
	echo "PROGRESS:68:Installing application requirements"
	/opt/station-archive/.venv/bin/python -m pip install -r /opt/station-archive/requirements.txt
	echo "PROGRESS:73:Repairing Gunicorn installation"
	/opt/station-archive/.venv/bin/python -m pip install --no-cache-dir --force-reinstall 'gunicorn>=23,<24'
	echo "PROGRESS:77:Fixing application dependency permissions"
	chown -R root:www-data /opt/station-archive/.venv
	chmod -R g+rX /opt/station-archive/.venv
	chown root:www-data /opt/station-archive/.venv/bin/gunicorn
	chmod 0750 /opt/station-archive/.venv/bin/gunicorn
	echo "PROGRESS:80:Verifying Gunicorn as the actual service user"
	(cd /opt/station-archive && /opt/station-archive/.venv/bin/python -c 'from gunicorn.app.wsgiapp import run; import gunicorn; print("Gunicorn verified:", gunicorn.__version__, gunicorn.__file__)')
	runuser -u www-data -- /opt/station-archive/.venv/bin/gunicorn --version
	echo "PROGRESS:84:Validating Nginx configuration"
	nginx -t
	echo "PROGRESS:88:Restarting application with the verified environment"
	systemctl restart station-archive
	systemctl is-active --quiet station-archive
	echo "PROGRESS:91:Waiting for the application health check"
	# Allow Gunicorn time to bind after systemd starts the service.
HTTP_CODE=000
for attempt in $(seq 1 30); do
  if systemctl is-active --quiet station-archive; then
    HTTP_CODE="$(curl --noproxy '*' -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$APP_PORT/" 2>/dev/null || true)"
    if [[ "$HTTP_CODE" =~ ^[0-9]{3}$ && "$HTTP_CODE" != 000 && "$HTTP_CODE" -lt 500 ]]; then
      break
    fi
  fi
  sleep 1
done
if ! [[ "$HTTP_CODE" =~ ^[0-9]{3}$ && "$HTTP_CODE" != 000 && "$HTTP_CODE" -lt 500 ]]; then
  echo "Application health check failed after 30 seconds (HTTP $HTTP_CODE)." >&2
  journalctl -u station-archive.service -n 60 --no-pager >&2 || true
  exit 1
fi
	echo "PROGRESS:97:Recording the installed version"
	TARGET_VERSION="$(cat /var/lib/station-archive/update-target-version 2>/dev/null || true)"
[[ "$TARGET_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Update failed: release version is missing or invalid." >&2; exit 1; }
printf '%s\n' "$TARGET_VERSION" > "$VERSION_FILE"
printf '%s\n' "$SOURCE_SHA" > /var/lib/station-archive/commit
chown www-data:www-data "$VERSION_FILE"
chmod 0640 "$VERSION_FILE"
SUCCESS=1
echo "PROGRESS:100:Update completed successfully"
echo "IP Management updated successfully."
UPDATER
chown root:root /usr/local/sbin/station-archive-update
chmod 0750 /usr/local/sbin/station-archive-update
install -o root -g root -m 0750 "$SOURCE_DIR/reconfigure_server.sh" /usr/local/sbin/station-archive-reconfigure
cat > /etc/systemd/system/station-archive-update.service <<'UPDATEUNIT'
[Unit]
Description=IP Management privileged updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/sbin/station-archive-update
StandardOutput=append:/var/lib/station-archive/update.log
StandardError=inherit
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=false
ReadWritePaths=/opt/station-archive /var/lib/station-archive /usr/local/sbin /etc/sudoers.d /etc/systemd/system
UMask=0077
UPDATEUNIT
cat > /etc/systemd/system/station-archive-reconfigure.service <<'RECONFIGUNIT'
[Unit]
Description=IP Management server address reconfiguration
After=network-online.target nginx.service
Wants=network-online.target
[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/sbin/station-archive-reconfigure
StandardOutput=journal
StandardError=journal
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=false
ReadWritePaths=/etc/nginx /etc/letsencrypt /etc/systemd/system /etc/station-archive /var/lib/station-archive /var/backups /usr/local/sbin -/etc/ufw
TimeoutStartSec=300
UMask=0077
RECONFIGUNIT
chown root:root /etc/systemd/system/station-archive-update.service
chmod 0644 /etc/systemd/system/station-archive-update.service
cat > /etc/sudoers.d/station-archive-update <<'SUDOERS'
www-data ALL=(root) NOPASSWD: /usr/bin/systemctl start station-archive-update.service, /usr/bin/systemctl --no-block start station-archive-reconfigure.service
SUDOERS
chmod 0440 /etc/sudoers.d/station-archive-update
visudo -cf /etc/sudoers.d/station-archive-update

systemctl daemon-reload
systemctl enable --now station-archive
if ! systemctl is-active --quiet station-archive; then
  echo "Application service failed to start. Recent service logs:" >&2
  journalctl -u station-archive -n 60 --no-pager >&2 || true
  exit 1
fi
nginx -t
systemctl reload nginx

ADMIN_CREDENTIALS="/run/station-archive-admin-credentials.$$"
install -o www-data -g www-data -m 0600 /dev/null "$ADMIN_CREDENTIALS"
printf '%s\n%s\n' "$ADMIN_USER" "$ADMIN_PASSWORD" > "$ADMIN_CREDENTIALS"
chmod 0600 "$ADMIN_CREDENTIALS"
cd /opt/station-archive
sudo -u www-data bash -c 'set -a; . /etc/station-archive/env; set +a; exec /opt/station-archive/.venv/bin/python - "$1"' _ "$ADMIN_CREDENTIALS" <<'PY'
import sys, sqlite3
from datetime import datetime, timezone
from app import DB_PATH, password_hash
with open(sys.argv[1], encoding="utf-8") as credentials:
    username = credentials.readline().rstrip("\n")
    password = credentials.readline().rstrip("\n")
with sqlite3.connect(DB_PATH) as db:
    existing = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        raise SystemExit("That username already exists in the database; installation stopped without changing it.")
    db.execute("INSERT INTO users(username,password_hash,created_at,role,totp_secret) VALUES(?,?,?,?,?)",
               (username, password_hash(password), datetime.now(timezone.utc).isoformat(timespec="seconds"), "superadmin", ""))
PY
rm -f -- "$ADMIN_CREDENTIALS"

unset ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM
echo
echo "IP Management installation completed. Sign in at https://$DOMAIN:$HTTPS_PORT"
echo "Runtime data: /var/lib/station-archive"
echo "Runtime configuration: /etc/station-archive/env"
echo "To update from the configured GitHub repository: sudo /usr/local/sbin/station-archive-update"
echo "Allow inbound TCP ports 80 and $HTTPS_PORT in your VPS provider firewall and host firewall."
