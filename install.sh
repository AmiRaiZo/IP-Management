#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root, for example: curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/install.sh | sudo bash" >&2
  exit 1
fi

prompt() { local name="$1" label="$2" default="${3:-}" value=""; if [[ -n "$default" ]]; then read -r -p "$label [$default]: " value < /dev/tty; value="${value:-$default}"; else read -r -p "$label: " value < /dev/tty; fi; printf -v "$name" '%s' "$value"; }
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

prompt DOMAIN "Domain name (DNS must point to this server)"
DOMAIN="${DOMAIN,,}"
[[ "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] || { echo "Invalid domain name." >&2; exit 1; }
prompt HTTPS_PORT "Public HTTPS port" "443"
valid_port "$HTTPS_PORT" || { echo "HTTPS port must be between 1 and 65535." >&2; exit 1; }
HTTPS_PORT=$((10#$HTTPS_PORT))
[[ "$HTTPS_PORT" != 80 ]] || { echo "HTTPS cannot use port 80." >&2; exit 1; }
prompt APP_PORT "Internal application port" "8088"
[[ "$APP_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$APP_PORT >= 1024 && 10#$APP_PORT <= 65535 )) || { echo "Application port must be between 1024 and 65535." >&2; exit 1; }
APP_PORT=$((10#$APP_PORT))
(( APP_PORT != HTTPS_PORT && APP_PORT != 80 )) || { echo "Choose an internal port different from ports 80 and the public HTTPS port." >&2; exit 1; }
prompt REPO_URL "Public GitHub repository HTTPS URL"
[[ "$REPO_URL" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$ ]] || { echo "Use a public GitHub URL such as https://github.com/OWNER/REPOSITORY.git" >&2; exit 1; }
REPO_URL="${REPO_URL%/}"
prompt ADMIN_USER "Superadmin username"
[[ "$ADMIN_USER" =~ ^[A-Za-z0-9_.@-]{3,80}$ ]] || { echo "Username must be 3–80 characters using English letters, numbers, dot, underscore, @, and hyphen." >&2; exit 1; }
read -r -s -p "Superadmin password: " ADMIN_PASSWORD < /dev/tty; printf '\n' > /dev/tty
read -r -s -p "Confirm superadmin password: " ADMIN_PASSWORD_CONFIRM < /dev/tty; printf '\n' > /dev/tty
[[ "$ADMIN_PASSWORD" == "$ADMIN_PASSWORD_CONFIRM" ]] || { echo "Passwords do not match." >&2; exit 1; }
[[ -n "$ADMIN_PASSWORD" ]] || { echo "Password must not be empty." >&2; exit 1; }

if [[ -e /opt/station-archive ]]; then
  echo "/opt/station-archive already exists. Installer stopped to protect the existing deployment." >&2
  exit 1
fi
echo "Install target: https://$DOMAIN:$HTTPS_PORT (internal port $APP_PORT)"
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
for required in app.py setup_admin.py requirements.txt templates static; do
  [[ -e "$SOURCE_DIR/$required" ]] || { echo "Repository is missing required path: $required" >&2; exit 1; }
done

install -d -o root -g root -m 0750 /opt/station-archive
rsync -a --delete --exclude='.git/' "$SOURCE_DIR/" /opt/station-archive/
chown -R root:root /opt/station-archive
chown root:www-data /opt/station-archive
chmod 0750 /opt/station-archive
python3 -m venv /opt/station-archive/.venv
/opt/station-archive/.venv/bin/pip install --upgrade pip
/opt/station-archive/.venv/bin/pip install -r /opt/station-archive/requirements.txt

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
APP_INTERNAL_PORT=$APP_PORT
EOF
  chmod 0640 /etc/station-archive/env
  chown root:www-data /etc/station-archive/env
fi
for setting in "APP_REPO_URL=$REPO_URL" "GITHUB_REPO=$REPO_URL" "APP_DOMAIN=$DOMAIN" "APP_HTTPS_PORT=$HTTPS_PORT" "PUBLIC_PORT=$HTTPS_PORT" "APP_INTERNAL_PORT=$APP_PORT"; do
  key="${setting%%=*}"
  if ! grep -qE "^${key}=" /etc/station-archive/env; then
    printf '%s\n' "$setting" >> /etc/station-archive/env
  fi
done
chown root:www-data /etc/station-archive/env
chmod 0640 /etc/station-archive/env
chown root:www-data /etc/station-archive
chmod 0750 /etc/station-archive

cat > /etc/systemd/system/station-archive.service <<EOF
[Unit]
Description=IP Archive Web Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/station-archive
EnvironmentFile=/etc/station-archive/env
ExecStart=/opt/station-archive/.venv/bin/gunicorn --workers 2 --bind 127.0.0.1:$APP_PORT --timeout 60 app:app
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
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
ln -s "$NGINX_FILE" "/etc/nginx/sites-enabled/station-archive-$DOMAIN"
nginx -t
systemctl enable --now nginx
if ! certbot certonly --webroot -w "$WEBROOT" --non-interactive --agree-tos --register-unsafely-without-email -d "$DOMAIN"; then
  echo "TLS certificate issuance failed. Check DNS and inbound TCP port 80, then run: certbot certonly --webroot -w $WEBROOT -d $DOMAIN" >&2
  exit 2
fi

cat >> "$NGINX_FILE" <<EOF

server {
    listen $HTTPS_PORT ssl;
    listen [::]:$HTTPS_PORT ssl;
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    client_max_body_size 2m;
    location / {
        proxy_pass http://127.0.0.1:$APP_PORT;
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
UPDATE_REPO="${GITHUB_REPO:-${APP_REPO_URL:-}}"
[[ "$UPDATE_REPO" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$ ]] || { echo "Configured repository URL is invalid." >&2; exit 1; }
[[ -d /opt/station-archive && -f /opt/station-archive/app.py ]] || { echo "Application installation not found." >&2; exit 1; }
[[ "${APP_INTERNAL_PORT:-}" =~ ^[0-9]{1,5}$ ]] && (( APP_INTERNAL_PORT >= 1 && APP_INTERNAL_PORT <= 65535 )) || { echo "Configured application port is invalid." >&2; exit 1; }
TMP="$(mktemp -d /tmp/station-archive-update.XXXXXX)"
DEPLOYED=0
SUCCESS=0
cleanup() {
  if (( DEPLOYED == 1 && SUCCESS == 0 )); then
    if rsync -a --delete --exclude='.git/' --exclude='.venv/' "$TMP/backup/" /opt/station-archive/; then
      chown -R root:root /opt/station-archive
      chown root:www-data /opt/station-archive
      chmod 0750 /opt/station-archive
      /opt/station-archive/.venv/bin/pip install -r /opt/station-archive/requirements.txt >/dev/null 2>&1 || true
      systemctl restart station-archive >/dev/null 2>&1 || true
      echo "Update failed; previous application files were restored." >&2
    else
      echo "Update failed and automatic rollback could not restore the previous files. Inspect /opt/station-archive and the service logs." >&2
    fi
  fi
  rm -rf -- "$TMP"
}
trap cleanup EXIT
git clone --depth 1 "${UPDATE_REPO%/}" "$TMP/source"
for required in app.py requirements.txt templates static; do [[ -e "$TMP/source/$required" ]] || { echo "Repository is missing required path: $required" >&2; exit 1; }; done
mkdir -p "$TMP/backup"
rsync -a --exclude='.git/' --exclude='.venv/' /opt/station-archive/ "$TMP/backup/"
DEPLOYED=1
systemctl stop station-archive.service
rsync -a --delete --exclude='.git/' --exclude='.venv/' "$TMP/source/" /opt/station-archive/
chown -R root:root /opt/station-archive
chown root:www-data /opt/station-archive
chmod 0750 /opt/station-archive
/opt/station-archive/.venv/bin/pip install -r /opt/station-archive/requirements.txt
nginx -t
systemctl restart station-archive
systemctl reload nginx
systemctl is-active --quiet station-archive
SUCCESS=1
echo "IP Archive updated successfully."
UPDATER
chown root:root /usr/local/sbin/station-archive-update
chmod 0750 /usr/local/sbin/station-archive-update
cat > /etc/sudoers.d/station-archive-update <<'SUDOERS'
www-data ALL=(root) NOPASSWD: /usr/local/sbin/station-archive-update
SUDOERS
chmod 0440 /etc/sudoers.d/station-archive-update
visudo -cf /etc/sudoers.d/station-archive-update

systemctl daemon-reload
systemctl enable --now station-archive
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
echo "IP Archive installation completed. Sign in at https://$DOMAIN:$HTTPS_PORT"
echo "Runtime data: /var/lib/station-archive"
echo "Runtime configuration: /etc/station-archive/env"
echo "To update from the configured GitHub repository: sudo /usr/local/sbin/station-archive-update"
echo "Allow inbound TCP ports 80 and $HTTPS_PORT in your VPS provider firewall and host firewall."
