#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ ${EUID} -eq 0 ]] || { echo "Must run as root." >&2; exit 1; }
APP_DIR=/opt/station-archive
DATA_DIR=/var/lib/station-archive
ENV_FILE=/etc/station-archive/env
SERVICE_FILE=/etc/systemd/system/station-archive.service
REQUEST_FILE="$DATA_DIR/reconfigure-request.json"
STATUS_FILE="$DATA_DIR/reconfigure-status.json"
WEBROOT=/var/www/station-archive-acme
write_status() {
  python3 - "$STATUS_FILE" "${1:-running}" "${2:-}" "${3:-${NEW_DOMAIN:-}}" "${4:-${NEW_PORT:-}}" <<'PY'
import json, os, sys, tempfile
from pathlib import Path
path = Path(sys.argv[1]); path.parent.mkdir(parents=True, exist_ok=True)
payload = {'state': sys.argv[2], 'message': sys.argv[3], 'domain': sys.argv[4], 'port': sys.argv[5]}
fd, name = tempfile.mkstemp(prefix='.reconfigure-status-', dir=path.parent)
with os.fdopen(fd, 'w', encoding='utf-8') as stream:
    json.dump(payload, stream, separators=(',', ':'))
    stream.write('\n')
os.chmod(name, 0o644)
os.replace(name, path)
PY
}
die() { write_status error "$*" "${NEW_DOMAIN:-}" "${NEW_PORT:-}" || true; echo "$*" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || { echo "Must run as root." >&2; exit 1; }
[[ -r "$REQUEST_FILE" && -r "$ENV_FILE" && -r "$SERVICE_FILE" ]] || die "Missing deployment request or server configuration."
command -v nginx >/dev/null && command -v certbot >/dev/null && command -v systemctl >/dev/null && command -v curl >/dev/null && command -v ss >/dev/null || die "Nginx, Certbot, systemd, curl and ss are required."

REQUEST_TEXT="$(python3 - "$REQUEST_FILE" <<'PY'
import json, re, sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text())
domain = str(payload.get('domain', '')).strip().lower().rstrip('.')
port = str(payload.get('port', ''))
if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*', domain):
    raise SystemExit('Invalid domain name.')
if not re.fullmatch(r'\d{1,5}', port) or not 1 <= int(port) <= 65535 or int(port) == 80:
    raise SystemExit('Invalid HTTPS port; choose 1-65535 except port 80.')
print(domain)
print(int(port))
PY
)" || die "The reconfiguration request is invalid."
NEW_DOMAIN="$(sed -n '1p' <<< "$REQUEST_TEXT")"
NEW_PORT="$(sed -n '2p' <<< "$REQUEST_TEXT")"
rm -f "$REQUEST_FILE"
write_status running "Validating DNS and preparing the new address…" "$NEW_DOMAIN" "$NEW_PORT"
set -a; . "$ENV_FILE"; set +a
OLD_DOMAIN="${APP_DOMAIN:-}"
OLD_PORT="${PUBLIC_PORT:-${APP_HTTPS_PORT:-}}"
OLD_INTERNAL="${APP_INTERNAL_PORT:-$OLD_PORT}"
[[ "$OLD_DOMAIN" =~ ^[A-Za-z0-9.-]+$ && "$OLD_PORT" =~ ^[0-9]{1,5}$ && "$OLD_INTERNAL" =~ ^[0-9]{1,5}$ ]] || die "Could not detect the existing domain or port from deployment configuration."
PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
[[ "$PUBLIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "Could not detect the public IPv4 address."
DNS_ADDRESSES="$(getent ahostsv4 "$NEW_DOMAIN" | awk '{print $1}' | sort -u || true)"
[[ -n "$DNS_ADDRESSES" ]] || die "DNS for $NEW_DOMAIN has no IPv4 address. Point it to this server or a correctly configured proxy before requesting SSL."
if ! grep -Fxq "$PUBLIC_IP" <<< "$DNS_ADDRESSES"; then
  echo "Note: DNS does not resolve directly to $PUBLIC_IP. SSL issuance will rely on the DNS proxy or forwarding being configured correctly." >&2
fi

if [[ "$NEW_PORT" != "$OLD_PORT" ]]; then
  if ss -H -ltn | awk '{print $4}' | grep -Eq "(^|:)$NEW_PORT$"; then
    die "Port $NEW_PORT is already in use. Choose a free HTTPS port."
  fi
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="/var/backups/station-archive-reconfigure-$STAMP"
install -d -o root -g root -m 0700 "$BACKUP"
cp -a "$ENV_FILE" "$BACKUP/env"
cp -a "$SERVICE_FILE" "$BACKUP/service"
OLD_AVAILABLE="/etc/nginx/sites-available/station-archive-$OLD_DOMAIN"
OLD_ENABLED="/etc/nginx/sites-enabled/station-archive-$OLD_DOMAIN"
[[ ! -e "$OLD_AVAILABLE" ]] || cp -a "$OLD_AVAILABLE" "$BACKUP/old-nginx"
OLD_ENABLED_TARGET="$(readlink "$OLD_ENABLED" 2>/dev/null || true)"
NEW_AVAILABLE="/etc/nginx/sites-available/station-archive-$NEW_DOMAIN"
NEW_ENABLED="/etc/nginx/sites-enabled/station-archive-$NEW_DOMAIN"
TEMP_ACME="/etc/nginx/sites-available/station-archive-acme-$NEW_DOMAIN"
TEMP_ACME_ENABLED="/etc/nginx/sites-enabled/station-archive-acme-$NEW_DOMAIN"
CERT_CREATED=0
SUCCESS=0
UFW_RULE_ADDED=0
DB_UPDATED=0

persist_database_address() {
  python3 - "$DATA_DIR/archive.sqlite3" "$1" "$2" <<'PY'
import sqlite3, sys
with sqlite3.connect(sys.argv[1], timeout=20) as db:
    db.execute("INSERT INTO app_settings(key,value) VALUES('public_domain',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (sys.argv[2],))
    db.execute("INSERT INTO app_settings(key,value) VALUES('public_port',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (sys.argv[3],))
PY
}

rollback() {
  status=$?
  if (( SUCCESS == 0 )); then
    echo "Reconfiguration failed; restoring the previous server configuration." >&2
    cp -a "$BACKUP/env" "$ENV_FILE" || true
    cp -a "$BACKUP/service" "$SERVICE_FILE" || true
    if (( DB_UPDATED == 1 )); then persist_database_address "$OLD_DOMAIN" "$OLD_PORT" || true; fi
    rm -f "$NEW_ENABLED" "$TEMP_ACME_ENABLED" "$NEW_AVAILABLE" "$TEMP_ACME"
    if [[ -f "$BACKUP/old-nginx" ]]; then cp -a "$BACKUP/old-nginx" "$OLD_AVAILABLE"; fi
    if [[ -n "$OLD_ENABLED_TARGET" ]]; then ln -sfn "$OLD_ENABLED_TARGET" "$OLD_ENABLED"; fi
    systemctl daemon-reload || true
    nginx -t && systemctl reload nginx || true
    systemctl restart station-archive.service || true
    if (( UFW_RULE_ADDED == 1 )) && command -v ufw >/dev/null 2>&1; then ufw --force delete allow "$NEW_PORT/tcp" >/dev/null 2>&1 || true; fi
    if (( CERT_CREATED == 1 )) && [[ "$NEW_DOMAIN" != "$OLD_DOMAIN" ]]; then
      certbot delete --cert-name "$NEW_DOMAIN" --non-interactive >/dev/null 2>&1 || true
    fi
    write_status error "The change failed. The previous server address and configuration were restored; check the server logs for details." "$NEW_DOMAIN" "$NEW_PORT" || true
    echo "Backup retained at $BACKUP" >&2
  fi
  exit "$status"
}
trap rollback EXIT

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  if ! ufw status 2>/dev/null | grep -Eq "^${NEW_PORT}/tcp[[:space:]]+ALLOW"; then
    ufw allow "$NEW_PORT/tcp" >/dev/null
    UFW_RULE_ADDED=1
  fi
fi

# Add a temporary HTTP challenge vhost for the new hostname while the old site stays online.
write_status running "Requesting and validating the HTTPS certificate…" "$NEW_DOMAIN" "$NEW_PORT"
install -d -o www-data -g www-data -m 0755 "$WEBROOT/.well-known/acme-challenge"
cat > "$TEMP_ACME" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $NEW_DOMAIN;
    location ^~ /.well-known/acme-challenge/ { root $WEBROOT; default_type "text/plain"; }
    location / { return 301 https://\$host:$NEW_PORT\$request_uri; }
}
EOF
ln -sfn "$TEMP_ACME" "$TEMP_ACME_ENABLED"
nginx -t
systemctl reload nginx

if [[ ! -s "/etc/letsencrypt/live/$NEW_DOMAIN/fullchain.pem" || ! -s "/etc/letsencrypt/live/$NEW_DOMAIN/privkey.pem" ]]; then
  CERT_CREATED=1
fi
certbot certonly --webroot -w "$WEBROOT" --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring --cert-name "$NEW_DOMAIN" -d "$NEW_DOMAIN"
[[ -s "/etc/letsencrypt/live/$NEW_DOMAIN/fullchain.pem" && -s "/etc/letsencrypt/live/$NEW_DOMAIN/privkey.pem" ]] || { echo "Certificate issuance did not produce the expected certificate files." >&2; exit 1; }

cat > "$NEW_AVAILABLE" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $NEW_DOMAIN;
    location ^~ /.well-known/acme-challenge/ { root $WEBROOT; default_type "text/plain"; }
    location / { return 301 https://\$host:$NEW_PORT\$request_uri; }
}

server {
    listen $PUBLIC_IP:$NEW_PORT ssl;
    server_name $NEW_DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$NEW_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$NEW_DOMAIN/privkey.pem;
    client_max_body_size 2m;
    location / {
        proxy_pass http://127.0.0.1:$NEW_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
    }
}
EOF

# Update the service listener and environment together; keep the prior config for rollback.
write_status running "Switching Nginx and the application listener…" "$NEW_DOMAIN" "$NEW_PORT"
python3 - "$ENV_FILE" "$NEW_DOMAIN" "$NEW_PORT" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1]); domain = sys.argv[2]; port = sys.argv[3]
values = {'APP_DOMAIN': domain, 'APP_HTTPS_PORT': port, 'PUBLIC_PORT': port, 'APP_INTERNAL_PORT': port}
lines = path.read_text().splitlines(); seen = set(); output = []
for line in lines:
    key = line.split('=', 1)[0] if '=' in line else ''
    if key in values:
        if key not in seen: output.append(f'{key}={values[key]}'); seen.add(key)
    else: output.append(line)
for key, value in values.items():
    if key not in seen: output.append(f'{key}={value}')
path.write_text('\n'.join(output) + '\n')
PY
python3 - "$SERVICE_FILE" "$OLD_INTERNAL" "$NEW_PORT" <<'PY'
from pathlib import Path
import re, sys
path = Path(sys.argv[1]); text = path.read_text()
updated, count = re.subn(r'(--bind\s+127\.0\.0\.1:)' + re.escape(sys.argv[2]) + r'\b', r'\g<1>' + sys.argv[3], text, count=1)
if count != 1: raise SystemExit('Could not safely update the Gunicorn bind port in the systemd service file.')
path.write_text(updated)
PY

ln -sfn "$NEW_AVAILABLE" "$NEW_ENABLED"
rm -f "$TEMP_ACME_ENABLED"
if [[ "$OLD_DOMAIN" != "$NEW_DOMAIN" ]]; then rm -f "$OLD_ENABLED"; fi
systemctl daemon-reload
nginx -t
systemctl restart station-archive.service
systemctl reload nginx

HTTP_CODE=000
for attempt in $(seq 1 30); do
  HTTP_CODE="$(curl --noproxy '*' -sS --connect-timeout 2 --max-time 4 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$NEW_PORT/" 2>/dev/null || true)"
  [[ "$HTTP_CODE" =~ ^[0-9]{3}$ && "$HTTP_CODE" != 000 && "$HTTP_CODE" -lt 500 ]] && break
  sleep 1
done
[[ "$HTTP_CODE" =~ ^[0-9]{3}$ && "$HTTP_CODE" != 000 && "$HTTP_CODE" -lt 500 ]] || { echo "New application listener failed health check (HTTP $HTTP_CODE)." >&2; exit 1; }
curl --noproxy '*' -kfsS --connect-timeout 3 --max-time 8 --resolve "$NEW_DOMAIN:$NEW_PORT:$PUBLIC_IP" "https://$NEW_DOMAIN:$NEW_PORT/" -o /dev/null || { echo "New HTTPS endpoint health check failed." >&2; exit 1; }

persist_database_address "$NEW_DOMAIN" "$NEW_PORT"
DB_UPDATED=1

# Only after the new HTTPS endpoint passes, remove the previous site's config and certificate.
if [[ "$OLD_DOMAIN" != "$NEW_DOMAIN" ]]; then
  rm -f "$OLD_ENABLED" "$OLD_AVAILABLE"
  nginx -t
  systemctl reload nginx
  if certbot certificates 2>/dev/null | grep -Fq "Certificate Name: $OLD_DOMAIN"; then
    certbot delete --cert-name "$OLD_DOMAIN" --non-interactive || { echo "Could not delete the old SSL certificate; rolling the site configuration back." >&2; exit 1; }
  fi
fi
SUCCESS=1
trap - EXIT
write_status success "The new HTTPS endpoint is active. Opening the new address…" "$NEW_DOMAIN" "$NEW_PORT" || true
echo "SUCCESS: https://$NEW_DOMAIN:$NEW_PORT"
echo "Old HTTPS port is no longer configured for this application. Backup: $BACKUP"
