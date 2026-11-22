#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this upgrade as root, for example: curl -fsSL https://raw.githubusercontent.com/OWNER/REPOSITORY/main/upgrade_existing.sh | sudo bash" >&2
  exit 1
fi

APP_DIR=/opt/station-archive
DATA_DIR=/var/lib/station-archive
ENV_FILE=/etc/station-archive/env
SERVICE_FILE=/etc/systemd/system/station-archive.service
normalize_venv_permissions() {
  local venv_dir="$1"
  [[ -x "$venv_dir/bin/python" && -d "$venv_dir/bin" ]] || return 1
  chown -R root:www-data "$venv_dir"
  find "$venv_dir" -type d -exec chmod 0750 {} +
  find "$venv_dir" -type f -exec chmod 0640 {} +
  find "$venv_dir/bin" -maxdepth 1 -type f -exec chmod 0750 {} +
}
verify_gunicorn_as_service_user() {
  local venv_dir="$1"
  runuser -u www-data -- /usr/bin/env -i \
    HOME=/var/lib/station-archive USER=www-data LOGNAME=www-data \
    PYTHONDONTWRITEBYTECODE=1 PATH=/usr/bin:/bin \
    "$venv_dir/bin/python" -c 'from gunicorn.app.wsgiapp import run; import gunicorn; print("Gunicorn import verified for www-data:", gunicorn.__version__, gunicorn.__file__)'
  runuser -u www-data -- /usr/bin/env -i \
    HOME=/var/lib/station-archive USER=www-data LOGNAME=www-data \
    PYTHONDONTWRITEBYTECODE=1 PATH=/usr/bin:/bin \
    "$venv_dir/bin/gunicorn" --version
}
if ! command -v apt-get >/dev/null 2>&1; then
  echo "Automatic dependency installation currently supports Debian and Ubuntu (apt-get)." >&2
  exit 1
fi
if [[ "${IPM_SYSTEM_DEPS_READY:-0}" != 1 ]]; then
  export DEBIAN_FRONTEND=noninteractive
  echo "Checking and installing IP Management server requirements..."
  SYSTEM_PACKAGES=(ca-certificates curl git rsync python3 python3-venv python3-pip nginx certbot openssl systemd sudo iproute2 util-linux procps)
  MISSING_PACKAGES=()
  for package in "${SYSTEM_PACKAGES[@]}"; do
    if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -qx 'install ok installed'; then
      MISSING_PACKAGES+=("$package")
    fi
  done
  if (( ${#MISSING_PACKAGES[@]} > 0 )); then
    echo "Installing missing system packages: ${MISSING_PACKAGES[*]}"
    apt-get update
    # Nginx's package postinst can try to start the service before this
    # upgrader refreshes the application's custom systemd preflight unit.
    # Suppress only that automatic start; the upgrader validates and restarts
    # Nginx after all current unit files and helpers have been installed.
    POLICY_RC_D=/usr/sbin/policy-rc.d
    POLICY_BACKUP=""
    if [[ -e "$POLICY_RC_D" || -L "$POLICY_RC_D" ]]; then
      POLICY_BACKUP="$(mktemp /usr/sbin/.policy-rc.d.ipm.XXXXXX)"
      cp -a "$POLICY_RC_D" "$POLICY_BACKUP"
    fi
    restore_policy_rc_d() {
      rm -f -- "$POLICY_RC_D"
      if [[ -n "$POLICY_BACKUP" && -e "$POLICY_BACKUP" ]]; then
        mv -f -- "$POLICY_BACKUP" "$POLICY_RC_D"
      fi
    }
    trap restore_policy_rc_d EXIT
    cat > "$POLICY_RC_D" <<'POLICY'
#!/bin/sh
case "${1:-}" in
  nginx|nginx.service) exit 101 ;;
esac
if [ -n "${IPM_POLICY_RC_D_BACKUP:-}" ] && [ -x "$IPM_POLICY_RC_D_BACKUP" ]; then
  exec "$IPM_POLICY_RC_D_BACKUP" "$@"
fi
exit 0
POLICY
    if [[ -n "$POLICY_BACKUP" ]]; then
      export IPM_POLICY_RC_D_BACKUP="$POLICY_BACKUP"
    fi
    chmod 0755 "$POLICY_RC_D"
    apt-get install -y "${MISSING_PACKAGES[@]}"
    restore_policy_rc_d
    trap - EXIT
    unset IPM_POLICY_RC_D_BACKUP
  else
    echo "All required system packages are already installed; skipping APT installation."
  fi
fi
for required_command in python3 systemctl nginx curl git rsync sudo visudo runuser ip ss certbot openssl; do
  if ! command -v "$required_command" >/dev/null 2>&1; then
    echo "Dependency installation finished, but required command '$required_command' is still unavailable. Check apt repositories and retry." >&2
    exit 1
  fi
done
python3 -m venv --help >/dev/null 2>&1 || { echo "Python venv support is unavailable after installing python3-venv." >&2; exit 1; }
systemctl show-environment >/dev/null 2>&1 || { echo "systemd is installed but is not running as the system service manager (PID 1). Use a Debian/Ubuntu VPS booted with systemd." >&2; exit 1; }
[[ -d "$APP_DIR" && -f "$APP_DIR/app.py" ]] || { echo "Existing application not found at $APP_DIR." >&2; exit 1; }
[[ -f "$ENV_FILE" && -f "$SERVICE_FILE" ]] || { echo "Expected existing environment file or systemd service is missing." >&2; exit 1; }

prompt() { local name="$1" label="$2" value=""; read -r -p "$label: " value < /dev/tty; printf -v "$name" '%s' "$value"; }
# Keep the upgrader aligned with the repository used by the installer.
REPO_URL="https://github.com/AmiRaiZo/IP-Management"

set -a
. "$ENV_FILE"
set +a
APP_PORT="$(systemctl show station-archive.service -p ExecStart --value | grep -oE -- '--bind[= ]+127\.0\.0\.1:[0-9]+' | grep -oE '[0-9]+$' | tail -n1 || true)"
if [[ -z "$APP_PORT" ]]; then
  APP_PORT="$(grep -RhoE 'proxy_pass[[:space:]]+http://127\.0\.0\.1:[0-9]+' /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null | grep -oE '[0-9]+$' | head -n1 || true)"
fi
[[ "$APP_PORT" =~ ^[0-9]{1,5}$ ]] && (( APP_PORT >= 1 && APP_PORT <= 65535 )) || { echo "Could not detect the existing internal application port from systemd or Nginx." >&2; exit 1; }

ENV_DOMAIN="${APP_DOMAIN:-${DOMAIN:-}}"
ENV_HTTPS_PORT="${PUBLIC_PORT:-${APP_HTTPS_PORT:-443}}"
DOMAIN=""
HTTPS_PORT=""
if [[ "$ENV_DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; then
  ENV_DOMAIN="${ENV_DOMAIN,,}"
  NGINX_PORT="$(python3 - "$ENV_DOMAIN" "$APP_PORT" <<'PY'
from pathlib import Path
import re, subprocess, sys
domain, app_port = sys.argv[1], int(sys.argv[2])
for root in (Path('/etc/nginx/sites-enabled'), Path('/etc/nginx/conf.d')):
    if not root.exists(): continue
    for path in sorted(root.iterdir()):
        if not path.is_file(): continue
        try: source = re.sub(r'(?m)^\s*#.*$', '', path.read_text(errors='ignore'))
        except OSError: continue
        for match in re.finditer(r'\bserver\s*\{', source):
            depth, index = 1, match.end()
            while index < len(source) and depth:
                if source[index] == '{': depth += 1
                elif source[index] == '}': depth -= 1
                index += 1
            if depth: continue
            block = source[match.end():index-1]
            names = re.search(r'(?m)^\s*server_name\s+([^;]+);', block)
            proxy = re.search(r'proxy_pass\s+http://127\.0\.0\.1:(\d+)\b', block)
            listen = re.search(r'(?m)^\s*listen\s+(?:(?:\d{1,3}\.){3}\d{1,3}:)?(?:\[::\]:)?(\d+)\s+ssl\b', block)
            cert = re.search(r'(?m)^\s*ssl_certificate\s+([^;]+);', block)
            if not (names and proxy and listen and cert): continue
            if domain not in names.group(1).split() or int(proxy.group(1)) != app_port: continue
            cert_path = Path(cert.group(1).strip().strip('\"\\\''))
            if not cert_path.is_file(): continue
            valid = subprocess.run(['openssl','x509','-in',str(cert_path),'-noout','-checkhost',domain,'-checkend','86400'], capture_output=True)
            if valid.returncode == 0:
                print(listen.group(1)); raise SystemExit(0)
raise SystemExit(1)
PY
)" || true
  if [[ "$NGINX_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$NGINX_PORT >= 1 && 10#$NGINX_PORT <= 65535 && 10#$NGINX_PORT != 80 )) && getent ahostsv4 "$ENV_DOMAIN" >/dev/null 2>&1; then
    DOMAIN="$ENV_DOMAIN"
    HTTPS_PORT="$NGINX_PORT"
  fi
fi

NEEDS_DOMAIN_RECOVERY=0
if [[ -z "$DOMAIN" ]]; then
  echo "The saved domain has no matching HTTPS proxy with a valid certificate, or its DNS no longer resolves."
  if ! (exec 9<>/dev/tty) 2>/dev/null; then
    echo "A new domain is required, but no interactive terminal is available. Re-run install.sh from an interactive terminal." >&2
    exit 1
  fi
  read -r -p "Enter the new domain name (without https:// or a port): " DOMAIN < /dev/tty
  DOMAIN="${DOMAIN,,}"
  python3 - "$DOMAIN" <<'PY'
import re, sys
if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', sys.argv[1]):
    raise SystemExit('Invalid domain. Enter a hostname such as panel.example.com, without URL scheme, path or port.')
PY
  [[ "$DOMAIN" != "${ENV_DOMAIN,,}" ]] || { echo "The previous domain is not usable; enter a different domain." >&2; exit 1; }
  HTTPS_PORT="$ENV_HTTPS_PORT"
  [[ "$HTTPS_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$HTTPS_PORT >= 1 && 10#$HTTPS_PORT <= 65535 && 10#$HTTPS_PORT != 80 )) || HTTPS_PORT=443
  NEEDS_DOMAIN_RECOVERY=1
fi

echo "Existing deployment target: https://$DOMAIN:$HTTPS_PORT, internal port $APP_PORT."
if (( NEEDS_DOMAIN_RECOVERY == 1 )); then
  echo "A new HTTPS site and matching certificate will be prepared. The old site and certificate will be retained."
else
  echo "The existing HTTPS site and matching certificate will be kept."
fi
read -r -p "Type UPGRADE to continue: " CONFIRM < /dev/tty
[[ "$CONFIRM" == UPGRADE ]] || { echo "Cancelled."; exit 1; }

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
RECOVERY_CHANGED=0
RECOVERY_WAS_ACTIVE=0
RECOVERY_NGINX_STOPPED=0
RECOVERY_SITE=""
RECOVERY_LINK=""
cleanup() {
  if (( SUCCESS == 0 )); then
    if (( RECOVERY_CHANGED == 1 )); then
      echo "Domain recovery failed; restoring the previous environment and Nginx site." >&2
      cp -a "$BACKUP_DIR/env" "$ENV_FILE" || true
      if [[ -n "$RECOVERY_SITE" ]]; then
        if [[ -e "$BACKUP_DIR/recovery-nginx-site" || -L "$BACKUP_DIR/recovery-nginx-site" ]]; then
          cp -a "$BACKUP_DIR/recovery-nginx-site" "$RECOVERY_SITE" || true
        else
          rm -f -- "$RECOVERY_SITE"
        fi
      fi
      if [[ -n "$RECOVERY_LINK" ]]; then
        if [[ -e "$BACKUP_DIR/recovery-nginx-link" || -L "$BACKUP_DIR/recovery-nginx-link" ]]; then
          cp -a "$BACKUP_DIR/recovery-nginx-link" "$RECOVERY_LINK" || true
        else
          rm -f -- "$RECOVERY_LINK"
        fi
      fi
    fi
    if (( RECOVERY_CHANGED == 1 && RECOVERY_WAS_ACTIVE == 1 )); then
      nginx -t && { if systemctl is-active --quiet nginx; then systemctl reload nginx; else systemctl start nginx; fi; } || true
    elif (( RECOVERY_CHANGED == 1 )); then
      if systemctl is-active --quiet nginx; then systemctl stop nginx || true; fi
    elif (( RECOVERY_NGINX_STOPPED == 1 && RECOVERY_WAS_ACTIVE == 1 )); then
      systemctl start nginx || true
    fi
  fi
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
      find "$APP_DIR/.venv" -type d -exec chmod 0750 {} + || true
      find "$APP_DIR/.venv" -type f -exec chmod 0640 {} + || true
      find "$APP_DIR/.venv/bin" -maxdepth 1 -type f -exec chmod 0750 {} + || true
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
for required in app.py requirements.txt templates static reconfigure_server.sh ip-management-recover-access station_archive_refresh_ip.py station_archive_upgrade_limits.py station_archive_domain_recovery.py station-archive-ip-refresh.service station-archive-ip-refresh.timer station-archive-ip-refresh-boot.service nginx-station-archive-ip-refresh.conf; do
  [[ -e "$WORK_DIR/source/$required" ]] || { echo "Repository is missing required path: $required" >&2; exit 1; }
done

if (( NEEDS_DOMAIN_RECOVERY == 1 )); then
  RECOVERY_SITE="/etc/nginx/sites-available/station-archive-$DOMAIN"
  RECOVERY_LINK="/etc/nginx/sites-enabled/station-archive-$DOMAIN"
  [[ ! -e "$RECOVERY_SITE" && ! -L "$RECOVERY_SITE" ]] || cp -a "$RECOVERY_SITE" "$BACKUP_DIR/recovery-nginx-site"
  [[ ! -e "$RECOVERY_LINK" && ! -L "$RECOVERY_LINK" ]] || cp -a "$RECOVERY_LINK" "$BACKUP_DIR/recovery-nginx-link"
  if systemctl is-active --quiet nginx; then RECOVERY_WAS_ACTIVE=1; fi

  CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
  CERT_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
  CERT_OK=0
  if [[ -s "$CERT_FILE" && -s "$CERT_KEY" ]] && openssl x509 -in "$CERT_FILE" -noout -checkhost "$DOMAIN" -checkend 86400 >/dev/null 2>&1; then CERT_OK=1; fi
  if (( CERT_OK == 0 )); then
    echo "Requesting a certificate for $DOMAIN using the standalone HTTP-01 challenge..."
    if (( RECOVERY_WAS_ACTIVE == 1 )); then systemctl stop nginx; RECOVERY_NGINX_STOPPED=1; fi
    if ! certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email --force-renewal --cert-name "$DOMAIN" -d "$DOMAIN"; then
      if (( RECOVERY_WAS_ACTIVE == 1 )); then systemctl start nginx || true; RECOVERY_NGINX_STOPPED=0; fi
      echo "Certificate issuance failed. Check DNS and inbound TCP port 80; the saved domain configuration was not switched." >&2
      exit 1
    fi
    openssl x509 -in "$CERT_FILE" -noout -checkhost "$DOMAIN" -checkend 86400 >/dev/null 2>&1 || { echo "Certbot did not provide a currently valid certificate for $DOMAIN." >&2; exit 1; }
  fi

  PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  [[ "$PUBLIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "Could not detect the VPS public IPv4 address; cannot create the HTTPS listener." >&2; exit 1; }
  RECOVERY_CHANGED=1
  python3 - "$WORK_DIR/source" "$RECOVERY_SITE" "$DOMAIN" "$PUBLIC_IP" "$HTTPS_PORT" "$APP_PORT" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from station_archive_domain_recovery import atomic_write_text, render_nginx_site
target = Path(sys.argv[2])
atomic_write_text(target, render_nginx_site(sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6])))
PY
  ln -sfn "$RECOVERY_SITE" "$RECOVERY_LINK"
  python3 - "$WORK_DIR/source" "$ENV_FILE" "$DOMAIN" "$HTTPS_PORT" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from station_archive_domain_recovery import atomic_update_env
atomic_update_env(Path(sys.argv[2]), {
    'APP_DOMAIN': sys.argv[3], 'DOMAIN': sys.argv[3],
    'APP_HTTPS_PORT': sys.argv[4], 'PUBLIC_PORT': sys.argv[4],
})
PY
  chown root:www-data "$ENV_FILE"
  chmod 0640 "$ENV_FILE"
  nginx -t
  if (( RECOVERY_WAS_ACTIVE == 1 )) && systemctl is-active --quiet nginx; then
    systemctl reload nginx
  fi
  echo "Prepared the new HTTPS vhost for $DOMAIN. The previous site's files and certificate were retained."
fi

# Keep the currently installed virtual environment and all data outside APP_DIR.
DEPLOYED=1
systemctl stop station-archive.service
rsync -a --delete --exclude='.git/' --exclude='.venv/' "$WORK_DIR/source/" "$APP_DIR/"
python3 "$APP_DIR/station_archive_upgrade_limits.py" --domain "$DOMAIN" --https-port "$HTTPS_PORT" --app-port "$APP_PORT"
install -o root -g root -m 0750 "$APP_DIR/ip-management-recover-access" /usr/local/sbin/ip-management-recover-access
chown -R root:www-data "$APP_DIR"
chown root:www-data "$APP_DIR"
find "$APP_DIR" -path "$APP_DIR/.venv" -prune -o -type d -exec chmod 0750 {} +
find "$APP_DIR" -path "$APP_DIR/.venv" -prune -o -type f -exec chmod 0640 {} +
if [[ -x "$APP_DIR/.venv/bin/python" && -d "$APP_DIR/.venv/bin" ]]; then
  normalize_venv_permissions "$APP_DIR/.venv"
fi
chown -R www-data:www-data "$DATA_DIR"
find "$DATA_DIR" -type d -exec chmod 0750 {} +
find "$DATA_DIR" -type f -exec chmod 0640 {} +
# Detect an incomplete/corrupt virtualenv before attempting an in-place pip repair.
if [[ ! -x "$APP_DIR/.venv/bin/python" ]] || ! verify_gunicorn_as_service_user "$APP_DIR/.venv" >/dev/null 2>&1; then
  if [[ -d "$APP_DIR/.venv" ]]; then mv "$APP_DIR/.venv" "$BACKUP_DIR/venv-before-rebuild"; fi
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/.venv/bin/python" -m pip install -r "$APP_DIR/requirements.txt"
"$APP_DIR/.venv/bin/python" -m pip install --no-cache-dir --force-reinstall 'gunicorn>=23,<24'
normalize_venv_permissions "$APP_DIR/.venv"
verify_gunicorn_as_service_user "$APP_DIR/.venv"

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

install -o root -g root -m 0750 "$WORK_DIR/source/station-archive-update" /usr/local/sbin/station-archive-update
bash -n /usr/local/sbin/station-archive-update
install -o root -g root -m 0750 "$WORK_DIR/source/reconfigure_server.sh" /usr/local/sbin/station-archive-reconfigure
install -o root -g root -m 0750 "$WORK_DIR/source/station_archive_refresh_ip.py" /usr/local/sbin/station-archive-refresh-ip
install -o root -g root -m 0644 "$WORK_DIR/source/station-archive-ip-refresh.service" /etc/systemd/system/station-archive-ip-refresh.service
install -o root -g root -m 0644 "$WORK_DIR/source/station-archive-ip-refresh.timer" /etc/systemd/system/station-archive-ip-refresh.timer
install -o root -g root -m 0644 "$WORK_DIR/source/station-archive-ip-refresh-boot.service" /etc/systemd/system/station-archive-ip-refresh-boot.service
install -d -o root -g root -m 0755 /etc/systemd/system/nginx.service.d
install -o root -g root -m 0644 "$WORK_DIR/source/nginx-station-archive-ip-refresh.conf" /etc/systemd/system/nginx.service.d/10-station-archive-ip-refresh.conf
# Permit only the fixed systemd start action from the web process. The actual
# updater runs as a separate root-owned systemd unit outside the web sandbox.
install -d -o root -g root -m 0755 /etc/systemd/system/station-archive.service.d
cat > /etc/systemd/system/station-archive.service.d/update-privileges.conf <<'OVERRIDE'
[Service]
NoNewPrivileges=false
Environment=PYTHONDONTWRITEBYTECODE=1
# sudo needs setuid/setgid within the service capability bounding set.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID
OVERRIDE
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
ReadWritePaths=/opt/station-archive /var/lib/station-archive /usr/local/sbin /etc/sudoers.d /etc/systemd/system /etc/nginx /var/backups
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
chown root:root /etc/systemd/system/station-archive-update.service /etc/systemd/system/station-archive.service.d/update-privileges.conf
chmod 0644 /etc/systemd/system/station-archive-update.service /etc/systemd/system/station-archive.service.d/update-privileges.conf
cat > /etc/sudoers.d/station-archive-update <<'SUDOERS'
www-data ALL=(root) NOPASSWD: /usr/bin/systemctl start station-archive-update.service, /usr/bin/systemctl --no-block start station-archive-reconfigure.service
SUDOERS
chmod 0440 /etc/sudoers.d/station-archive-update
visudo -cf /etc/sudoers.d/station-archive-update

systemctl daemon-reload
UPDATE_EXEC_START="$(systemctl show --property=ExecStart --value station-archive-update.service)"
if [[ "$UPDATE_EXEC_START" != *"/usr/local/sbin/station-archive-update"* || "$UPDATE_EXEC_START" == *"--bootstrapped"* ]]; then
  echo "Upgrade stopped: the effective systemd updater command is not canonical: $UPDATE_EXEC_START" >&2
  echo "Remove any station-archive-update.service drop-in that overrides ExecStart, then rerun the upgrade." >&2
  exit 1
fi
/usr/local/sbin/station-archive-refresh-ip
systemctl enable --now station-archive-ip-refresh.timer

nginx -t
systemctl daemon-reload
systemctl restart station-archive.service
# systemd can report the service active before Gunicorn has bound its socket.
# Retry readiness instead of rolling back on a transient connection-refused.
HTTP_CODE=000
for attempt in $(seq 1 30); do
  if systemctl is-active --quiet station-archive.service; then
    HTTP_CODE="$(curl --noproxy '*' -sS --connect-timeout 2 --max-time 5 -H "Host: $DOMAIN" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$APP_PORT/" 2>/dev/null || true)"
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
SOURCE_SHA="$(git -C "$WORK_DIR/source" rev-parse HEAD)"
printf '%s\n' "$SOURCE_SHA" > "$DATA_DIR/commit"
python3 - "$SOURCE_SHA" "$DATA_DIR/version" "$WORK_DIR/source/VERSION" <<'PY'
import json, re, sys
from pathlib import Path
from urllib.request import Request, urlopen
source_sha, output, version_path = sys.argv[1:]
version = Path(version_path).read_text(encoding="utf-8").strip()
try:
    req = Request("https://api.github.com/repos/AmiRaiZo/IP-Management/releases/latest",
                  headers={"Accept":"application/vnd.github+json", "User-Agent":"IP-Archive-Upgrader"})
    with urlopen(req, timeout=8) as response:
        release = json.loads(response.read(256_000).decode("utf-8"))
    if release.get("target_commitish") == source_sha:
        candidate = str(release.get("tag_name", "")).strip().lstrip("v")
    if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", candidate):
            version = candidate
except Exception:
    pass
Path(output).write_text(version + "\n", encoding="utf-8")
PY
chown www-data:www-data "$DATA_DIR/version"
chmod 0640 "$DATA_DIR/version"
SUCCESS=1
echo "Upgrade completed. Existing domain, public HTTPS port, Nginx configuration, SSL certificates, secrets, and database were preserved."
echo "Backups: $BACKUP_DIR"
echo "Application URL: https://$DOMAIN:$HTTPS_PORT"
echo "Updater: sudo /usr/local/sbin/station-archive-update"
