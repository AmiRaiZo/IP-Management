#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP_DIR=/opt/station-archive
DATA_DIR=/var/lib/station-archive
CONFIG_DIR=/etc/station-archive
ENV_FILE="$CONFIG_DIR/env"
SERVICE_FILE=/etc/systemd/system/station-archive.service
UPDATER=/usr/local/sbin/station-archive-update
SUDOERS_FILE=/etc/sudoers.d/station-archive-update
ACME_WEBROOT=/var/www/station-archive-acme
BACKUP_ROOT=/var/backups

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this uninstaller as root, for example: curl -fsSL https://raw.githubusercontent.com/AmiRaiZo/IP-Management/main/uninstall.sh | sudo bash" >&2
  exit 1
fi

if [[ ! -f "$SERVICE_FILE" && ! -f "$ENV_FILE" && ! -d "$APP_DIR" && ! -d "$DATA_DIR" ]]; then
  echo "No IP Archive installation was found in the standard locations."
  exit 0
fi

DOMAIN=""
for conf in /etc/nginx/sites-available/station-archive-*; do
  [[ -f "$conf" ]] || continue
  found="$(grep -E "^[[:space:]]*server_name[[:space:]]+" "$conf" | head -n1 | sed -E "s/^[[:space:]]*server_name[[:space:]]+([^;]+);.*/\1/" | awk "{print $1}")"
  if [[ -n "$found" && "$found" != "_" ]]; then DOMAIN="$found"; break; fi
done

echo "This will permanently remove the IP Archive installation:"
printf "  - Application: %s\n" "$APP_DIR"
printf "  - Database and runtime data: %s\n" "$DATA_DIR"
printf "  - Secrets and configuration: %s\n" "$CONFIG_DIR"
printf "  - systemd service and updater/sudoers entries\n"
printf "  - Nginx site configs named station-archive-* and ACME webroot\n"
printf "  - IP Archive-specific backups under %s\n" "$BACKUP_ROOT"
if [[ -n "$DOMAIN" ]]; then printf "  - TLS certificate for detected domain: %s (if certbot manages it)\n" "$DOMAIN"; fi
echo
echo "WARNING: database records, encrypted credentials, and secrets will be deleted."
echo "If you may need the existing records, stop now and make a secure backup first."
read -r -p "Type DELETE IP ARCHIVE DATA to permanently continue: " CONFIRM < /dev/tty
[[ "$CONFIRM" == "DELETE IP ARCHIVE DATA" ]] || { echo "Cancelled; nothing was removed."; exit 1; }

systemctl stop station-archive.service 2>/dev/null || true
systemctl disable station-archive.service 2>/dev/null || true
rm -f -- "$SERVICE_FILE"
systemctl daemon-reload
systemctl reset-failed station-archive.service 2>/dev/null || true
rm -f -- "$UPDATER" "$SUDOERS_FILE"

for conf in /etc/nginx/sites-available/station-archive-*; do [[ -e "$conf" || -L "$conf" ]] || continue; rm -f -- "$conf"; done
for conf in /etc/nginx/sites-enabled/station-archive-*; do [[ -e "$conf" || -L "$conf" ]] || continue; rm -f -- "$conf"; done
if command -v nginx >/dev/null 2>&1; then nginx -t && systemctl reload nginx || echo "Warning: Nginx validation/reload failed; unrelated site configuration may need attention." >&2; fi
if [[ -n "$DOMAIN" ]] && command -v certbot >/dev/null 2>&1; then certbot delete --cert-name "$DOMAIN" --non-interactive 2>/dev/null || true; fi

rm -rf -- "$APP_DIR" "$DATA_DIR" "$CONFIG_DIR" "$ACME_WEBROOT"
for backup in "$BACKUP_ROOT"/station-archive-upgrade-* "$BACKUP_ROOT"/station-archive-release-*; do [[ -e "$backup" ]] || continue; rm -rf -- "$backup"; done

echo "IP Archive has been removed from this server."
echo "Nginx, Certbot, Python, and other shared system packages were kept."
echo "You can now run the fresh installer from the repository README."
