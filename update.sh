#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP_DIR=/opt/station-archive
DATA_DIR=/var/lib/station-archive
BACKUP_ROOT=/var/backups
ENV_FILE=/etc/station-archive/env
REPO_SLUG=AmiRaiZo/IP-Management
API_URL="https://api.github.com/repos/$REPO_SLUG/releases/latest"
[[ ${EUID} -eq 0 ]] || { echo "Run the updater as root." >&2; exit 1; }
[[ -r "$ENV_FILE" && -d "$APP_DIR" ]] || { echo "IP Archive installation not found." >&2; exit 1; }
for cmd in curl python3 rsync systemctl; do command -v "$cmd" >/dev/null || { echo "Missing required command: $cmd" >&2; exit 1; }; done

TMP="$(mktemp -d /tmp/station-archive-release-update.XXXXXX)"
BACKUP=""
DEPLOYED=0
SUCCESS=0
cleanup() {
  rc=$?
  if (( DEPLOYED == 1 && SUCCESS == 0 )); then
    echo "Update failed. Restoring the previous application, configuration and data..." >&2
    if [[ -n "$BACKUP" && -d "$BACKUP/app" ]]; then
      rsync -a --delete --exclude='.venv/' "$BACKUP/app/" "$APP_DIR/" || true
      if [[ -d "$BACKUP/data" ]]; then rsync -a --delete "$BACKUP/data/" "$DATA_DIR/" || true; fi
      if [[ -f "$BACKUP/env" ]]; then install -o root -g www-data -m 0640 "$BACKUP/env" "$ENV_FILE" || true; fi
      python3 -m venv --clear "$APP_DIR/.venv" || true
      chown -R root:www-data "$APP_DIR/.venv" || true
      find "$APP_DIR/.venv" -type d -exec chmod 0750 {} + 2>/dev/null || true
      find "$APP_DIR/.venv" -type f -perm /u=r -exec chmod g+r {} + 2>/dev/null || true
      find "$APP_DIR/.venv" -type f -perm /u=x -exec chmod g+x {} + 2>/dev/null || true
      "$APP_DIR/.venv/bin/python" -m pip install -r "$APP_DIR/requirements.txt" >/dev/null 2>&1 || true
      systemctl restart station-archive.service || true
      echo "Rollback backup: $BACKUP" >&2
    else
      systemctl restart station-archive.service || true
    fi
  fi
  rm -rf -- "$TMP"
  exit "$rc"
}
trap cleanup EXIT

mkdir -p "$TMP/package"
python3 - "$API_URL" "$TMP/release.json" <<'PY'
import json, sys, urllib.request
req = urllib.request.Request(sys.argv[1], headers={"Accept":"application/vnd.github+json", "User-Agent":"IP-Archive-Updater"})
with urllib.request.urlopen(req, timeout=10) as response:
    release = json.load(response)
tag = release.get("tag_name", "")
assets = release.get("assets", [])
matches = [a for a in assets if a.get("name", "").startswith("station-archive-") and a.get("name", "").endswith(".zip")]
if not tag or not matches:
    raise SystemExit("The latest GitHub Release has no station-archive ZIP asset.")
asset = matches[0]
url = asset.get("browser_download_url", "")
if not url.startswith("https://github.com/AmiRaiZo/IP-Management/releases/download/"):
    raise SystemExit("Release asset URL failed validation.")
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump({"tag": tag, "url": url, "name": asset["name"]}, f)
PY
mapfile -t RELEASE_INFO < <(python3 - "$TMP/release.json" <<'PY'
import json, sys
r=json.load(open(sys.argv[1], encoding="utf-8"))
print(r["tag"])
print(r["url"])
print(r["name"])
PY
)
[[ ${#RELEASE_INFO[@]} -eq 3 ]] || { echo "Could not read release metadata." >&2; exit 1; }
RELEASE_TAG="${RELEASE_INFO[0]}"
ASSET_URL="${RELEASE_INFO[1]}"
ASSET_NAME="${RELEASE_INFO[2]}"
CURRENT_VERSION="$(cat "$APP_DIR/VERSION" 2>/dev/null || echo 0.0.0)"
CURRENT_VERSION="${CURRENT_VERSION#v}"
TARGET_VERSION="${RELEASE_TAG#v}"
if [[ "$CURRENT_VERSION" == "$TARGET_VERSION" ]]; then
  echo "IP Archive is already up to date ($RELEASE_TAG)."
  exit 0
fi
echo "Updating IP Archive from $CURRENT_VERSION to $RELEASE_TAG using GitHub Releases..."
curl --fail --location --retry 3 --retry-delay 1 "$ASSET_URL" -o "$TMP/$ASSET_NAME"
python3 - "$TMP/$ASSET_NAME" "$TMP/package" <<'PY'
import sys, zipfile
archive, dest = sys.argv[1:]
with zipfile.ZipFile(archive) as z:
    bad = z.testzip()
    if bad:
        raise SystemExit("Corrupt release archive: " + bad)
    for member in z.infolist():
        name = member.filename.replace("\\", "/")
        if name.startswith("/") or any(part == ".." for part in name.split("/")):
            raise SystemExit("Unsafe path in release archive.")
    z.extractall(dest)
PY
SOURCE="$TMP/package"
for required in app.py requirements.txt VERSION templates static update.sh; do
  [[ -e "$SOURCE/$required" ]] || { echo "Release archive is missing required path: $required" >&2; exit 1; }
done
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -o root -g root -m 0700 "$BACKUP_ROOT"
BACKUP="$BACKUP_ROOT/station-archive-release-$STAMP"
install -d -o root -g root -m 0700 "$BACKUP/app" "$BACKUP/data"
rsync -a --exclude='.venv/' "$APP_DIR/" "$BACKUP/app/"
rsync -a "$DATA_DIR/" "$BACKUP/data/"
install -o root -g root -m 0600 "$ENV_FILE" "$BACKUP/env"
echo "Backup created at $BACKUP"
DEPLOYED=1
systemctl stop station-archive.service
rsync -a --delete --exclude='.venv/' "$SOURCE/" "$APP_DIR/"
chown -R root:www-data "$APP_DIR"
chown root:www-data "$APP_DIR"
find "$APP_DIR" -path "$APP_DIR/.venv" -prune -o -type d -exec chmod 0750 {} +
find "$APP_DIR" -path "$APP_DIR/.venv" -prune -o -type f -exec chmod 0640 {} +
python3 -m venv --clear "$APP_DIR/.venv"
chown -R root:www-data "$APP_DIR/.venv"
find "$APP_DIR/.venv" -type d -exec chmod 0750 {} +
find "$APP_DIR/.venv" -type f -perm /u=r -exec chmod g+r {} +
find "$APP_DIR/.venv" -type f -perm /u=x -exec chmod g+x {} +
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip
"$APP_DIR/.venv/bin/python" -m pip install -r "$APP_DIR/requirements.txt"
nginx -t
systemctl restart station-archive.service
systemctl is-active --quiet station-archive.service
SUCCESS=1
echo "IP Archive update completed: $RELEASE_TAG"
echo "Backup: $BACKUP"
