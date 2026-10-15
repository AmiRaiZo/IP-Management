Warning: truncated output (original token count: 25243)
Total output lines: 1888

import hashlib
import hmac
import base64
import json
from io import BytesIO
import os
import re
import secrets
import sqlite3
import socket
import subprocess
import time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from ipaddress import ip_address, ip_network
from pathlib import Path

import pyotp
from PIL import Image, ImageOps, UnidentifiedImageError
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for, send_file
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.datastructures import MultiDict
from werkzeug.utils import secure_filename
from flask import send_from_directory
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("STATION_ARCHIVE_DATA", BASE_DIR / "instance"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "archive.sqlite3"
FERNET_KEY = os.environ.get("FERNET_KEY", "")
if not FERNET_KEY:
    raise RuntimeError("FERNET_KEY must be set in the environment")
vault = Fernet(FERNET_KEY.encode())
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or ""
if not app.secret_key:
    raise RuntimeError("SECRET_KEY must be set in the environment")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)
if os.environ.get("APP_DOMAIN", "").strip():
    # Reject arbitrary Host headers when the installer has configured a public domain.
    app.config["TRUSTED_HOSTS"] = [os.environ["APP_DOMAIN"].strip().lower()]
two_factor_serializer = URLSafeTimedSerializer(app.secret_key, salt="ip-management-remember-2fa")
REMEMBER_2FA_COOKIE = "ip_management_2fa"
REMEMBER_2FA_SECONDS = 24 * 60 * 60
VERSION_FILE = DATA_DIR / "version"
UPDATE_TARGET_FILE = DATA_DIR / "update-target"
UPDATE_TARGET_VERSION_FILE = DATA_DIR / "update-target-version"
UPDATE_REPOSITORY_FILE = DATA_DIR / "update-repository"
RECONFIGURE_STATUS_FILE = DATA_DIR / "reconfigure-status.json"
UPDATE_LOG_FILE = DATA_DIR / "update.log"
UPLOAD_DIR = DATA_DIR / "uploads"
AVATAR_DIR = UPLOAD_DIR / "avatars"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
AVATAR_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}


@contextmanager
def connect_db():
    db = sqlite3.connect(DB_PATH, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + digest.hex()


def password_matches(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
        return hmac.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def encrypt_authenticator_secret(secret):
    """Encrypt TOTP seeds at rest while marking ciphertext for safe migrations."""
    if not secret:
        return ""
    if str(secret).startswith("fernet:"):
        return str(secret)
    return "fernet:" + vault.encrypt(str(secret).encode("utf-8")).decode("ascii")


def decrypt_authenticator_secret(value):
    """Read encrypted seeds and transparently support legacy plaintext during migration."""
    value = str(value or "")
    if not value:
        return ""
    if not value.startswith("fernet:"):
        return value
    try:
        return vault.decrypt(value[len("fernet:"):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError):
        return ""


def save_sanitized_image(upload, destination, extension):
    """Decode and re-encode uploads so extension spoofing and embedded payloads are discarded."""
    formats = {".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG", ".webp": "WEBP"}
    image_format = formats.get(extension.lower())
    if not image_format:
        raise ValueError("Unsupported image format")
    try:
        upload.stream.seek(0)
        with Image.open(upload.stream) as source:
            if source.width < 1 or source.height < 1 or source.width * source.height > 16_000_000:
                raise ValueError("Image dimensions are too large")
            source.verify()
        upload.stream.seek(0)
        with Image.open(upload.stream) as source:
            image = ImageOps.exif_transpose(source)
            image.thumbnail((4096, 4096))
            keep_alpha = image_format == "PNG" or (image_format == "WEBP" and "A" in image.getbands())
            image = image.convert("RGBA" if keep_alpha else "RGB")
            options = {"optimize": True}
            if image_format in ("JPEG", "WEBP"):
                options["quality"] = 90
            image.save(destination, format=image_format, **options)
    except (OSError, ValueError, UnidentifiedImageError, Image.DecompressionBombError) as exc:
        raise ValueError("Uploaded file is not a valid supported image") from exc


def init_db():
    with connect_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, created_at TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'admin', totp_secret TEXT NOT NULL DEFAULT '', two_factor_enabled INTEGER NOT NULL DEFAULT 0, two_factor_enrolled INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, profile_image TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS user_recovery_codes (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          code_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS groups (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
          sort_order INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS ips (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '', ip_address TEXT NOT NULL,
          port INTEGER, username TEXT NOT NULL DEFAULT '', password_enc TEXT NOT NULL DEFAULT '',
          notes TEXT NOT NULL DEFAULT '', group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
          created_by TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS user_group_access (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
          PRIMARY KEY(user_id, group_id)
        );
        CREATE TABLE IF NOT EXISTS user_ip_access (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          ip_id INTEGER NOT NULL REFERENCES ips(id) ON DELETE CASCADE,
          can_view INTEGER NOT NULL DEFAULT 1,
          PRIMARY KEY(user_id, ip_id)
        );
        CREATE TABLE IF NOT EXISTS audit_log (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL,
          detail TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS security_events (
          id INTEGER PRIMARY KEY, event_type TEXT NOT NULL, remote_ip TEXT NOT NULL,
          attempted_username TEXT NOT NULL DEFAULT '', result TEXT NOT NULL,
          detail TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(remote_ip, created_at DESC);
        CREATE TABLE IF NOT EXISTS ip_access_rules (
          id INTEGER PRIMARY KEY, network TEXT NOT NULL UNIQUE, rule_type TEXT NOT NULL CHECK(rule_type IN ('block','allow')),
          note TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ips_ip ON ips(ip_address);
        CREATE INDEX IF NOT EXISTS idx_ips_name ON ips(name);
        """)
        # In-place migrations preserve the database created by the first release.
        user_cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
        for name, definition in (("role", "TEXT NOT NULL DEFAULT 'admin'"), ("totp_secret", "TEXT NOT NULL DEFAULT ''"), ("two_factor_enabled", "INTEGER NOT NULL DEFAULT 0"), ("two_factor_enrolled", "INTEGER NOT NULL DEFAULT 0"), ("enabled", "INTEGER NOT NULL DEFAULT 1"), ("can_view_passwords", "INTEGER NOT NULL DEFAULT 0")):
            if name not in user_cols:
                db.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
        if "profile_image" not in user_cols:
            db.execute("ALTER TABLE users ADD COLUMN profile_image TEXT NOT NULL DEFAULT ''")
        group_cols = {r[1] for r in db.execute("PRAGMA table_info(groups)")}
        if "sort_order" not in group_cols:
            db.execute("ALTER TABLE groups ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0")
            db.execute("UPDATE groups SET sort_order=id")
        db.execute("INSERT OR IGNORE INTO groups(name,description,created_at,sort_order) VALUES('Default','Default group for IP records',?,0)", (now(),))
        default_group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
        db.execute("UPDATE ips SET group_id=? WHERE group_id IS NULL", (default_group_id,))
        mode_row = db.execute("SELECT value FROM app_settings WHERE key='two_factor_mode'").fetchone()
        if not mode_row:
            legacy = db.execute("SELECT value FROM app_settings WHERE key='two_factor_required'").fetchone()
            legacy_required = bool(legacy and legacy["value"] == "1")
            db.execute("INSERT INTO app_settings(key,value) VALUES('two_factor_mode',?)", ("per_user" if legacy_required else "off",))
            if legacy_required:
                db.execute("UPDATE users SET two_factor_enabled=1")
        current_mode = db.execute("SELECT value FROM app_settings WHERE key='two_factor_mode'").fetchone()
        if "two_factor_enrolled" not in user_cols and (not current_mode or current_mode["value"] != "shared"):
            db.execute("UPDATE users SET two_factor_enrolled=1 WHERE totp_secret!=''")
        ip_cols = {r[1] for r in db.execute("PRAGMA table_info(ips)")}
        if not ip_cols:
            # Fresh DB already created the ips table above.
            ip_cols = {r[1] for r in db.execute("PRAGMA table_info(ips)")}
        old_cols = {r[1] for r in db.execute("PRAGMA table_info(stations)")} if db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='stations'").fetchone() else set()
        if old_cols:
            has_group = "group_id" in ip_cols
            db.execute("INSERT OR IGNORE INTO ips(id,name,ip_address,port,username,password_enc,notes,created_by,created_at,updated_at) SELECT id,name,ip_address,port,username,password_enc,notes,created_by,created_at,updated_at FROM stations")
            # The legacy table remains untouched so upgrades are reversible.
        if db.execute("SELECT 1 FROM users WHERE role='superadmin' LIMIT 1").fetchone() is None:
            first_user = db.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
            if first_user:
                db.execute("UPDATE users SET role='superadmin' WHERE id=?", (first_user["id"],))
        # Migrate legacy plaintext authenticator seeds to Fernet-encrypted values.
        # The decrypt helper remains backward-compatible if a row is restored from an old DB.
        for row in db.execute("SELECT id,totp_secret FROM users WHERE totp_secret!=''").fetchall():
            if not str(row["totp_secret"]).startswith("fernet:"):
                db.execute("UPDATE users SET totp_secret=? WHERE id=?",
                           (encrypt_authenticator_secret(row["totp_secret"]), row["id"]))
        shared_row = db.execute("SELECT value FROM app_settings WHERE key='shared_two_factor_secret'").fetchone()
        if shared_row and shared_row["value"] and not str(shared_row["value"]).startswith("fernet:"):
            db.execute("UPDATE app_settings SET value=? WHERE key='shared_two_factor_secret'",
                       (encrypt_authenticator_secret(shared_row["value"]),))


init_db()


def client_ip():
    # The app is deployed behind Nginx on loopback; ProxyFix trusts one proxy hop.
    return (request.remote_addr or "unknown")[:64]


def security_event(event_type, username="", result="info", detail=""):
    """Record security metadata only. Never record submitted passwords or TOTP codes."""
    try:
        with connect_db() as db:
            db.execute(
                "INSERT INTO security_events(event_type,remote_ip,attempted_username,result,detail,user_agent,created_at) VALUES(?,?,?,?,?,?,?)",
                (event_type[:40], client_ip(), str(username or "")[:80], result[:40], str(detail or "")[:240],
                 request.headers.get("User-Agent", "")[:240], now()),
            )
    except Exception:
        app.logger.exception("Could not write security event")


def failed_password_fingerprint(password):
    """Stable keyed fingerprint for correlating guesses without retaining the password."""
    value = str(password or "").encode("utf-8", errors="replace")[:1024]
    return hmac.new(app.secret_key.encode(), b"failed-login-password\0" + value, hashlib.sha256).hexdigest()[:16]


def recovery_code_hash(user_id, code):
    normalized = re.sub(r"[^A-Za-z0-9]", "", str(code or "")).upper()
    return hmac.new(app.secret_key.encode(), f"2fa-recovery:{user_id}:{normalized}".encode(), hashlib.sha256).hexdigest()


def consume_recovery_code(user_id, submitted):
    """Consume exactly one offline recovery code; only a keyed hash is stored."""
    normalized = re.sub(r"[^A-Za-z0-9]", "", str(submitted or "")).upper()
    if not normalized or len(normalized) > 40:
        return False
    candidate = recovery_code_hash(user_id, normalized)
    with connect_db() as db:
        row = db.execute("SELECT id,code_hash FROM user_recovery_codes WHERE user_id=?", (user_id,)).fetchall()
        matched = next((item for item in row if hmac.compare_digest(item["code_hash"], candidate)), None)
        if not matched:
            return False
        db.execute("DELETE FROM user_recovery_codes WHERE id=?", (matched["id"],))
    return True


def secure_setting(key):
    with connect_db() as db:
        row = db.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    if not row or not row["value"]:
        return ""
    try:
        return vault.decrypt(row["value"].encode()).decode()
    except (InvalidToken, ValueError, UnicodeDecodeError):
        return ""


def save_secure_setting(key, value):
    encrypted = vault.encrypt(str(value).encode()).decode() if value else ""
    with connect_db() as db:
        db.execute("INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, encrypted))


def send_telegram_security_alert(message):
    """Best-effort Telegram alert. Never include submitted passwords or TOTP codes."""
    token = secure_setting("telegram_bot_token_enc")
    chat_id = secure_setting("telegram_chat_id_enc")
    if not token or not chat_id:
        return False
    try:
        payload = {"chat_id": chat_id, "text": str(message)[:3900], "disable_web_page_preview": True}
        req = Request(f"https://api.telegram.org/bot{token}/sendMessage", data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=5) as response:
            result = json.loads(response.read(65536).decode("utf-8"))
        return bool(result.get("ok"))
    except (URLError, HTTPError, TimeoutError, ValueError, OSError):
        app.logger.warning("Telegram security notification failed")
        return False


def telegram_api(method, payload):
    token = secure_setting("telegram_bot_token_enc")
    if not token:
        return {}
    try:
        req = Request(f"https://api.telegram.org/bot{token}/{method}",
                      data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=5) as response:
            result = json.loads(response.read(65536).decode("utf-8"))
        return result if result.get("ok") else {}
    except (URLError, HTTPError, TimeoutError, ValueError, OSError):
        app.logger.warning("Telegram bot API request failed")
        return {}


def telegram_send(chat_id, text, reply_markup=None):
    payload = {"chat_id": str(chat_id), "text": str(text)[:3900], "disable_web_page_preview": True}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return telegram_api("sendMessage", payload)


def telegram_set_state(state):
    save_secure_setting("telegram_conversation_state_enc", json.dumps(state, ensure_ascii=False))


def telegram_get_state():
    raw = secure_setting("telegram_conversation_state_enc")
    try:
        value = json.loads(raw) if raw else {}
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


def telegram_menu(chat_id, message_id=None):
    markup = {"inline_keyboard": [[
        {"text": "➕ اد آیپی", "callback_data": "ip_add"},
        {"text": "🔎 سرچ", "callback_data": "ip_search"},
    ]]}
    if message_id:
        telegram_api("editMessageText", {"chat_id": str(chat_id), "message_id": message_id,
                         "text": "منوی IP Archive — یکی از گزینه‌ها را انتخاب کن:", "reply_markup": markup})
    else:
        telegram_send(chat_id, "منوی IP Archive — یکی از گزینه‌ها را انتخاب کن:", markup)


def handle_telegram_update(update):
    configured_chat = secure_setting("telegram_chat_id_enc")
    if not configured_chat:
        return
    callback = update.get("callback_query") or {}
    message = update.get("message") or callback.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = str(chat.get("id", ""))
    if chat_id != str(configured_chat):
        return
    if callback:
        telegram_api("answerCallbackQuery", {"callback_query_id": callback.get("id", "")})
        action = callback.get("data", "")
        if action == "menu":
            telegram_set_state({})
            telegram_menu(chat_id, message.get("message_id"))
        elif action == "ip_add":
            telegram_set_state({"mode": "add", "step": "name", "data": {}})
            telegram_send(chat_id, "مرحله ۱ از ۵ — نام این IP/سرور را وارد کن:")
        elif action == "ip_search":
            telegram_set_state({"mode": "search", "step": "query"})
            telegram_send(chat_id, "نام ثبت‌شده یا آدرس IP را بفرست:")
        return
    text = str(message.get("text", "")).strip()
    if text.lower() in ("ربات", "/start", "/menu"):
        telegram_set_stat…15243 tokens truncated…  output = _BytesIO(content.encode("utf-8-sig"))
    response = send_file(output, mimetype="text/plain; charset=utf-8", as_attachment=True,
                         download_name=f"ip-management-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt", max_age=0)
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.post("/settings/deployment")
@superadmin_required
def update_deployment_settings():
    action = request.form.get("action", "public")
    if action == "repository":
        repo_url = request.form.get("update_repository", "").strip().rstrip("/")
        password = request.form.get("current_password", "")
        user = current_user_row()
        if not user or not password_matches(password, user["password_hash"]):
            flash("Password confirmation failed. The update repository was not changed.", "error")
            return redirect(url_for("settings") + "#updates")
        if not normalize_github_repo(repo_url):
            flash("Enter a valid HTTPS GitHub repository URL.", "error")
            return redirect(url_for("settings") + "#updates")
        if normalize_github_repo(repo_url) != trusted_update_repository():
            flash("For security, the updater can only use the repository configured by the server installer. Change it in the server environment and redeploy if you need to switch trusted repositories.", "error")
            return redirect(url_for("settings") + "#updates")
        repo_url = trusted_update_repository()
        with connect_db() as db:
            db.execute("INSERT INTO app_settings(key,value) VALUES('update_repository',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (repo_url,))
        audit("update_repository_changed", repo_url)
        flash("Update repository saved after password confirmation.", "success")
        return redirect(url_for("settings") + "#updates")

    domain = request.form.get("public_domain", "").strip().lower().rstrip(".")
    port_text = request.form.get("public_port", "").strip()
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", domain):
        flash("Enter a valid public domain name without https:// or a path.", "error")
        return redirect(url_for("settings") + "#general")
    if not re.fullmatch(r"\d{1,5}", port_text) or not 1 <= int(port_text) <= 65535:
        flash("Public port must be a number from 1 to 65535.", "error")
        return redirect(url_for("settings") + "#general")
    if int(port_text) == 80:
        flash("Port 80 is reserved for HTTP and certificate verification. Choose another HTTPS port.", "error")
        return redirect(url_for("settings") + "#general")
    request_path = DATA_DIR / "reconfigure-request.json"
    request_path.write_text(json.dumps({"domain": domain, "port": int(port_text)}, separators=(",", ":")), encoding="utf-8")
    try:
        RECONFIGURE_STATUS_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    RECONFIGURE_STATUS_FILE.write_text(json.dumps({"state": "running", "message": "Preparing the new domain, SSL certificate and server port…", "domain": domain, "port": int(port_text)}, separators=(",", ":")), encoding="utf-8")
    try:
        result = subprocess.run(["sudo", "-n", "/usr/bin/systemctl", "--no-block", "start", "station-archive-reconfigure.service"],
                                capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        request_path.unlink(missing_ok=True)
        RECONFIGURE_STATUS_FILE.write_text(json.dumps({"state": "error", "message": str(exc)}, separators=(",", ":")), encoding="utf-8")
        flash(f"Server reconfiguration could not be completed: {exc}. The previous address was kept.", "error")
        return redirect(url_for("settings") + "#general")
    if result.returncode != 0:
        request_path.unlink(missing_ok=True)
        details = (result.stderr or result.stdout or "No details returned.").strip()[-700:]
        RECONFIGURE_STATUS_FILE.write_text(json.dumps({"state": "error", "message": details}, separators=(",", ":")), encoding="utf-8")
        flash(f"Server reconfiguration failed; the old configuration was preserved where possible. {details}", "error")
        return redirect(url_for("settings") + "#general")
    target_url = (f"https://{domain}:{int(port_text)}/login?server_reconfigured=1"
                  if domain != os.environ.get("APP_DOMAIN", "").lower()
                  else f"https://{domain}:{int(port_text)}" + url_for("settings") + "?reconfigured=1#general")
    return render_template("reconfigure_wait.html", target_url=target_url, target_domain=domain, target_port=int(port_text))


@app.get("/settings/deployment/status")
@superadmin_required
def deployment_reconfiguration_status():
    try:
        status = json.loads(RECONFIGURE_STATUS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        status = {"state": "running", "message": "Waiting for the server reconfiguration service…"}
    if status.get("state") == "running":
        try:
            active = subprocess.run(["/usr/bin/systemctl", "show", "-p", "ActiveState", "--value", "station-archive-reconfigure.service"],
                                    capture_output=True, text=True, timeout=2, check=False).stdout.strip()
            age = time.time() - RECONFIGURE_STATUS_FILE.stat().st_mtime
            if active == "failed" or (active == "inactive" and age > 30):
                status = {**status, "state": "error", "message": "The reconfiguration service stopped before reporting success. The previous address should remain active; check the server journal."}
        except (OSError, subprocess.TimeoutExpired):
            pass
    return status


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = request.user
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if new_password:
            if not password_matches(current_password, user["password_hash"]):
                flash("Current password is incorrect.", "error")
                return redirect(url_for("profile"))
            if not 12 <= len(new_password) <= 1024:
                flash("New password must be between 12 and 1024 characters.", "error")
                return redirect(url_for("profile"))
            if new_password != confirm_password:
                flash("New passwords do not match.", "error")
                return redirect(url_for("profile"))
        avatar = request.files.get("avatar")
        avatar_name = user["profile_image"] or ""
        if avatar and avatar.filename:
            ext = Path(secure_filename(avatar.filename)).suffix.lower()
            if ext not in ALLOWED_IMAGE_EXTENSIONS:
                flash("Profile image must be PNG, JPG, JPEG, or WEBP.", "error")
                return redirect(url_for("profile"))
            filename = f"user-{user['id']}{ext}"
            try:
                save_sanitized_image(avatar, AVATAR_DIR / filename, ext)
            except ValueError as exc:
                flash(str(exc), "error")
                return redirect(url_for("profile"))
            avatar_name = "avatars/" + filename
        with connect_db() as db:
            if new_password:
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(new_password), user["id"]))
            db.execute("UPDATE users SET profile_image=? WHERE id=?", (avatar_name, user["id"]))
        audit("profile_updated")
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user, two_factor_mode=two_factor_mode())


@app.post("/profile/recovery-codes")
@login_required
def generate_recovery_codes():
    user = request.user
    current_password = request.form.get("current_password", "")
    current_code = re.sub(r"\s", "", request.form.get("current_code", ""))
    if not password_matches(current_password, user["password_hash"]):
        flash("Current password is incorrect; recovery codes were not changed.", "error")
        return redirect(url_for("profile"))
    if user_requires_two_factor(user):
        mode = two_factor_mode()
        secret = shared_two_factor_secret() if mode == "shared" else decrypt_authenticator_secret(user["totp_secret"])
        if not secret or not pyotp.TOTP(secret).verify(current_code, valid_window=1):
            flash("Verify with your current authenticator before generating recovery codes.", "error")
            return redirect(url_for("profile"))
    codes = [secrets.token_hex(10).upper() for _ in range(10)]
    with connect_db() as db:
        db.execute("DELETE FROM user_recovery_codes WHERE user_id=?", (user["id"],))
        db.executemany("INSERT INTO user_recovery_codes(user_id,code_hash,created_at) VALUES(?,?,?)",
                       [(user["id"], recovery_code_hash(user["id"], code), now()) for code in codes])
    audit("two_factor_recovery_codes_generated", "count=10")
    response = app.make_response(render_template("recovery_codes.html", codes=codes, username=user["username"]))
    response.headers["Cache-Control"] = "no-store, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.get("/media/<path:filename>")
def media_file(filename):
    # The application logo is public so it can render on the sign-in page.
    # During 2FA, permit the pending user to load only their own profile image.
    if filename.startswith("avatars/") and not current_user_row():
        pending_id = session.get("pending_2fa_user_id")
        with connect_db() as db:
            pending = db.execute("SELECT profile_image FROM users WHERE id=? AND enabled=1", (pending_id,)).fetchone() if pending_id else None
        if not pending or pending["profile_image"] != filename:
            return redirect(url_for("login"))
    if filename not in {"brand.png", "brand.jpg", "brand.jpeg", "brand.webp"} and not filename.startswith("avatars/"):
        abort(404)
    return send_from_directory(UPLOAD_DIR, filename)


@app.get("/update")
@superadmin_required
def update_page():
    current = installed_version()
    with connect_db() as db:
        deployment = {row["key"]: row["value"] for row in db.execute(
            "SELECT key,value FROM app_settings WHERE key IN ('public_port','update_repository')")}
    return render_template("update_app.html", current_version=current,
                           github_repo=deployment.get("update_repository", os.environ.get("GITHUB_REPO", os.environ.get("APP_REPO_URL", "https://github.com/AmiRaiZo/IP-Management"))),
                           public_port=deployment.get("public_port", os.environ.get("PUBLIC_PORT", os.environ.get("APP_HTTPS_PORT", "443"))))


def installed_version(release=None):
    # Runtime version is written only after an update has completed successfully.
    try:
        value = VERSION_FILE.read_text(encoding="utf-8").strip().lstrip("v")
        if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", value):
            return value
        # Older updater versions stored the commit SHA instead of a version.
        if release and re.fullmatch(r"[0-9a-f]{40}", value) and value == release["sha"]:
            return release["version"]
    except OSError:
        pass
    try:
        value = (BASE_DIR / "VERSION").read_text(encoding="utf-8").strip().lstrip("v")
        if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", value):
            return value
    except OSError:
        pass
    return "Legacy / unversioned"


def latest_release():
    with connect_db() as db:
        row = db.execute("SELECT value FROM app_settings WHERE key='update_repository'").fetchone()
    repo_url = (row["value"] if row else trusted_update_repository()).rstrip("/")
    if normalize_github_repo(repo_url) != trusted_update_repository():
        raise ValueError("Configured update repository differs from the trusted repository set by the server installer. Restore the trusted repository in Settings before updating.")
    repo_url = trusted_update_repository()
    match = re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?", repo_url)
    if not match:
        raise ValueError("Configured GitHub repository URL is invalid.")
    base = f"https://api.github.com/repos/{match.group(1)}/{match.group(2)}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "IP-Archive-Updater"}
    req = Request(f"{base}/releases/latest", headers=headers)
    with urlopen(req, timeout=8) as response:
        payload = json.loads(response.read(256_000).decode("utf-8"))
    tag = str(payload.get("tag_name", "")).strip()
    version = tag.lstrip("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
        raise ValueError("Latest GitHub release has no valid semantic version tag.")
    sha = str(payload.get("target_commitish", "")).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        req = Request(f"{base}/commits/{tag}", headers=headers)
        with urlopen(req, timeout=8) as response:
            commit = json.loads(response.read(256_000).decode("utf-8"))
        sha = str(commit.get("sha", "")).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("GitHub did not return a valid release commit SHA.")
    return {"version": version, "sha": sha, "tag": tag}


@app.get("/update/check")
@superadmin_required
def check_update():
    current = installed_version()
    try:
        release = latest_release()
        current = installed_version(release)
    except (URLError, HTTPError, TimeoutError, ValueError, OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": f"Could not check GitHub: {exc}", "current": current}, 502
    available = current != release["version"]
    return {"ok": True, "current": current, "latest": release["version"],
            "latest_sha": release["sha"], "tag": release["tag"],
            "update_available": available,
            "message": f"Version {release['version']} is available." if available else "You already have the latest version."}


@app.get("/update/status")
@superadmin_required
def update_status():
    try:
        log = UPDATE_LOG_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError:
        log = ""
    progress = 0
    phase = "Waiting for update process…"
    done = False
    success = False
    for line in log.splitlines():
        match = re.match(r"PROGRESS:(\d{1,3}):(.*)", line)
        if match:
            progress = max(progress, min(99, int(match.group(1))))
            phase = match.group(2).strip()
        if "IP Management updated successfully." in line:
            progress, phase, done, success = 100, "Update completed successfully", True, True
        elif ("Update failed" in line or "Update failed;" in line or "Update process failed" in line
              or "unable to change to root gid" in line or "error initializing audit plugin" in line
              or "Traceback (most recent call last):" in line
              or re.match(r"^(ModuleNotFoundError|ImportError|SyntaxError|PermissionError|FileNotFoundError):", line.strip())
              or (("Operation not permitted" in line or line.lstrip().startswith("sudo:"))
                  and "unable to send audit message" not in line.lower())):
            done, success, phase = True, False, "Update failed"
    if not done and log and "Starting update" not in log and progress == 0:
        phase = "Running server update commands…"
    try:
        offset = max(0, int(request.args.get("offset", "0")))
    except ValueError:
        offset = 0
    log_reset = offset > len(log)
    if log_reset:
        offset = 0
    return {"log": log[offset:], "log_offset": len(log), "log_reset": log_reset,
            "progress": progress, "phase": phase, "done": done, "success": success,
            "current": installed_version()}


@app.post("/update")
@superadmin_required
def update_app():
    updater = "/usr/local/sbin/station-archive-update"
    if not os.path.isfile(updater):
        flash("Updater is not installed on this server.", "error")
        return redirect(url_for("settings"))
    target_sha = request.form.get("target_sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", target_sha):
        flash("Check for updates first, then select the available version.", "error")
        return redirect(url_for("update_page"))
    try:
        release = latest_release()
        current = installed_version(release)
        if release["sha"] != target_sha:
            flash("GitHub changed since the check. Check for updates again before installing.", "error")
            return redirect(url_for("update_page"))
        if release["version"] == current:
            flash("No update is available. Your installation is already current.", "success")
            return redirect(url_for("update_page"))
        UPDATE_TARGET_FILE.write_text(target_sha + "\n", encoding="utf-8")
        UPDATE_TARGET_VERSION_FILE.write_text(release["version"] + "\n", encoding="utf-8")
        with connect_db() as db:
            repo_row = db.execute("SELECT value FROM app_settings WHERE key='update_repository'").fetchone()
        configured_repo = trusted_update_repository()
        UPDATE_REPOSITORY_FILE.write_text(configured_repo.rstrip("/") + "\n", encoding="utf-8")
        UPDATE_LOG_FILE.write_text("Starting update…\n", encoding="utf-8")
        with UPDATE_LOG_FILE.open("a", encoding="utf-8") as log:
            subprocess.Popen(["sudo", "-n", "/usr/bin/systemctl", "start", "station-archive-update.service"], stdout=log, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        audit("update_requested", f"target={target_sha}")
        return redirect(url_for("update_progress"))
    except (subprocess.SubprocessError, OSError, URLError, HTTPError, TimeoutError, ValueError) as exc:
        flash(f"Update could not start: {exc}", "error")
    return redirect(url_for("update_page"))


@app.get("/update/progress")
@superadmin_required
def update_progress():
    return render_template("update_progress.html")


@app.get("/update/finish")
@superadmin_required
def update_finish():
    try:
        log = UPDATE_LOG_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError:
        log = ""
    if "IP Management updated successfully." in log:
        return redirect(url_for("index", update="success"))
    if "Update failed" in log or "Update process failed" in log:
        flash("Update failed. Review the server output on the Updates page and try again after fixing the issue.", "error")
        return redirect(url_for("update_page"))
    return redirect(url_for("update_progress"))


@app.errorhandler(400)
def bad_request(error):
    security_event("http_400", session.get("username", ""), "blocked", f"Bad request or CSRF check failed: {request.method} {request.path}")
    return render_template("error.html", code=400, message=getattr(error, "description", "Invalid request.")), 400


@app.errorhandler(403)
def forbidden(error):
    security_event("http_403", session.get("username", ""), "blocked", f"Authorization denied: {request.method} {request.path}")
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(error):
    security_event("http_404", session.get("username", ""), "blocked", f"Unknown path probe: {request.method} {request.path}")
    return render_template("error.html", code=404, message="The requested page or record was not found."), 404

