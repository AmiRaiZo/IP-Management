import hashlib
import hmac
import base64
import json
import html
from io import BytesIO
import os
import re
import secrets
import sqlite3
import socket
import subprocess
import time
import threading
from urllib.request import Request, urlopen
from urllib.parse import urlsplit
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
        CREATE TABLE IF NOT EXISTS telegram_login_codes (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          code_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, created_at TEXT NOT NULL
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


def telegram_login_code_hash(user_id, code):
    normalized = re.sub(r"\s", "", str(code or ""))
    return hmac.new(app.secret_key.encode(), f"telegram-login:{user_id}:{normalized}".encode(), hashlib.sha256).hexdigest()


def issue_telegram_login_code():
    """Issue a two-minute, one-use Telegram fallback code for the superadmin only."""
    with connect_db() as db:
        user = db.execute("SELECT id FROM users WHERE role='superadmin' AND enabled=1 ORDER BY id LIMIT 1").fetchone()
        if not user:
            return ""
        code = f"{secrets.randbelow(1_000_000):06d}"
        expires = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat(timespec="seconds")
        db.execute("DELETE FROM telegram_login_codes")
        db.execute("INSERT INTO telegram_login_codes(user_id,code_hash,expires_at,created_at) VALUES(?,?,?,?)",
                   (user["id"], telegram_login_code_hash(user["id"], code), expires, now()))
    return code


def consume_telegram_login_code(user_id, submitted):
    """Atomically consume a short-lived Telegram fallback code; never stores it in plaintext."""
    if not re.fullmatch(r"\d{6}", str(submitted or "").strip()):
        return False
    with connect_db() as db:
        row = db.execute("SELECT id,code_hash,expires_at FROM telegram_login_codes WHERE user_id=?", (user_id,)).fetchone()
        if not row or row["expires_at"] < now():
            if row:
                db.execute("DELETE FROM telegram_login_codes WHERE id=?", (row["id"],))
            return False
        candidate = telegram_login_code_hash(user_id, submitted)
        if not hmac.compare_digest(row["code_hash"], candidate):
            return False
        db.execute("DELETE FROM telegram_login_codes WHERE id=?", (row["id"],))
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
        message_id = (result.get("result") or {}).get("message_id") if isinstance(result, dict) else None
        if result.get("ok") and message_id:
            telegram_schedule_delete(chat_id, message_id, 120)
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
        if not result.get("ok"):
            description = str(result.get("description") or "unspecified Telegram API error")[:240]
            app.logger.warning("Telegram Bot API method %s failed: %s", method, description)
            return {}
        return result
    except HTTPError as exc:
        description = ""
        try:
            error_data = json.loads(exc.read(65536).decode("utf-8"))
            description = str(error_data.get("description") or "")
        except (ValueError, OSError, UnicodeDecodeError):
            pass
        app.logger.warning("Telegram Bot API method %s failed (HTTP %s): %s",
                           method, exc.code, description[:240] or "request rejected")
        return {}
    except (URLError, TimeoutError, ValueError, OSError) as exc:
        app.logger.warning("Telegram Bot API method %s request failed (%s)",
                           method, type(exc).__name__)
        return {}


TELEGRAM_MESSAGE_TTL_SECONDS = 120
_TELEGRAM_DELETE_TIMERS = {}
_TELEGRAM_DELETE_TIMERS_LOCK = threading.Lock()


def telegram_cancel_scheduled_delete(chat_id, message_id):
    try:
        key = (str(chat_id), int(message_id))
    except (TypeError, ValueError):
        return
    with _TELEGRAM_DELETE_TIMERS_LOCK:
        pending = _TELEGRAM_DELETE_TIMERS.pop(key, None)
    if pending and pending is not threading.current_thread():
        pending.cancel()


def telegram_schedule_delete(chat_id, message_id, delete_after=TELEGRAM_MESSAGE_TTL_SECONDS):
    """Schedule deletion; edits to the same message reset its expiry timer."""
    try:
        normalized_chat_id = str(chat_id)
        normalized_message_id = int(message_id)
        delay = float(delete_after)
    except (TypeError, ValueError):
        return None
    if delay <= 0:
        return None
    key = (normalized_chat_id, normalized_message_id)

    def expire():
        with _TELEGRAM_DELETE_TIMERS_LOCK:
            if _TELEGRAM_DELETE_TIMERS.get(key) is not timer:
                return
            _TELEGRAM_DELETE_TIMERS.pop(key, None)
        telegram_delete_message(normalized_chat_id, normalized_message_id)

    with _TELEGRAM_DELETE_TIMERS_LOCK:
        previous = _TELEGRAM_DELETE_TIMERS.pop(key, None)
        if previous:
            previous.cancel()
        timer = threading.Timer(delay, expire)
        timer.daemon = True
        _TELEGRAM_DELETE_TIMERS[key] = timer
        timer.start()
    return timer


def telegram_delete_message(chat_id, message_id):
    """Best-effort cleanup for a bot or user message; Telegram permissions still apply in groups."""
    telegram_cancel_scheduled_delete(chat_id, message_id)
    try:
        telegram_api("deleteMessage", {"chat_id": str(chat_id), "message_id": int(message_id)})
    except (TypeError, ValueError):
        return


def telegram_send(chat_id, text, reply_markup=None, parse_mode=None, delete_after=TELEGRAM_MESSAGE_TTL_SECONDS):
    """Send a temporary bot message and schedule its automatic cleanup."""
    payload = {"chat_id": str(chat_id), "text": str(text)[:3900], "disable_web_page_preview": True}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    if parse_mode:
        payload["parse_mode"] = parse_mode
    result = telegram_api("sendMessage", payload)
    message_id = (result.get("result") or {}).get("message_id") if isinstance(result, dict) else None
    if delete_after and message_id:
        telegram_schedule_delete(str(chat_id), message_id, delete_after)
    return result


def telegram_replace_message(chat_id, message_id, text, reply_markup=None, parse_mode=None):
    """Replace the current bot screen instead of stacking another page in the chat."""
    payload = {"chat_id": str(chat_id), "message_id": int(message_id), "text": str(text)[:3900],
               "disable_web_page_preview": True}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    if parse_mode:
        payload["parse_mode"] = parse_mode
    if message_id:
        result = telegram_api("editMessageText", payload)
        if result:
            telegram_schedule_delete(str(chat_id), message_id, TELEGRAM_MESSAGE_TTL_SECONDS)
            return result
        telegram_delete_message(chat_id, message_id)
    return telegram_send(chat_id, text, reply_markup, parse_mode)


def telegram_browse_groups(chat_id, message_id):
    with connect_db() as db:
        groups = db.execute("SELECT id,name FROM groups ORDER BY sort_order,id").fetchall()
    keyboard = [[{"text": str(group["name"])[:60], "callback_data": f"ip_browse_group:{group['id']}"}]
                for group in groups]
    keyboard.append([{"text": "⬅️ Menu", "callback_data": "menu"}])
    telegram_set_state({"mode": "browse_groups"})
    text = "Choose a group to view its IP records:" if groups else "No groups are available yet."
    telegram_replace_message(chat_id, message_id, text, {"inline_keyboard": keyboard})


def telegram_browse_group(chat_id, message_id, group_id):
    with connect_db() as db:
        group = db.execute("SELECT id,name FROM groups WHERE id=?", (group_id,)).fetchone()
        if not group:
            telegram_browse_groups(chat_id, message_id)
            return
        rows = db.execute("SELECT id,name FROM ips WHERE group_id=? ORDER BY name,id", (group_id,)).fetchall()
    keyboard = [[{"text": str(row["name"])[:60], "callback_data": f"ip_browse_ip:{group_id}:{row['id']}"}]
                for row in rows]
    keyboard.append([{"text": "⬅️ Groups", "callback_data": "ip_groups"}])
    keyboard.append([{"text": "⌂ Menu", "callback_data": "menu"}])
    telegram_set_state({"mode": "browse_ips", "group_id": int(group["id"]), "group_name": group["name"]})
    text = f"Group: {group['name']}\nChoose an IP record:" if rows else f"Group: {group['name']}\nNo IP records in this group."
    telegram_replace_message(chat_id, message_id, text, {"inline_keyboard": keyboard})


def telegram_code(value):
    """Render a value as Telegram inline code; clients can tap the value itself to copy it."""
    text = str(value if value not in (None, "") else "-")
    return f"<code>{html.escape(text)}</code>"


def telegram_browse_ip(chat_id, message_id, group_id, ip_id):
    state = telegram_get_state()
    if state.get("mode") != "browse_ips" or str(state.get("group_id")) != str(group_id):
        telegram_browse_groups(chat_id, message_id)
        return
    with connect_db() as db:
        row = db.execute(
            "SELECT ips.id,ips.name,ips.ip_address,ips.port,ips.username,ips.password_enc,ips.notes,groups.name AS group_name "
            "FROM ips JOIN groups ON groups.id=ips.group_id WHERE ips.id=? AND ips.group_id=?",
            (ip_id, group_id),
        ).fetchone()
    if not row:
        telegram_browse_group(chat_id, message_id, group_id)
        return
    try:
        password = vault.decrypt((row["password_enc"] or "").encode()).decode() if row["password_enc"] else "-"
    except (InvalidToken, ValueError, TypeError, UnicodeDecodeError):
        password = "-"
    detail = (
        f"📌 Name: {html.escape(str(row['name'] or '-'))}\n"
        f"🌐 IP: {telegram_code(row['ip_address'])}\n"
        f"🔌 Port: {telegram_code(row['port'])}\n"
        f"👤 Username: {telegram_code(row['username'])}\n"
        f"🔑 Password: {telegram_code(password)}\n"
        f"📁 Group: {html.escape(str(row['group_name'] or '-'))}\n"
        f"📝 Notes: {html.escape(str((row['notes'] or '-')[:1000]))}"
    )
    keyboard = [
        [{"text": "⬅️ IP names", "callback_data": f"ip_browse_group:{group_id}"}],
        [{"text": "⬅️ All groups", "callback_data": "ip_groups"},
         {"text": "⌂ Menu", "callback_data": "menu"}],
    ]
    telegram_set_state({"mode": "browse_detail", "group_id": int(group_id), "group_name": row["group_name"]})
    telegram_replace_message(chat_id, message_id, detail, {"inline_keyboard": keyboard}, parse_mode="HTML")


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
    markup = {"inline_keyboard": [
        [
            {"text": "➕ Add IP", "callback_data": "ip_add"},
            {"text": "🔎 Search", "callback_data": "ip_search"},
        ],
        [{"text": "📂 Display all groups", "callback_data": "ip_groups"}],
        [{"text": "🔐 2FA code", "callback_data": "telegram_2fa_code"}],
    ]}
    if message_id:
        telegram_replace_message(chat_id, message_id, "IP Management — choose an option:", markup)
    else:
        telegram_send(chat_id, "IP Management — choose an option:", markup)


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
        elif action == "ip_groups":
            telegram_browse_groups(chat_id, message.get("message_id"))
        elif action.startswith("ip_browse_group:"):
            try:
                selected_group_id = int(action.split(":", 1)[1])
            except (TypeError, ValueError):
                telegram_browse_groups(chat_id, message.get("message_id"))
                return
            telegram_browse_group(chat_id, message.get("message_id"), selected_group_id)
        elif action.startswith("ip_browse_ip:"):
            try:
                _, selected_group_id, selected_ip_id = action.split(":", 2)
                selected_group_id, selected_ip_id = int(selected_group_id), int(selected_ip_id)
            except (TypeError, ValueError):
                telegram_browse_groups(chat_id, message.get("message_id"))
                return
            telegram_browse_ip(chat_id, message.get("message_id"), selected_group_id, selected_ip_id)
        elif action == "telegram_2fa_code":
            telegram_set_state({})
            code = issue_telegram_login_code()
            if not code:
                telegram_send(chat_id, "No enabled superadmin account is available for login recovery.")
                return
            telegram_send(chat_id, f"Login code for IP Management:\n<code>{code}</code>", parse_mode="HTML")
        elif action.startswith("ip_group:"):
            state = telegram_get_state()
            if state.get("mode") != "add" or state.get("step") != "group":
                return
            try:
                selected_group_id = int(action.split(":", 1)[1])
            except (TypeError, ValueError):
                telegram_send(chat_id, "Invalid group. Send /start to begin again.")
                telegram_set_state({})
                return
            with connect_db() as db:
                selected_group = db.execute("SELECT id,name FROM groups WHERE id=?", (selected_group_id,)).fetchone()
            if not selected_group:
                telegram_send(chat_id, "That group no longer exists. Send /start to begin again.")
                telegram_set_state({})
                return
            data = state.get("data") or {}
            data["group_id"] = str(selected_group["id"])
            data["group_name"] = selected_group["name"]
            state.update(step="notes", data=data)
            telegram_set_state(state)
            telegram_send(chat_id, f"Selected group: {selected_group['name']}\nStep 7 of 7 — enter notes, or send - to skip:")
        elif action == "ip_add":
            telegram_set_state({"mode": "add", "step": "name", "data": {}})
            telegram_send(chat_id, "Step 1 of 7 — enter a name for this IP/server:")
        elif action == "ip_search":
            telegram_set_state({"mode": "search", "step": "query"})
            telegram_send(chat_id, "Send the saved name or IP address to search:")
        return
    text = str(message.get("text", "")).strip()
    command = text.lower()
    if command.startswith("/"):
        command = command.split("@", 1)[0]
    if command in ("/login_code", "/login-code", "/کدورود", "کد ورود", "کدورود"):
        if message.get("message_id"):
            telegram_delete_message(chat_id, message["message_id"])
        telegram_set_state({})
        code = issue_telegram_login_code()
        if not code:
            telegram_send(chat_id, "No enabled superadmin account is available for login recovery.")
            return
        telegram_send(chat_id, f"Login code for IP Management:\n<code>{code}</code>", parse_mode="HTML")
        return
    if command in ("ربات", "/start", "/menu"):
        if message.get("message_id"):
            telegram_delete_message(chat_id, message["message_id"])
        telegram_set_state({})
        telegram_menu(chat_id)
        return
    state = telegram_get_state()
    if not state:
        return
    if state.get("mode") == "search":
        # Search input can contain sensitive hostnames; remove it from the chat when possible.
        if message.get("message_id"):
            telegram_delete_message(chat_id, message["message_id"])
        term = text[:100]
        if not term:
            telegram_send(chat_id, "Please enter a name or IP address to search again.")
            return
        with connect_db() as db:
            rows = db.execute("SELECT name,ip_address,port,username,password_enc,notes FROM ips WHERE ip_address LIKE ? OR name LIKE ? ORDER BY name LIMIT 10",
                              (f"%{term}%", f"%{term}%")).fetchall()
        if not rows:
            # Keep the search state active so the user can try another name without restarting.
            telegram_send(chat_id, "No record matched that name or IP.\nPlease send another name or IP address, or use /menu to cancel.",
                          {"inline_keyboard": [[{"text": "⬅️ Menu", "callback_data": "menu"}]]})
            return
        telegram_set_state({})
        lines = ["Search results:"]
        for row in rows:
            try:
                password = vault.decrypt((row["password_enc"] or "").encode()).decode() if row["password_enc"] else "-"
            except (InvalidToken, ValueError, TypeError, UnicodeDecodeError):
                password = "-"
            block = (
                f"\n📌 Name: {html.escape(str(row['name'] or '-'))}"
                f"\n🌐 IP: {telegram_code(row['ip_address'])}"
                f"\n🔌 Port: {telegram_code(row['port'])}"
                f"\n👤 Username: {telegram_code(row['username'])}"
                f"\n🔑 Password: {telegram_code(password)}"
                f"\n📝 Notes: {html.escape(str((row['notes'] or '-')[:180]))}"
            )
            if len("\n".join(lines + [block])) > 3500:
                lines.append("\nMore results omitted to keep the message within Telegram's size limit.")
                break
            lines.append(block)
        telegram_send(chat_id, "\n".join(lines),
                      {"inline_keyboard": [[{"text": "⬅️ Menu", "callback_data": "menu"}]]},
                      parse_mode="HTML")
        return
    if state.get("mode") == "add":
        # Best-effort deletion also removes submitted passwords from the private bot chat.
        if message.get("message_id"):
            telegram_delete_message(chat_id, message["message_id"])
        step = state.get("step")
        data = state.get("data") or {}
        prompts = {
            "name": "Step 2 of 7 — enter the IP address or hostname:",
            "ip": "Step 3 of 7 — enter the port (for example, 22 or 443):",
            "port": "Step 4 of 7 — enter the connection username:",
            "username": "Step 5 of 7 — enter the connection password, or send - if there is no password:",
        }
        if step == "name":
            data["name"] = text[:120]
            state.update(step="ip", data=data)
            telegram_set_state(state)
            telegram_send(chat_id, prompts["name"])
            return
        if step == "ip":
            data["ip_address"] = text[:255]
            state.update(step="port", data=data)
            telegram_set_state(state)
            telegram_send(chat_id, prompts["ip"])
            return
        if step == "port":
            data["port"] = text[:10]
            state.update(step="username", data=data)
            telegram_set_state(state)
            telegram_send(chat_id, prompts["port"])
            return
        if step == "username":
            data["username"] = text[:120]
            state.update(step="password", data=data)
            telegram_set_state(state)
            telegram_send(chat_id, prompts["username"])
            return
        if step == "password":
            data["password"] = "" if text == "-" else text[:500]
            with connect_db() as db:
                groups = db.execute("SELECT id,name FROM groups ORDER BY sort_order,id").fetchall()
            if not groups:
                telegram_send(chat_id, "No groups are available. Create a group in IP Management first.")
                telegram_set_state({})
                return
            state.update(step="group", data=data)
            telegram_set_state(state)
            markup = {"inline_keyboard": [[{"text": str(group["name"])[:60], "callback_data": f"ip_group:{group['id']}"}] for group in groups]}
            telegram_send(chat_id, "Step 6 of 7 — choose a group:", markup)
            return
        if step == "notes":
            data["notes"] = "" if text == "-" else text[:3000]
            clean, error = validate_ip(MultiDict(data))
            if error:
                telegram_send(chat_id, f"Invalid information: {error}\nSend /start to begin again.")
                telegram_set_state({})
                return
            with connect_db() as db:
                cur = db.execute("INSERT INTO ips(name,ip_address,port,username,password_enc,notes,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                                 (clean["name"], clean["ip"], clean["port"], clean["username"], clean["password"] or "", clean["notes"], clean["group_id"], "telegram-bot", now(), now()))
            telegram_set_state({})
            saved_message = (
                f"IP record saved in IP Management.\n"
                f"📌 {html.escape(str(clean['name']))}\n"
                f"🌐 IP: {telegram_code(clean['ip'])}\n"
                f"🔌 Port: {telegram_code(clean['port'])}\n"
                f"📁 Group: {html.escape(str(data.get('group_name', 'Default')))}\n"
                f"Record ID: {cur.lastrowid}"
            )
            telegram_send(chat_id, saved_message,
                          {"inline_keyboard": [[{"text": "⬅️ Menu", "callback_data": "menu"}]]},
                          parse_mode="HTML")
def telegram_hostname():
    """Return a short configured host label without exposing local machine details."""
    return (os.environ.get("APP_HOSTNAME", "").strip() or socket.gethostname() or "IP Management")[:80]


def safe_telegram_username(value):
    return re.sub(r"[^A-Za-z0-9_.@-]", "?", str(value or "unknown"))[:80] or "(empty)"


def send_login_success_alert(username, remote_ip):
    return send_telegram_security_alert(
        "Successful sign-in to IP Management.\n"
        f"💻 Host: {telegram_hostname()}\n"
        f"👤 Username: {safe_telegram_username(username)}\n"
        f"🌐 IP address: {remote_ip}\n"
        f"⏰ Time (Iran): {jalali_datetime(now())}"
    )


def send_login_failure_alert(username, remote_ip, reason, password=""):
    """Alert on failure without disclosing raw credentials to Telegram or app logs."""
    guess_id = failed_password_fingerprint(password) if password else "not-applicable"
    return send_telegram_security_alert(
        "Failed sign-in to IP Management.\n"
        f"Reason: {reason}\n"
        f"💻 Host: {telegram_hostname()}\n"
        f"👤 Username: {safe_telegram_username(username)}\n"
        f"🌐 IP address: {remote_ip}\n"
        f"⏰ Time (Iran): {jalali_datetime(now())}\n"
        f"Password guess fingerprint: {guess_id}\n"
        "The raw password was not sent or stored."
    )


def jalali_datetime(value):
    """Convert an ISO UTC timestamp to a Persian-calendar date/time in Iran time."""
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        # Iran uses UTC+03:30 year-round; a fixed offset avoids OS tzdata dependencies.
        dt = dt.astimezone(timezone(timedelta(hours=3, minutes=30)))
        gy, gm, gd = dt.year, dt.month, dt.day
        g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
        gy2 = gy + 1 if gm > 2 else gy
        days = 355666 + 365 * gy + (gy2 + 3) // 4 - (gy2 + 99) // 100 + (gy2 + 399) // 400 + gd + g_d_m[gm - 1]
        jy = -1595 + 33 * (days // 12053)
        days %= 12053
        jy += 4 * (days // 1461)
        days %= 1461
        if days > 365:
            jy += (days - 1) // 365
            days = (days - 1) % 365
        if days < 186:
            jm, jd = 1 + days // 31, 1 + days % 31
        else:
            jm, jd = 7 + (days - 186) // 30, 1 + (days - 186) % 30
        return f"{jy:04d}/{jm:02d}/{jd:02d} {dt:%H:%M:%S}"
    except (ValueError, TypeError, OverflowError):
        return str(value or "—")


def audit(action, detail=""):
    with connect_db() as db:
        db.execute("INSERT INTO audit_log(username,action,detail,created_at) VALUES(?,?,?,?)",
                   (session.get("username", "system"), action, detail[:300], now()))


def current_user_row():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with connect_db() as db:
        return db.execute("SELECT * FROM users WHERE id=? AND enabled=1", (user_id,)).fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        user = current_user_row()
        if not user:
            session.clear()
            return redirect(url_for("login"))
        g_user = dict(user)
        request.user = g_user
        return fn(*args, **kwargs)
    return wrapped


def two_factor_mode():
    with connect_db() as db:
        row = db.execute("SELECT value FROM app_settings WHERE key='two_factor_mode'").fetchone()
    mode = row["value"] if row else "off"
    return mode if mode in ("off", "shared", "per_user") else "off"


def shared_two_factor_secret():
    with connect_db() as db:
        row = db.execute("SELECT value FROM app_settings WHERE key='shared_two_factor_secret'").fetchone()
    return decrypt_authenticator_secret(row["value"]) if row else ""


def user_requires_two_factor(user):
    mode = two_factor_mode()
    if mode == "shared":
        return bool(shared_two_factor_secret())
    if mode == "per_user":
        return bool(user and user["two_factor_enabled"])
    return False


def two_factor_required():
    return two_factor_mode() == "shared"


def remembered_two_factor(user_id):
    """Check the signed, device-local 24-hour second-factor trust cookie."""
    token = request.cookies.get(REMEMBER_2FA_COOKIE, "")
    if not token:
        return False
    try:
        payload = two_factor_serializer.loads(token, max_age=REMEMBER_2FA_SECONDS)
        return payload.get("uid") == user_id and payload.get("v") == 1
    except (BadSignature, SignatureExpired, AttributeError):
        return False


def remember_two_factor_response(response, user_id):
    """Trust this browser for 24 hours without making the login session persistent."""
    token = two_factor_serializer.dumps({"uid": user_id, "v": 1})
    response.set_cookie(
        REMEMBER_2FA_COOKIE, token, max_age=REMEMBER_2FA_SECONDS,
        httponly=True, secure=request.is_secure, samesite="Lax", path="/",
    )
    return response


def establish_login(user):
    session.clear()
    # Keep the authenticated session as a browser-session cookie. Passwords
    # are required again after the browser session ends.
    session.permanent = False
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    audit("login_success")
    security_event("login", user["username"], "success", "Password and any required second factor were accepted")


def superadmin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if request.user["role"] != "superadmin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


@app.before_request
def enforce_application_ip_rules():
    if request.endpoint == "static":
        return None
    ip = client_ip()
    try:
        address = ip_address(ip)
    except ValueError:
        security_event("ip_policy", session.get("username", ""), "blocked", "Could not determine a valid client IP")
        return "Access denied by IP security policy.", 403
    with connect_db() as db:
        rules = db.execute("SELECT network,rule_type FROM ip_access_rules").fetchall()
        setting = db.execute("SELECT value FROM app_settings WHERE key='ip_allowlist_enabled'").fetchone()
    networks = []
    for rule in rules:
        try:
            networks.append((ip_network(rule["network"], strict=False), rule["rule_type"]))
        except ValueError:
            continue
    if any(kind == "block" and address in network for network, kind in networks):
        security_event("ip_policy", session.get("username", ""), "blocked", "Client IP matches a blocked network")
        return "Access denied by IP security policy.", 403
    if setting and setting["value"] == "1" and not any(kind == "allow" and address in network for network, kind in networks):
        security_event("ip_policy", session.get("username", ""), "blocked", "Client IP is not on the application allowlist")
        return "Access denied by IP security policy.", 403


@app.before_request
def enforce_global_two_factor():
    if (session.get("user_id") and not session.get("two_factor_verified")
            and request.endpoint not in ("login", "static")):
        user = current_user_row()
        if user_requires_two_factor(user):
            session.clear()
            return redirect(url_for("login"))


@app.before_request
def csrf_guard():
    if request.endpoint == "telegram_webhook":
        return
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        if not token or not hmac.compare_digest(token, supplied):
            abort(400, "Invalid or expired form token. Refresh the page and try again.")


@app.context_processor
def inject_globals():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    user = current_user_row() if session.get("user_id") else None
    with connect_db() as db:
        settings_rows = db.execute("SELECT key,value FROM app_settings").fetchall()
    app_settings = {row["key"]: row["value"] for row in settings_rows}
    defaults = {"brand_name": "IP Management", "brand_subtitle": "NETWORK DIRECTORY", "brand_logo_text": "IP",
                "login_title": "Welcome back", "login_subtitle": "",
                "accent_color": "#4569e8", "footer_text": "IP Management · Secure network inventory",
                "app_description": "Keep connection details organized, searchable, and available to the right people.",
                "inventory_title": "IP addresses", "inventory_description": "Keep connection details organized, searchable, and available to the right people.",
                "group_label": "Groups", "user_label": "Users & permissions"}
    for key, value in defaults.items():
        app_settings.setdefault(key, value)
    app_settings["brand_name"] = "IP Management"
    return {"csrf_token": session["csrf_token"], "current_user": session.get("username"),
            "current_role": user["role"] if user else "", "dark_mode": True, "app_settings": app_settings,
            "current_avatar": user["profile_image"] if user else ""}


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def auth_throttle_response(attempted_username=""):
    """Apply one shared IP-based throttle to password, TOTP, and enrollment checks."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(timespec="seconds")
    with connect_db() as db:
        failures = db.execute(
            "SELECT COUNT(*) AS n FROM security_events WHERE remote_ip=? AND result='failed' "
            "AND event_type IN ('login','two_factor_login','two_factor_enrollment') AND created_at>=?",
            (client_ip(), cutoff),
        ).fetchone()["n"]
    if failures < 8:
        return None
    security_event("login_rate_limit", str(attempted_username or "")[:80], "throttled",
                   "Eight failed authentication checks from this IP in the last 15 minutes")
    response = app.make_response(("Too many failed authentication attempts. Wait 15 minutes and try again.", 429))
    response.headers["Retry-After"] = "900"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET" and request.args.get("server_reconfigured") == "1":
        flash("The server address was changed successfully. Please sign in again at this new address.", "success")
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "POST":
        limited = auth_throttle_response(request.form.get("username", ""))
        if limited:
            return limited
    if request.method == "GET" and request.args.get("reset") == "1":
        session.pop("pending_2fa_user_id", None)
        session.pop("pending_2fa_secret", None)
        session["csrf_token"] = secrets.token_urlsafe(32)
    if (request.method == "GET" and two_factor_mode() == "per_user"
            and session.get("pending_2fa_user_id") and session.get("pending_2fa_secret")):
        return redirect(url_for("setup_2fa"))
    if request.method == "POST":
        pending_id = session.get("pending_2fa_user_id")
        if pending_id:
            code = re.sub(r"\s", "", request.form.get("code", ""))
            with connect_db() as db:
                user = db.execute("SELECT * FROM users WHERE id=? AND enabled=1", (pending_id,)).fetchone()
            mode = two_factor_mode()
            secret = shared_two_factor_secret() if mode == "shared" else (decrypt_authenticator_secret(user["totp_secret"]) if user else "")
            totp_ok = bool(user and user_requires_two_factor(user) and secret and pyotp.TOTP(secret).verify(code, valid_window=1))
            recovery_ok = bool(user and user_requires_two_factor(user) and not totp_ok and consume_recovery_code(user["id"], code))
            telegram_code_ok = bool(user and user["role"] == "superadmin" and user_requires_two_factor(user)
                                    and not totp_ok and not recovery_ok and consume_telegram_login_code(user["id"], code))
            if user and user_requires_two_factor(user) and (totp_ok or recovery_ok or telegram_code_ok):
                establish_login(user)
                session["two_factor_verified"] = True
                if recovery_ok:
                    security_event("two_factor_recovery", user["username"], "success", "One-time offline recovery code consumed")
                    audit("two_factor_recovery_code_used")
                if telegram_code_ok:
                    security_event("two_factor_recovery", user["username"], "success", "Two-minute Telegram fallback code consumed")
                    audit("telegram_login_recovery_code_used")
                send_login_success_alert(user["username"], client_ip())
                flash(f"Welcome back, {user['username']}!", "welcome")
                response = redirect(safe_login_target())
                if totp_ok:
                    remember_two_factor_response(response, user["id"])
                return response
            time.sleep(0.35)
            security_event("two_factor_login", user["username"] if user else "", "failed", "Invalid or unavailable authenticator code")
            send_telegram_security_alert(
                "Failed second-factor verification for IP Management.\n"
                "Reason: Invalid 2FA code\n"
                f"💻 Host: {telegram_hostname()}\n"
                f"👤 Username: {safe_telegram_username(user['username'] if user else '')}\n"
                f"🌐 IP address: {client_ip()}\n"
                f"⏰ Time (Iran): {jalali_datetime(now())}\n"
                "The raw 2FA code was not stored or sent."
            )
            flash("The verification code is invalid. Try again.", "error")
            return render_template("login.html", stage="verify", login_user=dict(user) if user else None)

        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE username=? AND enabled=1", (username,)).fetchone()
        if user and len(password) <= 1024 and password_matches(password, user["password_hash"]):
            if user_requires_two_factor(user) and remembered_two_factor(user["id"]):
                establish_login(user)
                session["two_factor_verified"] = True
                send_login_success_alert(user["username"], client_ip())
                flash(f"Welcome back, {user['username']}!", "welcome")
                return redirect(safe_login_target())
            if user_requires_two_factor(user):
                mode = two_factor_mode()
                if mode == "per_user" and not decrypt_authenticator_secret(user["totp_secret"]):
                    security_event("login", username, "password_ok_2fa_pending", "Password accepted; authenticator enrollment is required")
                    session.clear()
                    session["pending_2fa_user_id"] = user["id"]
                    session["pending_2fa_secret"] = pyotp.random_base32()
                    session["csrf_token"] = secrets.token_urlsafe(32)
                    return redirect(url_for("setup_2fa"))
                secret = shared_two_factor_secret() if mode == "shared" else decrypt_authenticator_secret(user["totp_secret"])
                if not secret:
                    security_event("login", username, "blocked", "Second factor is required but not configured")
                    flash("Two-factor authentication is not configured. Contact the super administrator.", "error")
                    return redirect(url_for("login"))
                session.clear()
                session["pending_2fa_user_id"] = user["id"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                security_event("login", username, "password_ok_2fa_pending", "Password accepted; waiting for second factor")
                return render_template("login.html", stage="verify", login_user={"id": user["id"], "username": user["username"], "role": user["role"], "profile_image": user["profile_image"]})
            establish_login(user)
            send_login_success_alert(user["username"], client_ip())
            flash(f"Welcome back, {user['username']}!", "welcome")
            return redirect(safe_login_target())
        time.sleep(0.35)
        guess_id = failed_password_fingerprint(password)
        security_event("login", username, "failed", f"Invalid username/password or disabled account; password not stored; guess fingerprint={guess_id}")
        send_login_failure_alert(username, client_ip(), "Invalid username or password", password)
        flash("Invalid username or password.", "error")
    pending_user = None
    if session.get("pending_2fa_user_id"):
        with connect_db() as db:
            pending_user = db.execute("SELECT id,username,role,profile_image FROM users WHERE id=? AND enabled=1",
                                      (session["pending_2fa_user_id"],)).fetchone()
    return render_template("login.html", stage="verify" if session.get("pending_2fa_user_id") else "password",
                           login_user=dict(pending_user) if pending_user else None)


def safe_login_target():
    target = request.args.get("next", "")
    return target if target.startswith("/") and not target.startswith("//") else url_for("index")


def normalize_github_repo(value):
    value = str(value or "").strip().rstrip("/")
    match = re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?", value, re.IGNORECASE)
    if not match:
        return ""
    return f"https://github.com/{match.group(1).lower()}/{match.group(2).removesuffix('.git').lower()}"


def trusted_update_repository():
    configured = os.environ.get("GITHUB_REPO") or os.environ.get("APP_REPO_URL") or "https://github.com/AmiRaiZo/IP-Management"
    normalized = normalize_github_repo(configured)
    return normalized or "https://github.com/amiraizo/ip-management"


@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    # Enrollment is only allowed in the mandatory first-login flow.
    # Signed-in users cannot alter their own authenticator configuration.
    user_id = session.get("pending_2fa_user_id")
    secret = session.get("pending_2fa_secret")
    mode = two_factor_mode()
    if mode != "per_user" or not user_id or not secret:
        if session.get("user_id"):
            abort(403)
        session.pop("pending_2fa_secret", None)
        return redirect(url_for("login"))
    with connect_db() as db:
        user = db.execute("SELECT id,username,role,profile_image,two_factor_enabled,two_factor_enrolled FROM users WHERE id=? AND enabled=1", (user_id,)).fetchone()
    if not user or not user["two_factor_enabled"]:
        session.clear()
        return redirect(url_for("login"))
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="IP Management")
    if request.method == "POST":
        limited = auth_throttle_response(user["username"])
        if limited:
            return limited
        code = re.sub(r"\s", "", request.form.get("code", ""))
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            with connect_db() as db:
                db.execute("UPDATE users SET totp_secret=?,two_factor_enrolled=1 WHERE id=?", (encrypt_authenticator_secret(secret), user_id))
            session.clear()
            # Authentication must remain a browser-session cookie. Only the
            # separate signed 2FA-remember cookie is persistent (24 hours).
            # A permanent Flask session would keep the login alive after the
            # browser is closed and reopened.
            session.permanent = False
            session["user_id"] = user_id
            session["username"] = user["username"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            session["two_factor_verified"] = True
            audit("two_factor_enabled")
            security_event("two_factor_enrollment", user["username"], "success", "Authenticator enrollment completed")
            flash(f"Welcome back, {user['username']}! Two-factor authentication is enabled.", "welcome")
            response = redirect(url_for("index"))
            remember_two_factor_response(response, user_id)
            return response
        time.sleep(0.35)
        security_event("two_factor_enrollment", user["username"], "failed", "Invalid authenticator enrollment code")
        flash("The authenticator code is invalid. Try again.", "error")
    import qrcode
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_data_uri = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")
    return render_template("setup_2fa.html", secret=secret, uri=uri, qr_data_uri=qr_data_uri, user=dict(user))


@app.post("/logout")
@login_required
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))


def visible_ips(user):
    with connect_db() as db:
        if user["role"] == "superadmin":
            return db.execute(
                "SELECT ips.*, groups.name AS group_name FROM ips "
                "LEFT JOIN groups ON groups.id=ips.group_id "
                "ORDER BY COALESCE(NULLIF(TRIM(groups.name), ''), 'Default') COLLATE NOCASE, "
                "COALESCE(NULLIF(TRIM(ips.name), ''), ips.ip_address) COLLATE NOCASE, "
                "ips.ip_address COLLATE NOCASE LIMIT 1000"
            ).fetchall()
        rows = db.execute("""
          SELECT DISTINCT ips.*, groups.name AS group_name FROM ips
          LEFT JOIN groups ON groups.id=ips.group_id
          LEFT JOIN user_group_access uga ON uga.group_id=ips.group_id AND uga.user_id=?
          LEFT JOIN user_ip_access uia ON uia.ip_id=ips.id AND uia.user_id=?
          WHERE (uga.user_id IS NOT NULL OR uia.can_view=1)
            AND NOT EXISTS (SELECT 1 FROM user_ip_access deny WHERE deny.user_id=? AND deny.ip_id=ips.id AND deny.can_view=0)
          ORDER BY COALESCE(NULLIF(TRIM(groups.name), ''), 'Default') COLLATE NOCASE,
                   COALESCE(NULLIF(TRIM(ips.name), ''), ips.ip_address) COLLATE NOCASE,
                   ips.ip_address COLLATE NOCASE LIMIT 1000
        """, (user["id"], user["id"], user["id"])).fetchall()
        return rows


@app.route("/")
@login_required
def index():
    term = request.args.get("q", "").strip()[:100]
    group_filter = request.args.get("group", "").strip()
    all_visible = visible_ips(request.user)
    rows = list(all_visible)
    if group_filter == "ungrouped":
        rows = [r for r in rows if r["group_id"] is None]
    elif group_filter.isdigit():
        rows = [r for r in rows if r["group_id"] == int(group_filter)]
    if term:
        lower = term.casefold()
        rows = [r for r in rows if lower in (r["ip_address"] or "").casefold() or lower in (r["name"] or "").casefold() or lower in (r["username"] or "").casefold() or lower in (r["notes"] or "").casefold()]
    with connect_db() as db:
        if request.user["role"] == "superadmin":
            groups = db.execute("SELECT * FROM groups ORDER BY sort_order, id").fetchall()
        else:
            groups = db.execute("""
              SELECT DISTINCT groups.* FROM groups
              JOIN ips ON ips.group_id=groups.id
              LEFT JOIN user_group_access uga ON uga.group_id=groups.id AND uga.user_id=?
              LEFT JOIN user_ip_access uia ON uia.ip_id=ips.id AND uia.user_id=?
              WHERE (uga.user_id IS NOT NULL OR uia.can_view=1)
                AND NOT EXISTS (SELECT 1 FROM user_ip_access deny WHERE deny.user_id=? AND deny.ip_id=ips.id AND deny.can_view=0)
              ORDER BY groups.sort_order, groups.id
            """, (request.user["id"], request.user["id"], request.user["id"])).fetchall()
    show_ip_passwords = request.user["role"] == "superadmin" or bool(request.user.get("can_view_passwords", 0))
    if show_ip_passwords:
        prepared_rows = []
        for row in rows:
            item = dict(row)
            try:
                item["password_plain"] = vault.decrypt((row["password_enc"] or "").encode()).decode() if row["password_enc"] else ""
            except (InvalidToken, ValueError, TypeError):
                item["password_plain"] = ""
            prepared_rows.append(item)
        rows = prepared_rows
    return render_template("index.html", ips=rows, q=term, groups=groups, group_filter=group_filter,
                           show_ip_passwords=show_ip_passwords,
                           update_success=request.args.get("update") == "success")


def can_view_ip(ip_id, user=None):
    user = user or request.user
    if user["role"] == "superadmin":
        return True
    with connect_db() as db:
        row = db.execute("""SELECT ips.group_id,
          EXISTS(SELECT 1 FROM user_group_access a WHERE a.user_id=? AND a.group_id=ips.group_id) AS group_ok,
          (SELECT can_view FROM user_ip_access b WHERE b.user_id=? AND b.ip_id=ips.id) AS ip_rule
          FROM ips WHERE ips.id=?""", (user["id"], user["id"], ip_id)).fetchone()
    if not row:
        return False
    if row["ip_rule"] == 0:
        return False
    return bool(row["group_ok"] or row["ip_rule"] == 1)


def validate_ip(form):
    label = form.get("name", "").strip()[:120]
    address = form.get("ip_address", "").strip()[:255]
    username = form.get("username", "").strip()[:120]
    raw_port = form.get("port", "").strip()
    submitted_password = form.get("password", "")
    notes = form.get("notes", "").strip()[:3000]
    group_raw = form.get("group_id", "").strip()
    if not address:
        return None, "IP address or hostname is required."
    try:
        port = int(raw_port) if raw_port else None
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        return None, "Port must be a number between 1 and 65535."
    try:
        group_id = int(group_raw) if group_raw else None
    except ValueError:
        return None, "Select a valid group."
    with connect_db() as db:
        if group_id is None:
            default_group = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()
            group_id = default_group["id"] if default_group else None
        if group_id:
            if not db.execute("SELECT id FROM groups WHERE id=?", (group_id,)).fetchone():
                return None, "Selected group does not exist."
    if len(submitted_password) > 500:
        return None, "Connection password is too long."
    return {"name": label, "ip": address, "port": port, "username": username,
            "password": vault.encrypt(submitted_password.encode()).decode() if submitted_password else None,
            "notes": notes, "group_id": group_id}, None



def _markdown_cell_values(value):
    """Split Markdown <br> alternatives while keeping credential values otherwise intact."""
    value = html.unescape(str(value or ""))
    value = re.sub(r"(?i)<br\s*/?>", "\n", value)
    value = re.sub(r"(?i)</?(?:p|div|span)>", "", value)
    return [part.strip() for part in value.splitlines() if part.strip()]


def _is_import_placeholder(value):
    return str(value or "").strip().casefold() in {"", "-", "—", "–", "n/a", "na", "none", "null"}


def _markdown_header_key(value):
    value = html.unescape(str(value or "")).strip().strip(chr(96) + "*_~").casefold()
    value = re.sub(r"\s+", " ", value)
    aliases = {
        "name": {"name", "record name", "device", "device name", "نام", "نام دستگاه"},
        "ip": {"ip", "ip address", "address", "host", "ip/host", "آدرس", "آی پی", "آی‌پی"},
        "username": {"user", "username", "user name", "login", "نام کاربری", "کاربر"},
        "password": {"pass", "password", "passwd", "رمز", "رمز عبور"},
    }
    for key, values in aliases.items():
        if value in values:
            return key
    return ""


def _parse_markdown_import_address(value):
    """Return (host, port, error), without accepting extra labels in the host field."""
    address = str(value or "").strip().strip(chr(96))
    port = None
    ipv6_port = re.fullmatch(r"\[([^\]]+)\]:(\d{1,5})", address)
    host_port = re.fullmatch(r"([^:\s]+):(\d{1,5})", address)
    if ipv6_port:
        address, raw_port = ipv6_port.groups()
        try:
            ip_address(address)
        except ValueError:
            return "", None, "The address format needs review."
        port = int(raw_port)
    elif host_port:
        address, raw_port = host_port.groups()
        port = int(raw_port)
    if port is not None and not 1 <= port <= 65535:
        return "", None, "Port must be between 1 and 65535."
    if not address or any(character.isspace() for character in address):
        return "", None, "The IP field contains extra text or multiple values."
    try:
        ip_address(address)
    except ValueError:
        if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", address):
            return "", None, "The IP/host format needs review."
    return address, port, None


def parse_markdown_ip_inventory(content):
    """Parse NAME/IP/USER/PASS Markdown tables, marking ambiguous rows instead of guessing."""
    lines = str(content or "").splitlines()
    header_line = None
    column_map = {}
    expected_columns = 0
    for index, line in enumerate(lines):
        if not line.strip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        mapped = {}
        for column, cell in enumerate(cells):
            key = _markdown_header_key(cell)
            if key and key not in mapped:
                mapped[key] = column
        if {"name", "ip", "username", "password"}.issubset(mapped):
            header_line = index
            column_map = mapped
            expected_columns = len(cells)
            break
    if header_line is None:
        return [], "Could not find a Markdown table with NAME, IP, USER, and PASS columns."

    entries = []
    for index in range(header_line + 1, len(lines)):
        line = lines[index].strip()
        if not line:
            continue
        if not line.startswith("|"):
            if entries:
                break
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells):
            continue
        if not any(cells):
            continue

        entry = {
            "line": index + 1, "name": "", "ip": "", "port": None,
            "username": "", "password": "", "status": "review", "reason": "",
        }
        if len(cells) != expected_columns:
            entry["reason"] = "The row has a different number of columns than the header."
            entries.append(entry)
            continue

        def cell_at(key):
            column = column_map[key]
            return cells[column] if column < len(cells) else ""

        name_values = [part for part in _markdown_cell_values(cell_at("name"))
                       if not _is_import_placeholder(part)]
        ip_values = [part for part in _markdown_cell_values(cell_at("ip"))
                     if part.strip().casefold() not in {"--ip--", "-ip-", "ip"}
                     and not _is_import_placeholder(part)]
        user_values = [part for part in _markdown_cell_values(cell_at("username"))
                       if not _is_import_placeholder(part)]
        password_values = [part for part in _markdown_cell_values(cell_at("password"))
                           if not _is_import_placeholder(part)]

        if len(name_values) > 1:
            entry["reason"] = "The row has multiple names; review it manually."
        elif len(ip_values) != 1:
            entry["reason"] = ("The row has multiple IP/host values; review it manually."
                               if len(ip_values) > 1 else "The row has no IP/host value.")
        elif len(user_values) > 1:
            entry["ip"] = ip_values[0]
            entry["reason"] = "The row has multiple usernames; review it manually."
        elif len(password_values) > 1:
            entry["ip"] = ip_values[0]
            entry["reason"] = "The row has multiple password lines or notes; review it manually."
        else:
            address, port, address_error = _parse_markdown_import_address(ip_values[0])
            entry["ip"] = address or ip_values[0]
            entry["port"] = port
            if address_error:
                entry["reason"] = address_error
            else:
                entry["name"] = name_values[0].strip(chr(96)) if name_values else address
                entry["username"] = user_values[0] if user_values else ""
                entry["password"] = password_values[0] if password_values else ""
                if len(entry["name"]) > 120 or len(entry["username"]) > 120 or len(entry["password"]) > 500:
                    entry["reason"] = "A field exceeds the site's length limit."
                else:
                    entry["status"] = "ready"
        if entry["status"] != "ready" and not entry["reason"]:
            entry["reason"] = "This row needs manual review."
        entries.append(entry)
        if len(entries) >= 1000:
            entries.append({
                "line": index + 1, "name": "", "ip": "", "port": None,
                "username": "", "password": "", "status": "review",
                "reason": "Import stopped at the 1,000-row safety limit.",
            })
            break
    if not entries:
        return [], "No data rows were found in the Markdown table."
    return entries, None


MARKDOWN_IMPORT_DIR = DATA_DIR / "import-staging"
MARKDOWN_IMPORT_DIR.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(MARKDOWN_IMPORT_DIR, 0o700)
except OSError:
    pass


def _markdown_import_stage_path(token):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,100}", token):
        return None
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    return MARKDOWN_IMPORT_DIR / (digest + ".enc")


def _cleanup_markdown_import_staging():
    cutoff = time.time() - 900
    try:
        for path in MARKDOWN_IMPORT_DIR.iterdir():
            try:
                if path.is_file() and path.stat().st_mtime < cutoff:
                    path.unlink()
            except OSError:
                continue
    except OSError:
        pass


def _classify_markdown_import_duplicates(entries):
    """Mark existing or repeated host/port pairs; never write credential-bearing rows to logs."""
    with connect_db() as db:
        existing_rows = db.execute("SELECT ip_address, port FROM ips").fetchall()
    existing = {
        ((row["ip_address"] or "").strip().casefold(), row["port"])
        for row in existing_rows
    }
    seen = set()
    for entry in entries:
        if entry["status"] != "ready":
            continue
        key = ((entry["ip"] or "").strip().casefold(), entry["port"])
        if key in existing:
            entry["status"] = "duplicate"
            entry["reason"] = "This IP/port pair already exists in the directory."
        elif key in seen:
            entry["status"] = "duplicate"
            entry["reason"] = "This IP/port pair appears more than once in the file."
        else:
            seen.add(key)
    return entries


def _markdown_import_preview(entries):
    safe_rows = []
    for entry in entries:
        safe_rows.append({
            "line": entry["line"], "name": entry["name"], "ip": entry["ip"],
            "port": entry["port"], "status": entry["status"], "reason": entry["reason"],
        })
    return {
        "rows": safe_rows,
        "ready_count": sum(entry["status"] == "ready" for entry in entries),
        "duplicate_count": sum(entry["status"] == "duplicate" for entry in entries),
        "review_count": sum(entry["status"] == "review" for entry in entries),
    }


@app.route("/ips/import", methods=["GET", "POST"])
@superadmin_required
def ip_import():
    if request.method == "GET":
        return render_template("import_markdown.html", preview=None, import_token=None)

    action = request.form.get("action", "")
    if action == "preview":
        upload = request.files.get("file")
        if not upload or not upload.filename:
            flash("Choose the Markdown file first.", "error")
            return render_template("import_markdown.html", preview=None, import_token=None), 400
        if Path(upload.filename).suffix.casefold() not in {".md", ".markdown", ".txt"}:
            flash("Upload a .md, .markdown, or .txt file.", "error")
            return render_template("import_markdown.html", preview=None, import_token=None), 400
        raw_bytes = upload.read(1_000_001)
        if not raw_bytes:
            flash("The selected file is empty.", "error")
            return render_template("import_markdown.html", preview=None, import_token=None), 400
        if len(raw_bytes) > 1_000_000:
            flash("The Markdown file must be 1 MB or smaller.", "error")
            return render_template("import_markdown.html", preview=None, import_token=None), 400
        try:
            content = raw_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            flash("The file must use UTF-8 text encoding.", "error")
            return render_template("import_markdown.html", preview=None, import_token=None), 400

        entries, parse_error = parse_markdown_ip_inventory(content)
        if parse_error:
            flash(parse_error, "error")
            return render_template("import_markdown.html", preview=None, import_token=None), 400

        _cleanup_markdown_import_staging()
        old_token = session.get("markdown_import_token")
        old_path = _markdown_import_stage_path(old_token)
        if old_path:
            try:
                old_path.unlink(missing_ok=True)
            except OSError:
                pass
        entries = _classify_markdown_import_duplicates(entries)
        import_token = None
        if any(entry["status"] == "ready" for entry in entries):
            import_token = secrets.token_urlsafe(32)
            stage_path = _markdown_import_stage_path(import_token)
            stage_path.write_bytes(vault.encrypt(content.encode("utf-8")))
            try:
                os.chmod(stage_path, 0o600)
            except OSError:
                pass
            session["markdown_import_token"] = import_token
        else:
            session.pop("markdown_import_token", None)
        return render_template("import_markdown.html",
                               preview=_markdown_import_preview(entries),
                               import_token=import_token)

    if action == "import":
        import_token = request.form.get("import_token", "")
        stored_token = session.get("markdown_import_token", "")
        if not stored_token or not import_token or not secrets.compare_digest(import_token, stored_token):
            abort(400, description="The import preview expired. Upload the file again.")
        stage_path = _markdown_import_stage_path(stored_token)
        if not stage_path or not stage_path.is_file() or time.time() - stage_path.stat().st_mtime > 900:
            session.pop("markdown_import_token", None)
            abort(400, description="The import preview expired. Upload the file again.")
        try:
            content = vault.decrypt(stage_path.read_bytes()).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError, OSError):
            session.pop("markdown_import_token", None)
            abort(400, description="The staged import could not be read. Upload the file again.")
        finally:
            try:
                stage_path.unlink(missing_ok=True)
            except OSError:
                pass
        session.pop("markdown_import_token", None)

        entries, parse_error = parse_markdown_ip_inventory(content)
        if parse_error:
            flash(parse_error, "error")
            return redirect(url_for("ip_import"))
        entries = _classify_markdown_import_duplicates(entries)
        ready = [entry for entry in entries if entry["status"] == "ready"]
        created = 0
        with connect_db() as db:
            default_group = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()
            group_id = default_group["id"] if default_group else None
            existing = {
                ((row["ip_address"] or "").strip().casefold(), row["port"])
                for row in db.execute("SELECT ip_address, port FROM ips").fetchall()
            }
            for entry in ready:
                key = ((entry["ip"] or "").strip().casefold(), entry["port"])
                if key in existing:
                    continue
                password_enc = vault.encrypt(entry["password"].encode("utf-8")).decode("ascii") if entry["password"] else ""
                db.execute(
                    "INSERT INTO ips(name,ip_address,port,username,password_enc,notes,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (entry["name"], entry["ip"], entry["port"], entry["username"],
                     password_enc, "", group_id, request.user["username"], now(), now()),
                )
                existing.add(key)
                created += 1
        duplicates = sum(entry["status"] == "duplicate" for entry in entries) + (len(ready) - created)
        review_count = sum(entry["status"] == "review" for entry in entries)
        audit("ips_imported", f"created={created}; duplicates_skipped={duplicates}; rows_needing_review={review_count}; source=markdown")
        flash(f"Import complete: {created} records added, {duplicates} duplicates skipped, {review_count} rows need manual review.", "success")
        return redirect(url_for("index"))

    abort(400, description="Unknown import action.")


def safe_ip_return_url(value):
    """Accept only a local return URL to the IP directory, never an external redirect."""
    default = url_for("index")
    candidate = str(value or "").strip()
    if not candidate or len(candidate) > 2048 or "\\" in candidate:
        return default
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return default
    if parsed.scheme or parsed.netloc or parsed.path != "/" or candidate.startswith("//"):
        return default
    # Only keep the directory filters; a fragment is unnecessary for the return target.
    return "/" + ("?" + parsed.query if parsed.query else "")


@app.route("/ips/new", methods=["GET", "POST"])
@superadmin_required
def ip_new():
    return_to = safe_ip_return_url(request.form.get("return_to") or request.args.get("return_to"))
    with connect_db() as db:
        groups = db.execute("SELECT * FROM groups ORDER BY sort_order, id").fetchall()
        default_group = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()
    if request.method == "POST":
        data, error = validate_ip(request.form)
        if error:
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return {"ok": False, "error": error}, 400
            flash(error, "error")
        else:
            with connect_db() as db:
                cur = db.execute("INSERT INTO ips(name,ip_address,port,username,password_enc,notes,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (data["name"], data["ip"], data["port"], data["username"], data["password"] or "", data["notes"], data["group_id"], request.user["username"], now(), now()))
                ip_id = cur.lastrowid
            audit("ip_created", f"id={ip_id}; ip={data['ip']}")
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return {"ok": True, "message": "IP record created."}
            flash("IP record created.", "success")
            return redirect(return_to)
    return render_template("ip_form.html", ip=None, groups=groups,
                           default_group_id=default_group["id"] if default_group else None,
                           return_to=return_to)


@app.route("/ips/<int:ip_id>/edit", methods=["GET", "POST"])
@superadmin_required
def ip_edit(ip_id):
    return_to = safe_ip_return_url(request.form.get("return_to") or request.args.get("return_to"))
    with connect_db() as db:
        ip = db.execute("SELECT * FROM ips WHERE id=?", (ip_id,)).fetchone()
        groups = db.execute("SELECT * FROM groups ORDER BY sort_order, id").fetchall()
    if not ip:
        abort(404)
    if request.method == "POST":
        data, error = validate_ip(request.form)
        if error:
            flash(error, "error")
        else:
            enc = data["password"] if data["password"] is not None else ip["password_enc"]
            with connect_db() as db:
                db.execute("UPDATE ips SET name=?,ip_address=?,port=?,username=?,password_enc=?,notes=?,group_id=?,updated_at=? WHERE id=?",
                           (data["name"], data["ip"], data["port"], data["username"], enc, data["notes"], data["group_id"], now(), ip_id))
            audit("ip_updated", f"id={ip_id}; ip={data['ip']}")
            flash("IP record updated.", "success")
            return redirect(return_to)
    ip_data = dict(ip)
    try:
        ip_data["password_plain"] = vault.decrypt((ip["password_enc"] or "").encode()).decode() if ip["password_enc"] else ""
    except (InvalidToken, ValueError, TypeError):
        ip_data["password_plain"] = ""
    return render_template("ip_form.html", ip=ip_data, groups=groups,
                           default_group_id=None, return_to=return_to)


@app.post("/ips/<int:ip_id>/delete")
@superadmin_required
def ip_delete(ip_id):
    return_to = safe_ip_return_url(request.form.get("return_to"))
    with connect_db() as db:
        row = db.execute("SELECT ip_address FROM ips WHERE id=?", (ip_id,)).fetchone()
        if row:
            db.execute("DELETE FROM ips WHERE id=?", (ip_id,))
    if row:
        audit("ip_deleted", f"id={ip_id}; ip={row['ip_address']}")
        flash("IP record deleted.", "success")
    return redirect(return_to)


@app.route("/groups", methods=["GET", "POST"])
@superadmin_required
def groups():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:80]
        description = request.form.get("description", "").strip()[:300]
        if not name:
            flash("Group name is required.", "error")
        else:
            try:
                with connect_db() as db:
                    next_order = db.execute("SELECT COALESCE(MAX(sort_order), 0) + 1 FROM groups").fetchone()[0]
                    db.execute("INSERT INTO groups(name,description,created_at,sort_order) VALUES(?,?,?,?)", (name, description, now(), next_order))
                audit("group_created", name)
                flash("Group created.", "success")
                return redirect(url_for("groups"))
            except sqlite3.IntegrityError:
                flash("A group with that name already exists.", "error")
    with connect_db() as db:
        rows = db.execute("SELECT groups.*, COUNT(ips.id) AS ip_count FROM groups LEFT JOIN ips ON ips.group_id=groups.id GROUP BY groups.id ORDER BY groups.sort_order, groups.id").fetchall()
    return render_template("groups.html", groups=rows)


@app.post("/groups/<int:group_id>/move")
@superadmin_required
def group_move(group_id):
    direction = request.form.get("direction", "")
    if direction not in ("up", "down"):
        abort(400)
    moved = False
    with connect_db() as db:
        ordered = db.execute("SELECT id, sort_order FROM groups ORDER BY sort_order, id").fetchall()
        ids = [row["id"] for row in ordered]
        if group_id not in ids:
            abort(404)
        current = ids.index(group_id)
        target = current - 1 if direction == "up" else current + 1
        if 0 <= target < len(ids):
            first, second = ordered[current], ordered[target]
            db.execute("UPDATE groups SET sort_order=? WHERE id=?", (second["sort_order"], first["id"]))
            db.execute("UPDATE groups SET sort_order=? WHERE id=?", (first["sort_order"], second["id"]))
            moved = True
    if moved:
        audit("group_reordered", f"id={group_id}; direction={direction}")
    return redirect(url_for("groups"))


@app.post("/groups/<int:group_id>/delete")
@superadmin_required
def group_delete(group_id):
    with connect_db() as db:
        db.execute("DELETE FROM groups WHERE id=?", (group_id,))
    audit("group_deleted", f"id={group_id}")
    flash("Group deleted. IP records remain and become ungrouped.", "success")
    return redirect(url_for("groups"))


@app.route("/users", methods=["GET", "POST"])
@superadmin_required
def users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")
        role = request.form.get("role", "admin")
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,80}", username):
            flash("Username must be 3–80 characters using letters, numbers, dot, underscore, @ or hyphen.", "error")
        elif not 12 <= len(password) <= 1024:
            flash("Password must be between 12 and 1024 characters.", "error")
        elif role not in ("admin", "superadmin"):
            flash("Invalid role.", "error")
        else:
            try:
                with connect_db() as db:
                    cur = db.execute("INSERT INTO users(username,password_hash,created_at,role,totp_secret,two_factor_enabled,enabled) VALUES(?,?,?,?,?,1,1)", (username, password_hash(password), now(), role, ""))
                audit("user_created", f"id={cur.lastrowid}; username={username}; role={role}")
                flash("User created. Configure this account’s two-factor policy in user settings if per-user authentication is selected.", "success")
                return redirect(url_for("users"))
            except sqlite3.IntegrityError:
                flash("That username already exists.", "error")
    with connect_db() as db:
        rows = db.execute("SELECT id,username,role,enabled,created_at,two_factor_enabled,totp_secret FROM users ORDER BY username").fetchall()
    return render_template("users.html", users=rows, two_factor_mode=two_factor_mode())


@app.route("/users/<int:user_id>", methods=["GET", "POST"])
@superadmin_required
def user_edit(user_id):
    with connect_db() as db:
        user = db.execute("SELECT id,username,role,enabled,created_at,two_factor_enabled,can_view_passwords FROM users WHERE id=?", (user_id,)).fetchone()
        groups = db.execute("SELECT * FROM groups ORDER BY name").fetchall()
        ips = db.execute(
            "SELECT id,ip_address,name,group_id FROM ips "
            "ORDER BY COALESCE(NULLIF(TRIM(name), ''), ip_address) COLLATE NOCASE, "
            "ip_address COLLATE NOCASE"
        ).fetchall()
        allowed_groups = {r[0] for r in db.execute("SELECT group_id FROM user_group_access WHERE user_id=?", (user_id,))}
        ip_rules = {r[0]: r[1] for r in db.execute("SELECT ip_id,can_view FROM user_ip_access WHERE user_id=?", (user_id,))}
    if not user:
        abort(404)
    if request.method == "POST":
        role = request.form.get("role", "admin")
        enabled = 1 if request.form.get("enabled") == "1" else 0
        can_view_passwords = 1 if role == "superadmin" or request.form.get("can_view_passwords") == "1" else 0
        two_factor_setting_submitted = "two_factor_enabled" in request.form
        two_factor_enabled = (1 if request.form.get("two_factor_enabled") == "1" else 0
                              if two_factor_setting_submitted else int(user["two_factor_enabled"]))
        password = request.form.get("password", "")
        if user_id == request.user["id"] and (role != "superadmin" or not enabled):
            flash("You cannot remove your own superadmin role or disable your own account.", "error")
        elif password and not 12 <= len(password) <= 1024:
            flash("Password must be between 12 and 1024 characters.", "error")
        elif role not in ("admin", "superadmin"):
            flash("Invalid role.", "error")
        else:
            selected_groups = {int(x) for x in request.form.getlist("groups") if x.isdigit()}
            with connect_db() as db:
                db.execute("UPDATE users SET role=?,enabled=?,two_factor_enabled=?,can_view_passwords=? WHERE id=?", (role, enabled, two_factor_enabled, can_view_passwords, user_id))
                if two_factor_setting_submitted and not two_factor_enabled:
                    db.execute("UPDATE users SET totp_secret='',two_factor_enrolled=0 WHERE id=?", (user_id,))
                if password:
                    db.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(password), user_id))
                db.execute("DELETE FROM user_group_access WHERE user_id=?", (user_id,))
                db.executemany("INSERT INTO user_group_access(user_id,group_id) VALUES(?,?)", [(user_id, gid) for gid in selected_groups])
                db.execute("DELETE FROM user_ip_access WHERE user_id=?", (user_id,))
                for ip in ips:
                    mode = request.form.get(f"ip_{ip['id']}", "inherit")
                    if mode == "allow":
                        db.execute("INSERT INTO user_ip_access(user_id,ip_id,can_view) VALUES(?,?,1)", (user_id, ip["id"]))
                    elif mode == "deny":
                        db.execute("INSERT INTO user_ip_access(user_id,ip_id,can_view) VALUES(?,?,0)", (user_id, ip["id"]))
            audit("user_permissions_updated", f"id={user_id}; role={role}")
            flash("User and visibility permissions updated.", "success")
            return redirect(url_for("user_edit", user_id=user_id))
    return render_template("user_edit.html", user=user, groups=groups, ips=ips, allowed_groups=allowed_groups, ip_rules=ip_rules, two_factor_mode=two_factor_mode())


@app.post("/users/<int:user_id>/delete")
@superadmin_required
def user_delete(user_id):
    if user_id == request.user["id"]:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("users"))

    with connect_db() as db:
        user = db.execute(
            "SELECT id,username,role,enabled FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for("users"))

        if user["role"] == "superadmin" and user["enabled"]:
            remaining_superadmins = db.execute(
                "SELECT COUNT(*) FROM users WHERE role='superadmin' AND enabled=1 AND id<>?",
                (user_id,),
            ).fetchone()[0]
            if remaining_superadmins < 1:
                flash("You cannot delete the last enabled super administrator.", "error")
                return redirect(url_for("users"))

        # Related access rules, recovery codes and Telegram login codes cascade on user deletion.
        db.execute("DELETE FROM users WHERE id=?", (user_id,))

    audit("user_deleted", f"id={user_id}; username={user['username']}; role={user['role']}")
    flash(f"User {user['username']} deleted.", "success")
    return redirect(url_for("users"))


@app.post("/settings/security")
@superadmin_required
def update_security_settings():
    if request.form.get("action") == "generate_shared_secret":
        secret = pyotp.random_base32()
        with connect_db() as db:
            db.execute("INSERT INTO app_settings(key,value) VALUES('shared_two_factor_secret',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (encrypt_authenticator_secret(secret),))
            db.execute("UPDATE users SET two_factor_enrolled=0")
        session["show_shared_2fa_secret_once"] = True
        audit("shared_two_factor_secret_generated")
        flash("Shared Authenticator secret generated. Enroll the site Authenticator before enabling shared mode.", "success")
        return redirect(url_for("settings") + "#security")
    mode = request.form.get("two_factor_mode", "off")
    if mode not in ("off", "shared", "per_user"):
        flash("Select a valid two-factor policy.", "error")
        return redirect(url_for("settings") + "#security")
    if mode == "shared" and not shared_two_factor_secret():
        flash("Generate the shared Authenticator secret before enabling shared mode.", "error")
        return redirect(url_for("settings") + "#security")
    with connect_db() as db:
        db.execute("INSERT INTO app_settings(key,value) VALUES('two_factor_mode',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (mode,))
        db.execute("INSERT INTO app_settings(key,value) VALUES('two_factor_required',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("1" if mode == "shared" else "0",))
    audit("two_factor_policy_updated", f"mode={mode}")
    flash("Two-factor policy saved. Users must sign in again for the new policy to apply.", "success")
    return redirect(url_for("settings") + "#security")


@app.get("/security")
@superadmin_required
def security_center():
    with connect_db() as db:
        events = db.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 250").fetchall()
        rules = db.execute("SELECT * FROM ip_access_rules ORDER BY rule_type,network").fetchall()
        setting = db.execute("SELECT value FROM app_settings WHERE key='ip_allowlist_enabled'").fetchone()
    return render_template("security.html", events=[{**dict(row), "jalali_time": jalali_datetime(row["created_at"])} for row in events],
                           rules=[dict(row) for row in rules], allowlist_enabled=bool(setting and setting["value"] == "1"),
                           current_ip=client_ip())


@app.post("/security/rules")
@superadmin_required
def add_ip_access_rule():
    rule_type = request.form.get("rule_type", "block")
    raw_network = request.form.get("network", "").strip()
    note = request.form.get("note", "").strip()[:160]
    enabled = request.form.get("allowlist_enabled") == "1"
    if rule_type not in ("block", "allow"):
        flash("Choose a valid IP rule type.", "error")
        return redirect(url_for("security_center"))
    try:
        network = ip_network(raw_network, strict=False)
    except ValueError:
        flash("Enter a valid IPv4/IPv6 address or CIDR network.", "error")
        return redirect(url_for("security_center"))
    try:
        current = ip_address(client_ip())
        if rule_type == "block" and current in network:
            flash("You cannot block the IP address you are currently using.", "error")
            return redirect(url_for("security_center"))
        with connect_db() as db:
            if enabled:
                existing_allow = db.execute("SELECT network FROM ip_access_rules WHERE rule_type='allow'").fetchall()
                allowed_current = (rule_type == "allow" and current in network) or any(
                    current in ip_network(row["network"], strict=False) for row in existing_allow
                )
                if not allowed_current:
                    flash("To avoid locking yourself out, first add an allow rule that includes your current IP, then enable the allowlist.", "error")
                    return redirect(url_for("security_center"))
            db.execute("INSERT INTO ip_access_rules(network,rule_type,note,created_by,created_at) VALUES(?,?,?,?,?) "
                       "ON CONFLICT(network) DO UPDATE SET rule_type=excluded.rule_type,note=excluded.note,created_by=excluded.created_by,created_at=excluded.created_at",
                       (str(network), rule_type, note, session.get("username", ""), now()))
            db.execute("INSERT INTO app_settings(key,value) VALUES('ip_allowlist_enabled',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("1" if enabled else "0",))
    except (ValueError, TypeError):
        flash("The current client IP could not be validated. No changes were made.", "error")
        return redirect(url_for("security_center"))
    security_event("ip_rule_added", session.get("username", ""), "success", f"{rule_type} rule: {network}; allowlist={'enabled' if enabled else 'disabled'}")
    audit("ip_access_rule_updated", f"type={rule_type}; network={network}; allowlist={enabled}")
    flash("IP access rule saved for this application only.", "success")
    return redirect(url_for("security_center"))


@app.post("/security/rules/<int:rule_id>/delete")
@superadmin_required
def delete_ip_access_rule(rule_id):
    with connect_db() as db:
        row = db.execute("SELECT network,rule_type FROM ip_access_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            abort(404)
        db.execute("DELETE FROM ip_access_rules WHERE id=?", (rule_id,))
    security_event("ip_rule_removed", session.get("username", ""), "success", f"Removed {row['rule_type']} rule {row['network']}")
    audit("ip_access_rule_removed", f"type={row['rule_type']}; network={row['network']}")
    flash("IP rule removed.", "success")
    return redirect(url_for("security_center"))


@app.post("/settings/directory")
@superadmin_required
def update_directory_settings():
    show_passwords = "1" if request.form.get("show_ip_passwords") == "1" else "0"
    with connect_db() as db:
        db.execute("INSERT INTO app_settings(key,value) VALUES('show_ip_passwords',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (show_passwords,))
    audit("ip_password_visibility_updated", f"enabled={show_passwords}")
    flash("IP directory password visibility setting saved.", "success")
    return redirect(url_for("settings") + "#directory")


@app.route("/settings", methods=["GET", "POST"])
@superadmin_required
def settings():
    if request.method == "GET" and request.args.get("reconfigured") == "1":
        flash("Server address updated successfully. Nginx, the HTTPS certificate and application listener are using the new address.", "success")
    defaults = {"brand_name": "IP Management", "brand_subtitle": "NETWORK DIRECTORY", "brand_logo_text": "IP",
                "login_title": "Your network. Your command.", "login_subtitle": "Sign in to securely manage your IP inventory.",
                "accent_color": "#4569e8", "footer_text": "IP Management · Secure network inventory",
                "app_description": "Keep connection details organized, searchable, and available to the right people.",
                "inventory_title": "IP addresses", "inventory_description": "Keep connection details organized, searchable, and available to the right people.",
                "group_label": "Groups", "user_label": "Users & permissions"}
    if request.method == "POST":
        values = {key: request.form.get(key, "").strip()[:500] for key in defaults if key in request.form}
        if "brand_name" in values:
            values["brand_name"] = "IP Management"
        if "accent_color" in values and not re.fullmatch(r"#[0-9a-fA-F]{6}", values["accent_color"]):
            flash("Accent color must be a valid six-digit hex color.", "error")
            return redirect(url_for("settings") + "#branding")
        logo = request.files.get("brand_logo")
        logo_name = ""
        if logo and logo.filename:
            ext = Path(secure_filename(logo.filename)).suffix.lower()
            if ext not in ALLOWED_IMAGE_EXTENSIONS:
                flash("Logo must be PNG, JPG, JPEG, or WEBP.", "error")
                return redirect(url_for("settings") + "#branding")
            logo_name = "brand" + ext
            try:
                save_sanitized_image(logo, UPLOAD_DIR / logo_name, ext)
            except ValueError as exc:
                flash(str(exc), "error")
                return redirect(url_for("settings") + "#branding")
        with connect_db() as db:
            for key, value in values.items():
                db.execute("INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
            if logo_name:
                db.execute("INSERT INTO app_settings(key,value) VALUES('brand_logo',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (logo_name,))
        audit("application_settings_updated")
        flash("Application settings saved.", "success")
        return redirect(url_for("settings") + ("#branding" if "brand_subtitle" in values or "brand_logo_text" in values else "#text"))
    with connect_db() as db:
        values = {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM app_settings")}
        show_ip_passwords = values.get("show_ip_passwords", "0") == "1"
    for key, value in defaults.items():
        values.setdefault(key, value)
    values["brand_name"] = "IP Management"
    values.setdefault("brand_logo", "")
    # Reveal the shared enrollment seed/QR only once immediately after rotation.
    # Reopening Settings must not keep redisclosing this high-value secret to the browser.
    reveal_shared_secret = bool(session.pop("show_shared_2fa_secret_once", False))
    shared_secret = shared_two_factor_secret() if reveal_shared_secret else ""
    shared_uri = pyotp.TOTP(shared_secret).provisioning_uri(name="All users", issuer_name="IP Management") if shared_secret else ""
    shared_qr = ""
    if shared_uri:
        import qrcode
        qr_buffer = BytesIO()
        qrcode.make(shared_uri).save(qr_buffer, format="PNG")
        shared_qr = "data:image/png;base64," + base64.b64encode(qr_buffer.getvalue()).decode("ascii")
    with connect_db() as db:
        deployment = {row["key"]: row["value"] for row in db.execute(
            "SELECT key,value FROM app_settings WHERE key IN ('public_domain','public_port','update_repository')")}
    deployment.setdefault("public_domain", os.environ.get("APP_DOMAIN", ""))
    deployment.setdefault("public_port", os.environ.get("PUBLIC_PORT", os.environ.get("APP_HTTPS_PORT", "443")))
    deployment["update_repository"] = trusted_update_repository()
    return render_template("settings.html", app_values=values, deployment=deployment,
                           two_factor_mode=two_factor_mode(), shared_two_factor_secret=shared_secret,
                           shared_two_factor_uri=shared_uri, shared_two_factor_qr=shared_qr,
                           telegram_configured=bool(secure_setting("telegram_bot_token_enc") and secure_setting("telegram_chat_id_enc")),
                           show_ip_passwords=show_ip_passwords,
                           github_repo=deployment["update_repository"],
                           public_port=deployment["public_port"])


def configure_telegram_webhook(public_base=None):
    """Register the interactive bot webhook using the saved encrypted credentials."""
    if not secure_setting("telegram_bot_token_enc") or not secure_setting("telegram_chat_id_enc"):
        return False, "Enter and save both the bot token and numeric chat ID first."
    if public_base is None:
        public_base = (os.environ.get("APP_PUBLIC_URL", "").strip()
                       or request.url_root)
    public_base = str(public_base or "").strip().rstrip("/")
    if not public_base.lower().startswith("https://") or len(public_base) <= len("https://"):
        return False, "The public URL must be externally reachable over HTTPS. Check APP_PUBLIC_URL and the reverse-proxy HTTPS headers."
    webhook_secret = secure_setting("telegram_webhook_secret_enc") or secrets.token_urlsafe(32)
    save_secure_setting("telegram_webhook_secret_enc", webhook_secret)
    expected_url = public_base + url_for("telegram_webhook")
    result = telegram_api("setWebhook", {
        "url": expected_url,
        "secret_token": webhook_secret,
        "allowed_updates": ["message", "callback_query"],
    })
    if not result.get("ok"):
        return False, "Telegram rejected webhook registration. Check the application service log for the Telegram API error."
    info = telegram_api("getWebhookInfo", {})
    if info.get("ok"):
        actual_url = str((info.get("result") or {}).get("url") or "")
        if actual_url and actual_url != expected_url:
            return False, "Telegram reports a different webhook URL. Check APP_PUBLIC_URL."
        last_error = str((info.get("result") or {}).get("last_error_message") or "").strip()
        if last_error:
            app.logger.warning("Telegram reports a recent webhook delivery error: %s", last_error[:240])
            return False, "Telegram reports a webhook delivery error: " + last_error[:180] + ". Check the public HTTPS endpoint and webhook secret-token handling."
    return True, ""


@app.post("/settings/telegram")
@superadmin_required
def update_telegram_settings():
    action = request.form.get("action", "save")
    token = request.form.get("telegram_bot_token", "").strip()
    chat_id = request.form.get("telegram_chat_id", "").strip()
    if token or chat_id:
        if (not token or not chat_id
                or not re.fullmatch(r"\d{5,15}:[A-Za-z0-9_-]{20,100}", token)
                or not re.fullmatch(r"-?\d{1,20}", chat_id)):
            flash("Enter both a valid Telegram bot token and numeric chat ID. Leave both blank to keep the saved values.", "error")
            return redirect(url_for("settings") + "#notifications")
        save_secure_setting("telegram_bot_token_enc", token)
        save_secure_setting("telegram_chat_id_enc", chat_id)
        audit("telegram_security_alerts_configured")

    # Always re-register from stored credentials, even when the password fields are blank.
    # This makes the existing settings form a repair path for a missing or stale webhook.
    webhook_ok, webhook_error = configure_telegram_webhook()
    if not webhook_ok:
        app.logger.warning("Telegram interactive bot webhook setup failed: %s", webhook_error)
        flash("Interactive Telegram commands are not active: " + webhook_error, "error")
    elif action == "test":
        flash("Interactive Telegram bot webhook registered and verified.", "success")

    if action == "test":
        if send_telegram_security_alert("IP Management security notification test.\nThis confirms Telegram delivery; no passwords or authenticator codes are included."):
            flash("Telegram test notification sent.", "success")
        else:
            flash("Telegram test failed. Check the bot token, chat ID, bot access to the chat, and server internet access.", "error")
    elif webhook_ok:
        flash("Telegram settings saved and the interactive bot webhook registered.", "success")
    return redirect(url_for("settings") + "#notifications")


@app.post("/telegram/webhook")
def telegram_webhook():
    expected = secure_setting("telegram_webhook_secret_enc")
    supplied = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not expected or not hmac.compare_digest(expected, supplied):
        abort(403)
    update = request.get_json(silent=True)
    if not isinstance(update, dict):
        abort(400)
    handle_telegram_update(update)
    return {"ok": True}


@app.post("/settings/export.txt")
@superadmin_required
def export_text_backup():
    password = request.form.get("current_password", "")
    user = current_user_row()
    if not user or len(password) > 1024 or not password_matches(password, user["password_hash"]):
        security_event("backup_export", session.get("username", ""), "failed", "Re-authentication failed")
        abort(403)
    with connect_db() as db:
        users = db.execute("SELECT id,username,role,enabled,created_at,two_factor_enabled,two_factor_enrolled,can_view_passwords FROM users ORDER BY id").fetchall()
        groups = db.execute("SELECT id,name,description,created_at,sort_order FROM groups ORDER BY sort_order,id").fetchall()
        ips = db.execute("SELECT id,name,ip_address,port,username,password_enc,notes,group_id,created_by,created_at,updated_at FROM ips ORDER BY id").fetchall()
        settings = db.execute("SELECT key,value FROM app_settings ORDER BY key").fetchall()
        group_access = db.execute("SELECT user_id,group_id FROM user_group_access ORDER BY user_id,group_id").fetchall()
        ip_access = db.execute("SELECT user_id,ip_id,can_view FROM user_ip_access ORDER BY user_id,ip_id").fetchall()
        ip_rules = db.execute("SELECT network,rule_type,note,created_by,created_at FROM ip_access_rules ORDER BY id").fetchall()
        audit_rows = db.execute("SELECT username,action,detail,created_at FROM audit_log ORDER BY id DESC LIMIT 5000").fetchall()
        event_rows = db.execute("SELECT event_type,remote_ip,attempted_username,result,detail,user_agent,created_at FROM security_events ORDER BY id DESC LIMIT 5000").fetchall()
    safe_settings = {}
    secret_setting_keys = {"shared_two_factor_secret", "telegram_bot_token_enc", "telegram_chat_id_enc"}
    for row in settings:
        key, value = row["key"], row["value"]
        safe_settings[key] = "[REDACTED: secret]" if key in secret_setting_keys else value
    lines = [
        "IP MANAGEMENT - READABLE TEXT DATA BACKUP",
        f"Generated (UTC): {now()}",
        f"Generated by: {user['username']}",
        "=" * 78,
        "SECURITY NOTICE: This file contains confidential network inventory and connection passwords.",
        "Store it encrypted and share it only with authorized administrators.",
        "Account password hashes, TOTP seeds, Telegram bot token and Telegram chat ID are excluded/redacted.",
        "This is a readable data export, not a full source-code/system-image backup.",
        "=" * 78,
    ]
    def add_section(title, records):
        lines.extend(["", "# " + title, "-" * 78])
        if not records:
            lines.append("(no records)")
        for record in records:
            lines.append(json.dumps(dict(record), ensure_ascii=False, indent=2, default=str))
    add_section("USERS (password hashes and authenticator seeds excluded)", users)
    add_section("GROUPS", groups)
    ip_records = []
    for row in ips:
        record = dict(row)
        encrypted = record.pop("password_enc", "")
        try:
            record["connection_password"] = vault.decrypt(encrypted.encode()).decode() if encrypted else ""
        except (InvalidToken, ValueError, UnicodeDecodeError):
            record["connection_password"] = "[UNREADABLE: encryption key mismatch]"
        ip_records.append(record)
    add_section("IP RECORDS (connection passwords included for backup)", ip_records)
    add_section("APPLICATION SETTINGS (secrets redacted)", [{"key": k, "value": v} for k, v in safe_settings.items()])
    add_section("USER GROUP ACCESS", group_access)
    add_section("USER IP ACCESS", ip_access)
    add_section("APPLICATION IP RULES", ip_rules)
    add_section("LATEST AUDIT LOG (up to 5000)", audit_rows)
    add_section("LATEST SECURITY EVENTS (up to 5000; no raw passwords are logged)", event_rows)
    lines.extend(["", "# APPLICATION SOURCE FILES (UTF-8 text files only)", "-" * 78,
                  "Runtime secrets, environment files, virtual environments, SQLite files and binary media are deliberately excluded."])
    source_paths = []
    for name in ("app.py", "setup_admin.py", "requirements.txt", "README.md", "install.sh",
                 "upgrade_existing.sh", "reconfigure_server.sh", "VERSION", ".gitignore"):
        candidate = BASE_DIR / name
        if candidate.is_file():
            source_paths.append(candidate)
    for folder in (BASE_DIR / "templates", BASE_DIR / "static"):
        if folder.is_dir():
            source_paths.extend(p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in
                                {".py", ".html", ".js", ".css", ".md", ".txt", ".svg", ".json", ".xml"})
    for source_path in sorted(set(source_paths)):
        try:
            if source_path.stat().st_size > 1_000_000:
                continue
            source_text = source_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        lines.extend(["", f"--- FILE: {source_path.relative_to(BASE_DIR).as_posix()} ---", source_text,
                      f"--- END FILE: {source_path.relative_to(BASE_DIR).as_posix()} ---"])
    lines.extend(["", "# EXCLUDED ITEMS", "Binary logos/avatars and runtime environment/secrets are not embedded in this TXT file.",
                  "For disaster recovery, separately preserve the server environment secrets and binary uploads in an encrypted backup."])
    content = "\n".join(lines) + "\n"
    audit("text_backup_exported", f"users={len(users)}; groups={len(groups)}; ips={len(ips)}")
    from io import BytesIO as _BytesIO
    output = _BytesIO(content.encode("utf-8-sig"))
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
    # A rejected Host header can fail while Flask is creating the URL adapter.
    # In that case url_for() inside error.html raises a second exception and turns
    # the intended 400 into a 500. Keep this handler independent of routing.
    message = html.escape(str(getattr(error, "description", "Invalid request.")))
    body = (
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>400 Bad Request</title><body><main>"
        "<h1>400 — Bad Request</h1><p>"
        + message
        + "</p></main></body></html>"
    )
    return body, 400, {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"}


@app.errorhandler(403)
def forbidden(error):
    security_event("http_403", session.get("username", ""), "blocked", f"Authorization denied: {request.method} {request.path}")
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(error):
    security_event("http_404", session.get("username", ""), "blocked", f"Unknown path probe: {request.method} {request.path}")
    return render_template("error.html", code=404, message="The requested page or record was not found."), 404
