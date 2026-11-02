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
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for, send_file, jsonify
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
    LOGIN_APPROVAL_REQUIRED=True,
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
          code_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
          chat_id TEXT NOT NULL DEFAULT '', message_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS groups (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
          sort_order INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS account_groups (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS note_groups (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '',
          color TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS accounts (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, username TEXT NOT NULL, email TEXT NOT NULL,
          password_enc TEXT NOT NULL DEFAULT '', group_id INTEGER REFERENCES account_groups(id) ON DELETE SET NULL,
          created_by TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
          id INTEGER PRIMARY KEY, title TEXT NOT NULL DEFAULT '', service_url TEXT NOT NULL DEFAULT '',
          ip_name TEXT NOT NULL DEFAULT '', ip_address TEXT NOT NULL DEFAULT '', ip_port INTEGER,
          ip_username TEXT NOT NULL DEFAULT '', ip_password_enc TEXT NOT NULL DEFAULT '',
          account_name TEXT NOT NULL DEFAULT '', account_username TEXT NOT NULL DEFAULT '',
          account_email TEXT NOT NULL DEFAULT '', account_password_enc TEXT NOT NULL DEFAULT '',
          note_text TEXT NOT NULL DEFAULT '', wifi_ssid TEXT NOT NULL DEFAULT '', wifi_password_enc TEXT NOT NULL DEFAULT '',
          admin_ip TEXT NOT NULL DEFAULT '', admin_username TEXT NOT NULL DEFAULT '',
          admin_password_enc TEXT NOT NULL DEFAULT '', group_id INTEGER REFERENCES note_groups(id) ON DELETE SET NULL,
          created_by TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
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
        CREATE TABLE IF NOT EXISTS login_approval_requests (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          username TEXT NOT NULL, remote_ip TEXT NOT NULL, user_agent TEXT NOT NULL DEFAULT '',
          token_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          created_at TEXT NOT NULL, expires_at TEXT NOT NULL, decided_at TEXT NOT NULL DEFAULT '',
          telegram_chat_id TEXT NOT NULL DEFAULT '', telegram_message_id INTEGER,
          login_method TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS login_attempt_counters (
          scope TEXT NOT NULL, key_hash TEXT NOT NULL, failed_attempts INTEGER NOT NULL DEFAULT 0,
          window_started_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          PRIMARY KEY(scope,key_hash)
        );
        CREATE TABLE IF NOT EXISTS login_security_blocks (
          block_id TEXT PRIMARY KEY, username_hash TEXT NOT NULL DEFAULT '', ip_hash TEXT NOT NULL DEFAULT '',
          device_hash TEXT NOT NULL DEFAULT '', agent_hash TEXT NOT NULL DEFAULT '',
          username TEXT NOT NULL DEFAULT '', blocked_until TEXT NOT NULL,
          telegram_message_id INTEGER, telegram_chat_id TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_login_approval_user_status ON login_approval_requests(user_id,status,created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_login_security_blocks_expiry ON login_security_blocks(blocked_until);
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
        note_cols = {r[1] for r in db.execute("PRAGMA table_info(notes)")}
        for name, definition in (("wifi_ssid", "TEXT NOT NULL DEFAULT ''"),
                                 ("wifi_password_enc", "TEXT NOT NULL DEFAULT ''"),
                                 ("admin_ip", "TEXT NOT NULL DEFAULT ''"),
                                 ("admin_username", "TEXT NOT NULL DEFAULT ''"),
                                 ("admin_password_enc", "TEXT NOT NULL DEFAULT ''")):
            if name not in note_cols:
                db.execute(f"ALTER TABLE notes ADD COLUMN {name} {definition}")
        telegram_code_cols = {r[1] for r in db.execute("PRAGMA table_info(telegram_login_codes)")}
        if "chat_id" not in telegram_code_cols:
            db.execute("ALTER TABLE telegram_login_codes ADD COLUMN chat_id TEXT NOT NULL DEFAULT ''")
        if "message_id" not in telegram_code_cols:
            db.execute("ALTER TABLE telegram_login_codes ADD COLUMN message_id INTEGER")
        user_cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
        for name, definition in (("role", "TEXT NOT NULL DEFAULT 'admin'"), ("totp_secret", "TEXT NOT NULL DEFAULT ''"), ("two_factor_enabled", "INTEGER NOT NULL DEFAULT 0"), ("two_factor_enrolled", "INTEGER NOT NULL DEFAULT 0"), ("enabled", "INTEGER NOT NULL DEFAULT 1"), ("can_view_passwords", "INTEGER NOT NULL DEFAULT 0"), ("login_blocked_until", "TEXT NOT NULL DEFAULT ''"), ("login_block_message_id", "INTEGER"), ("login_block_chat_id", "TEXT NOT NULL DEFAULT ''")):
            if name not in user_cols:
                db.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
        if "profile_image" not in user_cols:
            db.execute("ALTER TABLE users ADD COLUMN profile_image TEXT NOT NULL DEFAULT ''")
        group_cols = {r[1] for r in db.execute("PRAGMA table_info(groups)")}
        if "color" not in group_cols:
            db.execute("ALTER TABLE groups ADD COLUMN color TEXT NOT NULL DEFAULT ''")
        account_group_cols = {r[1] for r in db.execute("PRAGMA table_info(account_groups)")}
        if "color" not in account_group_cols:
            db.execute("ALTER TABLE account_groups ADD COLUMN color TEXT NOT NULL DEFAULT ''")
        if "sort_order" not in group_cols:
            db.execute("ALTER TABLE groups ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0")
            db.execute("UPDATE groups SET sort_order=id")
        db.execute("INSERT OR IGNORE INTO groups(name,description,created_at,sort_order) VALUES('Default','Default group for IP records',?,0)", (now(),))
        default_group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
        db.execute("UPDATE ips SET group_id=? WHERE group_id IS NULL", (default_group_id,))
        db.execute("INSERT OR IGNORE INTO account_groups(name,description,created_at,sort_order) VALUES('Default','Default group for saved accounts',?,0)", (now(),))
        default_account_group_id = db.execute("SELECT id FROM account_groups WHERE name='Default'").fetchone()["id"]
        db.execute("UPDATE accounts SET group_id=? WHERE group_id IS NULL", (default_account_group_id,))
        db.execute("INSERT OR IGNORE INTO note_groups(name,description,color,created_at,sort_order) VALUES('Default','Default group for saved notes','#65758b',?,0)", (now(),))
        default_note_group_id = db.execute("SELECT id FROM note_groups WHERE name='Default'").fetchone()["id"]
        db.execute("UPDATE notes SET group_id=? WHERE group_id IS NULL", (default_note_group_id,))
        db.execute("CREATE INDEX IF NOT EXISTS idx_accounts_name ON accounts(name)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_accounts_group_id ON accounts(group_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_notes_group_id ON notes(group_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_notes_title ON notes(title)")
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
    raw_ip = (request.remote_addr or "unknown").strip()
    try:
        address = ip_address(raw_ip)
        return str(getattr(address, "ipv4_mapped", None) or address)
    except ValueError:
        return raw_ip[:64]


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


def recovery_code_is_valid(user_id, submitted):
    """Check a recovery code without consuming it while login approval is pending."""
    normalized = re.sub(r"[^A-Za-z0-9]", "", str(submitted or "")).upper()
    if not normalized or len(normalized) > 40:
        return False
    candidate = recovery_code_hash(user_id, normalized)
    with connect_db() as db:
        rows = db.execute("SELECT code_hash FROM user_recovery_codes WHERE user_id=?", (user_id,)).fetchall()
    return any(hmac.compare_digest(row["code_hash"], candidate) for row in rows)


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


def telegram_bind_login_code_message(code, chat_id, message_id):
    """Associate the short-lived code with its Telegram message so it can be replaced after use."""
    try:
        normalized_message_id = int(message_id)
    except (TypeError, ValueError):
        return False
    with connect_db() as db:
        row = db.execute("SELECT id,user_id,code_hash FROM telegram_login_codes ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return False
        expected_hash = telegram_login_code_hash(row["user_id"], code)
        if not hmac.compare_digest(row["code_hash"], expected_hash):
            return False
        db.execute("UPDATE telegram_login_codes SET chat_id=?,message_id=? WHERE id=?",
                   (str(chat_id)[:80], normalized_message_id, row["id"]))
    return True


def verify_telegram_login_code(user_id, submitted):
    """Validate a Telegram fallback code without consuming it before admin approval."""
    if not re.fullmatch(r"\d{6}", str(submitted or "").strip()):
        return None
    with connect_db() as db:
        row = db.execute("SELECT id,code_hash,expires_at,chat_id,message_id FROM telegram_login_codes WHERE user_id=?", (user_id,)).fetchone()
        if not row or row["expires_at"] < now():
            if row:
                db.execute("DELETE FROM telegram_login_codes WHERE id=?", (row["id"],))
            return None
        candidate = telegram_login_code_hash(user_id, submitted)
        if not hmac.compare_digest(row["code_hash"], candidate):
            return None
        return {"chat_id": row["chat_id"], "message_id": row["message_id"]}


def consume_telegram_login_code(user_id, submitted, allow_expired=False):
    """Atomically consume a short-lived code and return its source message metadata."""
    if not re.fullmatch(r"\d{6}", str(submitted or "").strip()):
        return None
    with connect_db() as db:
        row = db.execute("SELECT id,code_hash,expires_at,chat_id,message_id FROM telegram_login_codes WHERE user_id=?", (user_id,)).fetchone()
        if not row or (not allow_expired and row["expires_at"] < now()):
            if row and not allow_expired:
                db.execute("DELETE FROM telegram_login_codes WHERE id=?", (row["id"],))
            return None
        candidate = telegram_login_code_hash(user_id, submitted)
        if not hmac.compare_digest(row["code_hash"], candidate):
            return None
        message = {"chat_id": row["chat_id"], "message_id": row["message_id"]}
        db.execute("DELETE FROM telegram_login_codes WHERE id=?", (row["id"],))
    return message


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


def send_telegram_security_alert(message, reply_markup=None, delete_after=120):
    """Send a temporary security notice; never include passwords or reusable TOTP codes."""
    token = secure_setting("telegram_bot_token_enc")
    chat_id = secure_setting("telegram_chat_id_enc")
    if not token or not chat_id:
        return False
    try:
        payload = {"chat_id": chat_id, "text": str(message)[:3900], "disable_web_page_preview": True}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        req = Request(f"https://api.telegram.org/bot{token}/sendMessage", data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req, timeout=5) as response:
            result = json.loads(response.read(65536).decode("utf-8"))
        message_id = (result.get("result") or {}).get("message_id") if isinstance(result, dict) else None
        if result.get("ok") and message_id and delete_after:
            telegram_schedule_delete(chat_id, message_id, delete_after)
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


def telegram_edit_persistent_message(chat_id, message_id, text, reply_markup=None, parse_mode=None):
    """Edit an existing message and keep it permanently by cancelling its expiry timer."""
    try:
        payload = {"chat_id": str(chat_id), "message_id": int(message_id), "text": str(text)[:3900],
                   "disable_web_page_preview": True}
    except (TypeError, ValueError):
        return {}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    if parse_mode:
        payload["parse_mode"] = parse_mode
    result = telegram_api("editMessageText", payload)
    if result:
        telegram_cancel_scheduled_delete(chat_id, message_id)
    return result


def login_block_remaining(blocked_until):
    try:
        expiry = datetime.fromisoformat(str(blocked_until).replace("Z", "+00:00"))
        seconds = max(0, int((expiry - datetime.now(timezone.utc)).total_seconds() + 0.999))
    except (TypeError, ValueError):
        seconds = 0
    return seconds


def login_block_countdown_text(username, seconds):
    minutes, remainder = divmod(max(0, int(seconds)), 60)
    return (f"🔒 مسدودسازی ورود برای حساب: {username}\n\n"
            f"⏳ زمان باقی‌مانده: {minutes:02d}:{remainder:02d}\n"
            "با پایان زمان، امکان تلاش مجدد به‌صورت خودکار فعال می‌شود.")


_LOGIN_BLOCK_WORKER = None
_LOGIN_BLOCK_WORKER_LOCK = threading.Lock()
_LOGIN_BLOCK_WORKER_WAKE = threading.Event()
_LOGIN_BLOCK_WORKER_OWNER = secrets.token_hex(16)


def _claim_login_block_worker_lease():
    """Ensure only one WSGI process edits countdown messages at a time."""
    lease_until = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat(timespec="seconds")
    lease_value = f"{_LOGIN_BLOCK_WORKER_OWNER}|{lease_until}"
    with connect_db() as db:
        db.execute("INSERT OR IGNORE INTO app_settings(key,value) VALUES('telegram_login_block_worker_lease','')")
        claimed = db.execute(
            "UPDATE app_settings SET value=? WHERE key='telegram_login_block_worker_lease' "
            "AND (value='' OR substr(value,instr(value,'|')+1)<=? "
            "OR substr(value,1,instr(value,'|')-1)=?)",
            (lease_value, now(), _LOGIN_BLOCK_WORKER_OWNER),
        )
    return claimed.rowcount == 1


def _login_block_countdown_worker():
    """One process-local worker refreshes every active Telegram lock, including after restart."""
    while True:
        try:
            if not _claim_login_block_worker_lease():
                _LOGIN_BLOCK_WORKER_WAKE.wait(2)
                _LOGIN_BLOCK_WORKER_WAKE.clear()
                continue
            with connect_db() as db:
                rows = db.execute(
                    "SELECT id,username,login_blocked_until,login_block_message_id,login_block_chat_id "
                    "FROM users WHERE login_block_message_id IS NOT NULL AND login_block_chat_id!=''"
                ).fetchall()
            for row in rows:
                user_id = int(row["id"])
                message_id = int(row["login_block_message_id"] or 0)
                chat_id = str(row["login_block_chat_id"] or "")
                if not message_id or not chat_id:
                    continue
                remaining = login_block_remaining(row["login_blocked_until"])
                if remaining <= 0:
                    with connect_db() as db:
                        updated = db.execute(
                            "UPDATE users SET login_blocked_until='',login_block_message_id=NULL,login_block_chat_id='' "
                            "WHERE id=? AND login_block_message_id=? AND login_block_chat_id=? "
                            "AND login_blocked_until=?",
                            (user_id, message_id, chat_id, str(row["login_blocked_until"] or "")),
                        )
                    if updated.rowcount == 1:
                        telegram_edit_persistent_message(
                            chat_id, message_id,
                            f"✅ زمان مسدودسازی حساب {row['username']} به پایان رسید.\nامکان ورود مجدد فعال است.",
                            reply_markup={"inline_keyboard": []},
                        )
                    continue
                # Re-read the authoritative row immediately before editing, avoiding stale edits
                # after a manual release or a newer rejection replaced this message.
                with connect_db() as db:
                    current = db.execute(
                        "SELECT login_blocked_until,login_block_message_id,login_block_chat_id FROM users WHERE id=?",
                        (user_id,),
                    ).fetchone()
                if (not current or str(current["login_block_chat_id"] or "") != chat_id
                        or int(current["login_block_message_id"] or 0) != message_id
                        or str(current["login_blocked_until"] or "") != str(row["login_blocked_until"] or "")):
                    continue
                telegram_api("editMessageText", {
                    "chat_id": chat_id, "message_id": message_id,
                    "text": login_block_countdown_text(row["username"], remaining),
                    "reply_markup": {"inline_keyboard": [[{
                        "text": "🔓 رفع فوری مسدودی", "callback_data": f"login_unblock:{user_id}",
                    }]]},
                    "disable_web_page_preview": True,
                })
            with connect_db() as db:
                security_blocks = db.execute(
                    "SELECT block_id,username,blocked_until,telegram_message_id,telegram_chat_id "
                    "FROM login_security_blocks WHERE telegram_message_id IS NOT NULL AND telegram_chat_id!=''"
                ).fetchall()
            for block in security_blocks:
                if login_block_remaining(block["blocked_until"]) > 0:
                    continue
                with connect_db() as db:
                    expired = db.execute(
                        "UPDATE login_security_blocks SET blocked_until='',telegram_message_id=NULL,telegram_chat_id='' "
                        "WHERE block_id=? AND telegram_message_id=? AND telegram_chat_id=? AND blocked_until=?",
                        (block["block_id"], block["telegram_message_id"], block["telegram_chat_id"], block["blocked_until"]),
                    )
                if expired.rowcount == 1:
                    telegram_edit_persistent_message(
                        block["telegram_chat_id"], block["telegram_message_id"],
                        f"✅ مدت مسدودی {block['username'] or 'این مرورگر'} به پایان رسید.\nامکان ورود مجدد فعال است.",
                        reply_markup={"inline_keyboard": []},
                    )
        except Exception:
            app.logger.exception("Telegram login-block countdown worker failed")
        _LOGIN_BLOCK_WORKER_WAKE.wait(2)
        _LOGIN_BLOCK_WORKER_WAKE.clear()


def _ensure_login_block_countdown_worker():
    global _LOGIN_BLOCK_WORKER
    with _LOGIN_BLOCK_WORKER_LOCK:
        if _LOGIN_BLOCK_WORKER is None or not _LOGIN_BLOCK_WORKER.is_alive():
            _LOGIN_BLOCK_WORKER = threading.Thread(
                target=_login_block_countdown_worker, name="telegram-login-block-countdowns", daemon=True,
            )
            _LOGIN_BLOCK_WORKER.start()
    _LOGIN_BLOCK_WORKER_WAKE.set()
    return _LOGIN_BLOCK_WORKER


def telegram_start_login_block_countdown(user_id, username, chat_id, message_id):
    """Wake the shared countdown worker; it also recovers persisted timers at process startup."""
    return _ensure_login_block_countdown_worker()


def telegram_send_login_block_countdown(user_id, username, chat_id, blocked_until):
    seconds = login_block_remaining(blocked_until)
    markup = {"inline_keyboard": [[{
        "text": "🔓 رفع فوری مسدودی", "callback_data": f"login_unblock:{int(user_id)}",
    }]]}
    sent = telegram_send(chat_id, login_block_countdown_text(username, seconds), markup,
                         delete_after=0)
    message_id = (sent.get("result") or {}).get("message_id") if isinstance(sent, dict) else None
    if not message_id:
        return False
    with connect_db() as db:
        db.execute("UPDATE users SET login_block_message_id=?,login_block_chat_id=? WHERE id=?",
                   (int(message_id), str(chat_id), int(user_id)))
    telegram_start_login_block_countdown(user_id, username, chat_id, message_id)
    return True


def handle_login_unblock_callback(callback, configured_chat_id):
    message = callback.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = str(chat.get("id", ""))
    sender_id = str((callback.get("from") or {}).get("id", ""))
    try:
        match = re.fullmatch(r"login_unblock:(\d+)", str(callback.get("data") or ""))
        if not match:
            return False
        user_id = int(match.group(1))
        message_id = int(message.get("message_id") or 0)
    except (IndexError, TypeError, ValueError):
        return False
    if chat_id != str(configured_chat_id):
        return False
    if chat.get("type") == "private":
        if not sender_id or sender_id != chat_id:
            return False
    else:
        configured_admin = secure_setting("telegram_admin_user_id_enc")
        if not configured_admin or sender_id != str(configured_admin):
            return False
    with connect_db() as db:
        row = db.execute("SELECT username,login_blocked_until,login_block_message_id,login_block_chat_id FROM users WHERE id=?",
                         (user_id,)).fetchone()
        if (not row or str(row["login_block_chat_id"] or "") != chat_id
                or int(row["login_block_message_id"] or 0) != message_id
                or login_block_remaining(row["login_blocked_until"]) <= 0):
            return False
        updated = db.execute(
            "UPDATE users SET login_blocked_until='',login_block_message_id=NULL,login_block_chat_id='' "
            "WHERE id=? AND login_block_message_id=? AND login_block_chat_id=? AND login_blocked_until=?",
            (user_id, message_id, chat_id, row["login_blocked_until"]),
        )
        if updated.rowcount != 1:
            return False
        username = str(row["username"])
    telegram_edit_persistent_message(
        chat_id, message_id,
        f"✅ مسدودی حساب {username} به‌صورت فوری برداشته شد.\nامکان ورود مجدد فعال است.",
        reply_markup={"inline_keyboard": []},
    )
    return True


# Recover any persisted countdown messages when this application process starts.
_ensure_login_block_countdown_worker()


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



def telegram_browse_account_groups(chat_id, message_id):
    with connect_db() as db:
        groups = db.execute("SELECT id,name FROM account_groups ORDER BY sort_order,id").fetchall()
    keyboard = [[{"text": str(group["name"])[:60], "callback_data": f"account_browse_group:{group['id']}"}]
                for group in groups]
    keyboard.extend([
        [{"text": "➕ Add account", "callback_data": "account_add"},
         {"text": "🔎 Search accounts", "callback_data": "account_search"}],
        [{"text": "⬅️ Menu", "callback_data": "menu"}],
    ])
    telegram_set_state({"mode": "browse_account_groups"})
    text = "Account Vault — choose an account group:" if groups else "No account groups are available yet."
    telegram_replace_message(chat_id, message_id, text, {"inline_keyboard": keyboard})


def telegram_browse_account_group(chat_id, message_id, group_id):
    with connect_db() as db:
        group = db.execute("SELECT id,name FROM account_groups WHERE id=?", (group_id,)).fetchone()
        if not group:
            telegram_browse_account_groups(chat_id, message_id)
            return
        rows = db.execute(
            "SELECT id,name,username,email FROM accounts WHERE group_id=? ORDER BY name COLLATE NOCASE,id",
            (group_id,),
        ).fetchall()
    keyboard = []
    for row in rows:
        label = str(row["name"] or "Unnamed account")
        if row["username"]:
            label += f" · {row['username']}"
        keyboard.append([{"text": label[:60], "callback_data": f"account_browse_item:{group_id}:{row['id']}"}])
    keyboard.extend([
        [{"text": "➕ Add account", "callback_data": "account_add"}],
        [{"text": "⬅️ Account groups", "callback_data": "account_groups"},
         {"text": "⌂ Menu", "callback_data": "menu"}],
    ])
    telegram_set_state({"mode": "browse_accounts", "group_id": int(group["id"]), "group_name": group["name"]})
    text = f"Account group: {group['name']}\nChoose an account:" if rows else f"Account group: {group['name']}\nNo accounts in this group yet."
    telegram_replace_message(chat_id, message_id, text, {"inline_keyboard": keyboard})


def telegram_show_account(chat_id, message_id, account_id, source="browse", search_query=""):
    with connect_db() as db:
        row = db.execute(
            "SELECT accounts.*, account_groups.name AS group_name FROM accounts "
            "LEFT JOIN account_groups ON account_groups.id=accounts.group_id WHERE accounts.id=?",
            (account_id,),
        ).fetchone()
    if not row:
        telegram_replace_message(
            chat_id, message_id, "That account no longer exists.",
            {"inline_keyboard": [[{"text": "⬅️ Account groups", "callback_data": "account_groups"},
                                  {"text": "⌂ Menu", "callback_data": "menu"}]]},
        )
        telegram_set_state({})
        return
    try:
        password = vault.decrypt((row["password_enc"] or "").encode("ascii")).decode("utf-8") if row["password_enc"] else "-"
    except (InvalidToken, ValueError, TypeError, UnicodeDecodeError):
        password = "-"
    detail = (
        f"📌 Name: {html.escape(str(row['name'] or '-'))}\n"
        f"👤 Username: {telegram_code(row['username'])}\n"
        f"✉️ Email: {telegram_code(row['email'])}\n"
        f"🔑 Password: {telegram_code(password)}\n"
        f"📁 Account group: {html.escape(str(row['group_name'] or 'Default'))}\n"
        f"⏰ Last updated: {html.escape(str((row['updated_at'] or '-')[:19]))}"
    )
    group_id = row["group_id"]
    if source == "search":
        back_button = {"text": "⬅️ Search results", "callback_data": "account_search_back"}
    else:
        back_button = {"text": "⬅️ Group accounts", "callback_data": f"account_browse_group:{group_id}"}
    keyboard = [
        [{"text": "✏️ Edit account", "callback_data": f"account_edit:{row['id']}"},
         {"text": "🗑 Delete account", "callback_data": f"account_delete:{row['id']}"}],
        [back_button, {"text": "⌂ Menu", "callback_data": "menu"}],
    ]
    telegram_set_state({
        "mode": "account_detail", "account_id": int(row["id"]), "group_id": group_id,
        "source": source, "search_query": search_query[:100],
    })
    telegram_replace_message(chat_id, message_id, detail, {"inline_keyboard": keyboard}, parse_mode="HTML")


def telegram_search_accounts(chat_id, message_id, term, replace_message=False):
    query = str(term or "").strip()[:100]
    if not query:
        telegram_set_state({"mode": "account_search", "step": "query"})
        telegram_send(chat_id, "Please send an account name, username, or email to search.")
        return
    like = f"%{query}%"
    with connect_db() as db:
        rows = db.execute(
            "SELECT id,name,username,email FROM accounts "
            "WHERE name LIKE ? OR username LIKE ? OR email LIKE ? "
            "ORDER BY name COLLATE NOCASE,id LIMIT 10",
            (like, like, like),
        ).fetchall()
    if not rows:
        telegram_set_state({"mode": "account_search", "step": "query"})
        text = "No account matched that search. Send another name, username, or email, or use /menu to cancel."
        keyboard = {"inline_keyboard": [[{"text": "⬅️ Menu", "callback_data": "menu"}]]}
        if replace_message and message_id:
            telegram_replace_message(chat_id, message_id, text, keyboard)
        else:
            telegram_send(chat_id, text, keyboard)
        return
    ids = [int(row["id"]) for row in rows]
    keyboard = []
    for row in rows:
        label = str(row["name"] or "Unnamed account")
        if row["username"]:
            label += f" · {row['username']}"
        keyboard.append([{"text": label[:60], "callback_data": f"account_search_item:{row['id']}"}])
    keyboard.append([{"text": "⬅️ Menu", "callback_data": "menu"}])
    telegram_set_state({"mode": "account_search_results", "query": query, "account_ids": ids})
    text = f"Account search results for “{query}” — choose a record:"
    if replace_message and message_id:
        telegram_replace_message(chat_id, message_id, text, {"inline_keyboard": keyboard})
    else:
        telegram_send(chat_id, text, {"inline_keyboard": keyboard})


def telegram_save_account_edit(chat_id, message_id, selected_group_id=None):
    state = telegram_get_state()
    if state.get("mode") != "account_edit" or state.get("step") != "group":
        return
    try:
        account_id = int(state.get("account_id"))
    except (TypeError, ValueError):
        telegram_set_state({})
        telegram_send(chat_id, "The edit session expired. Open the account again.")
        return
    data = state.get("data") or {}
    password_action = data.get("password_action", "keep")
    form_data = {
        "name": data.get("name", ""),
        "username": data.get("username", ""),
        "email": data.get("email", ""),
        "password": data.get("password", "") if password_action == "set" else "",
        "group_id": str(selected_group_id if selected_group_id is not None else data.get("group_id", "")),
    }
    clean, error = validate_account(MultiDict(form_data))
    if error:
        telegram_set_state(state)
        telegram_send(chat_id, f"Invalid account details: {error}\nPlease run Edit account again.")
        return
    with connect_db() as db:
        current = db.execute("SELECT id,name,password_enc FROM accounts WHERE id=?", (account_id,)).fetchone()
        if not current:
            telegram_set_state({})
            telegram_send(chat_id, "That account was deleted before the edit could be saved.")
            return
        if password_action == "set":
            encrypted_password = clean["password_enc"] or ""
        elif password_action == "clear":
            encrypted_password = ""
        else:
            encrypted_password = current["password_enc"] or ""
        db.execute(
            "UPDATE accounts SET name=?,username=?,email=?,password_enc=?,group_id=?,updated_at=? WHERE id=?",
            (clean["name"], clean["username"], clean["email"], encrypted_password,
             clean["group_id"], now(), account_id),
        )
    audit("account_updated", f"id={account_id}; name={clean['name']}; source=telegram-bot")
    telegram_set_state({})
    telegram_replace_message(
        chat_id, message_id,
        f"✅ Account updated.\n📌 {html.escape(str(clean['name']))}\nAccount ID: {account_id}",
        {"inline_keyboard": [[{"text": "⬅️ Account groups", "callback_data": "account_groups"},
                              {"text": "⌂ Menu", "callback_data": "menu"}]]},
        parse_mode="HTML",
    )


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
            {"text": "🔎 Search IPs", "callback_data": "ip_search"},
        ],
        [{"text": "📂 IP groups", "callback_data": "ip_groups"}],
        [
            {"text": "➕ Add account", "callback_data": "account_add"},
            {"text": "🔎 Search accounts", "callback_data": "account_search"},
        ],
        [{"text": "🗂 Account groups", "callback_data": "account_groups"}],
        [{"text": "🔐 2FA code", "callback_data": "telegram_2fa_code"}],
    ]}
    if message_id:
        telegram_replace_message(chat_id, message_id, "IP Management — choose a section:", markup)
    else:
        telegram_send(chat_id, "IP Management — choose a section:", markup)


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
        action = callback.get("data", "")
        if action.startswith("login_approval:"):
            telegram_api("answerCallbackQuery", {"callback_query_id": callback.get("id", "")})
            handle_login_approval_callback(callback, configured_chat)
        elif action.startswith("login_unblock_group:"):
            released = handle_login_security_unblock_callback(callback, configured_chat)
            telegram_api("answerCallbackQuery", {
                "callback_query_id": callback.get("id", ""),
                "text": "مسدودی حساب، IP و مرورگر برداشته شد." if released else "این دکمه نامعتبر است یا مسدودی قبلاً پایان یافته است.",
                "show_alert": not released,
            })
        elif action.startswith("login_unblock:"):
            released = handle_login_unblock_callback(callback, configured_chat)
            telegram_api("answerCallbackQuery", {
                "callback_query_id": callback.get("id", ""),
                "text": "مسدودی حساب برداشته شد." if released else "این دکمه نامعتبر است یا مسدودی قبلاً پایان یافته است.",
                "show_alert": not released,
            })
        elif action == "ack_telegram_login":
            telegram_api("answerCallbackQuery", {"callback_query_id": callback.get("id", "")})
            # Legacy audit callbacks are intentionally inert; audit messages never open the bot menu.
            return
        else:
            telegram_api("answerCallbackQuery", {"callback_query_id": callback.get("id", "")})
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
            sent = telegram_send(chat_id, f"Login code for IP Management:\n<code>{code}</code>", parse_mode="HTML", delete_after=0)
            sent_message_id = (sent.get("result") or {}).get("message_id") if isinstance(sent, dict) else None
            if sent_message_id:
                telegram_bind_login_code_message(code, chat_id, sent_message_id)
        elif action == "account_groups":
            telegram_browse_account_groups(chat_id, message.get("message_id"))
        elif action.startswith("account_browse_group:"):
            try:
                selected_group_id = int(action.split(":", 1)[1])
            except (TypeError, ValueError):
                telegram_browse_account_groups(chat_id, message.get("message_id"))
                return
            telegram_browse_account_group(chat_id, message.get("message_id"), selected_group_id)
        elif action.startswith("account_browse_item:"):
            state = telegram_get_state()
            try:
                _, selected_group_id, selected_account_id = action.split(":", 2)
                selected_group_id, selected_account_id = int(selected_group_id), int(selected_account_id)
            except (TypeError, ValueError):
                telegram_browse_account_groups(chat_id, message.get("message_id"))
                return
            if state.get("mode") != "browse_accounts" or str(state.get("group_id")) != str(selected_group_id):
                telegram_browse_account_groups(chat_id, message.get("message_id"))
                return
            telegram_show_account(chat_id, message.get("message_id"), selected_account_id, source="browse")
        elif action.startswith("account_search_item:"):
            state = telegram_get_state()
            try:
                selected_account_id = int(action.split(":", 1)[1])
            except (TypeError, ValueError):
                telegram_menu(chat_id, message.get("message_id"))
                return
            if state.get("mode") != "account_search_results" or selected_account_id not in state.get("account_ids", []):
                telegram_menu(chat_id, message.get("message_id"))
                return
            telegram_show_account(
                chat_id, message.get("message_id"), selected_account_id,
                source="search", search_query=state.get("query", ""),
            )
        elif action == "account_search_back":
            state = telegram_get_state()
            if state.get("mode") != "account_detail" or state.get("source") != "search":
                telegram_menu(chat_id, message.get("message_id"))
                return
            telegram_search_accounts(chat_id, message.get("message_id"), state.get("search_query", ""), replace_message=True)
        elif action == "account_add":
            telegram_set_state({"mode": "account_add", "step": "name", "data": {}})
            telegram_send(chat_id, "Account Vault — Step 1 of 5: enter the account name (required):")
        elif action == "account_search":
            telegram_set_state({"mode": "account_search", "step": "query"})
            telegram_send(chat_id, "Send an account name, username, or email to search:")
        elif action.startswith("account_edit:"):
            state = telegram_get_state()
            try:
                selected_account_id = int(action.split(":", 1)[1])
            except (TypeError, ValueError):
                return
            if state.get("mode") != "account_detail" or int(state.get("account_id", 0)) != selected_account_id:
                return
            with connect_db() as db:
                row = db.execute(
                    "SELECT accounts.*, account_groups.name AS group_name FROM accounts "
                    "LEFT JOIN account_groups ON account_groups.id=accounts.group_id WHERE accounts.id=?",
                    (selected_account_id,),
                ).fetchone()
            if not row:
                telegram_set_state({})
                telegram_send(chat_id, "That account no longer exists.")
                return
            data = {
                "name": row["name"], "username": row["username"], "email": row["email"],
                "group_id": str(row["group_id"] or ""), "group_name": row["group_name"] or "Default",
                "password_action": "keep", "source": state.get("source", "browse"),
                "search_query": state.get("search_query", ""),
            }
            telegram_set_state({"mode": "account_edit", "step": "name", "account_id": selected_account_id, "data": data})
            telegram_send(chat_id, "Edit account — send a new name, or - to keep the current name:")
        elif action.startswith("account_delete:"):
            state = telegram_get_state()
            try:
                selected_account_id = int(action.split(":", 1)[1])
            except (TypeError, ValueError):
                return
            if state.get("mode") != "account_detail" or int(state.get("account_id", 0)) != selected_account_id:
                return
            with connect_db() as db:
                row = db.execute("SELECT name FROM accounts WHERE id=?", (selected_account_id,)).fetchone()
            if not row:
                telegram_set_state({})
                telegram_send(chat_id, "That account no longer exists.")
                return
            telegram_set_state({
                "mode": "account_delete_confirm", "account_id": selected_account_id,
                "group_id": state.get("group_id"), "source": state.get("source", "browse"),
                "search_query": state.get("search_query", ""), "name": row["name"],
            })
            telegram_replace_message(
                chat_id, message.get("message_id"),
                f"Delete account \"{html.escape(str(row['name']))}\"? This cannot be undone.",
                {"inline_keyboard": [
                    [{"text": "🗑 Confirm delete", "callback_data": f"account_delete_confirm:{selected_account_id}"}],
                    [{"text": "Cancel", "callback_data": "account_delete_cancel"}],
                ]},
                parse_mode="HTML",
            )
        elif action.startswith("account_delete_confirm:"):
            state = telegram_get_state()
            try:
                selected_account_id = int(action.split(":", 1)[1])
            except (TypeError, ValueError):
                return
            if state.get("mode") != "account_delete_confirm" or int(state.get("account_id", 0)) != selected_account_id:
                return
            with connect_db() as db:
                row = db.execute("SELECT name FROM accounts WHERE id=?", (selected_account_id,)).fetchone()
                if row:
                    db.execute("DELETE FROM accounts WHERE id=?", (selected_account_id,))
            telegram_set_state({})
            if row:
                audit("account_deleted", f"id={selected_account_id}; name={row['name']}; source=telegram-bot")
                telegram_replace_message(
                    chat_id, message.get("message_id"), f"✅ Account deleted: {html.escape(str(row['name']))}",
                    {"inline_keyboard": [[{"text": "🗂 Account groups", "callback_data": "account_groups"},
                                          {"text": "⌂ Menu", "callback_data": "menu"}]]},
                    parse_mode="HTML",
                )
            else:
                telegram_replace_message(chat_id, message.get("message_id"), "That account was already deleted.",
                                         {"inline_keyboard": [[{"text": "⌂ Menu", "callback_data": "menu"}]]})
        elif action == "account_delete_cancel":
            state = telegram_get_state()
            if state.get("mode") != "account_delete_confirm":
                return
            telegram_show_account(
                chat_id, message.get("message_id"), int(state.get("account_id")),
                source=state.get("source", "browse"), search_query=state.get("search_query", ""),
            )
        elif action.startswith("account_edit_group:"):
            state = telegram_get_state()
            try:
                selected_group_id = int(action.split(":", 1)[1])
            except (TypeError, ValueError):
                return
            if state.get("mode") != "account_edit" or state.get("step") != "group":
                return
            telegram_save_account_edit(chat_id, message.get("message_id"), selected_group_id)
        elif action == "account_edit_keep_group":
            state = telegram_get_state()
            if state.get("mode") != "account_edit" or state.get("step") != "group":
                return
            try:
                selected_group_id = int(state.get("data", {}).get("group_id"))
            except (TypeError, ValueError):
                selected_group_id = None
            telegram_save_account_edit(chat_id, message.get("message_id"), selected_group_id)
        elif action.startswith("account_group:"):
            state = telegram_get_state()
            if state.get("mode") != "account_add" or state.get("step") != "group":
                return
            try:
                selected_group_id = int(action.split(":", 1)[1])
            except (TypeError, ValueError):
                telegram_send(chat_id, "Invalid account group. Send /start to begin again.")
                telegram_set_state({})
                return
            with connect_db() as db:
                selected_group = db.execute("SELECT id,name FROM account_groups WHERE id=?", (selected_group_id,)).fetchone()
            if not selected_group:
                telegram_send(chat_id, "That account group no longer exists. Send /start to begin again.")
                telegram_set_state({})
                return
            data = state.get("data") or {}
            data["group_id"] = str(selected_group["id"])
            data["group_name"] = selected_group["name"]
            clean, error = validate_account(MultiDict(data))
            if error:
                telegram_set_state({})
                telegram_send(chat_id, f"Invalid account details: {error}\nSend /start to begin again.")
                return
            with connect_db() as db:
                cur = db.execute(
                    "INSERT INTO accounts(name,username,email,password_enc,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (clean["name"], clean["username"], clean["email"], clean["password_enc"] or "",
                     clean["group_id"], "telegram-bot", now(), now()),
                )
            telegram_set_state({})
            audit("account_created", f"id={cur.lastrowid}; name={clean['name']}; source=telegram-bot")
            telegram_send(
                chat_id,
                f"✅ Account saved.\n📌 {html.escape(str(clean['name']))}\n📁 Group: {html.escape(str(selected_group['name']))}\nRecord ID: {cur.lastrowid}",
                {"inline_keyboard": [[{"text": "🗂 Account groups", "callback_data": "account_groups"},
                                      {"text": "⌂ Menu", "callback_data": "menu"}]]},
                parse_mode="HTML",
            )
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
        sent = telegram_send(chat_id, f"Login code for IP Management:\n<code>{code}</code>", parse_mode="HTML", delete_after=0)
        sent_message_id = (sent.get("result") or {}).get("message_id") if isinstance(sent, dict) else None
        if sent_message_id:
            telegram_bind_login_code_message(code, chat_id, sent_message_id)
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
    if state.get("mode") == "account_search":
        if message.get("message_id"):
            telegram_delete_message(chat_id, message["message_id"])
        telegram_search_accounts(chat_id, None, text)
        return
    if state.get("mode") == "account_add":
        # Delete chat input best-effort; this flow may include account passwords.
        if message.get("message_id"):
            telegram_delete_message(chat_id, message["message_id"])
        step = state.get("step")
        data = state.get("data") or {}
        if step == "name":
            if not text:
                telegram_send(chat_id, "Account name is required. Please send a name:")
                return
            data["name"] = text[:120]
            state.update(step="username", data=data)
            telegram_set_state(state)
            telegram_send(chat_id, "Step 2 of 5 — send the username, or - to leave it blank:")
            return
        if step == "username":
            data["username"] = "" if text == "-" else text[:120]
            state.update(step="email", data=data)
            telegram_set_state(state)
            telegram_send(chat_id, "Step 3 of 5 — send the email, or - to leave it blank:")
            return
        if step == "email":
            data["email"] = "" if text == "-" else text[:254]
            state.update(step="password", data=data)
            telegram_set_state(state)
            telegram_send(chat_id, "Step 4 of 5 — send the password, or - to leave it blank:")
            return
        if step == "password":
            data["password"] = "" if text == "-" else text[:2000]
            with connect_db() as db:
                groups = db.execute("SELECT id,name FROM account_groups ORDER BY sort_order,id").fetchall()
            if not groups:
                telegram_set_state({})
                telegram_send(chat_id, "No account groups are available. Reopen Account Vault and try again.")
                return
            state.update(step="group", data=data)
            telegram_set_state(state)
            markup = {"inline_keyboard": [[
                {"text": str(group["name"])[:60], "callback_data": f"account_group:{group['id']}"}
            ] for group in groups]}
            markup["inline_keyboard"].append([{"text": "⬅️ Menu", "callback_data": "menu"}])
            telegram_send(chat_id, "Step 5 of 5 — choose an account group:", markup)
            return
        telegram_set_state({})
        telegram_send(chat_id, "The account setup session expired. Start again from Account Vault.")
        return
    if state.get("mode") == "account_edit":
        if message.get("message_id"):
            telegram_delete_message(chat_id, message["message_id"])
        step = state.get("step")
        data = state.get("data") or {}
        if step == "name":
            if text and text != "-":
                data["name"] = text[:120]
            if not data.get("name"):
                telegram_send(chat_id, "Account name is required. Send a name:")
                return
            state.update(step="username", data=data)
            telegram_set_state(state)
            telegram_send(chat_id, "Edit username — send a new value, - to keep it, or /clear to empty it:")
            return
        if step == "username":
            if text == "/clear":
                data["username"] = ""
            elif text != "-":
                data["username"] = text[:120]
            state.update(step="email", data=data)
            telegram_set_state(state)
            telegram_send(chat_id, "Edit email — send a new value, - to keep it, or /clear to empty it:")
            return
        if step == "email":
            if text == "/clear":
                data["email"] = ""
            elif text != "-":
                data["email"] = text[:254]
            state.update(step="password", data=data)
            telegram_set_state(state)
            telegram_send(chat_id, "Edit password — send a new password, - to keep it, or /clear to remove it:")
            return
        if step == "password":
            if text == "/clear":
                data["password_action"] = "clear"
                data.pop("password", None)
            elif text == "-":
                data["password_action"] = "keep"
                data.pop("password", None)
            else:
                data["password_action"] = "set"
                data["password"] = text[:2000]
            with connect_db() as db:
                groups = db.execute("SELECT id,name FROM account_groups ORDER BY sort_order,id").fetchall()
            if not groups:
                telegram_set_state({})
                telegram_send(chat_id, "No account groups are available. Reopen Account Vault and try again.")
                return
            state.update(step="group", data=data)
            telegram_set_state(state)
            keyboard = [[
                {"text": str(group["name"])[:55], "callback_data": f"account_edit_group:{group['id']}"}
            ] for group in groups]
            if data.get("group_id"):
                keyboard.insert(0, [{"text": f"✅ Keep current group: {str(data.get('group_name') or 'Default')[:35]}",
                                     "callback_data": "account_edit_keep_group"}])
            keyboard.append([{"text": "⬅️ Menu", "callback_data": "menu"}])
            telegram_send(chat_id, "Choose the account group to save the edit:", {"inline_keyboard": keyboard})
            return
        if step == "group":
            telegram_send(chat_id, "Choose an account group using the buttons above.")
            return
        telegram_set_state({})
        telegram_send(chat_id, "The edit session expired. Open the account again.")
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


def send_login_success_alert(username, remote_ip, telegram_code_used=False, telegram_code_value="",
                             telegram_code_message=None, user_agent=""):
    client_details = re.sub(r"[\r\n\t]+", " ", str(user_agent or "")).strip()[:350] or "Unknown"
    message = (
        "✅ Successful sign-in to IP Management.\n"
        f"💻 Host: {telegram_hostname()}\n"
        f"👤 Username: {safe_telegram_username(username)}\n"
        f"🛡 Account role: {'Superadmin' if telegram_code_used else 'Authenticated user'}\n"
        f"🌐 IP address: {remote_ip}\n"
        f"🧭 Browser / device: {client_details}\n"
        f"⏰ Time (Iran): {jalali_datetime(now())}"
    )
    if telegram_code_used:
        safe_code = re.sub(r"[^0-9]", "", str(telegram_code_value or ""))[:6]
        message += "\n🔐 Login method: Telegram one-time code."
        if safe_code:
            message += f"\n🔢 Code used: {safe_code}"
        message += "\n✅ The code was consumed by this sign-in and cannot be reused."
        if telegram_code_message:
            source_chat = telegram_code_message.get("chat_id")
            source_message_id = telegram_code_message.get("message_id")
            if source_chat and source_message_id:
                updated = telegram_edit_persistent_message(
                    source_chat, source_message_id, message,
                    reply_markup={"inline_keyboard": []},
                )
                if updated:
                    return True
                # Never leave a consumed login credential visible if Telegram rejects the edit.
                telegram_delete_message(source_chat, source_message_id)
        # Keep the audit notice even if Telegram no longer allows editing the original code message.
        return send_telegram_security_alert(message, delete_after=0)
    # Successful sign-ins are permanent audit records, never temporary bot notifications.
    return send_telegram_security_alert(message, delete_after=0)


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


def login_approval_token_hash(request_id, token):
    payload = f"login-approval:{int(request_id)}:{token}".encode("utf-8")
    return hmac.new(app.secret_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def login_approval_message(row, status="pending", login_method="", code_value=""):
    user_agent = re.sub(r"[\r\n\t]+", " ", str(row["user_agent"] or "")).strip()[:350] or "Unknown"
    message = (
        "🔐 IP Management — Login audit\n"
        f"💻 Host: {telegram_hostname()}\n"
        f"👤 Username: {safe_telegram_username(row['username'])}\n"
        f"🌐 IP address: {row['remote_ip']}\n"
        f"🧭 Browser / device: {user_agent}\n"
        f"⏰ Time (Iran): {jalali_datetime(row['created_at'])}"
    )
    if status == "pending":
        message += "\n\n⚠️ Correct username and password received. Allow this login?"
    elif status == "approved":
        message += "\n\n✅ Administrator approved this sign-in. Waiting for the user to complete any required second factor."
    elif status == "denied":
        message += "\n\n❌ Administrator rejected this sign-in. No session was created."
    elif status == "expired":
        message += "\n\n⌛ Approval request expired. No session was created."
    elif status == "canceled":
        message += "\n\n⚪ Sign-in request was canceled before authentication completed."
    elif status == "delivery_failed":
        message += "\n\n⚠️ Telegram approval could not be delivered. Sign-in was blocked."
    elif status == "success":
        message += f"\n\n✅ Login successful.\n🔑 Login method: {login_method or 'Administrator approval'}"
        safe_code = re.sub(r"[^0-9A-Za-z-]", "", str(code_value or ""))[:40]
        if safe_code:
            message += f"\n🔢 Code used: {safe_code}"
        message += "\n🧾 Permanent login audit record."
    return message[:3900]


def finish_login_approval_log(request_id, status, login_method="", code_value=""):
    with connect_db() as db:
        row = db.execute("SELECT * FROM login_approval_requests WHERE id=?", (request_id,)).fetchone()
        if not row:
            return False
        db.execute(
            "UPDATE login_approval_requests SET status=?,decided_at=?,login_method=? WHERE id=?",
            (status, now(), str(login_method or "")[:120], request_id),
        )
        saved = dict(row)
    if saved.get("telegram_chat_id") and saved.get("telegram_message_id"):
        result = telegram_edit_persistent_message(
            saved["telegram_chat_id"], saved["telegram_message_id"],
            login_approval_message(saved, status, login_method, code_value),
            reply_markup={"inline_keyboard": []},
        )
        if not result:
            telegram_api("editMessageReplyMarkup", {
                "chat_id": saved["telegram_chat_id"],
                "message_id": saved["telegram_message_id"],
                "reply_markup": {"inline_keyboard": []},
            })
        return bool(result)
    return False


def create_login_approval_request(user, remote_ip, user_agent=""):
    chat_id = secure_setting("telegram_chat_id_enc")
    if not secure_setting("telegram_bot_token_enc") or not chat_id:
        return None
    created_at = now()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds")
    token = secrets.token_urlsafe(12)
    clean_agent = re.sub(r"[\r\n\t]+", " ", str(user_agent or "")).strip()[:350]
    with connect_db() as db:
        cur = db.execute(
            "INSERT INTO login_approval_requests(user_id,username,remote_ip,user_agent,token_hash,status,created_at,expires_at,telegram_chat_id) "
            "VALUES(?,?,?,?,?,'pending',?,?,?)",
            (user["id"], user["username"], str(remote_ip or "unknown")[:64], clean_agent,
             "", created_at, expires_at, str(chat_id)[:80]),
        )
        request_id = cur.lastrowid
        db.execute("UPDATE login_approval_requests SET token_hash=? WHERE id=?",
                   (login_approval_token_hash(request_id, token), request_id))
        row = db.execute("SELECT * FROM login_approval_requests WHERE id=?", (request_id,)).fetchone()
    keyboard = {"inline_keyboard": [[
        {"text": "✅ تأیید ورود", "callback_data": f"login_approval:approve:{request_id}:{token}"},
        {"text": "❌ رد ورود", "callback_data": f"login_approval:deny:{request_id}:{token}"},
    ]]}
    sent = telegram_send(chat_id, login_approval_message(row), keyboard, delete_after=0)
    message_id = (sent.get("result") or {}).get("message_id") if isinstance(sent, dict) else None
    if not message_id:
        with connect_db() as db:
            db.execute("UPDATE login_approval_requests SET status='delivery_failed',decided_at=? WHERE id=?",
                       (now(), request_id))
        return None
    with connect_db() as db:
        db.execute("UPDATE login_approval_requests SET telegram_message_id=? WHERE id=?",
                   (int(message_id), request_id))
    return request_id


def handle_login_approval_callback(callback, configured_chat_id):
    match = re.fullmatch(
        r"login_approval:(approve|deny):(\d+):([A-Za-z0-9_-]{12,24})",
        str(callback.get("data") or ""),
    )
    if not match:
        return False
    decision, request_id, token = match.group(1), int(match.group(2)), match.group(3)
    message = callback.get("message") or {}
    message_chat = str((message.get("chat") or {}).get("id", ""))
    if message_chat != str(configured_chat_id):
        return False
    with connect_db() as db:
        row = db.execute(
            "SELECT * FROM login_approval_requests WHERE id=? AND telegram_chat_id=?",
            (request_id, message_chat),
        ).fetchone()
        if (not row or row["status"] != "pending"
                or int(row["telegram_message_id"] or 0) != int(message.get("message_id") or 0)
                or not hmac.compare_digest(row["token_hash"], login_approval_token_hash(request_id, token))):
            return False
        status = "expired" if row["expires_at"] <= now() else ("approved" if decision == "approve" else "denied")
        updated = db.execute(
            "UPDATE login_approval_requests SET status=?,decided_at=? WHERE id=? AND status='pending'",
            (status, now(), request_id),
        )
        if updated.rowcount != 1:
            return False
        if status == "denied":
            blocked_until = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(timespec="seconds")
            db.execute("UPDATE users SET login_blocked_until=?,login_block_message_id=NULL,login_block_chat_id='' WHERE id=?",
                       (blocked_until, row["user_id"]))
        saved = dict(row)
    edited = telegram_edit_persistent_message(
        message_chat, message.get("message_id"), login_approval_message(saved, status),
        reply_markup={"inline_keyboard": []},
    )
    if not edited:
        telegram_api("editMessageReplyMarkup", {
            "chat_id": message_chat, "message_id": message.get("message_id"),
            "reply_markup": {"inline_keyboard": []},
        })
    if status == "denied":
        telegram_send_login_block_countdown(saved["user_id"], saved["username"], message_chat, blocked_until)
    return True


def finalize_login_audit(approval_request_id, username, remote_ip, login_method,
                         code_value="", user_agent="", telegram_code_message=None):
    if approval_request_id:
        if "administrator approval" not in str(login_method or "").lower():
            login_method = f"{login_method} + Telegram administrator approval"
        result = finish_login_approval_log(approval_request_id, "success", login_method, code_value)
        if telegram_code_message:
            source_chat = telegram_code_message.get("chat_id")
            source_message_id = telegram_code_message.get("message_id")
            if source_chat and source_message_id:
                telegram_delete_message(source_chat, source_message_id)
        return result
    return send_login_success_alert(
        username, remote_ip, telegram_code_used=(login_method == "Telegram one-time code"),
        telegram_code_value=code_value, telegram_code_message=telegram_code_message,
        user_agent=user_agent,
    )


def continue_login_after_approval(user, approval_request_id, bypass_two_factor=False):
    if user_requires_two_factor(user):
        mode = two_factor_mode()
        if mode == "per_user" and not decrypt_authenticator_secret(user["totp_secret"]):
            session.clear()
            session["pending_2fa_user_id"] = user["id"]
            session["pending_2fa_secret"] = pyotp.random_base32()
            session["login_approval_id"] = approval_request_id
            session["csrf_token"] = secrets.token_urlsafe(32)
            security_event("login", user["username"], "password_ok_2fa_pending",
                           "Administrator approved password; authenticator enrollment is required")
            return redirect(url_for("setup_2fa"))
        if bypass_two_factor:
            clear_login_attempt_counters(user["username"])
            establish_login(user)
            session["two_factor_verified"] = True
            finalize_login_audit(
                approval_request_id, user["username"], client_ip(),
                "Administrator approval (2FA bypassed)",
                user_agent=request.headers.get("User-Agent", ""),
            )
            flash(f"Welcome back, {user['username']}!", "welcome")
            return redirect(safe_login_target())
        if remembered_two_factor(user["id"]):
            clear_login_attempt_counters(user["username"])
            establish_login(user)
            session["two_factor_verified"] = True
            finalize_login_audit(
                approval_request_id, user["username"], client_ip(),
                "Administrator approval + trusted 2FA device",
                user_agent=request.headers.get("User-Agent", ""),
            )
            flash(f"Welcome back, {user['username']}!", "welcome")
            return redirect(safe_login_target())
        secret = shared_two_factor_secret() if mode == "shared" else decrypt_authenticator_secret(user["totp_secret"])
        if not secret:
            finish_login_approval_log(approval_request_id, "canceled")
            flash("Two-factor authentication is not configured. Contact the super administrator.", "error")
            return redirect(url_for("login"))
        session.clear()
        session["pending_2fa_user_id"] = user["id"]
        session["login_approval_id"] = approval_request_id
        session["csrf_token"] = secrets.token_urlsafe(32)
        security_event("login", user["username"], "password_ok_2fa_pending",
                       "Administrator approved password; waiting for second factor")
        return render_template("login.html", stage="verify", login_user={
            "id": user["id"], "username": user["username"], "role": user["role"],
            "profile_image": user["profile_image"],
        })
    clear_login_attempt_counters(user["username"])
    establish_login(user)
    finalize_login_audit(
        approval_request_id, user["username"], client_ip(), "Administrator approval",
        user_agent=request.headers.get("User-Agent", ""),
    )
    flash(f"Welcome back, {user['username']}!", "welcome")
    return redirect(safe_login_target())


def login_approval_row_for_session():
    approval_id = session.get("pending_login_approval_id") or session.get("login_approval_id")
    if not approval_id:
        return None
    with connect_db() as db:
        return db.execute("SELECT * FROM login_approval_requests WHERE id=?", (approval_id,)).fetchone()


@app.get("/login/approval-status")
def login_approval_status():
    """Silent background status check; it never reloads or replaces the code page."""
    approval = login_approval_row_for_session()
    if not approval:
        return {"status": "missing"}, 404
    status = approval["status"]
    if status == "pending" and approval["expires_at"] <= now():
        finish_login_approval_log(approval["id"], "expired")
        status = "expired"
    return {"status": status}


@app.post("/login/approval-complete")
def complete_login_approval():
    """Create the authenticated session only after the administrator approved."""
    approval = login_approval_row_for_session()
    if not approval or approval["status"] != "approved":
        return {"ok": False, "status": approval["status"] if approval else "missing"}, 409
    with connect_db() as db:
        user = db.execute("SELECT * FROM users WHERE id=? AND enabled=1", (approval["user_id"],)).fetchone()
    if not user:
        finish_login_approval_log(approval["id"], "canceled")
        session.clear()
        return {"ok": False, "status": "disabled"}, 403

    if session.pop("pending_2fa_verified", False):
        method = session.pop("pending_2fa_method", "Authenticator app (TOTP)")
        encrypted_code = session.pop("pending_2fa_code_enc", "")
        remember_device = session.pop("pending_2fa_remember", False)
        telegram_code_message = session.pop("pending_2fa_telegram_message", None)
        try:
            used_code = vault.decrypt(encrypted_code.encode("ascii")).decode("utf-8") if encrypted_code else ""
        except (InvalidToken, ValueError, UnicodeDecodeError):
            used_code = ""
        if method == "One-time recovery code" and not consume_recovery_code(user["id"], used_code):
            finish_login_approval_log(approval["id"], "canceled")
            session.clear()
            return {"ok": False, "status": "verification_expired"}, 409
        if method == "Telegram one-time code":
            telegram_code_message = consume_telegram_login_code(user["id"], used_code, allow_expired=True)
            if not telegram_code_message:
                finish_login_approval_log(approval["id"], "canceled")
                session.clear()
                return {"ok": False, "status": "verification_expired"}, 409
        establish_login(user)
        session["two_factor_verified"] = True
        if method == "One-time recovery code":
            security_event("two_factor_recovery", user["username"], "success", "One-time offline recovery code consumed")
            audit("two_factor_recovery_code_used")
        elif method == "Telegram one-time code":
            security_event("two_factor_recovery", user["username"], "success", "Two-minute Telegram fallback code consumed")
            audit("telegram_login_recovery_code_used")
        finalize_login_audit(
            approval["id"], user["username"], client_ip(), method,
            code_value=used_code, user_agent=request.headers.get("User-Agent", ""),
            telegram_code_message=telegram_code_message,
        )
        flash(f"Welcome back, {user['username']}!", "welcome")
        response = jsonify(ok=True, redirect=safe_login_target())
        if remember_device:
            remember_two_factor_response(response, user["id"])
        return response

    response = continue_login_after_approval(user, approval["id"], bypass_two_factor=True)
    if response.status_code in (301, 302, 303, 307, 308):
        return {"ok": True, "redirect": response.location}
    # First-time authenticator enrollment intentionally remains mandatory.
    return {"ok": True, "redirect": url_for("setup_2fa")}


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
def identify_login_device():
    """Assign a random, persistent browser identifier; browsers cannot expose hardware IDs."""
    if request.path != "/login":
        return
    token = str(request.cookies.get("ipm_device_id") or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", token):
        token = secrets.token_urlsafe(32)
        request.environ["ipm.new_device_id"] = token
    request.environ["ipm.login_device_id"] = token


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
    # The UI deliberately emits validated, server-rendered style attributes for
    # per-group colors and responsive details. Keep scripts locked to self, but
    # explicitly allow style attributes (not inline style elements) so browsers
    # do not silently discard the selected group colors under this CSP.
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; style-src-elem 'self'; style-src-attr 'unsafe-inline'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    new_device_id = request.environ.get("ipm.new_device_id")
    if new_device_id:
        response.set_cookie(
            "ipm_device_id", new_device_id, max_age=365 * 24 * 60 * 60,
            httponly=True, secure=app.config.get("SESSION_COOKIE_SECURE", True), samesite="Lax", path="/",
        )
    return response


LOGIN_FAILURE_LIMIT = 3
LOGIN_FAILURE_WINDOW = timedelta(minutes=15)
LOGIN_SECURITY_BLOCK_DURATION = timedelta(minutes=15)


def login_device_id():
    token = str(request.environ.get("ipm.login_device_id") or request.cookies.get("ipm_device_id") or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", token):
        token = secrets.token_urlsafe(32)
        request.environ["ipm.login_device_id"] = token
        request.environ["ipm.new_device_id"] = token
    return token


def login_security_keys(username=""):
    """Return keyed hashes only; raw device IDs and usernames are never stored in lock tables."""
    values = {
        "ip": client_ip(),
        "device": login_device_id(),
    }
    if username:
        values["username"] = str(username).strip().casefold()[:80]
    return {
        scope: hmac.new(app.secret_key.encode(), f"login-lock:{scope}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()
        for scope, value in values.items() if value
    }


def active_login_security_block(username=""):
    keys = login_security_keys(username)
    clauses, params = [], [now()]
    for scope, key_hash in keys.items():
        column = {"ip": "ip_hash", "device": "device_hash", "username": "username_hash"}[scope]
        clauses.append(f"{column}=?")
        params.append(key_hash)
    if not clauses:
        return None
    with connect_db() as db:
        row = db.execute(
            "SELECT block_id,username,blocked_until FROM login_security_blocks "
            "WHERE blocked_until>? AND (" + " OR ".join(clauses) + ") ORDER BY blocked_until DESC LIMIT 1",
            params,
        ).fetchone()
    return dict(row) if row else None


def clear_login_attempt_counters(username=""):
    keys = login_security_keys(username)
    with connect_db() as db:
        for scope, key_hash in keys.items():
            db.execute("DELETE FROM login_attempt_counters WHERE scope=? AND key_hash=?", (scope, key_hash))


def send_login_security_block_alert(block_id, username, blocked_until):
    chat_id = secure_setting("telegram_chat_id_enc")
    if not chat_id:
        return False
    seconds = login_block_remaining(blocked_until)
    markup = {"inline_keyboard": [[{
        "text": "🔓 رفع مسدودی", "callback_data": f"login_unblock_group:{block_id}",
    }]]}
    label = username or "نام کاربری نامعتبر"
    sent = telegram_send(
        chat_id,
        f"🔒 مسدودسازی امنیتی ورود\n\n👤 حساب/نام واردشده: {label}\n"
        f"🌐 IP و شناسه مرورگر نیز مسدود شدند.\n⏳ مدت مسدودی: {max(1, (seconds + 59) // 60)} دقیقه\n"
        "پس از سه تلاش ناموفق رمز یا کد دومرحله‌ای، همه شناسه‌های مرتبط تا ۱۵ دقیقه قفل می‌شوند.",
        markup, delete_after=0,
    )
    message_id = (sent.get("result") or {}).get("message_id") if isinstance(sent, dict) else None
    if not message_id:
        return False
    with connect_db() as db:
        db.execute("UPDATE login_security_blocks SET telegram_message_id=?,telegram_chat_id=? WHERE block_id=?",
                   (int(message_id), str(chat_id), str(block_id)))
    return True


def register_login_failure(username="", detail="Invalid credentials"):
    """Atomically count failures and lock the account, source IP and browser token."""
    keys = login_security_keys(username)
    timestamp = datetime.now(timezone.utc)
    timestamp_text = timestamp.isoformat(timespec="seconds")
    cutoff = (timestamp - LOGIN_FAILURE_WINDOW).isoformat(timespec="seconds")
    counts = {}
    with connect_db() as db:
        # Serialize concurrent failures so parallel requests cannot race past the threshold
        # or create several independent lock groups for the same identifiers.
        db.execute("BEGIN IMMEDIATE")
        block_columns = {"ip": "ip_hash", "device": "device_hash", "username": "username_hash"}
        block_clauses = []
        block_params = [timestamp_text]
        for scope, key_hash in keys.items():
            column = block_columns[scope]
            block_clauses.append(f"{column}=?")
            block_params.append(key_hash)
        active = db.execute(
            "SELECT block_id,blocked_until FROM login_security_blocks WHERE blocked_until>? AND ("
            + " OR ".join(block_clauses) + ") ORDER BY blocked_until DESC LIMIT 1",
            block_params,
        ).fetchone()
        if active:
            return dict(active)
        for scope, key_hash in keys.items():
            row = db.execute("SELECT failed_attempts,window_started_at FROM login_attempt_counters WHERE scope=? AND key_hash=?",
                             (scope, key_hash)).fetchone()
            if not row or str(row["window_started_at"] or "") < cutoff:
                count = 1
                db.execute(
                    "INSERT INTO login_attempt_counters(scope,key_hash,failed_attempts,window_started_at,updated_at) "
                    "VALUES(?,?,1,?,?) ON CONFLICT(scope,key_hash) DO UPDATE SET failed_attempts=1,window_started_at=excluded.window_started_at,updated_at=excluded.updated_at",
                    (scope, key_hash, timestamp_text, timestamp_text),
                )
            else:
                count = int(row["failed_attempts"] or 0) + 1
                db.execute("UPDATE login_attempt_counters SET failed_attempts=?,updated_at=? WHERE scope=? AND key_hash=?",
                           (count, timestamp_text, scope, key_hash))
            counts[scope] = count
        if max(counts.values() or [0]) < LOGIN_FAILURE_LIMIT:
            return None
        blocked_until = (timestamp + LOGIN_SECURITY_BLOCK_DURATION).isoformat(timespec="seconds")
        block_id = secrets.token_urlsafe(12)
        db.execute(
            "INSERT INTO login_security_blocks(block_id,username_hash,ip_hash,device_hash,agent_hash,username,blocked_until,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (block_id, keys.get("username", ""), keys.get("ip", ""), keys.get("device", ""),
             keys.get("agent", ""), str(username or "")[:80], blocked_until, timestamp_text),
        )
    security_event("login_security_block", username, "blocked", f"Three failed authentication attempts; {detail}; account/IP/browser identifiers locked for 15 minutes")
    send_login_security_block_alert(block_id, username, blocked_until)
    return {"block_id": block_id, "blocked_until": blocked_until}


def login_failure_json(message, stage="password", clear_field="password", block=None):
    seconds = login_block_remaining(block["blocked_until"]) if block else 0
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        response = jsonify({
            "ok": False, "message": message, "stage": stage, "clear_field": clear_field,
            "blocked": bool(block), "retry_after": seconds,
        })
    else:
        flash(message, "error")
        pending_user = None
        if stage == "verify" and session.get("pending_2fa_user_id"):
            with connect_db() as db:
                row = db.execute("SELECT id,username,role,profile_image FROM users WHERE id=? AND enabled=1",
                                 (session["pending_2fa_user_id"],)).fetchone()
            pending_user = dict(row) if row else None
        response = app.make_response(render_template(
            "login.html", stage=stage, login_user=pending_user,
            two_factor_required=(stage == "verify"),
            approval_pending=bool(session.get("pending_login_approval_id") or session.get("login_approval_id")),
        ))
    response.status_code = 429 if block else 401
    if block:
        try:
            retry_after = int((datetime.fromisoformat(str(block["blocked_until"])) - datetime.now(timezone.utc)).total_seconds())
        except (TypeError, ValueError):
            retry_after = seconds
        response.headers["Retry-After"] = str(max(1, retry_after))
    return response


def handle_login_security_unblock_callback(callback, configured_chat_id):
    match = re.fullmatch(r"login_unblock_group:([A-Za-z0-9_-]{12,24})", str(callback.get("data") or ""))
    if not match:
        return False
    block_id = match.group(1)
    message = callback.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = str(chat.get("id", ""))
    sender_id = str((callback.get("from") or {}).get("id", ""))
    if chat_id != str(configured_chat_id):
        return False
    if chat.get("type") == "private":
        if not sender_id or sender_id != chat_id:
            return False
    else:
        configured_admin = secure_setting("telegram_admin_user_id_enc")
        if not configured_admin or sender_id != str(configured_admin):
            return False
    with connect_db() as db:
        row = db.execute("SELECT * FROM login_security_blocks WHERE block_id=? AND telegram_chat_id=? AND telegram_message_id=?",
                         (block_id, chat_id, int(message.get("message_id") or 0))).fetchone()
        if not row or login_block_remaining(row["blocked_until"]) <= 0:
            return False
        updated = db.execute("UPDATE login_security_blocks SET blocked_until='',telegram_message_id=NULL,telegram_chat_id='' "
                             "WHERE block_id=? AND telegram_chat_id=? AND telegram_message_id=? AND blocked_until=?",
                             (block_id, chat_id, int(message.get("message_id") or 0), row["blocked_until"]))
        if updated.rowcount != 1:
            return False
        for scope, column in (("username", "username_hash"), ("ip", "ip_hash"), ("device", "device_hash")):
            if row[column]:
                db.execute("DELETE FROM login_attempt_counters WHERE scope=? AND key_hash=?", (scope, row[column]))
        username = str(row["username"] or "")
    telegram_edit_persistent_message(chat_id, message.get("message_id"),
        f"✅ مسدودی ورود {username or 'این دستگاه'} به‌صورت کامل برداشته شد.\nحساب، IP و شناسه مرورگر دوباره مجاز هستند.",
        reply_markup={"inline_keyboard": []})
    return True


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET" and request.args.get("server_reconfigured") == "1":
        flash("The server address was changed successfully. Please sign in again at this new address.", "success")
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "POST":
        attempted_username = str(request.form.get("username", "")).strip()[:80]
        if not attempted_username and session.get("pending_2fa_user_id"):
            with connect_db() as db:
                pending_name = db.execute("SELECT username FROM users WHERE id=?", (session["pending_2fa_user_id"],)).fetchone()
            attempted_username = str(pending_name["username"] or "") if pending_name else ""
        active_block = active_login_security_block(attempted_username)
        if active_block:
            security_event("login_security_block", attempted_username, "throttled", "Active 15-minute account/IP/browser lock")
            return login_failure_json("This account or browser/device is temporarily blocked. Please wait for the 15-minute lock to expire or ask an administrator to release it.",
                                      "verify" if session.get("pending_2fa_user_id") else "password",
                                      "code" if session.get("pending_2fa_user_id") else "password", active_block)
        if attempted_username:
            with connect_db() as db:
                blocked_user = db.execute(
                    "SELECT login_blocked_until FROM users WHERE username=? COLLATE NOCASE AND enabled=1",
                    (attempted_username,),
                ).fetchone()
            blocked_until = str(blocked_user["login_blocked_until"] or "") if blocked_user else ""
            if blocked_until and blocked_until > now():
                security_event("login_rejection_lock", attempted_username[:80], "throttled",
                               "Login approval was rejected; account is blocked for 15 minutes")
                return login_failure_json("This account is temporarily blocked after a rejected login request. Wait 15 minutes and try again.",
                                          "password", "password", {"blocked_until": blocked_until})
            if blocked_until:
                with connect_db() as db:
                    db.execute("UPDATE users SET login_blocked_until='' WHERE username=? COLLATE NOCASE "
                               "AND login_blocked_until=?", (attempted_username, blocked_until))
    if request.method == "GET" and request.args.get("reset") == "1":
        pending_approval_id = session.pop("pending_login_approval_id", None) or session.pop("login_approval_id", None)
        if pending_approval_id:
            finish_login_approval_log(pending_approval_id, "canceled")
        session.pop("pending_2fa_user_id", None)
        session.pop("pending_2fa_secret", None)
        session.pop("pending_2fa_verified", None)
        session.pop("pending_2fa_method", None)
        session.pop("pending_2fa_code_enc", None)
        session.pop("pending_2fa_remember", None)
        session.pop("pending_2fa_telegram_message", None)
        session.pop("login_approval_id", None)
        session["csrf_token"] = secrets.token_urlsafe(32)
    if request.method == "GET" and session.get("pending_login_approval_id"):
        approval_id = session["pending_login_approval_id"]
        with connect_db() as db:
            approval = db.execute(
                "SELECT * FROM login_approval_requests WHERE id=?", (approval_id,)
            ).fetchone()
            approved_user = db.execute(
                "SELECT * FROM users WHERE id=? AND enabled=1",
                (approval["user_id"],),
            ).fetchone() if approval else None
        if approval and approval["status"] == "approved":
            if not approved_user:
                finish_login_approval_log(approval_id, "canceled")
                session.clear()
                flash("This account is no longer enabled.", "error")
                return redirect(url_for("login"))
            return continue_login_after_approval(approved_user, approval_id, bypass_two_factor=True)
        if approval and approval["status"] == "pending" and approval["expires_at"] <= now():
            finish_login_approval_log(approval_id, "expired")
            approval = None
        if not approval or approval["status"] in ("denied", "expired", "delivery_failed", "canceled"):
            session.pop("pending_login_approval_id", None)
            session.pop("login_approval_id", None)
            session.pop("pending_2fa_user_id", None)
            session.pop("pending_2fa_verified", None)
            flash("Unable to sign in. Please try again.", "error")
        else:
            login_user = dict(approved_user) if approved_user else {"username": approval["username"], "role": "admin"}
            needs_code = bool(approved_user and user_requires_two_factor(approved_user)
                              and not session.get("pending_2fa_verified"))
            return render_template("login.html", stage="verify", login_user=login_user,
                                   two_factor_required=needs_code, approval_pending=True)
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
            approval_id = session.get("login_approval_id")
            recovery_ok = bool(
                user and user_requires_two_factor(user) and not totp_ok
                and (recovery_code_is_valid(user["id"], code) if approval_id
                     else consume_recovery_code(user["id"], code))
            )
            telegram_code_message = None
            if user and user["role"] == "superadmin" and user_requires_two_factor(user) and not totp_ok and not recovery_ok:
                if approval_id:
                    telegram_code_message = verify_telegram_login_code(user["id"], code)
                else:
                    telegram_code_message = consume_telegram_login_code(user["id"], code)
            telegram_code_ok = telegram_code_message is not None
            if user and user_requires_two_factor(user) and (totp_ok or recovery_ok or telegram_code_ok):
                clear_login_attempt_counters(user["username"])
                if approval_id:
                    approval = login_approval_row_for_session()
                    if not approval or approval["status"] not in ("approved",):
                        if approval and approval["status"] == "pending":
                            method = ("Telegram one-time code" if telegram_code_ok else
                                      ("One-time recovery code" if recovery_ok else "Authenticator app (TOTP)"))
                            session["pending_2fa_verified"] = True
                            session["pending_2fa_method"] = method
                            session["pending_2fa_code_enc"] = vault.encrypt(code.encode("utf-8")).decode("ascii")
                            session["pending_2fa_remember"] = bool(totp_ok)
                            if telegram_code_message:
                                session["pending_2fa_telegram_message"] = {
                                    "chat_id": telegram_code_message.get("chat_id"),
                                    "message_id": telegram_code_message.get("message_id"),
                                }
                            return render_template("login.html", stage="verify", login_user=dict(user),
                                                   two_factor_required=False, approval_pending=True)
                        session.pop("pending_login_approval_id", None)
                        session.pop("login_approval_id", None)
                        session.pop("pending_2fa_user_id", None)
                        session.pop("pending_2fa_verified", None)
                        session.pop("pending_2fa_method", None)
                        session.pop("pending_2fa_code_enc", None)
                        session.pop("pending_2fa_remember", None)
                        session.pop("pending_2fa_telegram_message", None)
                        flash("Unable to sign in. Please try again.", "error")
                        return render_template("login.html", stage="password")
                establish_login(user)
                session["two_factor_verified"] = True
                if recovery_ok:
                    security_event("two_factor_recovery", user["username"], "success", "One-time offline recovery code consumed")
                    audit("two_factor_recovery_code_used")
                if telegram_code_ok:
                    security_event("two_factor_recovery", user["username"], "success", "Two-minute Telegram fallback code consumed")
                    audit("telegram_login_recovery_code_used")
                method = ("Telegram one-time code" if telegram_code_ok else
                          ("One-time recovery code" if recovery_ok else "Authenticator app (TOTP)"))
                finalize_login_audit(
                    approval_id, user["username"], client_ip(), method,
                    code_value=code, user_agent=request.headers.get("User-Agent", ""),
                    telegram_code_message=telegram_code_message,
                )
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
            failure_block = register_login_failure(attempted_username, "invalid second-factor code")
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return login_failure_json("The verification code is invalid. Try again." if not failure_block else
                                          "Three failed attempts. This account, IP and browser/device are blocked for 15 minutes.",
                                          "verify", "code", failure_block)
            if failure_block:
                return login_failure_json("Three failed attempts. This account, IP and browser/device are blocked for 15 minutes.",
                                          "verify", "code", failure_block)
            flash("The verification code is invalid. Try again.", "error")
            return render_template("login.html", stage="verify", login_user=dict(user) if user else None,
                                   two_factor_required=True,
                                   approval_pending=bool(session.get("pending_login_approval_id") or session.get("login_approval_id")))

        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE username=? AND enabled=1", (username,)).fetchone()
        if user and len(password) <= 1024 and password_matches(password, user["password_hash"]):
            if app.config.get("LOGIN_APPROVAL_REQUIRED", True):
                approval_id = create_login_approval_request(
                    user, client_ip(), request.headers.get("User-Agent", ""),
                )
                if not approval_id:
                    security_event("login_approval", username, "blocked",
                                   "Telegram administrator approval request could not be delivered")
                    flash("Unable to sign in right now. Please try again later.", "error")
                    return render_template("login.html", stage="password")
                session.clear()
                session["pending_login_approval_id"] = approval_id
                session["login_approval_id"] = approval_id
                if user_requires_two_factor(user):
                    session["pending_2fa_user_id"] = user["id"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                security_event("login", username, "password_ok_approval_pending",
                               "Password accepted; waiting for Telegram administrator approval")
                return render_template("login.html", stage="verify", login_user={
                    "id": user["id"], "username": user["username"], "role": user["role"],
                    "profile_image": user["profile_image"],
                }, two_factor_required=user_requires_two_factor(user), approval_pending=True)
            if user_requires_two_factor(user) and remembered_two_factor(user["id"]):
                clear_login_attempt_counters(username)
                establish_login(user)
                session["two_factor_verified"] = True
                send_login_success_alert(user["username"], client_ip(), user_agent=request.headers.get("User-Agent", ""))
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
            clear_login_attempt_counters(username)
            establish_login(user)
            send_login_success_alert(user["username"], client_ip(), user_agent=request.headers.get("User-Agent", ""))
            flash(f"Welcome back, {user['username']}!", "welcome")
            return redirect(safe_login_target())
        time.sleep(0.35)
        guess_id = failed_password_fingerprint(password)
        security_event("login", username, "failed", f"Invalid username/password or disabled account; password not stored; guess fingerprint={guess_id}")
        send_login_failure_alert(username, client_ip(), "Invalid username or password", password)
        failure_block = register_login_failure(username, "invalid username or password")
        failure_message = ("Invalid username or password." if not failure_block else
                           "Three failed attempts. This account, IP and browser/device are blocked for 15 minutes.")
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return login_failure_json(failure_message, "password", "password", failure_block)
        if failure_block:
            return login_failure_json(failure_message, "password", "password", failure_block)
        flash(failure_message, "error")
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
        active_block = active_login_security_block(user["username"])
        if active_block:
            response = app.make_response(("This account or browser/device is temporarily blocked. Wait for the 15-minute lock to expire or ask an administrator to release it.", 429))
            response.headers["Retry-After"] = str(max(1, login_block_remaining(active_block["blocked_until"])))
            return response
        code = re.sub(r"\s", "", request.form.get("code", ""))
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            clear_login_attempt_counters(user["username"])
            with connect_db() as db:
                db.execute("UPDATE users SET totp_secret=?,two_factor_enrolled=1 WHERE id=?", (encrypt_authenticator_secret(secret), user_id))
            approval_id = session.get("login_approval_id")
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
            finalize_login_audit(
                approval_id, user["username"], client_ip(),
                "Administrator approval + Authenticator enrollment",
                code_value=code, user_agent=request.headers.get("User-Agent", ""),
            )
            flash(f"Welcome back, {user['username']}! Two-factor authentication is enabled.", "welcome")
            response = redirect(url_for("index"))
            remember_two_factor_response(response, user_id)
            return response
        time.sleep(0.35)
        security_event("two_factor_enrollment", user["username"], "failed", "Invalid authenticator enrollment code")
        failure_block = register_login_failure(user["username"], "invalid authenticator enrollment code")
        if failure_block:
            response = app.make_response(("Three failed authenticator codes. This account, IP and browser/device are blocked for 15 minutes.", 429))
            response.headers["Retry-After"] = str(login_block_remaining(failure_block["blocked_until"]))
            return response
        flash("The authenticator code is invalid. Try again.", "error")
    import qrcode
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_data_uri = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")
    return render_template("setup_2fa.html", secret=secret, uri=uri, qr_data_uri=qr_data_uri, user=dict(user))


@app.post("/cancel-2fa-setup")
def cancel_2fa_setup():
    """Log out of the pending mandatory enrollment flow without disabling 2FA."""
    pending_user_id = session.get("pending_2fa_user_id")
    approval_id = session.get("login_approval_id")
    if not pending_user_id:
        if session.get("user_id"):
            abort(403)
        session.clear()
        return redirect(url_for("login"))

    with connect_db() as db:
        user = db.execute("SELECT username FROM users WHERE id=?", (pending_user_id,)).fetchone()
    security_event(
        "two_factor_enrollment",
        user["username"] if user else "",
        "info",
        "User logged out from the pending authenticator setup page",
    )
    if approval_id:
        finish_login_approval_log(approval_id, "canceled")
    session.clear()
    response = redirect(url_for("login"))
    response.delete_cookie(REMEMBER_2FA_COOKIE)
    return response


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
                "SELECT ips.*, groups.name AS group_name, groups.color AS group_color FROM ips "
                "LEFT JOIN groups ON groups.id=ips.group_id "
                "ORDER BY COALESCE(NULLIF(TRIM(groups.name), ''), 'Default') COLLATE NOCASE, "
                "COALESCE(NULLIF(TRIM(ips.name), ''), ips.ip_address) COLLATE NOCASE, "
                "ips.ip_address COLLATE NOCASE LIMIT 1000"
            ).fetchall()
        rows = db.execute("""
          SELECT DISTINCT ips.*, groups.name AS group_name, groups.color AS group_color FROM ips
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
        color = request.form.get("color", "").strip()[:7]
        if not re.fullmatch(r"#[0-9A-Fa-f]{6}", color): color = ""
        if not name:
            flash("Group name is required.", "error")
        else:
            try:
                with connect_db() as db:
                    next_order = db.execute("SELECT COALESCE(MAX(sort_order), 0) + 1 FROM groups").fetchone()[0]
                    db.execute("INSERT INTO groups(name,description,created_at,sort_order,color) VALUES(?,?,?,?,?)", (name, description, now(), next_order, color))
                audit("group_created", name)
                flash("Group created.", "success")
                return redirect(url_for("groups"))
            except sqlite3.IntegrityError:
                flash("A group with that name already exists.", "error")
    with connect_db() as db:
        rows = db.execute("SELECT groups.*, COUNT(ips.id) AS ip_count FROM groups LEFT JOIN ips ON ips.group_id=groups.id GROUP BY groups.id ORDER BY groups.sort_order, groups.id").fetchall()
    return render_template("groups.html", groups=rows)




@app.post("/groups/<int:group_id>/color")
@superadmin_required
def group_color_update(group_id):
    color = request.form.get("color", "").strip()[:7]
    if not re.fullmatch(r"#[0-9A-Fa-f]{6}", color):
        flash("Choose a valid group color.", "error")
    else:
        with connect_db() as db:
            cur = db.execute("UPDATE groups SET color=? WHERE id=?", (color, group_id))
            if not cur.rowcount:
                abort(404)
        audit("group_color_updated", f"{group_id}:{color}")
        flash("Group color updated.", "success")
    return redirect(url_for("groups"))

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



def safe_accounts_return_url(value):
    """Accept only a local URL for the separate Accounts directory."""
    default = url_for("accounts")
    candidate = str(value or "").strip()
    if not candidate or len(candidate) > 2048 or "\\" in candidate:
        return default
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return default
    if parsed.scheme or parsed.netloc or parsed.path != "/accounts" or candidate.startswith("//"):
        return default
    return "/accounts" + ("?" + parsed.query if parsed.query else "")


def validate_account(form):
    name = str(form.get("name", "")).strip()[:120]
    username = str(form.get("username", "")).strip()[:120]
    email = str(form.get("email", "")).strip()[:254]
    password = form.get("password", "")
    group_raw = str(form.get("group_id", "")).strip()

    if not name:
        return None, "Account name is required."
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return None, "Enter a valid email address when an email is provided."
    if len(password) > 2000:
        return None, "Password is too long."

    try:
        group_id = int(group_raw) if group_raw else None
    except ValueError:
        return None, "Select a valid account group."
    with connect_db() as db:
        if group_id is None:
            default_group = db.execute("SELECT id FROM account_groups WHERE name='Default'").fetchone()
            group_id = default_group["id"] if default_group else None
        if group_id and not db.execute("SELECT id FROM account_groups WHERE id=?", (group_id,)).fetchone():
            return None, "Selected account group does not exist."

    return {
        "name": name,
        "username": username,
        "email": email,
        "password_enc": vault.encrypt(password.encode("utf-8")).decode("ascii") if password else None,
        "group_id": group_id,
    }, None


@app.get("/accounts")
@superadmin_required
def accounts():
    term = request.args.get("q", "").strip()[:100]
    group_filter = request.args.get("group", "").strip()
    with connect_db() as db:
        groups = db.execute("SELECT * FROM account_groups ORDER BY sort_order, id").fetchall()
        rows = db.execute("""
            SELECT accounts.*, account_groups.name AS group_name, account_groups.color AS group_color
            FROM accounts LEFT JOIN account_groups ON account_groups.id=accounts.group_id
            ORDER BY COALESCE(NULLIF(TRIM(account_groups.name), ''), 'Default') COLLATE NOCASE,
                     accounts.name COLLATE NOCASE, accounts.id
        """).fetchall()
    rows = list(rows)
    if group_filter == "ungrouped":
        rows = [row for row in rows if row["group_id"] is None]
    elif group_filter.isdigit():
        rows = [row for row in rows if row["group_id"] == int(group_filter)]
    if term:
        needle = term.casefold()
        rows = [row for row in rows if any(
            needle in str(row[key] or "").casefold()
            for key in ("name", "username", "email", "group_name")
        )]
    prepared = []
    for row in rows:
        item = dict(row)
        try:
            item["password_plain"] = vault.decrypt((row["password_enc"] or "").encode("ascii")).decode("utf-8") if row["password_enc"] else ""
        except (InvalidToken, ValueError, TypeError, UnicodeDecodeError):
            item["password_plain"] = ""
        prepared.append(item)
    return render_template("accounts.html", accounts=prepared, groups=groups, q=term, group_filter=group_filter)


@app.route("/accounts/new", methods=["GET", "POST"])
@superadmin_required
def account_new():
    return_to = safe_accounts_return_url(request.form.get("return_to") or request.args.get("return_to"))
    with connect_db() as db:
        groups = db.execute("SELECT * FROM account_groups ORDER BY sort_order, id").fetchall()
        default_group = db.execute("SELECT id FROM account_groups WHERE name='Default'").fetchone()
    if request.method == "POST":
        data, error = validate_account(request.form)
        if error:
            flash(error, "error")
        else:
            with connect_db() as db:
                cursor = db.execute(
                    "INSERT INTO accounts(name,username,email,password_enc,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (data["name"], data["username"], data["email"], data["password_enc"] or "", data["group_id"],
                     request.user["username"], now(), now()),
                )
                account_id = cursor.lastrowid
            audit("account_created", f"id={account_id}; name={data['name']}")
            flash("Account saved.", "success")
            return redirect(return_to)
    return render_template("account_form.html", account=None, groups=groups,
                           default_group_id=default_group["id"] if default_group else None,
                           return_to=return_to)


@app.route("/accounts/<int:account_id>/edit", methods=["GET", "POST"])
@superadmin_required
def account_edit(account_id):
    return_to = safe_accounts_return_url(request.form.get("return_to") or request.args.get("return_to"))
    with connect_db() as db:
        account = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        groups = db.execute("SELECT * FROM account_groups ORDER BY sort_order, id").fetchall()
    if not account:
        abort(404)
    if request.method == "POST":
        data, error = validate_account(request.form)
        if error:
            flash(error, "error")
        else:
            encrypted_password = data["password_enc"] if data["password_enc"] is not None else account["password_enc"]
            with connect_db() as db:
                db.execute(
                    "UPDATE accounts SET name=?,username=?,email=?,password_enc=?,group_id=?,updated_at=? WHERE id=?",
                    (data["name"], data["username"], data["email"], encrypted_password,
                     data["group_id"], now(), account_id),
                )
            audit("account_updated", f"id={account_id}; name={data['name']}")
            flash("Account updated.", "success")
            return redirect(return_to)
    return render_template("account_form.html", account=account, groups=groups,
                           default_group_id=None, return_to=return_to)


@app.post("/accounts/<int:account_id>/delete")
@superadmin_required
def account_delete(account_id):
    return_to = safe_accounts_return_url(request.form.get("return_to"))
    with connect_db() as db:
        row = db.execute("SELECT name FROM accounts WHERE id=?", (account_id,)).fetchone()
        if row:
            db.execute("DELETE FROM accounts WHERE id=?", (account_id,))
    if row:
        audit("account_deleted", f"id={account_id}; name={row['name']}")
        flash("Account deleted.", "success")
    return redirect(return_to)


@app.route("/account-groups", methods=["GET", "POST"])
@superadmin_required
def account_groups():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:100]
        description = request.form.get("description", "").strip()[:500]
        color = request.form.get("color", "").strip()[:7]
        if not re.fullmatch(r"#[0-9A-Fa-f]{6}", color): color = ""
        if not name:
            flash("Account group name is required.", "error")
        else:
            try:
                with connect_db() as db:
                    next_order = db.execute("SELECT COALESCE(MAX(sort_order), 0) + 1 FROM account_groups").fetchone()[0]
                    db.execute(
                        "INSERT INTO account_groups(name,description,created_at,sort_order,color) VALUES(?,?,?,?,?)",
                        (name, description, now(), next_order, color),
                    )
                audit("account_group_created", name)
                flash("Account group created.", "success")
                return redirect(url_for("account_groups"))
            except sqlite3.IntegrityError:
                flash("An account group with that name already exists.", "error")
    with connect_db() as db:
        rows = db.execute(
            "SELECT account_groups.*, COUNT(accounts.id) AS account_count "
            "FROM account_groups LEFT JOIN accounts ON accounts.group_id=account_groups.id "
            "GROUP BY account_groups.id ORDER BY account_groups.sort_order, account_groups.id"
        ).fetchall()
    return render_template("account_groups.html", groups=rows)




@app.post("/account-groups/<int:group_id>/color")
@superadmin_required
def account_group_color_update(group_id):
    color = request.form.get("color", "").strip()[:7]
    if not re.fullmatch(r"#[0-9A-Fa-f]{6}", color):
        flash("Choose a valid account group color.", "error")
    else:
        with connect_db() as db:
            cur = db.execute("UPDATE account_groups SET color=? WHERE id=?", (color, group_id))
            if not cur.rowcount:
                abort(404)
        audit("account_group_color_updated", f"{group_id}:{color}")
        flash("Account group color updated.", "success")
    return redirect(url_for("account_groups"))

@app.post("/account-groups/<int:group_id>/move")
@superadmin_required
def account_group_move(group_id):
    direction = request.form.get("direction", "")
    if direction not in ("up", "down"):
        abort(400)
    moved = False
    with connect_db() as db:
        ordered = db.execute("SELECT id,sort_order FROM account_groups ORDER BY sort_order,id").fetchall()
        ids = [row["id"] for row in ordered]
        if group_id not in ids:
            abort(404)
        current = ids.index(group_id)
        target = current - 1 if direction == "up" else current + 1
        if 0 <= target < len(ids):
            first, second = ordered[current], ordered[target]
            db.execute("UPDATE account_groups SET sort_order=? WHERE id=?", (second["sort_order"], first["id"]))
            db.execute("UPDATE account_groups SET sort_order=? WHERE id=?", (first["sort_order"], second["id"]))
            moved = True
    if moved:
        audit("account_group_reordered", f"id={group_id}; direction={direction}")
    return redirect(url_for("account_groups"))


@app.post("/account-groups/<int:group_id>/delete")
@superadmin_required
def account_group_delete(group_id):
    with connect_db() as db:
        group = db.execute("SELECT id,name FROM account_groups WHERE id=?", (group_id,)).fetchone()
        if not group:
            abort(404)
        if group["name"] == "Default":
            flash("The Default account group cannot be deleted.", "error")
            return redirect(url_for("account_groups"))
        default_group = db.execute("SELECT id FROM account_groups WHERE name='Default'").fetchone()
        db.execute("UPDATE accounts SET group_id=? WHERE group_id=?", (default_group["id"], group_id))
        db.execute("DELETE FROM account_groups WHERE id=?", (group_id,))
    audit("account_group_deleted", f"id={group_id}; name={group['name']}")
    flash("Account group deleted. Its accounts were moved to Default.", "success")
    return redirect(url_for("account_groups"))


def safe_notes_return_url(value):
    """Accept only a local URL for the independent Notes directory."""
    default = url_for("notes")
    candidate = str(value or "").strip()
    if not candidate or len(candidate) > 2048 or "\\" in candidate:
        return default
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return default
    if parsed.scheme or parsed.netloc or parsed.path != "/notes" or candidate.startswith("//"):
        return default
    return "/notes" + ("?" + parsed.query if parsed.query else "")


def validate_note(form):
    """Validate an all-optional composite note/IP/account record."""
    title = str(form.get("title", "")).strip()[:160]
    service_url = str(form.get("service_url", "")).strip()[:500]
    ip_name = str(form.get("ip_name", "")).strip()[:120]
    ip_address = str(form.get("ip_address", "")).strip()[:255]
    ip_port_raw = str(form.get("ip_port", "")).strip()
    ip_username = str(form.get("ip_username", "")).strip()[:120]
    ip_password = form.get("ip_password", "")
    account_name = str(form.get("account_name", "")).strip()[:120]
    account_username = str(form.get("account_username", "")).strip()[:120]
    account_email = str(form.get("account_email", "")).strip()[:254]
    account_password = form.get("account_password", "")
    note_text = str(form.get("note_text", "")).strip()[:20000]
    wifi_ssid = str(form.get("wifi_ssid", "")).strip()[:256]
    wifi_password = form.get("wifi_password", "")
    admin_ip = str(form.get("admin_ip", "")).strip()[:255]
    admin_username = str(form.get("admin_username", "")).strip()[:120]
    admin_password = form.get("admin_password", "")
    group_raw = str(form.get("group_id", "")).strip()

    if ip_port_raw:
        if not re.fullmatch(r"\d{1,5}", ip_port_raw) or not 1 <= int(ip_port_raw) <= 65535:
            return None, "IP port must be a number between 1 and 65535."
        ip_port = int(ip_port_raw)
    else:
        ip_port = None
    if account_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", account_email):
        return None, "Enter a valid account email address when one is provided."
    if len(ip_password) > 2000 or len(account_password) > 2000 or len(wifi_password) > 2000 or len(admin_password) > 2000:
        return None, "Passwords must be 2000 characters or fewer."

    try:
        group_id = int(group_raw) if group_raw else None
    except ValueError:
        return None, "Select a valid notes group."
    with connect_db() as db:
        if group_id is None:
            default_group = db.execute("SELECT id FROM note_groups WHERE name='Default'").fetchone()
            group_id = default_group["id"] if default_group else None
        if group_id and not db.execute("SELECT id FROM note_groups WHERE id=?", (group_id,)).fetchone():
            return None, "Selected notes group does not exist."

    return {
        "title": title,
        "service_url": service_url,
        "ip_name": ip_name,
        "ip_address": ip_address,
        "ip_port": ip_port,
        "ip_username": ip_username,
        "ip_password_enc": vault.encrypt(ip_password.encode("utf-8")).decode("ascii") if ip_password else None,
        "account_name": account_name,
        "account_username": account_username,
        "account_email": account_email,
        "account_password_enc": vault.encrypt(account_password.encode("utf-8")).decode("ascii") if account_password else None,
        "note_text": note_text,
        "wifi_ssid": wifi_ssid,
        "wifi_password_enc": vault.encrypt(wifi_password.encode("utf-8")).decode("ascii") if wifi_password else None,
        "admin_ip": admin_ip,
        "admin_username": admin_username,
        "admin_password_enc": vault.encrypt(admin_password.encode("utf-8")).decode("ascii") if admin_password else None,
        "group_id": group_id,
    }, None


@app.get("/notes")
@superadmin_required
def notes():
    term = request.args.get("q", "").strip()[:100]
    group_filter = request.args.get("group", "").strip()
    with connect_db() as db:
        groups = db.execute("SELECT * FROM note_groups ORDER BY sort_order, id").fetchall()
        rows = db.execute("""
            SELECT notes.*, note_groups.name AS group_name, note_groups.color AS group_color
            FROM notes LEFT JOIN note_groups ON note_groups.id=notes.group_id
            ORDER BY COALESCE(NULLIF(TRIM(note_groups.name), ''), 'Default') COLLATE NOCASE,
                     COALESCE(NULLIF(TRIM(notes.title), ''), printf('Entry %08d', notes.id)) COLLATE NOCASE,
                     notes.id DESC
        """).fetchall()
    rows = list(rows)
    if group_filter == "ungrouped":
        rows = [row for row in rows if row["group_id"] is None]
    elif group_filter.isdigit():
        rows = [row for row in rows if row["group_id"] == int(group_filter)]
    if term:
        needle = term.casefold()
        searchable = ("title", "service_url", "ip_name", "ip_address", "ip_username",
                      "account_name", "account_username", "account_email", "note_text", "wifi_ssid", "admin_ip", "admin_username", "group_name")
        rows = [row for row in rows if any(needle in str(row[key] or "").casefold() for key in searchable)]
    prepared = []
    for row in rows:
        item = dict(row)
        for encrypted_key, plain_key in (("ip_password_enc", "ip_password_plain"),
                                          ("account_password_enc", "account_password_plain"),
                                          ("wifi_password_enc", "wifi_password_plain"),
                                          ("admin_password_enc", "admin_password_plain")):
            try:
                item[plain_key] = vault.decrypt((row[encrypted_key] or "").encode("ascii")).decode("utf-8") if row[encrypted_key] else ""
            except (InvalidToken, ValueError, TypeError, UnicodeDecodeError):
                item[plain_key] = ""
        prepared.append(item)
    return render_template("notes.html", notes=prepared, groups=groups, q=term, group_filter=group_filter)


@app.route("/notes/new", methods=["GET", "POST"])
@superadmin_required
def note_new():
    return_to = safe_notes_return_url(request.form.get("return_to") or request.args.get("return_to"))
    with connect_db() as db:
        groups = db.execute("SELECT * FROM note_groups ORDER BY sort_order, id").fetchall()
        default_group = db.execute("SELECT id FROM note_groups WHERE name='Default'").fetchone()
    if request.method == "POST":
        data, error = validate_note(request.form)
        if error:
            flash(error, "error")
        else:
            with connect_db() as db:
                cursor = db.execute("""
                    INSERT INTO notes(title,service_url,ip_name,ip_address,ip_port,ip_username,ip_password_enc,
                                      account_name,account_username,account_email,account_password_enc,note_text,
                                      wifi_ssid,wifi_password_enc,admin_ip,admin_username,admin_password_enc,group_id,created_by,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (data["title"], data["service_url"], data["ip_name"], data["ip_address"], data["ip_port"],
                      data["ip_username"], data["ip_password_enc"] or "", data["account_name"],
                      data["account_username"], data["account_email"], data["account_password_enc"] or "",
                      data["note_text"], data["wifi_ssid"], data["wifi_password_enc"] or "", data["admin_ip"],
                      data["admin_username"], data["admin_password_enc"] or "",
                      data["group_id"], request.user["username"], now(), now()))
                note_id = cursor.lastrowid
            audit("note_created", f"id={note_id}; group_id={data['group_id']}")
            flash("Note saved.", "success")
            return redirect(return_to)
    return render_template("notes_form.html", note=None, groups=groups,
                           default_group_id=default_group["id"] if default_group else None,
                           return_to=return_to, form_data=request.form if request.method == "POST" else {})


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@superadmin_required
def note_edit(note_id):
    return_to = safe_notes_return_url(request.form.get("return_to") or request.args.get("return_to"))
    with connect_db() as db:
        note = db.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
        groups = db.execute("SELECT * FROM note_groups ORDER BY sort_order, id").fetchall()
    if not note:
        abort(404)
    if request.method == "POST":
        data, error = validate_note(request.form)
        if error:
            flash(error, "error")
        else:
            ip_password_enc = data["ip_password_enc"] if data["ip_password_enc"] is not None else note["ip_password_enc"]
            account_password_enc = data["account_password_enc"] if data["account_password_enc"] is not None else note["account_password_enc"]
            wifi_password_enc = data["wifi_password_enc"] if data["wifi_password_enc"] is not None else note["wifi_password_enc"]
            admin_password_enc = data["admin_password_enc"] if data["admin_password_enc"] is not None else note["admin_password_enc"]
            with connect_db() as db:
                db.execute("""
                    UPDATE notes SET title=?,service_url=?,ip_name=?,ip_address=?,ip_port=?,ip_username=?,
                        ip_password_enc=?,account_name=?,account_username=?,account_email=?,account_password_enc=?,
                        note_text=?,wifi_ssid=?,wifi_password_enc=?,admin_ip=?,admin_username=?,admin_password_enc=?,group_id=?,updated_at=? WHERE id=?
                """, (data["title"], data["service_url"], data["ip_name"], data["ip_address"], data["ip_port"],
                      data["ip_username"], ip_password_enc, data["account_name"], data["account_username"],
                      data["account_email"], account_password_enc, data["note_text"], data["wifi_ssid"],
                      wifi_password_enc, data["admin_ip"], data["admin_username"], admin_password_enc, data["group_id"], now(), note_id))
            audit("note_updated", f"id={note_id}; group_id={data['group_id']}")
            flash("Note updated.", "success")
            return redirect(return_to)
    return render_template("notes_form.html", note=note, groups=groups, default_group_id=None,
                           return_to=return_to, form_data=request.form if request.method == "POST" else {})


@app.post("/notes/<int:note_id>/delete")
@superadmin_required
def note_delete(note_id):
    return_to = safe_notes_return_url(request.form.get("return_to"))
    with connect_db() as db:
        row = db.execute("SELECT id,title FROM notes WHERE id=?", (note_id,)).fetchone()
        if row:
            db.execute("DELETE FROM notes WHERE id=?", (note_id,))
    if row:
        audit("note_deleted", f"id={note_id}; title={row['title']}")
        flash("Note deleted.", "success")
    return redirect(return_to)


@app.route("/note-groups", methods=["GET", "POST"])
@superadmin_required
def note_groups():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:100]
        description = request.form.get("description", "").strip()[:500]
        color = request.form.get("color", "").strip()[:7]
        if not re.fullmatch(r"#[0-9A-Fa-f]{6}", color):
            color = "#65758b"
        if not name:
            flash("Notes group name is required.", "error")
        else:
            try:
                with connect_db() as db:
                    next_order = db.execute("SELECT COALESCE(MAX(sort_order), 0) + 1 FROM note_groups").fetchone()[0]
                    db.execute("INSERT INTO note_groups(name,description,color,created_at,sort_order) VALUES(?,?,?,?,?)",
                               (name, description, color, now(), next_order))
                audit("note_group_created", name)
                flash("Notes group created.", "success")
                return redirect(url_for("note_groups"))
            except sqlite3.IntegrityError:
                flash("A notes group with that name already exists.", "error")
    with connect_db() as db:
        rows = db.execute("""
            SELECT note_groups.*, COUNT(notes.id) AS note_count
            FROM note_groups LEFT JOIN notes ON notes.group_id=note_groups.id
            GROUP BY note_groups.id ORDER BY note_groups.sort_order, note_groups.id
        """).fetchall()
    return render_template("note_groups.html", groups=rows)


@app.post("/note-groups/<int:group_id>/color")
@superadmin_required
def note_group_color_update(group_id):
    color = request.form.get("color", "").strip()[:7]
    if not re.fullmatch(r"#[0-9A-Fa-f]{6}", color):
        flash("Choose a valid notes group color.", "error")
    else:
        with connect_db() as db:
            cur = db.execute("UPDATE note_groups SET color=? WHERE id=?", (color, group_id))
            if not cur.rowcount:
                abort(404)
        audit("note_group_color_updated", f"{group_id}:{color}")
        flash("Notes group color updated.", "success")
    return redirect(url_for("note_groups"))


@app.post("/note-groups/<int:group_id>/move")
@superadmin_required
def note_group_move(group_id):
    direction = request.form.get("direction", "")
    if direction not in ("up", "down"):
        abort(400)
    moved = False
    with connect_db() as db:
        ordered = db.execute("SELECT id,sort_order FROM note_groups ORDER BY sort_order,id").fetchall()
        ids = [row["id"] for row in ordered]
        if group_id not in ids:
            abort(404)
        current = ids.index(group_id)
        target = current - 1 if direction == "up" else current + 1
        if 0 <= target < len(ids):
            first, second = ordered[current], ordered[target]
            db.execute("UPDATE note_groups SET sort_order=? WHERE id=?", (second["sort_order"], first["id"]))
            db.execute("UPDATE note_groups SET sort_order=? WHERE id=?", (first["sort_order"], second["id"]))
            moved = True
    if moved:
        audit("note_group_reordered", f"id={group_id}; direction={direction}")
    return redirect(url_for("note_groups"))


@app.post("/note-groups/<int:group_id>/delete")
@superadmin_required
def note_group_delete(group_id):
    with connect_db() as db:
        group = db.execute("SELECT id,name FROM note_groups WHERE id=?", (group_id,)).fetchone()
        if not group:
            abort(404)
        if group["name"] == "Default":
            flash("The Default notes group cannot be deleted.", "error")
            return redirect(url_for("note_groups"))
        default_group = db.execute("SELECT id FROM note_groups WHERE name='Default'").fetchone()
        db.execute("UPDATE notes SET group_id=? WHERE group_id=?", (default_group["id"], group_id))
        db.execute("DELETE FROM note_groups WHERE id=?", (group_id,))
    audit("note_group_deleted", f"id={group_id}; name={group['name']}")
    flash("Notes group deleted. Its entries were moved to Default.", "success")
    return redirect(url_for("note_groups"))


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
        login_blocks = db.execute("SELECT block_id,username,blocked_until,created_at FROM login_security_blocks WHERE blocked_until>? ORDER BY created_at DESC",
                                  (now(),)).fetchall()
    return render_template("security.html", events=[{**dict(row), "jalali_time": jalali_datetime(row["created_at"])} for row in events],
                           rules=[dict(row) for row in rules], allowlist_enabled=bool(setting and setting["value"] == "1"),
                           current_ip=client_ip(), login_blocks=[{**dict(row), "remaining_seconds": login_block_remaining(row["blocked_until"])} for row in login_blocks])


@app.post("/security/login-blocks/<block_id>/unblock")
@superadmin_required
def unblock_login_security_block(block_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]{12,24}", str(block_id or "")):
        abort(404)
    with connect_db() as db:
        row = db.execute("SELECT * FROM login_security_blocks WHERE block_id=?", (block_id,)).fetchone()
        if not row:
            abort(404)
        db.execute("UPDATE login_security_blocks SET blocked_until='',telegram_message_id=NULL,telegram_chat_id='' WHERE block_id=?",
                   (block_id,))
        for scope, column in (("username", "username_hash"), ("ip", "ip_hash"), ("device", "device_hash")):
            if row[column]:
                db.execute("DELETE FROM login_attempt_counters WHERE scope=? AND key_hash=?", (scope, row[column]))
    if row["telegram_message_id"] and row["telegram_chat_id"]:
        telegram_edit_persistent_message(row["telegram_chat_id"], row["telegram_message_id"],
            f"✅ مسدودی ورود {row['username'] or 'این مرورگر'} توسط مدیر سیستم برداشته شد.\nحساب، IP و شناسه مرورگر دوباره مجاز هستند.",
            reply_markup={"inline_keyboard": []})
    audit("login_security_block_released", f"block_id={block_id}; username={row['username']}")
    flash("Login block, IP and browser/device restrictions were released.", "success")
    return redirect(url_for("security_center"))


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
        if re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?", value):
            return value
        # Older updater versions stored the commit SHA instead of a version.
        if release and re.fullmatch(r"[0-9a-f]{40}", value) and value == release["sha"]:
            return release["version"]
    except OSError:
        pass
    try:
        value = (BASE_DIR / "VERSION").read_text(encoding="utf-8").strip().lstrip("v")
        if re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?", value):
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
    try:
        with urlopen(req, timeout=8) as response:
            payload = json.loads(response.read(256_000).decode("utf-8"))
    except HTTPError as exc:
        # GitHub's unauthenticated REST API has a small shared-IP rate limit.
        # If it is exhausted, use the public release page and git's public refs
        # instead; neither requires a personal access token.
        if exc.code not in (403, 429):
            raise
        release_page = Request(
            f"https://github.com/{match.group(1)}/{match.group(2)}/releases/latest",
            headers={"User-Agent": "IP-Archive-Updater"},
        )
        with urlopen(release_page, timeout=12) as response:
            final_url = response.geturl()
        release_match = re.search(r"/releases/tag/([^/?#]+)", final_url)
        if not release_match:
            raise ValueError("GitHub API rate limit was reached and the latest release page did not identify a release tag.") from exc
        fallback_tag = release_match.group(1)
        if not re.fullmatch(r"v?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?", fallback_tag):
            raise ValueError("GitHub API rate limit was reached and the latest release tag is invalid.") from exc
        version = fallback_tag.lstrip("v")
        refs = subprocess.run(
            ["git", "ls-remote", f"https://github.com/{match.group(1)}/{match.group(2)}.git",
             f"refs/tags/{fallback_tag}", f"refs/tags/{fallback_tag}^{{}}"],
            capture_output=True, text=True, timeout=12, check=False,
        )
        if refs.returncode != 0:
            raise ValueError("GitHub API rate limit was reached; could not resolve the latest release commit using public Git refs.") from exc
        resolved = {}
        for line in refs.stdout.splitlines():
            fields = line.split()
            if len(fields) == 2 and re.fullmatch(r"[0-9a-f]{40}", fields[0]):
                resolved[fields[1]] = fields[0]
        sha = resolved.get(f"refs/tags/{fallback_tag}^{{}}", resolved.get(f"refs/tags/{fallback_tag}", ""))
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("GitHub API rate limit was reached; the latest release commit could not be verified.") from exc
        return {"version": version, "sha": sha, "tag": fallback_tag}
    tag = str(payload.get("tag_name", "")).strip()
    version = tag.lstrip("v")
    if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?", version):
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
