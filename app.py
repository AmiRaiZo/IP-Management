import hashlib
import hmac
import base64
import json
from io import BytesIO
import os
import re
import secrets
import sqlite3
import subprocess
import time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from ipaddress import ip_address
from pathlib import Path

import pyotp
from cryptography.fernet import Fernet
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
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
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
two_factor_serializer = URLSafeTimedSerializer(app.secret_key, salt="ip-archive-remember-2fa")
REMEMBER_2FA_COOKIE = "ip_archive_2fa"
REMEMBER_2FA_SECONDS = 24 * 60 * 60
VERSION_FILE = DATA_DIR / "version"
UPDATE_TARGET_FILE = DATA_DIR / "update-target"
UPDATE_TARGET_VERSION_FILE = DATA_DIR / "update-target-version"
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


def init_db():
    with connect_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, created_at TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'admin', totp_secret TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, profile_image TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS groups (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
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
        CREATE INDEX IF NOT EXISTS idx_ips_ip ON ips(ip_address);
        CREATE INDEX IF NOT EXISTS idx_ips_name ON ips(name);
        """)
        # In-place migrations preserve the database created by the first release.
        user_cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
        for name, definition in (("role", "TEXT NOT NULL DEFAULT 'admin'"), ("totp_secret", "TEXT NOT NULL DEFAULT ''"), ("enabled", "INTEGER NOT NULL DEFAULT 1")):
            if name not in user_cols:
                db.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
        if "profile_image" not in user_cols:
            db.execute("ALTER TABLE users ADD COLUMN profile_image TEXT NOT NULL DEFAULT ''")
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


init_db()


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


def remembered_two_factor(user_id):
    token = request.cookies.get(REMEMBER_2FA_COOKIE, "")
    if not token:
        return False
    try:
        payload = two_factor_serializer.loads(token, max_age=REMEMBER_2FA_SECONDS)
        return payload.get("uid") == user_id
    except (BadSignature, SignatureExpired, AttributeError):
        return False


def establish_login(user):
    session.clear()
    # Keep the authenticated session as a browser-session cookie. Passwords
    # are required again after the browser session ends; only 2FA is remembered.
    session.permanent = False
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    audit("login_success")


def superadmin_required(fn):
    @wraps(fn)
    @login_required
    def wrapped(*args, **kwargs):
        if request.user["role"] != "superadmin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


@app.before_request
def csrf_guard():
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
    defaults = {"brand_name": "IP Archive", "brand_subtitle": "NETWORK DIRECTORY", "brand_logo_text": "IP",
                "login_title": "Your network. Your command.", "login_subtitle": "Sign in to securely manage your IP inventory.",
                "accent_color": "#4569e8", "footer_text": "IP Archive · Secure network inventory",
                "app_description": "Keep connection details organized, searchable, and available to the right people.",
                "inventory_title": "IP addresses", "inventory_description": "Keep connection details organized, searchable, and available to the right people.",
                "group_label": "Groups", "user_label": "Users & permissions"}
    for key, value in defaults.items():
        app_settings.setdefault(key, value)
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


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "GET" and request.args.get("reset") == "1":
        session.pop("pending_2fa_user_id", None)
        session.pop("pending_2fa_secret", None)
        session["csrf_token"] = secrets.token_urlsafe(32)
    if request.method == "POST":
        pending_id = session.get("pending_2fa_user_id")
        if pending_id:
            code = re.sub(r"\s", "", request.form.get("code", ""))
            with connect_db() as db:
                user = db.execute("SELECT * FROM users WHERE id=? AND enabled=1", (pending_id,)).fetchone()
            if user and user["totp_secret"] and pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
                establish_login(user)
                response = redirect(safe_login_target())
                response.set_cookie(REMEMBER_2FA_COOKIE, two_factor_serializer.dumps({"uid": user["id"]}),
                                    max_age=REMEMBER_2FA_SECONDS, httponly=True, secure=app.config["SESSION_COOKIE_SECURE"], samesite="Lax", path="/")
                return response
            time.sleep(0.35)
            flash("The verification code is invalid. Try again.", "error")
            return render_template("login.html", stage="verify")

        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE username=? AND enabled=1", (username,)).fetchone()
        if user and password_matches(password, user["password_hash"]) and not user["totp_secret"]:
            session.clear()
            session["pending_2fa_user_id"] = user["id"]
            session["pending_2fa_secret"] = pyotp.random_base32()
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("setup_2fa"))
        if user and password_matches(password, user["password_hash"]):
            if remembered_two_factor(user["id"]):
                establish_login(user)
                return redirect(safe_login_target())
            session.clear()
            session["pending_2fa_user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            return render_template("login.html", stage="verify")
        time.sleep(0.35)
        flash("Invalid username or password.", "error")
    return render_template("login.html", stage="verify" if session.get("pending_2fa_user_id") else "password")


def safe_login_target():
    target = request.args.get("next", "")
    return target if target.startswith("/") and not target.startswith("//") else url_for("index")


@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    authenticated_user = current_user_row() if session.get("user_id") else None
    if authenticated_user and not session.get("setup_2fa_user_id"):
        session["setup_2fa_user_id"] = authenticated_user["id"]
        session["setup_2fa_secret"] = pyotp.random_base32()
    user_id = session.get("pending_2fa_user_id") or session.get("setup_2fa_user_id")
    secret = session.get("pending_2fa_secret") or session.get("setup_2fa_secret")
    if not user_id or not secret:
        return redirect(url_for("login"))
    with connect_db() as db:
        user = db.execute("SELECT id,username FROM users WHERE id=? AND enabled=1", (user_id,)).fetchone()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="IP Archive")
    if request.method == "POST":
        code = re.sub(r"\s", "", request.form.get("code", ""))
        if pyotp.TOTP(secret).verify(code, valid_window=1):
            with connect_db() as db:
                db.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, user_id))
            if authenticated_user:
                session.pop("setup_2fa_user_id", None)
                session.pop("setup_2fa_secret", None)
                audit("two_factor_reconfigured")
                flash("Two-factor authentication settings updated.", "success")
                return redirect(url_for("settings"))
            session.clear()
            # Authentication must remain a browser-session cookie. Only the
            # separate signed 2FA-remember cookie is persistent (24 hours).
            # A permanent Flask session would keep the login alive after the
            # browser is closed and reopened.
            session.permanent = False
            session["user_id"] = user_id
            session["username"] = user["username"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            audit("two_factor_enabled")
            flash("Two-factor authentication is enabled.", "success")
            return redirect(url_for("index"))
        flash("The authenticator code is invalid. Try again.", "error")
    import qrcode
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_data_uri = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")
    return render_template("setup_2fa.html", secret=secret, uri=uri, qr_data_uri=qr_data_uri)


@app.post("/logout")
@login_required
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))


def visible_ips(user):
    with connect_db() as db:
        if user["role"] == "superadmin":
            return db.execute("SELECT ips.*, groups.name AS group_name FROM ips LEFT JOIN groups ON groups.id=ips.group_id ORDER BY ips.ip_address LIMIT 1000").fetchall()
        rows = db.execute("""
          SELECT DISTINCT ips.*, groups.name AS group_name FROM ips
          LEFT JOIN groups ON groups.id=ips.group_id
          LEFT JOIN user_group_access uga ON uga.group_id=ips.group_id AND uga.user_id=?
          LEFT JOIN user_ip_access uia ON uia.ip_id=ips.id AND uia.user_id=?
          WHERE (uga.user_id IS NOT NULL OR uia.can_view=1)
            AND NOT EXISTS (SELECT 1 FROM user_ip_access deny WHERE deny.user_id=? AND deny.ip_id=ips.id AND deny.can_view=0)
          ORDER BY ips.ip_address LIMIT 1000
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
            groups = db.execute("SELECT * FROM groups ORDER BY name").fetchall()
        else:
            groups = db.execute("""
              SELECT DISTINCT groups.* FROM groups
              JOIN ips ON ips.group_id=groups.id
              LEFT JOIN user_group_access uga ON uga.group_id=groups.id AND uga.user_id=?
              LEFT JOIN user_ip_access uia ON uia.ip_id=ips.id AND uia.user_id=?
              WHERE (uga.user_id IS NOT NULL OR uia.can_view=1)
                AND NOT EXISTS (SELECT 1 FROM user_ip_access deny WHERE deny.user_id=? AND deny.ip_id=ips.id AND deny.can_view=0)
              ORDER BY groups.name
            """, (request.user["id"], request.user["id"], request.user["id"])).fetchall()
    return render_template("index.html", ips=rows, q=term, groups=groups, group_filter=group_filter)


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
    if group_id:
        with connect_db() as db:
            if not db.execute("SELECT id FROM groups WHERE id=?", (group_id,)).fetchone():
                return None, "Selected group does not exist."
    if len(submitted_password) > 500:
        return None, "Connection password is too long."
    return {"name": label, "ip": address, "port": port, "username": username,
            "password": vault.encrypt(submitted_password.encode()).decode() if submitted_password else None,
            "notes": notes, "group_id": group_id}, None


@app.route("/ips/new", methods=["GET", "POST"])
@superadmin_required
def ip_new():
    with connect_db() as db:
        groups = db.execute("SELECT * FROM groups ORDER BY name").fetchall()
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
            return redirect(url_for("index"))
    return render_template("ip_form.html", ip=None, groups=groups)


@app.route("/ips/<int:ip_id>/edit", methods=["GET", "POST"])
@superadmin_required
def ip_edit(ip_id):
    with connect_db() as db:
        ip = db.execute("SELECT * FROM ips WHERE id=?", (ip_id,)).fetchone()
        groups = db.execute("SELECT * FROM groups ORDER BY name").fetchall()
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
            return redirect(url_for("index"))
    return render_template("ip_form.html", ip=ip, groups=groups)


@app.post("/ips/<int:ip_id>/delete")
@superadmin_required
def ip_delete(ip_id):
    with connect_db() as db:
        row = db.execute("SELECT ip_address FROM ips WHERE id=?", (ip_id,)).fetchone()
        if row:
            db.execute("DELETE FROM ips WHERE id=?", (ip_id,))
    if row:
        audit("ip_deleted", f"id={ip_id}; ip={row['ip_address']}")
        flash("IP record deleted.", "success")
    return redirect(url_for("index"))


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
                    db.execute("INSERT INTO groups(name,description,created_at) VALUES(?,?,?)", (name, description, now()))
                audit("group_created", name)
                flash("Group created.", "success")
                return redirect(url_for("groups"))
            except sqlite3.IntegrityError:
                flash("A group with that name already exists.", "error")
    with connect_db() as db:
        rows = db.execute("SELECT groups.*, COUNT(ips.id) AS ip_count FROM groups LEFT JOIN ips ON ips.group_id=groups.id GROUP BY groups.id ORDER BY groups.name").fetchall()
    return render_template("groups.html", groups=rows)


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
        elif not password:
            flash("Password cannot be empty.", "error")
        elif role not in ("admin", "superadmin"):
            flash("Invalid role.", "error")
        else:
            secret = pyotp.random_base32()
            try:
                with connect_db() as db:
                    cur = db.execute("INSERT INTO users(username,password_hash,created_at,role,totp_secret,enabled) VALUES(?,?,?,?,?,1)", (username, password_hash(password), now(), role, secret))
                audit("user_created", f"id={cur.lastrowid}; username={username}; role={role}")
                uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="IP Archive")
                flash(f"User created. Configure an authenticator app with this secret: {secret} | URI: {uri}", "success")
                return redirect(url_for("users"))
            except sqlite3.IntegrityError:
                flash("That username already exists.", "error")
    with connect_db() as db:
        rows = db.execute("SELECT id,username,role,enabled,created_at FROM users ORDER BY username").fetchall()
    return render_template("users.html", users=rows)


@app.route("/users/<int:user_id>", methods=["GET", "POST"])
@superadmin_required
def user_edit(user_id):
    with connect_db() as db:
        user = db.execute("SELECT id,username,role,enabled,created_at FROM users WHERE id=?", (user_id,)).fetchone()
        groups = db.execute("SELECT * FROM groups ORDER BY name").fetchall()
        ips = db.execute("SELECT id,ip_address,name,group_id FROM ips ORDER BY ip_address").fetchall()
        allowed_groups = {r[0] for r in db.execute("SELECT group_id FROM user_group_access WHERE user_id=?", (user_id,))}
        ip_rules = {r[0]: r[1] for r in db.execute("SELECT ip_id,can_view FROM user_ip_access WHERE user_id=?", (user_id,))}
    if not user:
        abort(404)
    if request.method == "POST":
        role = request.form.get("role", "admin")
        enabled = 1 if request.form.get("enabled") == "1" else 0
        password = request.form.get("password", "")
        if user_id == request.user["id"] and (role != "superadmin" or not enabled):
            flash("You cannot remove your own superadmin role or disable your own account.", "error")
        elif role not in ("admin", "superadmin"):
            flash("Invalid role.", "error")
        else:
            selected_groups = {int(x) for x in request.form.getlist("groups") if x.isdigit()}
            with connect_db() as db:
                db.execute("UPDATE users SET role=?,enabled=? WHERE id=?", (role, enabled, user_id))
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
    return render_template("user_edit.html", user=user, groups=groups, ips=ips, allowed_groups=allowed_groups, ip_rules=ip_rules)


@app.route("/settings", methods=["GET", "POST"])
@superadmin_required
def settings():
    defaults = {"brand_name": "IP Archive", "brand_subtitle": "NETWORK DIRECTORY", "brand_logo_text": "IP",
                "login_title": "Your network. Your command.", "login_subtitle": "Sign in to securely manage your IP inventory.",
                "accent_color": "#4569e8", "footer_text": "IP Archive · Secure network inventory",
                "app_description": "Keep connection details organized, searchable, and available to the right people.",
                "inventory_title": "IP addresses", "inventory_description": "Keep connection details organized, searchable, and available to the right people.",
                "group_label": "Groups", "user_label": "Users & permissions"}
    if request.method == "POST":
        values = {key: request.form.get(key, "").strip()[:500] for key in defaults}
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", values.get("accent_color", "")):
            flash("Accent color must be a valid six-digit hex color.", "error")
            return redirect(url_for("settings"))
        logo = request.files.get("brand_logo")
        logo_name = ""
        if logo and logo.filename:
            ext = Path(secure_filename(logo.filename)).suffix.lower()
            if ext not in ALLOWED_IMAGE_EXTENSIONS:
                flash("Logo must be PNG, JPG, JPEG, or WEBP.", "error")
                return redirect(url_for("settings"))
            logo_name = "brand" + ext
            logo.save(UPLOAD_DIR / logo_name)
        with connect_db() as db:
            for key, value in values.items():
                db.execute("INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
            if logo_name:
                db.execute("INSERT INTO app_settings(key,value) VALUES('brand_logo',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (logo_name,))
        audit("application_settings_updated")
        flash("Application appearance and text settings saved.", "success")
        return redirect(url_for("settings"))
    with connect_db() as db:
        values = {row["key"]: row["value"] for row in db.execute("SELECT key,value FROM app_settings")}
    for key, value in defaults.items():
        values.setdefault(key, value)
    values.setdefault("brand_logo", "")
    return render_template("settings.html", app_values=values,
                           github_repo=os.environ.get("GITHUB_REPO", os.environ.get("APP_REPO_URL", "not configured")),
                           public_port=os.environ.get("PUBLIC_PORT", os.environ.get("APP_HTTPS_PORT", "443")))


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
            if len(new_password) < 10:
                flash("New password must be at least 10 characters.", "error")
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
            avatar.save(AVATAR_DIR / filename)
            avatar_name = "avatars/" + filename
        with connect_db() as db:
            if new_password:
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(new_password), user["id"]))
            db.execute("UPDATE users SET profile_image=? WHERE id=?", (avatar_name, user["id"]))
        audit("profile_updated")
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)


@app.get("/media/<path:filename>")
@login_required
def media_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)


@app.get("/update")
@superadmin_required
def update_page():
    current = installed_version()
    return render_template("update_app.html", current_version=current,
                           github_repo=os.environ.get("GITHUB_REPO", os.environ.get("APP_REPO_URL", "https://github.com/AmiRaiZo/IP-Management")),
                           public_port=os.environ.get("PUBLIC_PORT", os.environ.get("APP_HTTPS_PORT", "443")))


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
    repo_url = os.environ.get("GITHUB_REPO", os.environ.get("APP_REPO_URL", "https://github.com/AmiRaiZo/IP-Management")).rstrip("/")
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
        log = UPDATE_LOG_FILE.read_text(encoding="utf-8", errors="replace")[-30000:]
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
        if "IP Archive updated successfully." in line:
            progress, phase, done, success = 100, "Update completed successfully", True, True
        elif "Update failed" in line or "Update failed;" in line or "Update process failed" in line:
            done, success, phase = True, False, "Update failed. Check the log output below."
    if not done and log and "Starting update" not in log and progress == 0:
        phase = "Running server update commands…"
    return {"log": log, "progress": progress, "phase": phase, "done": done, "success": success,
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
        UPDATE_LOG_FILE.write_text("Starting update…\n", encoding="utf-8")
        with UPDATE_LOG_FILE.open("a", encoding="utf-8") as log:
            subprocess.Popen(["sudo", "-n", updater], stdout=log, stderr=subprocess.STDOUT,
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
    if "IP Archive updated successfully." in log:
        flash("Update completed successfully. The latest version is now installed.", "success")
        return redirect(url_for("index"))
    if "Update failed" in log or "Update process failed" in log:
        flash("Update failed. Review the server output on the Updates page and try again after fixing the issue.", "error")
        return redirect(url_for("update_page"))
    return redirect(url_for("update_progress"))


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "Invalid request.")), 400


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="The requested page or record was not found."), 404