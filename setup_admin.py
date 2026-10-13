import getpass
import re
import sqlite3
from datetime import datetime, timezone

from app import DB_PATH, password_hash

username = input("Superadmin username: ").strip()
if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,80}", username):
    raise SystemExit("Username must be 3-80 characters using letters, numbers, dot, underscore, @ or hyphen.")
password = getpass.getpass("Superadmin password: ")
confirm = getpass.getpass("Confirm password: ")
if not password or password != confirm:
    raise SystemExit("Password must not be empty and both entries must match.")
with sqlite3.connect(DB_PATH) as db:
    if db.execute("SELECT 1 FROM users WHERE role='superadmin' LIMIT 1").fetchone():
        raise SystemExit("A superadmin account already exists. Use the web user management page instead.")
    db.execute("INSERT INTO users(username,password_hash,created_at,role,totp_secret,enabled) VALUES(?,?,?,'superadmin','',1)",
               (username, password_hash(password), datetime.now(timezone.utc).isoformat(timespec="seconds")))
print("Superadmin account created. On first login, configure an authenticator app to enable two-factor authentication.")
