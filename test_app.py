import os
import tempfile
import unittest
from datetime import datetime, timezone

from cryptography.fernet import Fernet
import pyotp

TEMP_DATA = tempfile.TemporaryDirectory()
os.environ["SECRET_KEY"] = "test-only-secret-key"
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
os.environ["STATION_ARCHIVE_DATA"] = TEMP_DATA.name
os.environ["COOKIE_SECURE"] = "0"

import app as archive


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        archive.app.config["TESTING"] = True
        self.client = archive.app.test_client()
        with archive.connect_db() as db:
            db.execute("DELETE FROM user_ip_access")
            db.execute("DELETE FROM user_group_access")
            db.execute("DELETE FROM ips")
            db.execute("DELETE FROM groups")
            db.execute("DELETE FROM users")

    def csrf(self):
        with self.client.session_transaction() as sess:
            return sess["csrf_token"]

    def create_user(self, username, role="superadmin", secret=None):
        secret = secret if secret is not None else pyotp.random_base32()
        with archive.connect_db() as db:
            cur = db.execute(
                "INSERT INTO users(username,password_hash,created_at,role,totp_secret,enabled) VALUES(?,?,?,?,?,1)",
                (username, archive.password_hash("test-pass"), archive.now(), role, secret),
            )
            return cur.lastrowid, secret

    def login(self, username, secret, password="test-pass"):
        self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": username, "password": password,
        })
        if response.status_code == 200 and b'name="code"' in response.data:
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "code": pyotp.TOTP(secret).now(),
            })
        return response

    def test_private_pages_require_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_first_login_requires_enrollment_and_enables_totp(self):
        with archive.connect_db() as db:
            db.execute("INSERT INTO users(username,password_hash,created_at,role,totp_secret,enabled) VALUES(?,?,?,?,?,1)",
                       ("firstadmin", archive.password_hash("pw"), archive.now(), "superadmin", ""))
        self.client.get("/login")
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "firstadmin", "password": "pw"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("setup-2fa", response.location)
        response = self.client.get("/setup-2fa")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"data:image/png;base64,", response.data)
        with self.client.session_transaction() as sess:
            secret = sess["pending_2fa_secret"]
        response = self.client.post("/setup-2fa", data={"csrf_token": self.csrf(), "code": pyotp.TOTP(secret).now()})
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            user = db.execute("SELECT totp_secret FROM users WHERE username='firstadmin'").fetchone()
        self.assertEqual(user["totp_secret"], secret)

    def test_password_then_totp_and_remember_2fa_for_one_day(self):
        _, secret = self.create_user("two-step")
        self.client.get("/login")
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "two-step", "password": "test-pass"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Authenticator code', response.data)
        self.assertNotIn(b'name="password"', response.data)
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": pyotp.TOTP(secret).now()})
        self.assertEqual(response.status_code, 302)
        self.assertIsNotNone(self.client.get_cookie("ip_archive_2fa"))
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "two-step", "password": "test-pass"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/", response.location)

    def test_superadmin_can_create_group_and_ip_password_is_encrypted(self):
        _, secret = self.create_user("rootadmin")
        self.assertEqual(self.login("rootadmin", secret).status_code, 302)
        response = self.client.post("/groups", data={"csrf_token": self.csrf(), "name": "Routers", "description": "Core devices"})
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            group = db.execute("SELECT id FROM groups WHERE name='Routers'").fetchone()
        response = self.client.post("/ips/new", data={
            "csrf_token": self.csrf(), "name": "Core Router", "ip_address": "192.0.2.10",
            "port": "443", "username": "operator", "password": "device-secret", "group_id": str(group["id"]),
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            row = db.execute("SELECT * FROM ips WHERE ip_address='192.0.2.10'").fetchone()
        self.assertIsNotNone(row)
        self.assertNotEqual(row["password_enc"], "device-secret")
        self.assertEqual(archive.vault.decrypt(row["password_enc"].encode()).decode(), "device-secret")
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"192.0.2.10", response.data)
        self.assertNotIn(b"device-secret", response.data)

    def test_group_access_and_explicit_ip_deny(self):
        user_id, secret = self.create_user("limited", "admin")
        with archive.connect_db() as db:
            group_id = db.execute("INSERT INTO groups(name,created_at) VALUES(?,?)", ("Field", archive.now())).lastrowid
            ip_id = db.execute("INSERT INTO ips(name,ip_address,group_id,created_at,updated_at) VALUES(?,?,?,?,?)",
                                ("Field Router", "198.51.100.5", group_id, archive.now(), archive.now())).lastrowid
            db.execute("INSERT INTO user_group_access(user_id,group_id) VALUES(?,?)", (user_id, group_id))
        self.assertEqual(self.login("limited", secret).status_code, 302)
        response = self.client.get("/")
        self.assertIn(b"198.51.100.5", response.data)
        with archive.connect_db() as db:
            db.execute("INSERT INTO user_ip_access(user_id,ip_id,can_view) VALUES(?,?,0)", (user_id, ip_id))
        response = self.client.get("/")
        self.assertNotIn(b"198.51.100.5", response.data)

    def test_superadmin_pages_render(self):
        _, secret = self.create_user("adminpages")
        self.login("adminpages", secret)
        for path in ("/", "/groups", "/users", "/settings", "/update", "/ips/new"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])

    def test_legacy_database_migrates_records_and_promotes_first_user(self):
        with archive.connect_db() as db:
            db.execute("CREATE TABLE stations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, ip_address TEXT NOT NULL, port INTEGER, username TEXT NOT NULL, password_enc TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
            db.execute("INSERT INTO stations VALUES(1,'Legacy router','203.0.113.10',22,'root','encrypted','old record','old-admin',?,?)", (archive.now(), archive.now()))
            db.execute("INSERT INTO users(username,password_hash,created_at,role,totp_secret,enabled) VALUES(?,?,?,?,?,1)",
                       ("legacyadmin", archive.password_hash("pw"), archive.now(), "admin", ""))
        archive.init_db()
        with archive.connect_db() as db:
            ip = db.execute("SELECT * FROM ips WHERE ip_address='203.0.113.10'").fetchone()
            user = db.execute("SELECT role FROM users WHERE username='legacyadmin'").fetchone()
        self.assertIsNotNone(ip)
        self.assertEqual(ip["name"], "Legacy router")
        self.assertEqual(user["role"], "superadmin")


if __name__ == "__main__":
    unittest.main()