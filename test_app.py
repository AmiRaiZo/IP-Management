import os
import tempfile
import unittest
from io import BytesIO
from unittest.mock import patch
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
            db.execute("INSERT INTO groups(name,description,created_at,sort_order) VALUES('Default','Default group for IP records',?,0)", (archive.now(),))
            db.execute("DELETE FROM users")
            db.execute("DELETE FROM app_settings WHERE key IN ('public_domain','public_port','update_repository')")
            db.execute("INSERT INTO app_settings(key,value) VALUES('two_factor_mode','per_user') ON CONFLICT(key) DO UPDATE SET value='per_user'")

    def csrf(self):
        with self.client.session_transaction() as sess:
            return sess["csrf_token"]

    def create_user(self, username, role="superadmin", secret=None):
        secret = secret if secret is not None else pyotp.random_base32()
        with archive.connect_db() as db:
            cur = db.execute(
                "INSERT INTO users(username,password_hash,created_at,role,totp_secret,two_factor_enabled,enabled) VALUES(?,?,?,?,?,1,1)",
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
            db.execute("INSERT INTO users(username,password_hash,created_at,role,totp_secret,two_factor_enabled,enabled) VALUES(?,?,?,?,?,1,1)",
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
        with self.client.session_transaction() as sess:
            self.assertFalse(sess.permanent, "Login session must expire when the browser session ends")
        with archive.connect_db() as db:
            user = db.execute("SELECT totp_secret FROM users WHERE username='firstadmin'").fetchone()
        self.assertEqual(user["totp_secret"], secret)

    def test_password_then_totp_and_remember_2fa_for_one_day(self):
        _, secret = self.create_user("two-step")
        self.client.get("/login")
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "two-step", "password": "test-pass"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Authenticator code', response.data)
        self.assertIn(b'WELCOME BACK', response.data)
        self.assertIn(b'two-step', response.data)
        self.assertIn(b'ID #', response.data)
        self.assertNotIn(b'name="password"', response.data)
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": pyotp.TOTP(secret).now()})
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(self.client.get_cookie("ip_management_2fa"))
        response = self.client.get(response.location)
        self.assertIn(b'Welcome back, two-step!', response.data)
        self.assertIn(b'data-auto-dismiss="8000"', response.data)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "two-step", "password": "test-pass"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Authenticator code', response.data)

    def test_global_two_factor_policy_is_superadmin_controlled(self):
        _, secret = self.create_user("policyadmin", role="superadmin")
        self.assertEqual(self.login("policyadmin", secret).status_code, 302)
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"name=\"two_factor_mode\"", response.data)
        self.assertIn(b'data-settings-tab="security">Two-factor authentication</a>', response.data)
        self.assertEqual(response.data.count(b'id="security" data-settings-section="security"'), 1)
        self.assertNotIn(b'data-settings-tab="two-factor"', response.data)
        self.assertNotIn(b'<h2>Security</h2>', response.data)
        response = self.client.post("/settings/security", data={
            "csrf_token": self.csrf(), "two_factor_mode": "off",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(archive.two_factor_mode(), "off")

        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        _, user_secret = self.create_user("policyuser", role="admin")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "policyuser", "password": "test-pass",
        })
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("setup-2fa", response.location)

    def test_regular_user_cannot_change_two_factor_configuration(self):
        _, secret = self.create_user("ordinary", role="admin")
        self.assertEqual(self.login("ordinary", secret).status_code, 302)
        response = self.client.get("/setup-2fa")
        self.assertEqual(response.status_code, 403)
        response = self.client.post("/settings/security", data={
            "csrf_token": self.csrf(), "two_factor_mode": "off",
        })
        self.assertEqual(response.status_code, 403)

    def test_shared_authenticator_policy_requires_site_code_for_every_user(self):
        _, admin_secret = self.create_user("shared-admin", role="superadmin")
        self.assertEqual(self.login("shared-admin", admin_secret).status_code, 302)
        response = self.client.post("/settings/security", data={
            "csrf_token": self.csrf(), "action": "generate_shared_secret",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            shared = db.execute("SELECT value FROM app_settings WHERE key='shared_two_factor_secret'").fetchone()["value"]
        response = self.client.post("/settings/security", data={
            "csrf_token": self.csrf(), "two_factor_mode": "shared",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(archive.two_factor_mode(), "shared")
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "shared-admin", "password": "test-pass",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("setup-2fa", response.location)
        response = self.client.get("/setup-2fa")
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/setup-2fa", data={
            "csrf_token": self.csrf(), "code": pyotp.TOTP(shared).now(),
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            enrolled = db.execute("SELECT two_factor_enrolled FROM users WHERE username='shared-admin'").fetchone()
        self.assertEqual(enrolled["two_factor_enrolled"], 1)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "shared-admin", "password": "test-pass",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Authenticator code", response.data)
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "code": pyotp.TOTP(shared).now(),
        })
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as sess:
            self.assertTrue(sess.get("two_factor_verified"))

    def test_superadmin_controls_per_user_two_factor_setting(self):
        admin_id, admin_secret = self.create_user("peruser-admin", role="superadmin")
        self.assertEqual(self.login("peruser-admin", admin_secret).status_code, 302)
        user_id, _ = self.create_user("selected-user", role="admin", secret="")
        response = self.client.get(f"/users/{user_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="two_factor_enabled"', response.data)
        response = self.client.post(f"/users/{user_id}", data={
            "csrf_token": self.csrf(), "role": "admin", "enabled": "1",
            "two_factor_enabled": "1", "password": "",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            row = db.execute("SELECT two_factor_enabled FROM users WHERE id=?", (user_id,)).fetchone()
        self.assertEqual(row["two_factor_enabled"], 1)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "selected-user", "password": "test-pass",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("setup-2fa", response.location)

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
        self.assertIn(b"device-secret", response.data)

    def test_default_group_and_password_visibility_and_copy_are_available(self):
        _, secret = self.create_user("passwordarchive")
        self.assertEqual(self.login("passwordarchive", secret).status_code, 302)
        form = self.client.get("/ips/new").get_data(as_text=True)
        self.assertIn('data-toggle-password="password"', form)
        self.assertRegex(form, r'<option value="\d+" selected>Default</option>')
        response = self.client.post("/ips/new", data={
            "csrf_token": self.csrf(), "name": "Archive entry", "ip_address": "192.0.2.55",
            "username": "vault-user", "password": "super-secret", "port": "22",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            row = db.execute("SELECT group_id,password_enc FROM ips WHERE ip_address='192.0.2.55'").fetchone()
            default_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
        self.assertEqual(row["group_id"], default_id)
        self.assertNotEqual(row["password_enc"], "super-secret")
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("super-secret", page)
        self.assertIn("<th>Password</th>", page)
        self.assertIn('data-copy-value="super-secret"', page)
        edit_page = self.client.get("/ips/1/edit").get_data(as_text=True)
        self.assertIn('id="password" name="password" type="password"', edit_page)
        self.assertIn('value="super-secret"', edit_page)
        self.assertIn('data-copy-value="super-secret"', edit_page)
        response = self.client.post("/settings/directory", data={
            "csrf_token": self.csrf(), "show_ip_passwords": "1",
        })
        self.assertEqual(response.status_code, 302)
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("<th>Password</th>", page)
        self.assertIn("super-secret", page)
        response = self.client.post("/settings/directory", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 302)
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("super-secret", page)
        self.assertIn("<th>Password</th>", page)

    def test_non_superadmin_never_receives_saved_ip_passwords(self):
        user_id, secret = self.create_user("limited-password-view", role="admin")
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
            ip_id = db.execute(
                "INSERT INTO ips(name,ip_address,username,password_enc,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                ("Restricted router", "192.0.2.99", "operator", archive.vault.encrypt(b"hidden-device-secret").decode(), group_id, "root", archive.now(), archive.now()),
            ).lastrowid
            db.execute("INSERT INTO user_group_access(user_id,group_id) VALUES(?,?)", (user_id, group_id))
        self.assertEqual(self.login("limited-password-view", secret).status_code, 302)
        directory = self.client.get("/")
        self.assertEqual(directory.status_code, 200)
        self.assertNotIn(b"hidden-device-secret", directory.data)
        self.assertNotIn(b"<th>Password</th>", directory.data)
        edit = self.client.get(f"/ips/{ip_id}/edit")
        self.assertEqual(edit.status_code, 403)
        self.assertNotIn(b"hidden-device-secret", edit.data)

    def test_superadmin_can_grant_password_visibility_to_selected_user(self):
        _, root_secret = self.create_user("password-permission-root")
        self.assertEqual(self.login("password-permission-root", root_secret).status_code, 302)
        user_id, user_secret = self.create_user("password-reader", role="admin")
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
            db.execute(
                "INSERT INTO ips(name,ip_address,username,password_enc,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                ("Permitted router", "192.0.2.100", "operator", archive.vault.encrypt(b"allowed-secret").decode(), group_id, "root", archive.now(), archive.now()),
            )
        edit_page = self.client.get(f"/users/{user_id}")
        self.assertEqual(edit_page.status_code, 200)
        self.assertIn(b'name="can_view_passwords"', edit_page.data)
        response = self.client.post(f"/users/{user_id}", data={
            "csrf_token": self.csrf(), "role": "admin", "enabled": "1",
            "can_view_passwords": "1", "groups": [str(group_id)],
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            row = db.execute("SELECT can_view_passwords FROM users WHERE id=?", (user_id,)).fetchone()
        self.assertEqual(row["can_view_passwords"], 1)

        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.assertEqual(self.login("password-reader", user_secret).status_code, 302)
        directory = self.client.get("/")
        self.assertEqual(directory.status_code, 200)
        self.assertIn(b"<th>Password</th>", directory.data)
        self.assertIn(b"allowed-secret", directory.data)
        self.assertIn(b'data-copy-value="allowed-secret"', directory.data)

    def test_update_success_button_says_ok(self):
        _, secret = self.create_user("update-success-user")
        self.assertEqual(self.login("update-success-user", secret).status_code, 302)
        response = self.client.get("/?update=success")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="close-update-success">OK</button>', response.data)
        self.assertNotIn(b"Back to IP addresses", response.data)

    def test_superadmin_can_reorder_groups_and_order_is_persisted(self):
        _, secret = self.create_user("grouporder")
        self.assertEqual(self.login("grouporder", secret).status_code, 302)
        for name in ("Alpha", "Bravo", "Charlie"):
            self.client.post("/groups", data={"csrf_token": self.csrf(), "name": name})
        with archive.connect_db() as db:
            before = [row["name"] for row in db.execute("SELECT name FROM groups ORDER BY sort_order, id")]
            bravo_id = db.execute("SELECT id FROM groups WHERE name='Bravo'").fetchone()["id"]
        self.assertEqual(before, ["Default", "Alpha", "Bravo", "Charlie"])
        response = self.client.post(f"/groups/{bravo_id}/move", data={
            "csrf_token": self.csrf(), "direction": "up",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            after = [row["name"] for row in db.execute("SELECT name FROM groups ORDER BY sort_order, id")]
        self.assertEqual(after, ["Default", "Bravo", "Alpha", "Charlie"])
        response = self.client.get("/groups")
        self.assertLess(response.data.index(b"Bravo"), response.data.index(b"Alpha"))

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

    def test_login_copy_is_minimal_and_password_toggle_is_present(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("<h1>Welcome back</h1>", page)
        self.assertIn('data-toggle-password="password"', page)
        for removed in ("Encrypted access", "Sign in to securely manage your IP inventory.",
                        "Your network.", "Your command.", "Continue securely",
                        "IP Archive · Secure network inventory", "STEP 02 · SECURITY CHECK",
                        "One last step.", "Enter the 6-digit code from your authenticator app to continue."):
            self.assertNotIn(removed, page)

    def test_profile_is_not_in_sidebar_navigation_but_account_row_links_to_it(self):
        _, secret = self.create_user("profilelink")
        self.login("profilelink", secret)
        response = self.client.get("/")
        page = response.get_data(as_text=True)
        self.assertIn('class="profile-account" href="/profile"', page)
        self.assertNotIn(">My profile</a>", page)

    def test_login_and_two_factor_pages_have_only_minimal_copy(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<h1>Welcome back</h1>", response.data)
        self.assertNotIn(b"IP Archive", response.data)
        _, secret = self.create_user("minimalverify")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "minimalverify", "password": "test-pass",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<h1>Verification code</h1>", response.data)
        self.assertNotIn(b"IP Archive", response.data)
        for removed in (b"Encrypted access", b"STEP 02", b"One last step.",
                        b"Your network. Your command.", b"Secure network inventory"):
            self.assertNotIn(removed, response.data)

    def test_profile_requires_login_and_password_change_is_secure(self):
        response = self.client.get("/profile")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

        _, secret = self.create_user("profile-secure", role="admin")
        self.assertEqual(self.login("profile-secure", secret).status_code, 302)
        response = self.client.get("/profile")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Change password", response.data)
        response = self.client.post("/profile", data={
            "csrf_token": self.csrf(), "current_password": "wrong-password",
            "new_password": "long-new-password", "confirm_password": "long-new-password",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            user = db.execute("SELECT password_hash FROM users WHERE username='profile-secure'").fetchone()
        self.assertTrue(archive.password_matches("test-pass", user["password_hash"]))
        response = self.client.post("/profile", data={
            "csrf_token": self.csrf(), "current_password": "test-pass",
            "new_password": "long-new-password", "confirm_password": "long-new-password",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            user = db.execute("SELECT password_hash FROM users WHERE username='profile-secure'").fetchone()
        self.assertTrue(archive.password_matches("long-new-password", user["password_hash"]))

    def test_profile_avatar_upload_renders_in_sidebar_and_is_served(self):
        user_id, secret = self.create_user("avatar-user", role="admin")
        self.assertEqual(self.login("avatar-user", secret).status_code, 302)
        response = self.client.post("/profile", data={
            "csrf_token": self.csrf(),
            "avatar": (BytesIO(b"test-image-bytes"), "avatar.png"),
        }, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            user = db.execute("SELECT profile_image FROM users WHERE id=?", (user_id,)).fetchone()
        self.assertEqual(user["profile_image"], f"avatars/user-{user_id}.png")
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn('src="/media/avatars/user-', page)
        self.assertIn('class="profile-dot"', page)
        profile_page = self.client.get("/profile").get_data(as_text=True)
        self.assertIn('id="avatar"', profile_page)
        image_response = self.client.get("/media/" + user["profile_image"])
        self.assertEqual(image_response.status_code, 200)
        self.assertEqual(image_response.data, b"test-image-bytes")

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


    def test_update_status_ignores_sudo_audit_warning_until_real_failure(self):
        user_id, _ = self.create_user("status-admin")
        with patch.object(archive, "UPDATE_LOG_FILE") as log_file:
            log_file.read_text.return_value = "\n".join([
                "Starting update…",
                "sudo: unable to send audit message: Operation not permitted",
                "PROGRESS:12:Downloading repository and checking target version",
            ])
            with self.client.session_transaction() as sess:
                sess["user_id"] = user_id
                sess["two_factor_verified"] = True
            response = self.client.get("/update/status")
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertFalse(payload["done"])
            self.assertEqual(payload["progress"], 12)

    def test_update_status_marks_python_traceback_as_failure(self):
        user_id, _ = self.create_user("status-traceback-admin")
        with patch.object(archive, "UPDATE_LOG_FILE") as log_file:
            log_file.read_text.return_value = "\n".join([
                "Starting update…",
                "PROGRESS:80:Verifying Gunicorn as the actual service user",
                "Traceback (most recent call last):",
                "ModuleNotFoundError: No module named 'gunicorn.app'",
            ])
            with self.client.session_transaction() as sess:
                sess["user_id"] = user_id
                sess["two_factor_verified"] = True
            response = self.client.get("/update/status")
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertTrue(payload["done"])
            self.assertFalse(payload["success"])
            self.assertEqual(payload["phase"], "Update failed")

    def test_superadmin_can_save_public_domain_and_port_settings(self):
        _, secret = self.create_user("deployment-settings")
        self.assertEqual(self.login("deployment-settings", secret).status_code, 302)
        with patch.object(archive.subprocess, "run", return_value=archive.subprocess.CompletedProcess([], 0, "", "")) as run:
            response = self.client.post("/settings/deployment", data={
                "csrf_token": self.csrf(), "action": "public",
                "public_domain": "archive.example.com", "public_port": "8443",
            })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Applying your new address", response.data)
        self.assertIn("--no-block", run.call_args.args[0])
        with archive.connect_db() as db:
            settings = {r["key"]: r["value"] for r in db.execute(
                "SELECT key,value FROM app_settings WHERE key IN ('public_domain','public_port')")}
        self.assertNotEqual(settings.get("public_domain"), "archive.example.com", "the privileged reconfiguration service persists settings only after the new endpoint passes health checks")

    def test_failed_server_reconfiguration_does_not_save_new_address(self):
        _, secret = self.create_user("failed-reconfigure")
        self.assertEqual(self.login("failed-reconfigure", secret).status_code, 302)
        with archive.connect_db() as db:
            db.execute("INSERT INTO app_settings(key,value) VALUES('public_domain','old.example.com') ON CONFLICT(key) DO UPDATE SET value='old.example.com'")
            db.execute("INSERT INTO app_settings(key,value) VALUES('public_port','443') ON CONFLICT(key) DO UPDATE SET value='443'")
        with patch.object(archive.subprocess, "run", return_value=archive.subprocess.CompletedProcess([], 1, "", "DNS is not pointing here")):
            response = self.client.post("/settings/deployment", data={
                "csrf_token": self.csrf(), "action": "public",
                "public_domain": "new.example.com", "public_port": "8443",
            })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            settings = {r["key"]: r["value"] for r in db.execute(
                "SELECT key,value FROM app_settings WHERE key IN ('public_domain','public_port')")}
        self.assertEqual(settings, {"public_domain": "old.example.com", "public_port": "443"})

    def test_update_repository_requires_current_password(self):
        _, secret = self.create_user("repository-settings")
        self.assertEqual(self.login("repository-settings", secret).status_code, 302)
        payload = {
            "csrf_token": self.csrf(), "action": "repository",
            "update_repository": "https://github.com/example/private-archive",
        }
        payload["current_password"] = "wrong-password"
        response = self.client.post("/settings/deployment", data=payload)
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            self.assertIsNone(db.execute("SELECT value FROM app_settings WHERE key='update_repository'").fetchone())
        payload["current_password"] = "test-pass"
        response = self.client.post("/settings/deployment", data=payload)
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            saved = db.execute("SELECT value FROM app_settings WHERE key='update_repository'").fetchone()
        self.assertEqual(saved["value"], "https://github.com/example/private-archive")

if __name__ == "__main__":
    unittest.main()
