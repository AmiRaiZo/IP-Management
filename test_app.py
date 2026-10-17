import os
import tempfile
import re
import shutil
import subprocess
from pathlib import Path
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
            db.execute("DELETE FROM user_recovery_codes")
            db.execute("DELETE FROM telegram_login_codes")
            db.execute("DELETE FROM security_events")
            db.execute("DELETE FROM ip_access_rules")
            db.execute("DELETE FROM app_settings WHERE key='ip_allowlist_enabled'")
            db.execute("DELETE FROM app_settings WHERE key IN ('public_domain','public_port','update_repository', 'telegram_bot_token_enc', 'telegram_chat_id_enc', 'telegram_webhook_secret_enc', 'telegram_conversation_state_enc')")
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

    def test_untrusted_host_returns_400_without_error_template_routing(self):
        with patch.dict(archive.app.config, {"TRUSTED_HOSTS": ["archive.example.com"]}):
            response = self.client.get("/", headers={"Host": "127.0.0.1:443"})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"400", response.data)
        self.assertNotIn(b"Internal Server Error", response.data)

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
        self.assertTrue(user["totp_secret"].startswith("fernet:"))
        self.assertNotEqual(user["totp_secret"], secret)
        self.assertEqual(archive.decrypt_authenticator_secret(user["totp_secret"]), secret)

    def test_password_then_totp_and_remember_2fa_for_one_day(self):
        _, secret = self.create_user("two-step")
        self.client.get("/login")
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "two-step", "password": "test-pass"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Authenticator code', response.data)
        self.assertNotIn(b'or recovery code', response.data)
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
        self.assertNotIn(b'or recovery code', response.data)

    def test_recovery_codes_are_shown_once_hashed_and_single_use(self):
        user_id, secret = self.create_user("recovery-user")
        self.assertEqual(self.login("recovery-user", secret).status_code, 302)
        response = self.client.post("/profile/recovery-codes", data={
            "csrf_token": self.csrf(), "current_password": "test-pass", "current_code": pyotp.TOTP(secret).now(),
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        import re
        codes = re.findall(r"<code>([A-F0-9]{20})</code>", response.get_data(as_text=True))
        self.assertEqual(len(codes), 10)
        with archive.connect_db() as db:
            stored = db.execute("SELECT code_hash FROM user_recovery_codes WHERE user_id=?", (user_id,)).fetchall()
        self.assertEqual(len(stored), 10)
        self.assertNotIn(codes[0], " ".join(row["code_hash"] for row in stored))

        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "recovery-user", "password": "test-pass"})
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": codes[0]})
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=?", (user_id,)).fetchone()[0], 9)

        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        self.client.post("/login", data={"csrf_token": self.csrf(), "username": "recovery-user", "password": "test-pass"})
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": codes[0]})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"verification code is invalid", response.data)

    def test_recovery_code_generation_requires_current_authenticator(self):
        _, secret = self.create_user("recovery-reauth")
        self.assertEqual(self.login("recovery-reauth", secret).status_code, 302)
        response = self.client.post("/profile/recovery-codes", data={
            "csrf_token": self.csrf(), "current_password": "test-pass", "current_code": "000000",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            count = db.execute("SELECT COUNT(*) FROM user_recovery_codes").fetchone()[0]
        self.assertEqual(count, 0)

    def test_telegram_command_issues_two_minute_single_use_superadmin_code(self):
        user_id, secret = self.create_user("telegram-code-admin", role="superadmin")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        with patch.object(archive, "telegram_send") as send:
            archive.handle_telegram_update({"message": {
                "chat": {"id": 12345, "type": "private"}, "text": "/login_code"
            }})
        self.assertTrue(send.called)
        message = send.call_args.args[1]
        import re
        match = re.search(r"(?<!\d)(\d{6})(?!\d)", message)
        self.assertIsNotNone(match)
        code = match.group(1)
        with archive.connect_db() as db:
            row = db.execute("SELECT code_hash,expires_at FROM telegram_login_codes WHERE user_id=?", (user_id,)).fetchone()
        self.assertIsNotNone(row)
        self.assertNotIn(code, row["code_hash"])

        self.client.get("/login")
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "telegram-code-admin", "password": "test-pass"})
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": code})
        self.assertEqual(response.status_code, 302)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        self.client.post("/login", data={"csrf_token": self.csrf(), "username": "telegram-code-admin", "password": "test-pass"})
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": code})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"verification code is invalid", response.data)

    def test_telegram_menu_has_english_2fa_button_and_callback_issues_code(self):
        user_id, _ = self.create_user("telegram-button-admin", role="superadmin")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        with patch.object(archive, "telegram_send") as send, patch.object(archive, "telegram_api", return_value={"ok": True}):
            archive.telegram_menu("12345")
            menu_markup = send.call_args.args[2]
            self.assertEqual(menu_markup["inline_keyboard"][1][0]["text"], "🔐 2FA code")
            self.assertEqual(menu_markup["inline_keyboard"][1][0]["callback_data"], "telegram_2fa_code")
            archive.handle_telegram_update({"callback_query": {
                "id": "callback-2fa", "data": "telegram_2fa_code",
                "message": {"message_id": 10, "chat": {"id": 12345, "type": "private"}},
            }})
        messages = [str(call.args[1]) for call in send.call_args_list]
        code_messages = [message for message in messages if "Login code for IP Management" in message]
        self.assertEqual(len(code_messages), 1)
        self.assertRegex(code_messages[0], r"\b\d{6}\b")
        self.assertIn("<code>", code_messages[0])
        self.assertNotIn("2 minutes", code_messages[0])
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telegram_login_codes WHERE user_id=?", (user_id,)).fetchone()[0], 1)

    def test_telegram_login_code_expired_code_is_rejected(self):
        user_id, _ = self.create_user("expired-telegram-code", role="superadmin")
        code = "123456"
        with archive.connect_db() as db:
            db.execute("INSERT INTO telegram_login_codes(user_id,code_hash,expires_at,created_at) VALUES(?,?,?,?)",
                       (user_id, archive.telegram_login_code_hash(user_id, code), "2000-01-01T00:00:00+00:00", archive.now()))
        self.assertFalse(archive.consume_telegram_login_code(user_id, code))
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telegram_login_codes").fetchone()[0], 0)

    def test_authenticated_session_without_verified_2fa_is_rejected_server_side(self):
        user_id, _ = self.create_user("cannot-skip-2fa")
        self.client.get("/login")
        with self.client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = "cannot-skip-2fa"
            sess["csrf_token"] = "test-csrf"
            sess.pop("two_factor_verified", None)
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

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
            shared_stored = db.execute("SELECT value FROM app_settings WHERE key='shared_two_factor_secret'").fetchone()["value"]
        self.assertTrue(shared_stored.startswith("fernet:"))
        shared = archive.decrypt_authenticator_secret(shared_stored)
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
        self.assertNotIn(b"or recovery code", response.data)
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

    def test_ip_directory_values_are_boxed_and_columns_centered(self):
        _, secret = self.create_user("directory-layout")
        self.assertEqual(self.login("directory-layout", secret).status_code, 302)
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
            db.execute(
                "INSERT INTO ips(name,ip_address,port,username,password_enc,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("Layout router", "192.0.2.55", 8291, "netadmin", archive.vault.encrypt(b"layout-secret").decode(), group_id, "root", archive.now(), archive.now()),
            )
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn('aria-label="Copy port"><code>8291</code></button>', page)
        self.assertIn('aria-label="Copy username"><code>netadmin</code></button>', page)
        self.assertIn('aria-label="Copy IP address"><code>192.0.2.55</code></button>', page)
        self.assertIn('<th>Name</th>', page)
        self.assertIn('.inventory-panel .table-scroll table th:first-child,.inventory-panel .table-scroll table td:first-child{text-align:left}', (archive.BASE_DIR / 'static' / 'style.css').read_text(encoding='utf-8'))
        self.assertIn('.inventory-panel .table-scroll .record-name{justify-content:flex-start}', (archive.BASE_DIR / 'static' / 'style.css').read_text(encoding='utf-8'))
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
        image_data = BytesIO()
        archive.Image.new("RGB", (2, 2), (20, 120, 220)).save(image_data, format="PNG")
        image_data.seek(0)
        response = self.client.post("/profile", data={
            "csrf_token": self.csrf(),
            "avatar": (image_data, "avatar.png"),
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
        with archive.Image.open(BytesIO(image_response.data)) as sanitized:
            self.assertEqual(sanitized.format, "PNG")
            self.assertEqual(sanitized.size, (2, 2))

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
            "update_repository": "https://github.com/AmiRaiZo/IP-Management",
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
        self.assertEqual(saved["value"], "https://github.com/amiraizo/ip-management")

    def test_untrusted_update_repository_is_rejected(self):
        _, secret = self.create_user("repository-allowlist")
        self.assertEqual(self.login("repository-allowlist", secret).status_code, 302)
        response = self.client.post("/settings/deployment", data={
            "csrf_token": self.csrf(), "action": "repository",
            "update_repository": "https://github.com/someone-else/malicious-repo",
            "current_password": "test-pass",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            saved = db.execute("SELECT value FROM app_settings WHERE key='update_repository'").fetchone()
        self.assertIsNone(saved)

    def test_new_accounts_require_strong_password_and_default_to_per_user_mfa(self):
        _, secret = self.create_user("account-policy-admin")
        self.assertEqual(self.login("account-policy-admin", secret).status_code, 302)
        self.client.post("/users", data={
            "csrf_token": self.csrf(), "username": "weak-new-user", "password": "short", "role": "admin",
        })
        with archive.connect_db() as db:
            self.assertIsNone(db.execute("SELECT id FROM users WHERE username='weak-new-user'").fetchone())
        self.client.post("/users", data={
            "csrf_token": self.csrf(), "username": "strong-new-user", "password": "correct-horse-battery", "role": "admin",
        })
        with archive.connect_db() as db:
            row = db.execute("SELECT two_factor_enabled FROM users WHERE username='strong-new-user'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["two_factor_enabled"], 1)

    def test_failed_login_is_logged_without_storing_password(self):
        self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "attacker-name", "password": "do-not-store-this-secret",
        })
        self.assertEqual(response.status_code, 200)
        with archive.connect_db() as db:
            event = db.execute("SELECT * FROM security_events WHERE event_type='login' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(event["attempted_username"], "attacker-name")
        self.assertEqual(event["result"], "failed")
        self.assertEqual(event["remote_ip"], "127.0.0.1")
        self.assertNotIn("do-not-store-this-secret", str(dict(event)))
        self.assertRegex(event["detail"], r"guess fingerprint=[0-9a-f]{16}")

    @patch.object(archive, "send_telegram_security_alert", return_value=True)
    def test_failed_login_sends_only_metadata_and_guess_fingerprint_to_telegram(self, telegram):
        self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "telegram-guess", "password": "never-send-this-password",
        })
        self.assertEqual(response.status_code, 200)
        telegram.assert_called_once()
        alert = telegram.call_args.args[0]
        self.assertIn("telegram-guess", alert)
        self.assertIn("127.0.0.1", alert)
        self.assertIn("Password guess fingerprint:", alert)
        self.assertIn("Failed sign-in to IP Management", alert)
        self.assertIn("Host:", alert)
        self.assertIn("Time (Iran):", alert)
        self.assertNotIn("never-send-this-password", alert)

    @patch.object(archive, "send_telegram_security_alert", return_value=True)
    def test_failed_2fa_sends_alert_without_authenticator_code(self, telegram):
        _, secret = self.create_user("bad-2fa-alert")
        self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "bad-2fa-alert", "password": "test-pass",
        })
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "code": "123456",
        })
        self.assertEqual(response.status_code, 200)
        telegram.assert_called_once()
        alert = telegram.call_args.args[0]
        self.assertIn("Failed second-factor verification", alert)
        self.assertIn("Reason: Invalid 2FA code", alert)
        self.assertIn("bad-2fa-alert", alert)
        self.assertNotIn("123456", alert)

    def test_telegram_credentials_are_encrypted_and_superadmin_only(self):
        _, secret = self.create_user("telegram-admin", role="superadmin")
        self.assertEqual(self.login("telegram-admin", secret).status_code, 302)
        response = self.client.post("/settings/telegram", data={
            "csrf_token": self.csrf(), "telegram_bot_token": "123456:abcdefghijklmnopqrstuvwxyzABCDE_12345",
            "telegram_chat_id": "-1001234567890", "action": "save",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            token_row = db.execute("SELECT value FROM app_settings WHERE key='telegram_bot_token_enc'").fetchone()
            chat_row = db.execute("SELECT value FROM app_settings WHERE key='telegram_chat_id_enc'").fetchone()
        self.assertNotIn("123456:abcdefghijklmnopqrstuvwxyzABCDE_12345", token_row["value"])
        self.assertNotIn("-1001234567890", chat_row["value"])
        self.assertEqual(archive.secure_setting("telegram_chat_id_enc"), "-1001234567890")
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        _, user_secret = self.create_user("telegram-regular", role="admin")
        with patch.object(archive, "send_telegram_security_alert", return_value=True):
            self.assertEqual(self.login("telegram-regular", user_secret).status_code, 302)
        response = self.client.post("/settings/telegram", data={"csrf_token": self.csrf(), "action": "save"})
        self.assertEqual(response.status_code, 403)

    def test_shared_2fa_seed_is_not_repeatedly_disclosed_by_settings(self):
        _, secret = self.create_user("one-time-secret-admin", role="superadmin")
        self.assertEqual(self.login("one-time-secret-admin", secret).status_code, 302)
        response = self.client.post("/settings/security", data={
            "csrf_token": self.csrf(), "action": "generate_shared_secret",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            seed_stored = db.execute("SELECT value FROM app_settings WHERE key='shared_two_factor_secret'").fetchone()["value"]
        seed = archive.decrypt_authenticator_secret(seed_stored)
        self.assertTrue(seed_stored.startswith("fernet:"))
        first_view = self.client.get("/settings")
        self.assertEqual(first_view.status_code, 200)
        self.assertIn(seed.encode(), first_view.data)
        second_view = self.client.get("/settings")
        self.assertEqual(second_view.status_code, 200)
        self.assertNotIn(seed.encode(), second_view.data)

    def test_legacy_plaintext_totp_seeds_are_readable_for_migration_and_encrypt_on_write(self):
        legacy_seed = pyotp.random_base32()
        self.assertEqual(archive.decrypt_authenticator_secret(legacy_seed), legacy_seed)
        encrypted = archive.encrypt_authenticator_secret(legacy_seed)
        self.assertTrue(encrypted.startswith("fernet:"))
        self.assertNotIn(legacy_seed, encrypted)
        self.assertEqual(archive.decrypt_authenticator_secret(encrypted), legacy_seed)

    def test_database_startup_migrates_legacy_plaintext_totp_seeds(self):
        user_seed = pyotp.random_base32()
        shared_seed = pyotp.random_base32()
        with archive.connect_db() as db:
            db.execute("INSERT INTO users(username,password_hash,created_at,role,totp_secret,two_factor_enabled,enabled) VALUES(?,?,?,?,?,1,1)",
                       ("legacy-seed-user", archive.password_hash("test-pass"), archive.now(), "admin", user_seed))
            db.execute("INSERT INTO app_settings(key,value) VALUES('shared_two_factor_secret',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (shared_seed,))
        archive.init_db()
        with archive.connect_db() as db:
            stored_user_seed = db.execute("SELECT totp_secret FROM users WHERE username='legacy-seed-user'").fetchone()["totp_secret"]
            stored_shared_seed = db.execute("SELECT value FROM app_settings WHERE key='shared_two_factor_secret'").fetchone()["value"]
        self.assertTrue(stored_user_seed.startswith("fernet:"))
        self.assertTrue(stored_shared_seed.startswith("fernet:"))
        self.assertEqual(archive.decrypt_authenticator_secret(stored_user_seed), user_seed)
        self.assertEqual(archive.decrypt_authenticator_secret(stored_shared_seed), shared_seed)

    def test_readable_txt_backup_requires_password_and_contains_data_without_auth_secrets(self):
        _, secret = self.create_user("backup-admin", role="superadmin")
        self.assertEqual(self.login("backup-admin", secret).status_code, 302)
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
            db.execute("INSERT INTO ips(name,ip_address,port,username,password_enc,notes,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       ("Router A", "192.0.2.10", 22, "root", archive.vault.encrypt(b"device-secret").decode(), "test-note", group_id, "backup-admin", archive.now(), archive.now()))
            db.execute("INSERT INTO app_settings(key,value) VALUES('shared_two_factor_secret',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("TOPSECRETSEED",))
        bad = self.client.post("/settings/export.txt", data={"csrf_token": self.csrf(), "current_password": "wrong-password"})
        self.assertEqual(bad.status_code, 403)
        response = self.client.post("/settings/export.txt", data={"csrf_token": self.csrf(), "current_password": "test-pass"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response.content_type)
        self.assertIn("attachment;", response.headers.get("Content-Disposition", ""))
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        body = response.data.decode("utf-8-sig")
        self.assertIn("READABLE TEXT DATA BACKUP", body)
        self.assertIn("192.0.2.10", body)
        self.assertIn("device-secret", body)
        self.assertIn("[REDACTED: secret]", body)
        self.assertNotIn("TOPSECRETSEED", body)
        self.assertNotIn("test-pass", body)
        with archive.connect_db() as db:
            account_hash = db.execute("SELECT password_hash FROM users WHERE username='backup-admin'").fetchone()["password_hash"]
        self.assertNotIn(account_hash, body)
        self.assertIn("--- FILE: app.py ---", body)
        self.assertIn("--- FILE: templates/settings.html ---", body)

    def test_security_and_backup_routes_reject_regular_user_and_missing_csrf(self):
        _, secret = self.create_user("route-guard-admin", role="admin")
        self.assertEqual(self.login("route-guard-admin", secret).status_code, 302)
        self.assertEqual(self.client.get("/security").status_code, 403)
        self.assertEqual(self.client.get("/settings").status_code, 403)
        self.assertEqual(self.client.post("/settings/export.txt", data={"current_password": "test-pass"}).status_code, 400)

    def test_protected_json_endpoints_and_security_headers(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("default-src 'self'", response.headers.get("Content-Security-Policy", ""))
        for path in ("/security", "/settings/deployment/status", "/update/check", "/update/status"):
            with self.subTest(path=path):
                guarded = self.client.get(path)
                self.assertIn(guarded.status_code, (302, 403))
                self.assertNotIn(b"shared_two_factor_secret", guarded.data)

    def test_repeated_failed_logins_are_rate_limited(self):
        self.client.get("/login")
        for _ in range(8):
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "unknown-account", "password": "wrong",
            })
            self.assertEqual(response.status_code, 200)
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "unknown-account", "password": "wrong",
        })
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers.get("Retry-After"), "900")

    def test_2fa_enrollment_guesses_are_rate_limited_too(self):
        user_id, _ = self.create_user("enrollment-throttle")
        self.client.get("/login")
        with self.client.session_transaction() as sess:
            sess["pending_2fa_user_id"] = user_id
            sess["pending_2fa_secret"] = pyotp.random_base32()
            sess["csrf_token"] = "enrollment-csrf"
        for _ in range(8):
            response = self.client.post("/setup-2fa", data={"csrf_token": "enrollment-csrf", "code": "not-a-code"})
            self.assertEqual(response.status_code, 200)
        response = self.client.post("/setup-2fa", data={"csrf_token": "enrollment-csrf", "code": "not-a-code"})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers.get("Retry-After"), "900")

    def test_telegram_webhook_rejects_missing_or_wrong_secret(self):
        with archive.app.test_request_context("/telegram/webhook"):
            archive.save_secure_setting("telegram_webhook_secret_enc", "expected-secret")
        response = self.client.post("/telegram/webhook", json={"message": {"text": "ربات"}})
        self.assertEqual(response.status_code, 403)
        response = self.client.post("/telegram/webhook", json={"message": {"text": "ربات"}},
                                    headers={"X-Telegram-Bot-Api-Secret-Token": "wrong-secret"})
        self.assertEqual(response.status_code, 403)

    def test_telegram_webhook_rejects_unconfigured_chat(self):
        archive.save_secure_setting("telegram_webhook_secret_enc", "expected-secret")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        with patch.object(archive, "telegram_menu") as menu:
            response = self.client.post("/telegram/webhook", json={
                "message": {"chat": {"id": 99999, "type": "private"}, "text": "ربات"}
            }, headers={"X-Telegram-Bot-Api-Secret-Token": "expected-secret"})
        self.assertEqual(response.status_code, 200)
        menu.assert_not_called()

    def test_telegram_add_flow_requests_password_and_selects_group_with_buttons(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        callback = {"callback_query": {"id": "cb1", "data": "ip_add", "message": {
            "message_id": 1, "chat": {"id": 12345, "type": "private"}}}}
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
        with patch.object(archive, "telegram_send") as send, patch.object(archive, "telegram_api", return_value={"ok": True}):
            archive.handle_telegram_update(callback)
            for value in ("Router via bot", "192.0.2.55", "22", "admin", "device-secret",):
                archive.handle_telegram_update({"message": {"chat": {"id": 12345, "type": "private"}, "text": value}})
            group_prompt = next(call for call in send.call_args_list if "choose a group" in call.args[1])
            self.assertEqual(group_prompt.args[2]["inline_keyboard"][0][0]["callback_data"], f"ip_group:{group_id}")
            archive.handle_telegram_update({"callback_query": {"id": "cb2", "data": f"ip_group:{group_id}", "message": {
                "message_id": 2, "chat": {"id": 12345, "type": "private"}}}})
            archive.handle_telegram_update({"message": {"chat": {"id": 12345, "type": "private"}, "text": "test record"}})
        with archive.connect_db() as db:
            row = db.execute("SELECT name,ip_address,port,username,password_enc,notes,group_id,created_by FROM ips WHERE ip_address='192.0.2.55'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["name"], "Router via bot")
        self.assertEqual(row["port"], 22)
        self.assertEqual(row["username"], "admin")
        self.assertEqual(archive.vault.decrypt(row["password_enc"].encode()).decode(), "device-secret")
        self.assertEqual(row["group_id"], group_id)
        self.assertEqual(row["notes"], "test record")
        self.assertEqual(row["created_by"], "telegram-bot")
        self.assertTrue(any("IP record saved in IP Management" in call.args[1] for call in send.call_args_list))

    def test_authenticator_page_loads_profile_image_with_initial_fallback(self):
        with archive.connect_db() as db:
            user_id = db.execute("INSERT INTO users(username,password_hash,created_at,role,totp_secret,two_factor_enabled,enabled,profile_image) VALUES(?,?,?,?,?,1,1,?)",
                                 ("avatar-login", archive.password_hash("test-pass"), archive.now(), "superadmin", pyotp.random_base32(), "avatars/missing-profile.png")).lastrowid
        self.client.get("/login")
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "avatar-login", "password": "test-pass"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'login-user-avatar-image', response.data)
        self.assertIn(b'login-user-avatar-fallback', response.data)
        self.assertIn(b'Authenticator code', response.data)
        self.assertNotIn(b'or recovery code', response.data)

    def test_telegram_login_code_message_is_minimal_and_formatted_for_copying(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        self.create_user("telegram-code-admin", role="superadmin")
        callback = {"callback_query": {"id": "cb-code", "data": "telegram_2fa_code", "message": {
            "message_id": 1, "chat": {"id": 12345, "type": "private"}}}}
        with patch.object(archive, "telegram_send") as send, patch.object(archive, "telegram_api", return_value={"ok": True}):
            archive.handle_telegram_update(callback)
        message = next(call for call in send.call_args_list if "Login code for IP Management" in call.args[1])
        self.assertRegex(message.args[1], r"^Login code for IP Management:\n<code>\d{6}</code>$")
        self.assertEqual(message.kwargs.get("parse_mode"), "HTML")
        self.assertNotIn("Expires", message.args[1])
        self.assertNotIn("IP Archive", message.args[1])

    def test_telegram_search_results_never_include_saved_connection_password(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
            db.execute("INSERT INTO ips(name,ip_address,port,username,password_enc,notes,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       ("Search Router", "192.0.2.77", 22, "root", archive.vault.encrypt(b"do-not-send-device-secret").decode(), "sample", group_id, "test", archive.now(), archive.now()))
        archive.telegram_set_state({"mode": "search", "step": "query"})
        with patch.object(archive, "telegram_send") as send:
            archive.handle_telegram_update({"message": {"chat": {"id": 12345, "type": "private"}, "text": "Search Router"}})
        output = "\n".join(str(call.args[1]) for call in send.call_args_list)
        self.assertIn("192.0.2.77", output)
        self.assertNotIn("do-not-send-device-secret", output)

    def test_application_ip_block_does_not_require_os_firewall(self):
        _, secret = self.create_user("ip-rules-admin")
        self.assertEqual(self.login("ip-rules-admin", secret).status_code, 302)
        response = self.client.post("/security/rules", data={
            "csrf_token": self.csrf(), "rule_type": "block", "network": "203.0.113.55", "note": "test rule",
        })
        self.assertEqual(response.status_code, 302)
        blocked = self.client.get("/login", environ_overrides={"REMOTE_ADDR": "203.0.113.55"})
        self.assertEqual(blocked.status_code, 403)
        with archive.connect_db() as db:
            row = db.execute("SELECT network,rule_type FROM ip_access_rules WHERE network='203.0.113.55/32'").fetchone()
        self.assertEqual((row["network"], row["rule_type"]), ("203.0.113.55/32", "block"))

    def test_security_center_is_superadmin_only_and_shows_jalali_time(self):
        _, secret = self.create_user("security-admin")
        self.assertEqual(self.login("security-admin", secret).status_code, 302)
        with archive.app.test_request_context("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}):
            archive.security_event("login", "sample-user", "failed", "test event")
        response = self.client.get("/security")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security & login logs", response.data)
        self.assertIn(b"Not stored by design", response.data)
        with archive.app.test_request_context("/", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}):
            self.assertEqual(archive.jalali_datetime("2026-03-21T00:00:00+00:00")[:10], "1405/01/01")

if __name__ == "__main__":
    unittest.main()


class ReleaseScriptSyntaxTests(unittest.TestCase):
    def test_deployment_shell_scripts_have_valid_bash_syntax(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is not installed on this platform")
        root = Path(__file__).resolve().parent
        for name in ("install.sh", "station-archive-update"):
            with self.subTest(script=name):
                script = root / name
                self.assertTrue(script.is_file(), f"missing deployment script: {name}")
                result = subprocess.run([bash, "-n", str(script)], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, f"{name}: {result.stderr}")

    def test_updater_refreshes_installed_helper_after_validation(self):
        updater = Path(__file__).with_name("station-archive-update").read_text(encoding="utf-8")
        self.assertIn('bash -n "$TMP/station-archive-update.new"', updater)
        self.assertIn('install -o root -g root -m 0750 "$TMP/station-archive-update.new" /usr/local/sbin/station-archive-update', updater)
        self.assertIn("station-archive-update; do", updater)
        bootstrap = updater.index('Refreshing the privileged updater from the verified release')
        deploy = updater.index("rsync -a --delete --exclude='.git/'")
        self.assertLess(bootstrap, deploy, "updater must refresh itself before deployment steps")
        self.assertIn('UPDATER_BOOTSTRAPPED=1 exec /usr/local/sbin/station-archive-update', updater)
        self.assertIn('bash -n "$BOOTSTRAP_TMP/updater.new"', updater)
