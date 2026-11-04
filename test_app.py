import os
import tempfile
import re
import shutil
import subprocess
from pathlib import Path
import unittest
from io import BytesIO
from unittest.mock import MagicMock, patch
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
        archive.app.config["LOGIN_APPROVAL_REQUIRED"] = False
        self.client = archive.app.test_client()
        with archive.connect_db() as db:
            db.execute("DELETE FROM user_ip_access")
            db.execute("DELETE FROM user_group_access")
            db.execute("DELETE FROM ips")
            db.execute("DELETE FROM accounts")
            db.execute("DELETE FROM notes")
            db.execute("DELETE FROM account_groups")
            db.execute("DELETE FROM note_groups")
            db.execute("DELETE FROM groups")
            db.execute("INSERT INTO groups(name,description,created_at,sort_order) VALUES('Default','Default group for IP records',?,0)", (archive.now(),))
            db.execute("INSERT INTO account_groups(name,description,created_at,sort_order) VALUES('Default','Default group for saved accounts',?,0)", (archive.now(),))
            db.execute("INSERT INTO note_groups(name,description,color,created_at,sort_order) VALUES('Default','Default group for saved notes','#65758b',?,0)", (archive.now(),))
            db.execute("DELETE FROM users")
            db.execute("DELETE FROM login_approval_requests")
            db.execute("DELETE FROM user_recovery_codes")
            db.execute("DELETE FROM telegram_login_codes")
            db.execute("DELETE FROM security_events")
            db.execute("DELETE FROM login_attempt_counters")
            db.execute("DELETE FROM login_security_blocks")
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

    def test_user_can_log_out_from_mandatory_2fa_setup_and_must_enroll_again(self):
        with archive.connect_db() as db:
            db.execute(
                "INSERT INTO users(username,password_hash,created_at,role,totp_secret,two_factor_enabled,enabled) "
                "VALUES(?,?,?,?,?,1,1)",
                ("pending-logout-user", archive.password_hash("test-pass"), archive.now(), "admin", ""),
            )

        self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "pending-logout-user", "password": "test-pass",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("/setup-2fa", response.location)

        setup_page = self.client.get("/setup-2fa")
        self.assertEqual(setup_page.status_code, 200)
        self.assertIn(b"Log out", setup_page.data)
        self.assertIn(b"name=" + b'"csrf_token"', setup_page.data)

        response = self.client.post("/cancel-2fa-setup", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)
        with self.client.session_transaction() as sess:
            self.assertNotIn("pending_2fa_user_id", sess)
            self.assertNotIn("pending_2fa_secret", sess)
            self.assertNotIn("user_id", sess)

        # Logging out is not a way around the required authenticator: next sign-in starts setup again.
        self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "pending-logout-user", "password": "test-pass",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("/setup-2fa", response.location)

        # The POST action is protected by the global CSRF check.
        response = self.client.post("/cancel-2fa-setup", data={"csrf_token": "invalid"})
        self.assertEqual(response.status_code, 400)

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
        remembered_cookie = self.client.get_cookie("ip_management_2fa")
        self.assertIsNotNone(remembered_cookie)
        response = self.client.get(response.location)
        self.assertIn(b'Welcome back, two-step!', response.data)
        self.assertIn(b'data-auto-dismiss="8000"', response.data)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "two-step", "password": "test-pass"})
        self.assertEqual(response.status_code, 302, "A trusted device must not be prompted for a second factor again within 24 hours")
        response = self.client.get(response.location)
        self.assertIn(b'Welcome back, two-step!', response.data)

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
        # Explicitly remove the trusted-device cookie so this test exercises recovery-code login.
        self.client.delete_cookie("ip_management_2fa")
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

    def test_telegram_command_issues_and_consumes_a_single_use_superadmin_code(self):
        user_id, _ = self.create_user("telegram-code-admin", role="superadmin")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        with patch.object(archive, "telegram_send") as send:
            archive.handle_telegram_update({"message": {
                "chat": {"id": 12345, "type": "private"}, "text": "/login_code"
            }})
        self.assertTrue(send.called)
        message = send.call_args.args[1]
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
        with patch.object(archive, "send_login_success_alert") as success_alert:
            response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": code})
        self.assertEqual(response.status_code, 302)
        success_alert.assert_called_once()
        self.assertTrue(success_alert.call_args.kwargs.get("telegram_code_used"))
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telegram_login_codes WHERE user_id=?", (user_id,)).fetchone()[0], 0)

        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.get("/login")
        self.client.post("/login", data={"csrf_token": self.csrf(), "username": "telegram-code-admin", "password": "test-pass"})
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": code})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"verification code is invalid", response.data)

    def test_telegram_menu_includes_display_all_groups_button(self):
        with patch.object(archive, "telegram_send") as send:
            archive.telegram_menu("12345")
        markup = send.call_args.args[2]
        self.assertEqual(markup["inline_keyboard"][1][0]["text"], "📂 IP groups")
        self.assertEqual(markup["inline_keyboard"][1][0]["callback_data"], "ip_groups")

    def test_telegram_menu_commands_accept_plain_and_bot_qualified_commands(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        commands = ("ربات", "/start", "/menu", "/start@IPManagementBot", "/menu@IPManagementBot")
        with patch.object(archive, "telegram_menu") as menu:
            for command in commands:
                archive.handle_telegram_update({"message": {
                    "chat": {"id": 12345, "type": "private"}, "text": command
                }})
        self.assertEqual(menu.call_count, len(commands))

    def test_telegram_settings_re_registers_webhook_using_saved_credentials(self):
        _, secret = self.create_user("telegram-webhook-repair-admin", role="superadmin")
        self.assertEqual(self.login("telegram-webhook-repair-admin", secret).status_code, 302)
        archive.save_secure_setting("telegram_bot_token_enc", "123456:abcdefghijklmnopqrstuvwxyzABCDE_12345")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        archive.save_secure_setting("telegram_webhook_secret_enc", "saved-webhook-secret")
        webhook_url = "https://archive.example.com/telegram/webhook"
        with patch.dict(os.environ, {"APP_PUBLIC_URL": "https://archive.example.com"}), \
             patch.object(archive, "telegram_api", return_value={"ok": True, "result": {"url": webhook_url}}) as api, \
             patch.object(archive, "send_telegram_security_alert", return_value=True):
            response = self.client.post("/settings/telegram", data={
                "csrf_token": self.csrf(), "action": "test",
            })
        self.assertEqual(response.status_code, 302)
        api.assert_any_call("setWebhook", {
            "url": webhook_url,
            "secret_token": "saved-webhook-secret",
            "allowed_updates": ["message", "callback_query"],
        })
        api.assert_any_call("getWebhookInfo", {})

    def test_telegram_settings_surfaces_webhook_registration_failure(self):
        _, secret = self.create_user("telegram-webhook-failure-admin", role="superadmin")
        self.assertEqual(self.login("telegram-webhook-failure-admin", secret).status_code, 302)
        archive.save_secure_setting("telegram_bot_token_enc", "123456:abcdefghijklmnopqrstuvwxyzABCDE_12345")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        archive.save_secure_setting("telegram_webhook_secret_enc", "saved-webhook-secret")
        with patch.dict(os.environ, {"APP_PUBLIC_URL": "https://archive.example.com"}), \
             patch.object(archive, "telegram_api", return_value={}), \
             patch.object(archive, "send_telegram_security_alert", return_value=True):
            response = self.client.post("/settings/telegram", data={
                "csrf_token": self.csrf(), "action": "test",
            })
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as sess:
            messages = [message for _, message in sess.get("_flashes", [])]
        self.assertTrue(any("Interactive Telegram commands are not active" in message for message in messages))

    def test_telegram_settings_surfaces_webhook_delivery_errors(self):
        _, secret = self.create_user("telegram-webhook-delivery-admin", role="superadmin")
        self.assertEqual(self.login("telegram-webhook-delivery-admin", secret).status_code, 302)
        archive.save_secure_setting("telegram_bot_token_enc", "123456:abcdefghijklmnopqrstuvwxyzABCDE_12345")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        archive.save_secure_setting("telegram_webhook_secret_enc", "saved-webhook-secret")
        webhook_url = "https://archive.example.com/telegram/webhook"
        responses = [
            {"ok": True, "result": True},
            {"ok": True, "result": {
                "url": webhook_url,
                "last_error_message": "Wrong response from the webhook: 403 Forbidden",
            }},
        ]
        with patch.dict(os.environ, {"APP_PUBLIC_URL": "https://archive.example.com"}), \
             patch.object(archive, "telegram_api", side_effect=responses), \
             patch.object(archive, "send_telegram_security_alert", return_value=True):
            response = self.client.post("/settings/telegram", data={
                "csrf_token": self.csrf(), "action": "test",
            })
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as sess:
            messages = [message for _, message in sess.get("_flashes", [])]
        self.assertTrue(any("403 Forbidden" in message for message in messages))

    def test_telegram_group_browser_replaces_screens_and_shows_ip_details_only_on_selection(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        encrypted = archive.vault.encrypt(b"Router-Secret-9").decode()
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM groups LIMIT 1").fetchone()[0]
            db.execute("INSERT INTO groups(name,description,created_at,sort_order) VALUES(?,?,?,?)",
                       ("Remote Sites", "Remote network devices", archive.now(), 1))
            remote_id = db.execute("SELECT id FROM groups WHERE name='Remote Sites'").fetchone()[0]
            db.execute("INSERT INTO ips(name,ip_address,port,username,password_enc,notes,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       ("Branch Router", "192.0.2.77", "8291", "netadmin", encrypted, "Branch office", remote_id, "test", archive.now(), archive.now()))
            ip_id = db.execute("SELECT id FROM ips WHERE name='Branch Router'").fetchone()[0]
            db.execute("INSERT INTO ips(name,ip_address,port,username,password_enc,notes,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       ("Core Switch", "192.0.2.88", "22", "admin", "", "Core network", group_id, "test", archive.now(), archive.now()))
        with patch.object(archive, "telegram_api", return_value={"ok": True, "result": {"message_id": 501}}) as api:
            archive.handle_telegram_update({"callback_query": {"id": "browse-groups", "data": "ip_groups",
                "message": {"message_id": 101, "chat": {"id": 12345, "type": "private"}}}})
            group_calls = [call.args[1] for call in api.call_args_list if call.args[0] == "editMessageText"]
            self.assertEqual(len(group_calls), 1)
            self.assertIn("Choose a group", group_calls[-1]["text"])
            group_buttons = group_calls[-1]["reply_markup"]["inline_keyboard"]
            self.assertIn("Remote Sites", [button["text"] for row in group_buttons for button in row])
            self.assertEqual(archive.telegram_get_state()["mode"], "browse_groups")

            archive.handle_telegram_update({"callback_query": {"id": "browse-ips", "data": f"ip_browse_group:{remote_id}",
                "message": {"message_id": 101, "chat": {"id": 12345, "type": "private"}}}})
            ip_calls = [call.args[1] for call in api.call_args_list if call.args[0] == "editMessageText"]
            ip_screen = ip_calls[-1]
            self.assertIn("Branch Router", [button["text"] for row in ip_screen["reply_markup"]["inline_keyboard"] for button in row])
            self.assertNotIn("192.0.2.77", ip_screen["text"])
            self.assertNotIn("192.0.2.77", str(ip_screen["reply_markup"]))
            self.assertEqual(archive.telegram_get_state()["mode"], "browse_ips")

            archive.handle_telegram_update({"callback_query": {"id": "browse-details", "data": f"ip_browse_ip:{remote_id}:{ip_id}",
                "message": {"message_id": 101, "chat": {"id": 12345, "type": "private"}}}})
            detail_calls = [call.args[1] for call in api.call_args_list if call.args[0] == "editMessageText"]
            detail = detail_calls[-1]
            self.assertIn("📌 Name: Branch Router", detail["text"])
            self.assertNotIn("<code>Branch Router</code>", detail["text"])
            self.assertIn("<code>192.0.2.77</code>", detail["text"])
            self.assertIn("<code>8291</code>", detail["text"])
            self.assertIn("<code>netadmin</code>", detail["text"])
            self.assertIn("<code>Router-Secret-9</code>", detail["text"])
            self.assertIn("Branch office", detail["text"])
            self.assertEqual(detail["parse_mode"], "HTML")
            self.assertNotIn("copy_text", str(detail.get("reply_markup", {})))
            self.assertEqual(detail["message_id"], 101)
            self.assertEqual(archive.telegram_get_state()["mode"], "browse_detail")

    def test_telegram_one_time_code_alert_contains_user_code_and_has_no_ack_or_menu_button(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        with patch.object(archive, "send_telegram_security_alert", return_value=True) as alert:
            self.assertTrue(archive.send_login_success_alert(
                "one-time-admin", "203.0.113.81", telegram_code_used=True, telegram_code_value="246810"
            ))
        text = alert.call_args.args[0]
        self.assertIn("one-time-admin", text)
        self.assertIn("Code used: 246810", text)
        self.assertIn("cannot be reused", text)
        self.assertEqual(alert.call_args.kwargs.get("delete_after"), 0)
        self.assertNotIn("reply_markup", alert.call_args.kwargs)

        with (
            patch.object(archive, "telegram_api", return_value={"ok": True}),
            patch.object(archive, "telegram_edit_persistent_message") as replace,
        ):
            archive.handle_telegram_update({"callback_query": {
                "id": "confirm-one-time", "data": "ack_telegram_login",
                "message": {"message_id": 222, "text": text, "chat": {"id": 12345, "type": "private"}},
            }})
        replace.assert_not_called()


    def test_telegram_account_vault_supports_add_search_browse_edit_and_confirmed_delete(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM account_groups WHERE name='Default'").fetchone()["id"]

        with (
            patch.object(archive, "telegram_api", return_value={"ok": True}),
            patch.object(archive, "telegram_send") as send,
            patch.object(archive, "telegram_replace_message") as replace,
            patch.object(archive, "audit"),
        ):
            archive.handle_telegram_update({"callback_query": {
                "id": "account-add", "data": "account_add",
                "message": {"message_id": 10, "chat": {"id": 12345, "type": "private"}},
            }})
            for message_id, value in ((11, "Bot Work Email"), (12, "-"),
                                       (13, "bot-work@example.com"), (14, "vault-password-42")):
                archive.handle_telegram_update({"message": {
                    "message_id": message_id, "chat": {"id": 12345, "type": "private"}, "text": value,
                }})
            group_prompt = next(call for call in send.call_args_list if "choose an account group" in call.args[1].lower())
            self.assertEqual(group_prompt.args[2]["inline_keyboard"][0][0]["callback_data"], f"account_group:{group_id}")
            archive.handle_telegram_update({"callback_query": {
                "id": "account-add-group", "data": f"account_group:{group_id}",
                "message": {"message_id": 15, "chat": {"id": 12345, "type": "private"}},
            }})
            with archive.connect_db() as db:
                row = db.execute("SELECT * FROM accounts WHERE name='Bot Work Email'").fetchone()
            self.assertIsNotNone(row)
            account_id = row["id"]
            encrypted_password = row["password_enc"]
            self.assertNotEqual(encrypted_password, "vault-password-42")
            self.assertEqual(archive.vault.decrypt(encrypted_password.encode()).decode(), "vault-password-42")
            self.assertEqual(row["email"], "bot-work@example.com")
            self.assertEqual(row["group_id"], group_id)

            archive.handle_telegram_update({"callback_query": {
                "id": "account-search", "data": "account_search",
                "message": {"message_id": 20, "chat": {"id": 12345, "type": "private"}},
            }})
            archive.handle_telegram_update({"message": {
                "message_id": 21, "chat": {"id": 12345, "type": "private"}, "text": "bot-work@example.com",
            }})
            self.assertEqual(archive.telegram_get_state()["mode"], "account_search_results")
            archive.handle_telegram_update({"callback_query": {
                "id": "account-select-search", "data": f"account_search_item:{account_id}",
                "message": {"message_id": 22, "chat": {"id": 12345, "type": "private"}},
            }})
            detail = replace.call_args.args[2]
            self.assertIn("Bot Work Email", detail)
            self.assertIn("bot-work@example.com", detail)
            self.assertIn("vault-password-42", detail)
            markup = replace.call_args.args[3]
            self.assertIn(f"account_edit:{account_id}", str(markup))
            self.assertIn(f"account_delete:{account_id}", str(markup))

            archive.handle_telegram_update({"callback_query": {
                "id": "account-edit", "data": f"account_edit:{account_id}",
                "message": {"message_id": 23, "chat": {"id": 12345, "type": "private"}},
            }})
            for message_id, value in ((24, "Bot Work Email Updated"), (25, "-"), (26, "-"), (27, "-")):
                archive.handle_telegram_update({"message": {
                    "message_id": message_id, "chat": {"id": 12345, "type": "private"}, "text": value,
                }})
            edit_state = archive.telegram_get_state()
            self.assertEqual(edit_state["mode"], "account_edit")
            self.assertEqual(edit_state["step"], "group")
            archive.handle_telegram_update({"callback_query": {
                "id": "account-edit-keep-group", "data": "account_edit_keep_group",
                "message": {"message_id": 28, "chat": {"id": 12345, "type": "private"}},
            }})
            with archive.connect_db() as db:
                edited = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
            self.assertEqual(edited["name"], "Bot Work Email Updated")
            self.assertEqual(edited["password_enc"], encrypted_password, "Edit should keep password when '-' is sent")

            archive.telegram_show_account("12345", 29, account_id, source="browse")
            archive.handle_telegram_update({"callback_query": {
                "id": "account-delete", "data": f"account_delete:{account_id}",
                "message": {"message_id": 29, "chat": {"id": 12345, "type": "private"}},
            }})
            self.assertEqual(archive.telegram_get_state()["mode"], "account_delete_confirm")
            archive.handle_telegram_update({"callback_query": {
                "id": "account-delete-confirm", "data": f"account_delete_confirm:{account_id}",
                "message": {"message_id": 29, "chat": {"id": 12345, "type": "private"}},
            }})
            with archive.connect_db() as db:
                self.assertIsNone(db.execute("SELECT id FROM accounts WHERE id=?", (account_id,)).fetchone())


    def test_telegram_menu_has_account_vault_and_2fa_actions(self):
        user_id, _ = self.create_user("telegram-button-admin", role="superadmin")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        with patch.object(archive, "telegram_send") as send, patch.object(archive, "telegram_api", return_value={"ok": True}):
            archive.telegram_menu("12345")
            menu_markup = send.call_args.args[2]
            buttons = [button for row in menu_markup["inline_keyboard"] for button in row]
            callbacks = {button["callback_data"] for button in buttons}
            labels = {button["text"] for button in buttons}
            self.assertIn("telegram_2fa_code", callbacks)
            self.assertIn("account_add", callbacks)
            self.assertIn("account_search", callbacks)
            self.assertIn("account_groups", callbacks)
            self.assertIn("🔐 2FA code", labels)
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

    def test_telegram_search_shows_decrypted_saved_password(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        encrypted = archive.vault.encrypt(b"Saved-Pass-42").decode()
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM groups LIMIT 1").fetchone()[0]
            db.execute("INSERT INTO ips(name,ip_address,port,username,password_enc,notes,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                       ("Office Router", "192.0.2.10", "8291", "admin", encrypted, "Core router", group_id, "test", archive.now(), archive.now()))
        archive.telegram_set_state({"mode": "search", "step": "query"})
        with patch.object(archive, "telegram_send") as send:
            archive.handle_telegram_update({"message": {
                "message_id": 77, "chat": {"id": 12345, "type": "private"}, "text": "Office Router"
            }})
        result_text = send.call_args.args[1]
        self.assertIn("Name: Office Router", result_text)
        self.assertNotIn("<code>Office Router</code>", result_text)
        self.assertIn("Password: <code>Saved-Pass-42</code>", result_text)
        self.assertIn("Username: <code>admin</code>", result_text)
        self.assertIn("IP: <code>192.0.2.10</code>", result_text)
        self.assertEqual(send.call_args.kwargs.get("parse_mode"), "HTML")
        self.assertNotIn("copy_text", str(send.call_args.args[2]))
        self.assertEqual(archive.telegram_get_state(), {})

    def test_telegram_add_flow_deletes_user_input_messages(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        archive.telegram_set_state({"mode": "add", "step": "password", "data": {
            "name": "Router", "ip_address": "192.0.2.2", "port": "22", "username": "admin"
        }})
        with patch.object(archive, "telegram_api", return_value={}) as api, patch.object(archive, "telegram_send"):
            archive.handle_telegram_update({"message": {
                "message_id": 81, "chat": {"id": 12345, "type": "private"}, "text": "sensitive-password"
            }})
        self.assertTrue(any(call.args[0] == "deleteMessage" and call.args[1].get("message_id") == 81
                            for call in api.call_args_list))

    def test_telegram_search_miss_prompts_for_another_query(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        archive.telegram_set_state({"mode": "search", "step": "query"})
        with patch.object(archive, "telegram_send") as send:
            archive.handle_telegram_update({"message": {
                "message_id": 78, "chat": {"id": 12345, "type": "private"}, "text": "no-such-record"
            }})
        self.assertEqual(archive.telegram_get_state().get("mode"), "search")
        self.assertIn("send another name or IP address", send.call_args.args[1])

    def test_telegram_sent_messages_are_scheduled_for_deletion_after_two_minutes(self):
        with patch.object(archive, "telegram_api", return_value={"ok": True, "result": {"message_id": 909}}), \
             patch.object(archive, "telegram_schedule_delete") as schedule:
            archive.telegram_send("12345", "Temporary 2FA code")
        schedule.assert_called_once_with("12345", 909, archive.TELEGRAM_MESSAGE_TTL_SECONDS)

    def test_edited_telegram_screens_reset_the_auto_delete_timer(self):
        with patch.object(archive, "telegram_api", return_value={"ok": True, "result": True}), \
             patch.object(archive, "telegram_schedule_delete") as schedule:
            archive.telegram_replace_message("12345", 321, "Updated screen",
                                             {"inline_keyboard": [[{"text": "Menu", "callback_data": "menu"}]]})
        schedule.assert_called_once_with("12345", 321, archive.TELEGRAM_MESSAGE_TTL_SECONDS)

    def test_auto_delete_scheduler_replaces_an_existing_timer_for_the_same_message(self):
        key = ("12345", 909)
        with patch.object(archive.threading, "Timer") as timer:
            first_timer, second_timer = MagicMock(), MagicMock()
            timer.side_effect = [first_timer, second_timer]
            archive.telegram_schedule_delete("12345", 909, 120)
            self.assertIs(archive._TELEGRAM_DELETE_TIMERS[key], first_timer)
            archive.telegram_schedule_delete("12345", 909, 120)
            self.assertIs(archive._TELEGRAM_DELETE_TIMERS[key], second_timer)
            first_timer.cancel.assert_called_once()
            self.assertEqual(timer.call_count, 2)
            self.assertTrue(second_timer.daemon)
            second_timer.start.assert_called_once()
            archive.telegram_cancel_scheduled_delete("12345", 909)

    def test_menu_command_input_is_deleted_and_menu_is_temporary(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        with patch.object(archive, "telegram_api", return_value={}) as api, \
             patch.object(archive, "telegram_send") as send:
            archive.handle_telegram_update({"message": {
                "message_id": 88, "chat": {"id": 12345, "type": "private"}, "text": "/start",
            }})
        self.assertTrue(any(call.args[0] == "deleteMessage" and call.args[1].get("message_id") == 88
                            for call in api.call_args_list))
        self.assertTrue(send.called)
        self.assertGreater(send.call_args.kwargs.get("delete_after", archive.TELEGRAM_MESSAGE_TTL_SECONDS), 0)

    def test_telegram_security_alerts_are_scheduled_for_auto_deletion(self):
        archive.save_secure_setting("telegram_bot_token_enc", "123456:abcdefghijklmnopqrstuvwxyzABCDE_12345")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, limit):
                return b'{"ok":true,"result":{"message_id":901}}'

        with patch.object(archive, "urlopen", return_value=FakeResponse()), \
             patch.object(archive, "telegram_schedule_delete") as schedule:
            self.assertTrue(archive.send_telegram_security_alert("Temporary security alert"))
        schedule.assert_called_once_with("12345", 901, 120)

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

        # Create a real account through the admin UI while global shared mode is active.
        response = self.client.post("/users", data={
            "csrf_token": self.csrf(), "username": "shared-new-user",
            "password": "new-user-pass-123", "role": "admin",
        })
        self.assertEqual(response.status_code, 302)
        users_page = self.client.get("/users")
        self.assertEqual(users_page.status_code, 200)
        users_html = users_page.get_data(as_text=True)
        self.assertIn("Shared Authenticator", users_html)
        self.assertNotIn("Pending setup", users_html)

        # Existing and newly created accounts use the same shared code; neither enrolls a private secret.
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.client.delete_cookie("ip_management_2fa")
        for index, (username, password) in enumerate((
            ("shared-admin", "test-pass"),
            ("shared-new-user", "new-user-pass-123"),
        )):
            if index:
                self.client.post("/logout", data={"csrf_token": self.csrf()})
                self.client.delete_cookie("ip_management_2fa")
            self.client.get("/login")
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": username, "password": password,
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Authenticator code", response.data)
            self.assertNotIn(b"Verify and enable 2FA", response.data)
            self.assertNotIn(b"Scan the QR code", response.data)

            # Account-level enrollment is unavailable when the global shared policy is active.
            setup_response = self.client.get("/setup-2fa")
            self.assertEqual(setup_response.status_code, 302)
            self.assertIn("/login", setup_response.location)

            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "code": pyotp.TOTP(shared).now(),
            })
            self.assertEqual(response.status_code, 302)
            with self.client.session_transaction() as sess:
                self.assertTrue(sess.get("two_factor_verified"))
                self.assertEqual(sess.get("username"), username)
            with archive.connect_db() as db:
                user = db.execute(
                    "SELECT totp_secret,two_factor_enrolled FROM users WHERE username=?", (username,)
                ).fetchone()
            self.assertNotEqual(user["totp_secret"], shared)
            self.assertEqual(user["two_factor_enrolled"], 0)
            profile_response = self.client.get("/profile")
            self.assertEqual(profile_response.status_code, 200)
            self.assertIn(b"Shared Authenticator required", profile_response.data)
            self.assertNotIn(b"Reconfigure two-factor authentication", profile_response.data)

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

    def test_ip_edit_and_delete_preserve_filtered_return_url(self):
        _, secret = self.create_user("return-filter-admin")
        self.assertEqual(self.login("return-filter-admin", secret).status_code, 302)
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
            ip_id = db.execute(
                "INSERT INTO ips(name,ip_address,port,username,password_enc,group_id,created_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                ("Filter Target Router", "192.0.2.170", 22, "operator", "", group_id,
                 "return-filter-admin", archive.now(), archive.now()),
            ).lastrowid

        return_to = f"/?q=Filter%20Target&group={group_id}"
        encoded_return_to = "%2F%3Fq%3DFilter%2520Target%26group%3D" + str(group_id)
        edit_page = self.client.get(f"/ips/{ip_id}/edit?return_to={encoded_return_to}")
        self.assertEqual(edit_page.status_code, 200)
        edit_html = edit_page.get_data(as_text=True)
        self.assertIn(f'name="return_to" value="/?q=Filter%20Target&amp;group={group_id}"', edit_html)
        self.assertIn(f'href="/?q=Filter%20Target&amp;group={group_id}"', edit_html)

        response = self.client.post(f"/ips/{ip_id}/edit", data={
            "csrf_token": self.csrf(), "return_to": return_to,
            "name": "Filter Target Router Updated", "ip_address": "192.0.2.170",
            "port": "22", "username": "operator", "password": "",
            "notes": "", "group_id": str(group_id),
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, return_to)

        response = self.client.post(f"/ips/{ip_id}/delete", data={
            "csrf_token": self.csrf(), "return_to": return_to,
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, return_to)
        with archive.connect_db() as db:
            self.assertIsNone(db.execute("SELECT id FROM ips WHERE id=?", (ip_id,)).fetchone())

        # Return URLs must not become an open redirect to an external website.
        response = self.client.post(f"/ips/{ip_id}/delete", data={
            "csrf_token": self.csrf(), "return_to": "https://attacker.example/",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")

    def test_ip_directory_is_sorted_by_group_name_then_ip_name_a_to_z(self):
        superadmin_id, superadmin_secret = self.create_user("sort-records-root")
        self.assertEqual(self.login("sort-records-root", superadmin_secret).status_code, 302)
        with archive.connect_db() as db:
            default_group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
            alpha_group_id = db.execute(
                "INSERT INTO groups(name,description,created_at,sort_order) VALUES(?,?,?,0)",
                ("Alpha group", "Alphabetical sort test", archive.now()),
            ).lastrowid
            zulu_group_id = db.execute(
                "INSERT INTO groups(name,description,created_at,sort_order) VALUES(?,?,?,0)",
                ("Zulu group", "Alphabetical sort test", archive.now()),
            ).lastrowid
            entries = [
                ("zulu router", "192.0.2.10", default_group_id),
                ("Bravo switch 2", "192.0.2.40", default_group_id),
                ("Alpha router", "192.0.2.20", default_group_id),
                ("bravo switch", "192.0.2.30", default_group_id),
                ("Omega node", "192.0.2.50", alpha_group_id),
                ("alpha node", "192.0.2.60", alpha_group_id),
                ("charlie node", "192.0.2.70", zulu_group_id),
                ("bravo node", "192.0.2.80", zulu_group_id),
            ]
            for name, address, group_id in entries:
                db.execute(
                    "INSERT INTO ips(name,ip_address,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                    (name, address, group_id, "sort-test", archive.now(), archive.now()),
                )

        expected_records = [
            ("alpha node", "Alpha group"),
            ("Omega node", "Alpha group"),
            ("Alpha router", "Default"),
            ("bravo switch", "Default"),
            ("Bravo switch 2", "Default"),
            ("zulu router", "Default"),
            ("bravo node", "Zulu group"),
            ("charlie node", "Zulu group"),
        ]

        def assert_directory_order(page, expected):
            # Mobile cards retain name and group metadata on the outer card wrapper.
            # Parse whole article blocks instead of relying on attribute order inside
            # the nested detail button, which also carries modal-specific fields.
            mobile_cards = re.findall(r'<article class="mobile-ip-card[^\"]*".*?</article>', page, re.S)
            mobile_records = []
            for card in mobile_cards:
                name_match = re.search(r'class="mobile-ip-title"><strong[^>]*>(.*?)</strong>', card, re.S)
                group_match = re.search(r'<span class="group-tag"[^>]*>([^<]+)</span>', card)
                if name_match and group_match:
                    mobile_records.append((name_match.group(1), group_match.group(1)))
            self.assertEqual(
                mobile_records, expected,
                "Mobile IP directory must sort group names A-Z, then IP names A-Z within each group",
            )

            table = page[page.index('<tbody>'):]
            desktop_rows = re.findall(r'<tr data-search-row.*?</tr>', table, re.S)
            desktop_records = []
            for row in desktop_rows:
                name_match = re.search(r'<strong[^>]*>(.*?)</strong>', row, re.S)
                group_match = re.search(r'<span class="group-tag"[^>]*>(.*?)</span>', row, re.S)
                if name_match and group_match:
                    desktop_records.append((name_match.group(1), group_match.group(1)))
            self.assertEqual(
                desktop_records, expected,
                "Desktop IP directory must sort group names A-Z, then IP names A-Z within each group",
            )

        directory = self.client.get("/")
        self.assertEqual(directory.status_code, 200)
        assert_directory_order(directory.get_data(as_text=True), expected_records)

        # The permissions editor keeps its own alphabetical IP-name ordering.
        user_settings = self.client.get(f"/users/{superadmin_id}")
        self.assertEqual(user_settings.status_code, 200)
        settings_page = user_settings.get_data(as_text=True)
        settings_start = settings_page.index('class="ip-rule-list"')
        settings_list = settings_page[settings_start:]
        settings_sorted_names = sorted((name for name, _, _ in entries), key=str.casefold)
        settings_positions = [settings_list.index(f"<strong>{name}</strong>") for name in settings_sorted_names]
        self.assertEqual(settings_positions, sorted(settings_positions),
                         "IP visibility settings must remain sorted by IP name A-Z")

        admin_id, admin_secret = self.create_user("sort-records-limited", role="admin")
        with archive.connect_db() as db:
            db.execute(
                "INSERT INTO user_group_access(user_id,group_id) VALUES(?,?)",
                (admin_id, default_group_id),
            )
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.assertEqual(self.login("sort-records-limited", admin_secret).status_code, 302)
        limited_directory = self.client.get("/")
        self.assertEqual(limited_directory.status_code, 200)
        limited_expected = [
            (name, "Default")
            for name, _, group_id in sorted(entries, key=lambda row: row[0].casefold())
            if group_id == default_group_id
        ]
        assert_directory_order(limited_directory.get_data(as_text=True), limited_expected)

    def test_account_vault_crud_uses_separate_groups_and_encrypted_passwords(self):
        _, secret = self.create_user("account-vault-root")
        self.assertEqual(self.login("account-vault-root", secret).status_code, 302)

        response = self.client.get("/accounts")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Accounts", response.data)
        response = self.client.get("/account-groups")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Account groups", response.data)

        # A group with the same name may exist independently in both subsystems.
        response = self.client.post("/groups", data={
            "csrf_token": self.csrf(), "name": "Mail", "description": "IP-side group",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            ip_group = db.execute("SELECT id FROM groups WHERE name='Mail'").fetchone()
        response = self.client.post("/account-groups", data={
            "csrf_token": self.csrf(), "name": "Mail", "description": "Account-only group",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            account_group = db.execute("SELECT id FROM account_groups WHERE name='Mail'").fetchone()
            self.assertIsNotNone(db.execute("SELECT id FROM groups WHERE name='Mail'").fetchone())
            self.assertNotEqual(
                db.execute("SELECT description FROM groups WHERE id=?", (ip_group["id"],)).fetchone()["description"],
                db.execute("SELECT description FROM account_groups WHERE id=?", (account_group["id"],)).fetchone()["description"],
            )
            default_account_group = db.execute("SELECT id FROM account_groups WHERE name='Default'").fetchone()["id"]

        response = self.client.post("/accounts/new", data={
            "csrf_token": self.csrf(), "return_to": f"/accounts?q=Work&group={account_group['id']}",
            "name": "Work Email", "username": "amir.work", "email": "amir@example.com",
            "password": "account-secret-value", "group_id": str(account_group["id"]),
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, f"/accounts?q=Work&group={account_group['id']}")
        with archive.connect_db() as db:
            row = db.execute("SELECT * FROM accounts WHERE name='Work Email'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["group_id"], account_group["id"])
        self.assertNotEqual(row["password_enc"], "account-secret-value")
        self.assertEqual(archive.vault.decrypt(row["password_enc"].encode()).decode(), "account-secret-value")
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ips WHERE ip_address='amir@example.com'").fetchone()[0], 0)

        response = self.client.get("/accounts?q=amir")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Work Email", response.data)
        self.assertIn(b"amir@example.com", response.data)
        self.assertIn(b'data-copy-value="account-secret-value"', response.data)
        self.assertIn(b">Edit account</a>", response.data)
        self.assertIn("••••••••".encode("utf-8"), response.data)

        account_id = row["id"]
        original_password_enc = row["password_enc"]
        response = self.client.post(f"/accounts/{account_id}/edit", data={
            "csrf_token": self.csrf(), "return_to": "/accounts?q=Work",
            "name": "Work Email", "username": "amir.work", "email": "work@example.com",
            "password": "", "group_id": str(account_group["id"]),
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/accounts?q=Work")
        with archive.connect_db() as db:
            row = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        self.assertEqual(row["email"], "work@example.com")
        self.assertEqual(row["password_enc"], original_password_enc, "Blank edit password must preserve the saved secret")

        response = self.client.post(f"/accounts/{account_id}/edit", data={
            "csrf_token": self.csrf(), "name": "Work Email", "username": "amir.work",
            "email": "work@example.com", "password": "replaced-account-secret",
            "group_id": str(account_group["id"]),
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            row = db.execute("SELECT password_enc FROM accounts WHERE id=?", (account_id,)).fetchone()
            self.assertEqual(archive.vault.decrypt(row["password_enc"].encode()).decode(), "replaced-account-secret")
            db.execute(
                "INSERT INTO ips(name,ip_address,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                ("Mail Gateway", "192.0.2.91", ip_group["id"], "account-vault-root", archive.now(), archive.now()),
            )

        # Deleting an account group changes only the account subsystem and moves its records to Default.
        response = self.client.post(f"/account-groups/{account_group['id']}/delete", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            row = db.execute("SELECT group_id FROM accounts WHERE id=?", (account_id,)).fetchone()
            self.assertEqual(row["group_id"], default_account_group)
            self.assertIsNotNone(db.execute("SELECT id FROM groups WHERE id=?", (ip_group["id"],)).fetchone())
            self.assertIsNotNone(db.execute("SELECT id FROM ips WHERE ip_address='192.0.2.91'").fetchone())

        response = self.client.post(f"/accounts/{account_id}/delete", data={
            "csrf_token": self.csrf(), "return_to": "https://example.com/",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/accounts", "External return destinations must be rejected")
        with archive.connect_db() as db:
            self.assertIsNone(db.execute("SELECT id FROM accounts WHERE id=?", (account_id,)).fetchone())

    def test_account_name_is_only_required_field(self):
        _, secret = self.create_user("account-minimal-root")
        self.assertEqual(self.login("account-minimal-root", secret).status_code, 302)

        form_page = self.client.get("/accounts/new")
        self.assertEqual(form_page.status_code, 200)
        self.assertIn(b'name="name" required', form_page.data)
        self.assertNotIn(b'name="username" required', form_page.data)
        self.assertNotIn(b'name="email" type="email" required', form_page.data)
        self.assertNotIn(b"'required' if not account else ''", form_page.data)
        self.assertNotIn(b"Only account groups appear here; IP groups are not shared.", form_page.data)

        response = self.client.post("/accounts/new", data={
            "csrf_token": self.csrf(),
            "name": "Name Only Account",
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("/accounts", response.location)
        with archive.connect_db() as db:
            row = db.execute("SELECT * FROM accounts WHERE name='Name Only Account'").fetchone()
            default_group = db.execute("SELECT id FROM account_groups WHERE name='Default'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["username"], "")
        self.assertEqual(row["email"], "")
        self.assertEqual(row["password_enc"], "")
        self.assertEqual(row["group_id"], default_group["id"])

        # The display name stays mandatory; optional fields never compensate for a missing name.
        response = self.client.post("/accounts/new", data={
            "csrf_token": self.csrf(),
            "name": "   ",
            "username": "optional-user",
            "email": "optional@example.com",
            "password": "optional-password",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Account name is required.", response.data)
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM accounts WHERE username='optional-user'").fetchone()[0], 0)

    def test_ip_and_account_cards_render_only_populated_optional_fields(self):
        _, secret = self.create_user("conditional-card-root")
        self.assertEqual(self.login("conditional-card-root", secret).status_code, 302)

        response = self.client.post("/ips/new", data={
            "csrf_token": self.csrf(), "name": "Minimal IP", "ip_address": "192.0.2.120",
        })
        self.assertEqual(response.status_code, 302)
        response = self.client.post("/accounts/new", data={
            "csrf_token": self.csrf(), "name": "Minimal Account",
        })
        self.assertEqual(response.status_code, 302)

        ip_page = self.client.get("/").get_data(as_text=True)
        ip_card = ip_page.split('data-scroll-record="ip-', 1)[1].split("</article>", 1)[0]
        self.assertIn("Minimal IP", ip_card)
        self.assertIn("192.0.2.120", ip_card)
        for label in ("Port", "Username", "Password"):
            self.assertNotIn(f'mobile-data-label">{label}', ip_card)

        account_page = self.client.get("/accounts").get_data(as_text=True)
        account_card = account_page.split('data-scroll-record="account-', 1)[1].split("</article>", 1)[0]
        self.assertIn("Minimal Account", account_card)
        for label in ("Username", "Email", "Password"):
            self.assertNotIn(f'mobile-data-label">{label}', account_card)

        response = self.client.post("/ips/new", data={
            "csrf_token": self.csrf(), "name": "Complete IP", "ip_address": "192.0.2.121",
            "port": "8291", "username": "router-user", "password": "router-secret",
        })
        self.assertEqual(response.status_code, 302)
        response = self.client.post("/accounts/new", data={
            "csrf_token": self.csrf(), "name": "Complete Account", "username": "portal-user",
            "email": "portal@example.test", "password": "portal-secret",
        })
        self.assertEqual(response.status_code, 302)

        ip_page = self.client.get("/").get_data(as_text=True)
        ip_card = ip_page.split('data-search="complete ip', 1)[1].split("</article>", 1)[0]
        for value in ("192.0.2.121", "8291", "router-user", 'data-copy-value="router-secret"', "data-reveal-password"):
            self.assertIn(value, ip_card)
        account_page = self.client.get("/accounts").get_data(as_text=True)
        account_card = account_page.split('data-search="complete account', 1)[1].split("</article>", 1)[0]
        for value in ("portal-user", "portal@example.test", 'data-copy-value="portal-secret"', "data-reveal-password"):
            self.assertIn(value, account_card)

    def test_account_vault_is_superadmin_only_and_validates_email(self):
        _, secret = self.create_user("account-vault-limited", role="admin")
        self.assertEqual(self.login("account-vault-limited", secret).status_code, 302)
        self.assertEqual(self.client.get("/accounts").status_code, 403)
        self.assertEqual(self.client.get("/account-groups").status_code, 403)
        self.assertEqual(self.client.get("/accounts/new").status_code, 403)

        self.client.post("/logout", data={"csrf_token": self.csrf()})
        _, root_secret = self.create_user("account-vault-validation-root")
        self.assertEqual(self.login("account-vault-validation-root", root_secret).status_code, 302)
        response = self.client.post("/accounts/new", data={
            "csrf_token": self.csrf(), "name": "Bad Email", "username": "bad-email",
            "email": "not-an-email", "password": "safe-secret", "group_id": "",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Enter a valid email address", response.data)
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM accounts WHERE name='Bad Email'").fetchone()[0], 0)

    def test_notes_vault_stores_optional_ip_account_and_note_fields_with_independent_groups(self):
        _, secret = self.create_user("notes-vault-root")
        self.assertEqual(self.login("notes-vault-root", secret).status_code, 302)

        for path in ("/notes", "/note-groups", "/notes/new"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
        form_page = self.client.get("/notes/new").get_data(as_text=True)
        self.assertIn('name="ip_address"', form_page)
        self.assertIn('name="account_email"', form_page)
        self.assertIn('name="note_text"', form_page)
        self.assertIn('name="wifi_ssid"', form_page)
        self.assertIn('name="wifi_password"', form_page)
        self.assertIn('name="admin_ip"', form_page)
        self.assertIn('name="admin_username"', form_page)
        self.assertIn('name="admin_password"', form_page)
        self.assertNotIn('name="title" required', form_page)
        self.assertNotIn('name="ip_address" required', form_page)
        self.assertNotIn('name="account_email" type="email" required', form_page)
        self.assertNotIn('name="note_text" required', form_page)
        self.assertNotIn('name="wifi_ssid" required', form_page)
        self.assertNotIn('name="wifi_password" required', form_page)
        self.assertNotIn('name="admin_ip" required', form_page)
        self.assertNotIn('name="admin_username" required', form_page)
        self.assertNotIn('name="admin_password" required', form_page)

        # Group names are independent across all three directories.
        self.assertEqual(self.client.post("/groups", data={
            "csrf_token": self.csrf(), "name": "Shared",
        }).status_code, 302)
        self.assertEqual(self.client.post("/account-groups", data={
            "csrf_token": self.csrf(), "name": "Shared",
        }).status_code, 302)
        self.assertEqual(self.client.post("/note-groups", data={
            "csrf_token": self.csrf(), "name": "Shared", "description": "Mixed references", "color": "#d97706",
        }).status_code, 302)
        with archive.connect_db() as db:
            ip_group = db.execute("SELECT id FROM groups WHERE name='Shared'").fetchone()
            account_group = db.execute("SELECT id FROM account_groups WHERE name='Shared'").fetchone()
            note_group = db.execute("SELECT id FROM note_groups WHERE name='Shared'").fetchone()
            default_note_group = db.execute("SELECT id FROM note_groups WHERE name='Default'").fetchone()
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT description FROM groups WHERE id=?", (ip_group["id"],)).fetchone()["description"], "")
            self.assertEqual(db.execute("SELECT description FROM account_groups WHERE id=?", (account_group["id"],)).fetchone()["description"], "")
            self.assertEqual(db.execute("SELECT name FROM note_groups WHERE id=?", (note_group["id"],)).fetchone()["name"], "Shared")

        # Even an entirely blank entry can be saved; no content field is mandatory.
        response = self.client.post("/notes/new", data={
            "csrf_token": self.csrf(), "group_id": str(default_note_group["id"]),
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            empty = db.execute("SELECT * FROM notes WHERE title='' AND ip_address='' AND account_email='' AND note_text=''").fetchone()
        self.assertIsNotNone(empty)
        empty_page = self.client.get("/notes").get_data(as_text=True)
        empty_card = empty_page.split(f'data-scroll-record="note-{empty["id"]}"', 1)[1].split("</article>", 1)[0]
        for label in ("Website / URL", "IP address", "IP port", "IP username", "IP password", "Account name", "Account username", "Account email", "Account password", "Note"):
            self.assertNotIn(label, empty_card)
        self.assertIn(f"Saved note #{empty['id']}", empty_card)
        self.assertIn('class="btn btn-small btn-secondary note-card-edit"', empty_card)
        self.assertIn('class="btn btn-small btn-danger note-card-delete"', empty_card)
        notes_css = (archive.BASE_DIR / "static" / "style.css").read_text(encoding="utf-8")
        self.assertRegex(notes_css, r"\.note-card-actions\{[^}]*display:grid;grid-template-columns:repeat\(2,minmax\(0,1fr\)\)")
        self.assertRegex(notes_css, r"\.note-card-actions \.btn\{[^}]*width:100%")
        self.assertRegex(notes_css, r"\.note-card-actions>\.note-card-edit,\.note-card-actions>form\{[^}]*display:flex;[^}]*width:100%;[^}]*min-width:0;[^}]*flex:1 1 0")
        self.assertRegex(notes_css, r"\.note-card-actions>\.note-card-edit,\.note-card-actions>form>\.note-card-delete\{[^}]*width:100%;[^}]*min-width:0;[^}]*flex:1 1 0")

        response = self.client.post("/notes/new", data={
            "csrf_token": self.csrf(), "return_to": f"/notes?q=Gateway&group={note_group['id']}",
            "title": "Edge gateway credentials", "service_url": "https://router.example.test",
            "ip_name": "Remote gateway", "ip_address": "192.0.2.44", "ip_port": "8291",
            "ip_username": "router-admin", "ip_password": "ip-vault-secret",
            "account_name": "Monitoring portal", "account_username": "monitor-user",
            "account_email": "monitor@example.test", "account_password": "account-vault-secret",
            "wifi_ssid": "AMSCO-Staff", "wifi_password": "wifi-vault-secret", "admin_ip": "192.168.10.1",
            "admin_username": "wifi-root", "admin_password": "admin-wifi-secret",
            "note_text": "Primary access details\\nUse the backup link during maintenance.",
            "group_id": str(note_group["id"]),
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, f"/notes?q=Gateway&group={note_group['id']}")
        with archive.connect_db() as db:
            saved = db.execute("SELECT * FROM notes WHERE title='Edge gateway credentials'").fetchone()
        self.assertIsNotNone(saved)
        self.assertEqual(saved["group_id"], note_group["id"])
        self.assertEqual(saved["ip_port"], 8291)
        self.assertNotEqual(saved["ip_password_enc"], "ip-vault-secret")
        self.assertNotEqual(saved["account_password_enc"], "account-vault-secret")
        self.assertEqual(archive.vault.decrypt(saved["ip_password_enc"].encode()).decode(), "ip-vault-secret")
        self.assertEqual(archive.vault.decrypt(saved["account_password_enc"].encode()).decode(), "account-vault-secret")
        self.assertEqual(saved["wifi_ssid"], "AMSCO-Staff")
        self.assertNotEqual(saved["wifi_password_enc"], "wifi-vault-secret")
        self.assertEqual(archive.vault.decrypt(saved["wifi_password_enc"].encode()).decode(), "wifi-vault-secret")
        self.assertEqual(saved["admin_ip"], "192.168.10.1")
        self.assertEqual(saved["admin_username"], "wifi-root")
        self.assertNotEqual(saved["admin_password_enc"], "admin-wifi-secret")
        self.assertEqual(archive.vault.decrypt(saved["admin_password_enc"].encode()).decode(), "admin-wifi-secret")

        listing = self.client.get("/notes?q=Gateway&group=" + str(note_group["id"]))
        self.assertEqual(listing.status_code, 200)
        card = listing.get_data(as_text=True).split(f'data-scroll-record="note-{saved["id"]}"', 1)[1].split("</article>", 1)[0]
        for value in ("Edge gateway credentials", "router.example.test", "Remote gateway", "192.0.2.44", "8291",
                      "router-admin", "Monitoring portal", "monitor-user", "monitor@example.test", "Primary access details"):
            self.assertIn(value, card)
        for value in ("AMSCO-Staff", "192.168.10.1", "wifi-root"):
            self.assertIn(value, card)
        self.assertIn('data-copy-value="ip-vault-secret"', card)
        self.assertIn('data-copy-value="account-vault-secret"', card)
        self.assertIn('data-copy-value="wifi-vault-secret"', card)
        self.assertIn('data-copy-value="admin-wifi-secret"', card)
        self.assertEqual(len(re.findall(r'class="note-field(?:\s|")', card)), 16)

        # Blank replacement passwords preserve the encrypted values, while other fields update normally.
        response = self.client.post(f"/notes/{saved['id']}/edit", data={
            "csrf_token": self.csrf(), "return_to": "/notes?q=Gateway", "title": "Updated gateway",
            "ip_address": "192.0.2.45", "ip_port": "8291", "account_email": "monitor@example.test",
            "group_id": str(note_group["id"]),
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/notes?q=Gateway")
        with archive.connect_db() as db:
            updated = db.execute("SELECT * FROM notes WHERE id=?", (saved["id"],)).fetchone()
        self.assertEqual(updated["title"], "Updated gateway")
        self.assertEqual(updated["ip_address"], "192.0.2.45")
        self.assertEqual(updated["ip_password_enc"], saved["ip_password_enc"])
        self.assertEqual(updated["account_password_enc"], saved["account_password_enc"])
        self.assertEqual(updated["wifi_password_enc"], saved["wifi_password_enc"])
        self.assertEqual(updated["admin_password_enc"], saved["admin_password_enc"])

        # Invalid optional values are rejected only when supplied.
        response = self.client.post("/notes/new", data={
            "csrf_token": self.csrf(), "title": "Invalid port", "ip_port": "70000",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"IP port must be a number", response.data)
        with archive.connect_db() as db:
            self.assertIsNone(db.execute("SELECT id FROM notes WHERE title='Invalid port'").fetchone())

        # Group color/order/delete operations affect only notes, not IPs or Accounts.
        response = self.client.post(f"/note-groups/{note_group['id']}/color", data={
            "csrf_token": self.csrf(), "color": "#c2410c",
        })
        self.assertEqual(response.status_code, 302)
        response = self.client.post(f"/note-groups/{note_group['id']}/move", data={
            "csrf_token": self.csrf(), "direction": "up",
        })
        self.assertEqual(response.status_code, 302)
        groups_page = self.client.get("/note-groups").get_data(as_text=True)
        self.assertIn("#c2410c", groups_page)
        response = self.client.post(f"/note-groups/{note_group['id']}/delete", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT group_id FROM notes WHERE id=?", (saved["id"],)).fetchone()["group_id"], default_note_group["id"])
            self.assertIsNotNone(db.execute("SELECT id FROM groups WHERE id=?", (ip_group["id"],)).fetchone())
            self.assertIsNotNone(db.execute("SELECT id FROM account_groups WHERE id=?", (account_group["id"],)).fetchone())

        response = self.client.post(f"/notes/{saved['id']}/delete", data={
            "csrf_token": self.csrf(), "return_to": "https://example.com/",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/notes", "External return destinations must be rejected")
        with archive.connect_db() as db:
            self.assertIsNone(db.execute("SELECT id FROM notes WHERE id=?", (saved["id"],)).fetchone())
            self.assertIsNotNone(db.execute("SELECT id FROM notes WHERE id=?", (empty["id"],)).fetchone())

    def test_notes_vault_is_superadmin_only(self):
        _, secret = self.create_user("notes-vault-limited", role="admin")
        self.assertEqual(self.login("notes-vault-limited", secret).status_code, 302)
        for path in ("/notes", "/notes/new", "/note-groups"):
            self.assertEqual(self.client.get(path).status_code, 403, path)

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

    def test_superadmin_can_preview_and_import_markdown_ip_inventory(self):
        _, secret = self.create_user("markdown-import-admin")
        self.assertEqual(self.login("markdown-import-admin", secret).status_code, 302)
        markdown = (
            "| NAME | IP | USER | PASS |\n"
            "|---|---|---|---|\n"
            "| Core Router | 192.0.2.10:35300 | operator | import-secret-one |\n"
            "| Switch | 192.0.2.20 | admin | import-secret-two |\n"
            "| Multi IP | 192.0.2.30<br />192.0.2.31 | admin | import-secret-three |\n"
            "| Ambiguous | 192.0.2.40 | user-a<br />user-b | pass-a<br />pass-b |\n"
            "| Router alias | 192.0.2.10:35300 | another-user | duplicate-secret |\n"
        )
        response = self.client.post("/ips/import", data={
            "csrf_token": self.csrf(), "action": "preview",
            "file": (BytesIO(markdown.encode("utf-8")), "PASWORD.md"),
        }, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Import preview", page)
        self.assertIn("2</strong> ready to import", page)
        self.assertIn("1</strong> duplicates skipped", page)
        self.assertIn("2</strong> need manual review", page)
        self.assertIn("multiple IP/host values", page)
        for credential in ("import-secret-one", "import-secret-two", "import-secret-three", "pass-a", "pass-b", "duplicate-secret"):
            self.assertNotIn(credential, page)
        match = re.search(r'name="import_token" value="([A-Za-z0-9_-]+)"', page)
        self.assertIsNotNone(match)

        response = self.client.post("/ips/import", data={
            "csrf_token": self.csrf(), "action": "import", "import_token": match.group(1),
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")
        with archive.connect_db() as db:
            rows = db.execute("SELECT ip_address,port,username,password_enc FROM ips ORDER BY ip_address").fetchall()
            self.assertEqual(len(rows), 2)
            router = db.execute("SELECT * FROM ips WHERE ip_address='192.0.2.10'").fetchone()
            switch = db.execute("SELECT * FROM ips WHERE ip_address='192.0.2.20'").fetchone()
            audit_row = db.execute("SELECT detail FROM audit_log WHERE action='ips_imported' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(router["port"], 35300)
        self.assertEqual(router["username"], "operator")
        self.assertNotEqual(router["password_enc"], "import-secret-one")
        self.assertEqual(archive.vault.decrypt(router["password_enc"].encode()).decode(), "import-secret-one")
        self.assertEqual(archive.vault.decrypt(switch["password_enc"].encode()).decode(), "import-secret-two")
        self.assertNotIn("import-secret", audit_row["detail"])
        self.assertNotIn("duplicate-secret", audit_row["detail"])
        page = self.client.get(response.location).get_data(as_text=True)
        self.assertIn("2 records added", page)
        self.assertIn("2 rows need manual review", page)

    def test_markdown_import_is_superadmin_only(self):
        _, secret = self.create_user("markdown-import-limited", role="admin")
        self.assertEqual(self.login("markdown-import-limited", secret).status_code, 302)
        response = self.client.get("/ips/import")
        self.assertEqual(response.status_code, 403)
        response = self.client.post("/ips/import", data={"csrf_token": self.csrf(), "action": "preview"})
        self.assertEqual(response.status_code, 403)

    def test_markdown_import_rejects_unrecognized_table(self):
        _, secret = self.create_user("markdown-import-invalid")
        self.assertEqual(self.login("markdown-import-invalid", secret).status_code, 302)
        response = self.client.post("/ips/import", data={
            "csrf_token": self.csrf(), "action": "preview",
            "file": (BytesIO(b"| Host | Login |\n|---|---|\n| 192.0.2.55 | admin |"), "bad.md"),
        }, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Could not find a Markdown table", response.data)
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ips").fetchone()[0], 0)

    def test_ip_edit_form_omits_password_copy_controls(self):
        _, secret = self.create_user("edit-form-no-copy")
        self.assertEqual(self.login("edit-form-no-copy", secret).status_code, 302)
        with archive.connect_db() as db:
            ip_id = db.execute(
                "INSERT INTO ips(name,ip_address,password_enc,created_at,updated_at) VALUES(?,?,?,?,?)",
                ("Edit password router", "192.0.2.202", archive.vault.encrypt(b"edit-form-secret").decode(), archive.now(), archive.now()),
            ).lastrowid
        response = self.client.get(f"/ips/{ip_id}/edit")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertNotIn("Connection passwords are stored securely. Click the copy button to copy the current password.", page)
        self.assertNotIn("Copy current password", page)
        self.assertNotIn('data-copy-value="edit-form-secret"', page)
        self.assertIn('id="password" name="password" type="password"', page)
        self.assertIn("Leave blank to keep current password", page)

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
        self.assertNotIn('data-copy-value="super-secret"', edit_page)
        self.assertNotIn("Copy current password", edit_page)
        self.assertNotIn("Connection passwords are stored securely. Click the copy button to copy the current password.", edit_page)
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
        self.assertNotIn(b"<span>Password</span></span></th>", directory.data)
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

    def test_ip_directory_values_are_boxed_and_table_headers_are_simple(self):
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
        self.assertIn('data-copy-value="netadmin"', page)
        self.assertIn('aria-label="Copy IP address"><code>192.0.2.55</code></button>', page)
        self.assertIn('<th class="name-column">Name</th>', page)
        self.assertIn('<th>IP address / host</th>', page)
        self.assertNotIn('class="column-icon', page)
        self.assertIn('class="data-field-icon icon-ip"', page)
        self.assertIn('class="data-field-icon icon-port"', page)
        stylesheet = (archive.BASE_DIR / "static" / "style.css").read_text(encoding="utf-8")
        self.assertIn(".mobile-data-row{display:grid;grid-template-columns:27px 92px minmax(0,1fr)", stylesheet)
        self.assertIn(".mobile-ip-actions{display:flex!important", stylesheet)
        self.assertIn(".inventory-panel .table-scroll .record-avatar{position:absolute;left:0;top:50%;transform:translateY(-50%);border-radius:50%}", stylesheet)
        self.assertIn(".profile-info{display:grid;gap:3px;min-width:0;flex:1}", stylesheet)

    def test_mobile_ip_directory_shows_inline_details_and_direct_edit_delete_actions(self):
        _, secret = self.create_user("mobile-ip-directory")
        self.assertEqual(self.login("mobile-ip-directory", secret).status_code, 302)
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
            db.execute(
                "INSERT INTO ips(name,ip_address,port,username,password_enc,notes,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("Mobile router", "192.0.2.99", 8728, "mobile-user", archive.vault.encrypt(b"mobile-secret").decode(), "Uplink device", group_id, "root", archive.now(), archive.now()),
            )
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertNotIn("Keep connection details organized, searchable, and available to the right people.", page)
        self.assertIn('class="mobile-ip-list" data-mobile-ip-list', page)
        self.assertIn('class="mobile-ip-card" role="listitem"', page)
        self.assertIn('data-scroll-record="ip-', page)
        self.assertIn('class="mobile-ip-fields"', page)
        self.assertIn('class="data-field-icon icon-ip"', page)
        self.assertNotIn('class="mobile-data-label">Group</span>', page)
        self.assertIn('class="record-title"', page)
        self.assertIn('class="record-title"', page)
        self.assertIn('<span class="record-title"><strong>Mobile router</strong><span class="group-tag"', page)
        self.assertNotIn('style="--group-color: #169b78"', page)
        self.assertIn('class="mobile-data-label">IP address</span>', page)
        self.assertIn('class="mobile-data-label">Port</span>', page)
        self.assertIn('class="mobile-data-label">Username</span>', page)
        self.assertIn('class="mobile-data-label">Notes</span>', page)
        self.assertIn('data-copy-value="192.0.2.99"', page)
        self.assertIn('data-copy-value="8728"', page)
        self.assertIn('data-copy-value="mobile-user"', page)
        self.assertIn('data-copy-value="mobile-secret"', page)
        self.assertIn("Uplink device", page)
        self.assertIn("mobile-ip-edit", page)
        self.assertTrue(re.search(r'href="/ips/\d+/edit"', page))
        self.assertTrue(re.search(r'action="/ips/\d+/delete"', page))
        self.assertIn('name="csrf_token"', page)
        self.assertNotIn('id="mobile-ip-details-modal"', page)
        self.assertNotIn('class="column-icon', page)
        script = (archive.BASE_DIR / "static" / "app.js").read_text(encoding="utf-8")
        self.assertNotIn("document.querySelectorAll('[data-mobile-ip-card]')", script)
        self.assertIn("event.target.closest('[data-copy-value]')", script)
        self.assertIn("mobileRows.forEach(row =>", script)
        stylesheet = (archive.BASE_DIR / "static" / "style.css").read_text(encoding="utf-8")
        self.assertIn(".mobile-ip-list{display:grid!important;gap:11px;padding:13px12px16px!important}", "".join(stylesheet.split()))
        self.assertIn(".mobile-ip-actions{display:flex!important", stylesheet)
        self.assertIn(".mobile-ip-list.mobile-ip-card>.mobile-ip-actions{padding:12px15px13px!important}", "".join(stylesheet.split()))
        self.assertIn(".account-inventory-panel.mobile-account-list{display:grid!important;gap:10px;padding:13px12px16px!important}", "".join(stylesheet.split()))

    def test_update_success_button_says_ok(self):
        _, secret = self.create_user("update-success-user")
        self.assertEqual(self.login("update-success-user", secret).status_code, 302)
        response = self.client.get("/?update=success")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="close-update-success">OK</button>', response.data)
        self.assertNotIn(b"Back to IP addresses", response.data)

    def test_group_colors_are_saved_and_rendered_as_explicit_inline_styles(self):
        _, secret = self.create_user("group-colors")
        self.assertEqual(self.login("group-colors", secret).status_code, 302)

        response = self.client.post("/groups", data={
            "csrf_token": self.csrf(), "name": "Colorized IPs", "color": "#e11d48",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            ip_group_id = db.execute("SELECT id FROM groups WHERE name='Colorized IPs'").fetchone()["id"]
        response = self.client.post(f"/groups/{ip_group_id}/color", data={
            "csrf_token": self.csrf(), "color": "#db2777",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            saved_ip_color = db.execute("SELECT color FROM groups WHERE id=?", (ip_group_id,)).fetchone()["color"]
            db.execute(
                "INSERT INTO ips(name,ip_address,group_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                ("Colored router", "192.0.2.211", ip_group_id, "group-colors", archive.now(), archive.now()),
            )
        self.assertEqual(saved_ip_color, "#db2777")

        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("color: #db2777 !important", page)
        self.assertIn("background-color: #db277722 !important", page)
        self.assertIn('class="group-tag" data-group-color="#db2777" style="--group-color: #db2777 !important; color: #db2777 !important;', page)
        self.assertIn('<div class="mobile-ip-title"><strong>Colored router</strong></div>', page)
        self.assertIn('<span class="record-title"><strong>Colored router</strong><span class="group-tag"', page)
        self.assertNotIn('<strong style="color: #db2777 !important">Colored router</strong>', page)
        groups_page = self.client.get("/groups").get_data(as_text=True)
        self.assertIn('style="--group-color: #db2777; color: #db2777 !important"', groups_page)

        response = self.client.post("/account-groups", data={
            "csrf_token": self.csrf(), "name": "Colorized Accounts", "color": "#16a34a",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            account_group_id = db.execute("SELECT id FROM account_groups WHERE name='Colorized Accounts'").fetchone()["id"]
        response = self.client.post(f"/account-groups/{account_group_id}/color", data={
            "csrf_token": self.csrf(), "color": "#0f766e",
        })
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            saved_account_color = db.execute(
                "SELECT color FROM account_groups WHERE id=?", (account_group_id,)
            ).fetchone()["color"]
            db.execute(
                "INSERT INTO accounts(name,username,email,password_enc,group_id,created_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                ("Colored mailbox", "color-user", "color@example.test", "", account_group_id,
                 "group-colors", archive.now(), archive.now()),
            )
        self.assertEqual(saved_account_color, "#0f766e")
        account_page = self.client.get("/accounts").get_data(as_text=True)
        self.assertIn("color: #0f766e !important", account_page)
        self.assertIn("background-color: #0f766e22 !important", account_page)
        self.assertIn('class="group-tag" data-group-color="#0f766e" style="--group-color: #0f766e !important; color: #0f766e !important;', account_page)
        self.assertIn('class="mobile-ip-card mobile-account-card"', account_page)
        self.assertNotIn('class="mobile-data-row mobile-account-group-row"', account_page)
        self.assertIn('class="record-title"><strong>Colored mailbox</strong>', account_page)
        self.assertNotIn('<strong style="color: #0f766e !important">Colored mailbox</strong>', account_page)
        self.assertIn('class="mobile-ip-title mobile-account-title"><strong>Colored mailbox</strong>', account_page)
        self.assertIn('class="group-tag" data-group-color="#0f766e" style="--group-color: #0f766e !important;', account_page)

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

    def test_superadmin_can_delete_user_and_preserves_self_account(self):
        root_id, root_secret = self.create_user("delete-root")
        self.assertEqual(self.login("delete-root", root_secret).status_code, 302)
        target_id, _ = self.create_user("delete-target", role="admin")
        with archive.connect_db() as db:
            group_id = db.execute("SELECT id FROM groups WHERE name='Default'").fetchone()["id"]
            ip_id = db.execute(
                "INSERT INTO ips(name,ip_address,created_at,updated_at) VALUES(?,?,?,?)",
                ("Delete test IP", "192.0.2.201", archive.now(), archive.now()),
            ).lastrowid
            db.execute("INSERT INTO user_group_access(user_id,group_id) VALUES(?,?)", (target_id, group_id))
            db.execute("INSERT INTO user_ip_access(user_id,ip_id,can_view) VALUES(?,?,1)", (target_id, ip_id))
            db.execute("INSERT INTO user_recovery_codes(user_id,code_hash,created_at) VALUES(?,?,?)",
                       (target_id, "delete-test-recovery-hash", archive.now()))
            db.execute("INSERT INTO telegram_login_codes(user_id,code_hash,expires_at,created_at) VALUES(?,?,?,?)",
                       (target_id, "delete-test-telegram-hash", archive.now(), archive.now()))

        listing = self.client.get("/users")
        self.assertEqual(listing.status_code, 200)
        page = listing.get_data(as_text=True)
        self.assertIn(f'action="/users/{target_id}/delete"', page)
        self.assertIn('data-confirm="Delete this user account? This cannot be undone."', page)

        response = self.client.post(f"/users/{target_id}/delete", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/users")
        with archive.connect_db() as db:
            self.assertIsNone(db.execute("SELECT id FROM users WHERE id=?", (target_id,)).fetchone())
            self.assertEqual(db.execute("SELECT COUNT(*) FROM user_group_access WHERE user_id=?", (target_id,)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM user_ip_access WHERE user_id=?", (target_id,)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=?", (target_id,)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telegram_login_codes WHERE user_id=?", (target_id,)).fetchone()[0], 0)
            self.assertIsNotNone(db.execute("SELECT id FROM users WHERE id=?", (root_id,)).fetchone())
        self.assertIn(b"User delete-target deleted.", self.client.get("/users").data)

        self_id = root_id
        response = self.client.post(f"/users/{self_id}/delete", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            self.assertIsNotNone(db.execute("SELECT id FROM users WHERE id=?", (self_id,)).fetchone())
        self.assertIn(b"You cannot delete your own account.", self.client.get("/users").data)

    def test_regular_admin_cannot_delete_a_user(self):
        _, secret = self.create_user("delete-not-allowed", role="admin")
        self.assertEqual(self.login("delete-not-allowed", secret).status_code, 302)
        response = self.client.post("/users/999/delete", data={"csrf_token": self.csrf()})
        self.assertIn(response.status_code, (302, 403))

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
        stylesheet = (archive.BASE_DIR / 'static' / 'style.css').read_text(encoding='utf-8')
        self.assertIn('.profile-info{display:grid;gap:3px;min-width:0;flex:1}', stylesheet)
        self.assertNotIn('text-align:right;justify-items:end', stylesheet)
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
        csp = response.headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("style-src-attr 'unsafe-inline'", csp)
        self.assertIn("style-src-elem 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("script-src 'unsafe-inline'", csp)
        for path in ("/security", "/settings/deployment/status", "/update/check", "/update/status"):
            with self.subTest(path=path):
                guarded = self.client.get(path)
                self.assertIn(guarded.status_code, (302, 403))
                self.assertNotIn(b"shared_two_factor_secret", guarded.data)

    def test_repeated_failed_logins_are_rate_limited(self):
        self.client.get("/login")
        for _ in range(2):
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "unknown-account", "password": "wrong",
            })
            self.assertEqual(response.status_code, 200)
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "unknown-account", "password": "wrong",
        })
        self.assertEqual(response.status_code, 429)
        self.assertIn("text/html", response.content_type)
        self.assertGreater(int(response.headers.get("Retry-After")), 0)
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM login_security_blocks").fetchone()[0], 1)
        # A different username on the same browser must still be rejected.
        alternate = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "another-account", "password": "wrong",
        })
        self.assertEqual(alternate.status_code, 429)

    def test_new_browser_and_new_username_cannot_bypass_ip_lock(self):
        self.client.get("/login", environ_overrides={"REMOTE_ADDR": "198.51.100.44"})
        for _ in range(3):
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "first-account", "password": "wrong",
            }, environ_overrides={"REMOTE_ADDR": "198.51.100.44"})
        self.assertEqual(response.status_code, 429)
        original_device = self.client.get_cookie("ipm_device_id").value

        fresh_browser = archive.app.test_client()
        fresh_browser.get("/login", environ_overrides={"REMOTE_ADDR": "198.51.100.44"})
        self.assertNotEqual(fresh_browser.get_cookie("ipm_device_id").value, original_device)
        with fresh_browser.session_transaction() as sess:
            fresh_csrf = sess["csrf_token"]
        blocked = fresh_browser.post("/login", data={
            "csrf_token": fresh_csrf, "username": "completely-different-account", "password": "wrong",
        }, environ_overrides={"REMOTE_ADDR": "198.51.100.44"})
        self.assertEqual(blocked.status_code, 429)

    def test_client_ip_normalizes_ipv4_mapped_ipv6(self):
        with archive.app.test_request_context("/", environ_overrides={"REMOTE_ADDR": "::ffff:192.0.2.25"}):
            self.assertEqual(archive.client_ip(), "192.0.2.25")

    def test_login_block_follows_browser_and_account_across_changed_ip(self):
        self.client.get("/login")
        for _ in range(3):
            self.client.post("/login", data={"csrf_token": self.csrf(), "username": "locked-identity", "password": "wrong"})
        device_cookie = self.client.get_cookie("ipm_device_id").value
        other_browser = archive.app.test_client()
        other_browser.set_cookie("ipm_device_id", device_cookie)
        other_browser.get("/login", environ_overrides={"REMOTE_ADDR": "198.51.100.20"})
        with other_browser.session_transaction() as sess:
            other_csrf = sess["csrf_token"]
        same_device_new_ip = other_browser.post("/login", data={
            "csrf_token": other_csrf, "username": "another-name", "password": "wrong",
        }, environ_overrides={"REMOTE_ADDR": "198.51.100.20"})
        self.assertEqual(same_device_new_ip.status_code, 429)
        different_device_same_ip = archive.app.test_client()
        different_device_same_ip.get("/login", environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
        with different_device_same_ip.session_transaction() as sess:
            same_ip_csrf = sess["csrf_token"]
        same_ip = different_device_same_ip.post("/login", data={
            "csrf_token": same_ip_csrf, "username": "another-name", "password": "wrong",
        }, environ_overrides={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(same_ip.status_code, 429)
        different_network_same_account = archive.app.test_client()
        different_network_same_account.get("/login", environ_overrides={"REMOTE_ADDR": "203.0.113.80"})
        with different_network_same_account.session_transaction() as sess:
            other_csrf = sess["csrf_token"]
        same_account = different_network_same_account.post("/login", data={
            "csrf_token": other_csrf,
            "username": "locked-identity", "password": "wrong",
        }, environ_overrides={"REMOTE_ADDR": "203.0.113.80"})
        self.assertEqual(same_account.status_code, 429)

    def test_login_failure_ajax_keeps_form_and_only_clears_password(self):
        self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "typed-even-if-wrong", "password": "wrong",
        }, headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json["clear_field"], "password")
        self.assertEqual(response.json["stage"], "password")
        page = self.client.get("/login")
        self.assertIn(b'data-login-form', page.data)
        self.assertIn(b'data-login-feedback', page.data)
        script = (archive.BASE_DIR / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("form[data-login-form]", script)
        self.assertIn("field.value = ''", script)

    def test_three_bad_totp_codes_block_account_ip_and_browser_for_15_minutes(self):
        user_id, _ = self.create_user("three-bad-totp")
        self.client.get("/login")
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "three-bad-totp", "password": "test-pass",
        })
        self.assertEqual(response.status_code, 200)
        for attempt in range(3):
            headers = {"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"} if attempt == 2 else None
            response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": "000000"}, headers=headers)
            self.assertEqual(response.status_code, 429 if attempt == 2 else 200)
        self.assertEqual(response.json["clear_field"], "code")
        with archive.connect_db() as db:
            block = db.execute("SELECT * FROM login_security_blocks ORDER BY created_at DESC LIMIT 1").fetchone()
        self.assertIsNotNone(block)
        self.assertEqual(block["username"], "three-bad-totp")
        self.assertTrue(block["ip_hash"])
        self.assertTrue(block["device_hash"])
        remaining = archive.login_block_remaining(block["blocked_until"])
        self.assertGreaterEqual(remaining, 899)
        self.assertLessEqual(remaining, 900)

    def test_password_and_totp_failures_share_the_same_three_attempt_budget(self):
        self.create_user("combined-failure-budget")
        self.client.get("/login")
        for _ in range(2):
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "combined-failure-budget", "password": "wrong",
            })
            self.assertEqual(response.status_code, 200)
        response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "combined-failure-budget", "password": "test-pass",
        })
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": "000000"})
        self.assertEqual(response.status_code, 429)
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM login_security_blocks").fetchone()[0], 1)

    def test_login_security_unblock_callback_clears_all_scopes_and_is_authorized(self):
        archive.save_secure_setting("telegram_bot_token_enc", "test-bot-token")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        self.client.get("/login")
        with patch.object(archive, "telegram_send", return_value={"ok": True, "result": {"message_id": 321}}):
            for _ in range(3):
                self.client.post("/login", data={"csrf_token": self.csrf(), "username": "release-me", "password": "wrong"})
        with archive.connect_db() as db:
            block = db.execute("SELECT * FROM login_security_blocks ORDER BY created_at DESC LIMIT 1").fetchone()
        self.assertEqual(block["telegram_message_id"], 321)
        callback = {"data": f"login_unblock_group:{block['block_id']}", "from": {"id": 12345},
                    "message": {"message_id": 321, "chat": {"id": 12345, "type": "private"}}}
        unauthorized = {**callback, "from": {"id": 99999}}
        self.assertFalse(archive.handle_login_security_unblock_callback(unauthorized, "12345"))
        with patch.object(archive, "telegram_api", return_value={"ok": True}) as api:
            archive.handle_telegram_update({"callback_query": {**callback, "id": "group-unblock-callback"}})
        callback_answers = [call.args[1] for call in api.call_args_list if call.args and call.args[0] == "answerCallbackQuery"]
        self.assertEqual(len(callback_answers), 1)
        self.assertIn("برداشته شد", callback_answers[0]["text"])
        with archive.connect_db() as db:
            released = db.execute("SELECT blocked_until,telegram_message_id,telegram_chat_id FROM login_security_blocks WHERE block_id=?",
                                  (block["block_id"],)).fetchone()
            self.assertEqual(released["blocked_until"], "")
            self.assertIsNone(released["telegram_message_id"])
            self.assertEqual(released["telegram_chat_id"], "")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM login_attempt_counters").fetchone()[0], 0)
        retry = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "different-user", "password": "wrong"})
        self.assertEqual(retry.status_code, 200)

    def test_superadmin_security_page_can_manually_release_login_block(self):
        _, secret = self.create_user("security-release-admin")
        self.assertEqual(self.login("security-release-admin", secret).status_code, 302)
        attacker = archive.app.test_client()
        attacker.get("/login")
        with attacker.session_transaction() as sess:
            attacker_csrf = sess["csrf_token"]
        for _ in range(3):
            attacker.post("/login", data={"csrf_token": attacker_csrf, "username": "blocked-on-this-ip", "password": "wrong"})
        page = self.client.get("/security")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Active login blocks", page.data)
        self.assertIn("رفع مسدودی".encode("utf-8"), page.data)
        with archive.connect_db() as db:
            block = db.execute("SELECT block_id FROM login_security_blocks WHERE blocked_until!='' ORDER BY created_at DESC LIMIT 1").fetchone()
        self.assertIsNotNone(block)
        response = self.client.post(f"/security/login-blocks/{block['block_id']}/unblock", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 302)
        with archive.connect_db() as db:
            released = db.execute("SELECT blocked_until FROM login_security_blocks WHERE block_id=?", (block["block_id"],)).fetchone()
        self.assertEqual(released["blocked_until"], "")

    def test_2fa_enrollment_guesses_are_rate_limited_too(self):
        user_id, _ = self.create_user("enrollment-throttle")
        self.client.get("/login")
        with self.client.session_transaction() as sess:
            sess["pending_2fa_user_id"] = user_id
            sess["pending_2fa_secret"] = pyotp.random_base32()
            sess["csrf_token"] = "enrollment-csrf"
        for _ in range(2):
            response = self.client.post("/setup-2fa", data={"csrf_token": "enrollment-csrf", "code": "not-a-code"})
            self.assertEqual(response.status_code, 200)
        response = self.client.post("/setup-2fa", data={"csrf_token": "enrollment-csrf", "code": "not-a-code"})
        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response.headers.get("Retry-After")), 0)

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

    def test_telegram_code_login_replaces_original_message_with_permanent_audit_record(self):
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        self.create_user("telegram-audit-admin", role="superadmin")
        calls = []

        def telegram_api_stub(method, payload):
            calls.append((method, payload))
            if method == "sendMessage":
                return {"ok": True, "result": {"message_id": 77}}
            if method == "editMessageText":
                return {"ok": True, "result": {"message_id": 77}}
            return {"ok": True}

        callback = {"callback_query": {"id": "cb-audit", "data": "telegram_2fa_code", "message": {
            "message_id": 1, "chat": {"id": 12345, "type": "private"}}}}
        with patch.object(archive, "telegram_api", side_effect=telegram_api_stub):
            archive.handle_telegram_update(callback)
            with archive.connect_db() as db:
                saved_message = db.execute(
                    "SELECT chat_id,message_id FROM telegram_login_codes ORDER BY id DESC LIMIT 1"
                ).fetchone()
            self.assertEqual((saved_message["chat_id"], saved_message["message_id"]), ("12345", 77))
            self.assertNotIn(("12345", 77), archive._TELEGRAM_DELETE_TIMERS)

            code_message = next(payload["text"] for method, payload in calls if method == "sendMessage")
            code = re.search(r"<code>(\d{6})</code>", code_message).group(1)
            self.client.get("/login")
            password_response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "telegram-audit-admin", "password": "test-pass",
            })
            self.assertEqual(password_response.status_code, 200)
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "code": code,
            }, headers={"User-Agent": "Test Browser/42 (Windows 11)"})

        self.assertEqual(response.status_code, 302)
        edited = [payload for method, payload in calls if method == "editMessageText"]
        self.assertEqual(len(edited), 1)
        self.assertEqual((edited[0]["chat_id"], edited[0]["message_id"]), ("12345", 77))
        self.assertIn("telegram-audit-admin", edited[0]["text"])
        self.assertIn("Account role: Superadmin", edited[0]["text"])
        self.assertIn("127.0.0.1", edited[0]["text"])
        self.assertIn("Test Browser/42 (Windows 11)", edited[0]["text"])
        self.assertIn(f"Code used: {code}", edited[0]["text"])
        self.assertIn("cannot be reused", edited[0]["text"])
        self.assertNotIn(("12345", 77), archive._TELEGRAM_DELETE_TIMERS)
        self.assertFalse(any(method == "deleteMessage" for method, _ in calls))
        self.assertEqual(edited[0].get("reply_markup"), {"inline_keyboard": []})

        acknowledge = {"callback_query": {"id": "cb-ack", "data": "ack_telegram_login", "message": {
            "message_id": 77, "chat": {"id": 12345, "type": "private"}, "text": edited[0]["text"]}}}
        with patch.object(archive, "telegram_api", side_effect=telegram_api_stub):
            archive.handle_telegram_update(acknowledge)
        follow_up_edits = [payload for method, payload in calls if method == "editMessageText"]
        self.assertEqual(len(follow_up_edits), 1)
        self.assertNotIn("Login acknowledged", follow_up_edits[-1]["text"])
        self.assertNotIn(("12345", 77), archive._TELEGRAM_DELETE_TIMERS)
        self.assertFalse(any(method == "deleteMessage" for method, _ in calls))
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telegram_login_codes").fetchone()[0], 0)

    def test_telegram_code_login_removes_code_message_when_in_place_edit_fails(self):
        with (
            patch.object(archive, "telegram_edit_persistent_message", return_value={}) as edit,
            patch.object(archive, "telegram_delete_message") as delete,
            patch.object(archive, "send_telegram_security_alert", return_value=True) as alert,
        ):
            result = archive.send_login_success_alert(
                "telegram-fallback-admin", "203.0.113.19", telegram_code_used=True,
                telegram_code_value="654321", telegram_code_message={"chat_id": "12345", "message_id": 91},
                user_agent="Firefox on Linux",
            )

        self.assertTrue(result)
        edit.assert_called_once()
        delete.assert_called_once_with("12345", 91)
        alert.assert_called_once()
        self.assertEqual(alert.call_args.kwargs.get("delete_after"), 0)
        self.assertIn("Code used: 654321", alert.call_args.args[0])

    def test_password_login_shows_code_screen_and_waits_for_approval_before_session(self):
        archive.app.config["LOGIN_APPROVAL_REQUIRED"] = True
        archive.save_secure_setting("telegram_bot_token_enc", "test-bot-token")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        _, secret = self.create_user("approval-admin")
        calls = []

        def telegram_api_stub(method, payload):
            calls.append((method, payload))
            return {"ok": True, "result": {"message_id": 77}}

        with patch.object(archive, "telegram_send", return_value={"ok": True, "result": {"message_id": 77}}) as send, \
             patch.object(archive, "telegram_api", side_effect=telegram_api_stub):
            self.client.get("/login")
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "approval-admin", "password": "test-pass",
            }, headers={"User-Agent": "Test Browser/42 (Windows 11)"})
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Verification code", response.data)
            self.assertIn(b"data-login-approval-status", response.data)
            self.assertEqual(send.call_args.kwargs.get("delete_after"), 0)
            self.assertIn("approval-admin", send.call_args.args[1])
            self.assertIn("127.0.0.1", send.call_args.args[1])
            self.assertIn("Test Browser/42 (Windows 11)", send.call_args.args[1])
            self.assertNotIn("test-pass", send.call_args.args[1])
            keyboard = send.call_args.args[2]["inline_keyboard"][0]
            self.assertEqual(len(keyboard), 2)
            self.assertIn("approve", keyboard[0]["callback_data"])
            self.assertIn("deny", keyboard[1]["callback_data"])
            with self.client.session_transaction() as sess:
                approval_id = sess["pending_login_approval_id"]
                self.assertNotIn("user_id", sess)
            with archive.connect_db() as db:
                pending = db.execute("SELECT * FROM login_approval_requests WHERE id=?", (approval_id,)).fetchone()
            self.assertEqual(pending["status"], "pending")
            self.assertEqual(pending["telegram_message_id"], 77)

            callback = {"callback_query": {"id": "approval-yes", "data": keyboard[0]["callback_data"],
                "message": {"message_id": 77, "chat": {"id": 12345, "type": "private"}}}}
            archive.handle_telegram_update(callback)
            with archive.connect_db() as db:
                self.assertEqual(db.execute("SELECT status FROM login_approval_requests WHERE id=?", (approval_id,)).fetchone()[0], "approved")
            with self.client.session_transaction() as sess:
                self.assertEqual(sess["login_approval_id"], approval_id)
                self.assertEqual(sess["pending_2fa_user_id"], pending["user_id"])
            self.assertEqual(self.client.get("/login/approval-status").json["status"], "approved")
            code = pyotp.TOTP(secret).now()
            response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": code})

        self.assertEqual(response.status_code, 302)
        edited = [payload for method, payload in calls if method == "editMessageText"]
        self.assertEqual(len(edited), 2)
        self.assertEqual((edited[-1]["chat_id"], edited[-1]["message_id"]), ("12345", 77))
        self.assertIn("Login successful", edited[-1]["text"])
        self.assertIn("Login method: Authenticator app (TOTP) + Telegram administrator approval", edited[-1]["text"])
        self.assertIn(f"Code used: {code}", edited[-1]["text"])
        self.assertEqual(edited[-1]["reply_markup"], {"inline_keyboard": []})
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT status FROM login_approval_requests WHERE id=?", (approval_id,)).fetchone()[0], "success")

    def test_telegram_login_approval_rejects_request_and_never_creates_session(self):
        archive.app.config["LOGIN_APPROVAL_REQUIRED"] = True
        archive.save_secure_setting("telegram_bot_token_enc", "test-bot-token")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        self.create_user("approval-denied")
        with patch.object(archive, "telegram_send", side_effect=[
                 {"ok": True, "result": {"message_id": 88}},
                 {"ok": True, "result": {"message_id": 89}},
             ]) as send, \
             patch.object(archive, "telegram_api", return_value={"ok": True, "result": {"message_id": 89}}), \
             patch.object(archive, "telegram_start_login_block_countdown") as start_countdown:
            self.client.get("/login")
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "approval-denied", "password": "test-pass",
            })
            self.assertEqual(response.status_code, 200)
            callback_data = send.call_args.args[2]["inline_keyboard"][0][1]["callback_data"]
            with self.client.session_transaction() as sess:
                approval_id = sess["pending_login_approval_id"]
            archive.handle_telegram_update({"callback_query": {"id": "approval-no", "data": callback_data,
                "from": {"id": 12345},
                "message": {"message_id": 88, "chat": {"id": 12345, "type": "private"}}}})
            response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"unable to sign in", response.data.lower())
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)
            self.assertNotIn("pending_login_approval_id", sess)
        with archive.connect_db() as db:
            approval = db.execute("SELECT status,user_id FROM login_approval_requests WHERE id=?", (approval_id,)).fetchone()
            self.assertEqual(approval["status"], "denied")
            blocked_user = db.execute("SELECT login_blocked_until,login_block_message_id,login_block_chat_id FROM users WHERE id=?",
                                      (approval["user_id"],)).fetchone()
            blocked_until = blocked_user["login_blocked_until"]
        self.assertGreater(blocked_until, archive.now())
        self.assertEqual(blocked_user["login_block_message_id"], 89)
        self.assertEqual(blocked_user["login_block_chat_id"], "12345")
        self.assertRegex(send.call_args_list[1].args[1], r"14:5[0-9]|15:00")
        self.assertIn("login_unblock:", send.call_args_list[1].args[2]["inline_keyboard"][0][0]["callback_data"])
        start_countdown.assert_called_once_with(approval["user_id"], "approval-denied", "12345", 89)
        blocked_response = self.client.post("/login", data={
            "csrf_token": self.csrf(), "username": "approval-denied", "password": "test-pass",
        })
        self.assertEqual(blocked_response.status_code, 429)
        self.assertEqual(blocked_response.headers.get("Retry-After"), "899")
        with patch.object(archive, "telegram_api", return_value={"ok": True}) as telegram_api_mock:
            archive.handle_telegram_update({"callback_query": {
                "id": "manual-unblock", "data": f"login_unblock:{approval['user_id']}",
                "from": {"id": 12345},
                "message": {"message_id": 89, "chat": {"id": 12345, "type": "private"}},
            }})
        with archive.connect_db() as db:
            released = db.execute("SELECT login_blocked_until,login_block_message_id,login_block_chat_id FROM users WHERE id=?",
                                  (approval["user_id"],)).fetchone()
        self.assertEqual(released["login_blocked_until"], "")
        self.assertIsNone(released["login_block_message_id"])
        self.assertEqual(released["login_block_chat_id"], "")
        self.assertTrue(any(call.args and call.args[0] == "editMessageText"
                            for call in telegram_api_mock.call_args_list))

    def test_login_block_countdown_formats_minutes_and_seconds(self):
        self.assertEqual(archive.login_block_countdown_text("test-user", 899).splitlines()[2],
                         "⏳ زمان باقی‌مانده: 14:59")
        self.assertEqual(archive.login_block_countdown_text("test-user", 65).splitlines()[2],
                         "⏳ زمان باقی‌مانده: 01:05")

    def test_login_unblock_callback_requires_authorized_sender_and_exact_message(self):
        user_id, _ = self.create_user("countdown-auth")
        blocked_until = (archive.datetime.now(archive.timezone.utc) + archive.timedelta(minutes=10)).isoformat(timespec="seconds")
        with archive.connect_db() as db:
            db.execute("UPDATE users SET login_blocked_until=?,login_block_message_id=456,login_block_chat_id='12345' WHERE id=?",
                       (blocked_until, user_id))
        unauthorized = {"data": f"login_unblock:{user_id}", "from": {"id": 99999},
                        "message": {"message_id": 456, "chat": {"id": 12345, "type": "private"}}}
        self.assertFalse(archive.handle_login_unblock_callback(unauthorized, "12345"))
        stale_message = {"data": f"login_unblock:{user_id}", "from": {"id": 12345},
                         "message": {"message_id": 455, "chat": {"id": 12345, "type": "private"}}}
        self.assertFalse(archive.handle_login_unblock_callback(stale_message, "12345"))
        with archive.connect_db() as db:
            still_blocked = db.execute("SELECT login_blocked_until FROM users WHERE id=?", (user_id,)).fetchone()[0]
        self.assertEqual(still_blocked, blocked_until)
        authorized = {"data": f"login_unblock:{user_id}", "from": {"id": 12345},
                      "message": {"message_id": 456, "chat": {"id": 12345, "type": "private"}}}
        with patch.object(archive, "telegram_api", return_value={"ok": True}):
            self.assertTrue(archive.handle_login_unblock_callback(authorized, "12345"))
        with archive.connect_db() as db:
            released = db.execute("SELECT login_blocked_until,login_block_message_id,login_block_chat_id FROM users WHERE id=?",
                                  (user_id,)).fetchone()
        self.assertEqual(released["login_blocked_until"], "")
        self.assertIsNone(released["login_block_message_id"])
        self.assertEqual(released["login_block_chat_id"], "")

    def test_login_block_countdown_uses_one_shared_worker(self):
        first = archive.telegram_start_login_block_countdown(1, "one", "12345", 1)
        second = archive.telegram_start_login_block_countdown(2, "two", "12345", 2)
        self.assertIs(first, second)
        self.assertTrue(first.is_alive())

    def test_ip_and_account_cards_pin_action_footers_and_scroll_fields(self):
        stylesheet = (archive.BASE_DIR / "static" / "style.css").read_text(encoding="utf-8")
        compact = "".join(stylesheet.split())
        self.assertIn(".mobile-ip-card,.mobile-account-card{display:flex!important;flex-direction:column!important;height:500px;min-height:500px;max-height:500px}", compact)
        self.assertIn(".mobile-ip-fields,.mobile-account-fields{flex:11auto;min-height:0;overflow-y:auto;overscroll-behavior:auto}", compact)
        self.assertIn(".mobile-ip-actions,.mobile-account-actions{flex:00auto;margin-top:auto!important;min-height:62px;align-items:center}", compact)
        self.assertIn(".account-inventory-panel.mobile-account-card.mobile-ip-card{display:flex!important;flex-direction:column!important}", compact)

    def test_admin_can_approve_login_without_authenticator_code(self):
        archive.app.config["LOGIN_APPROVAL_REQUIRED"] = True
        archive.save_secure_setting("telegram_bot_token_enc", "test-bot-token")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        self.create_user("approval-bypass")
        with patch.object(archive, "telegram_send", return_value={"ok": True, "result": {"message_id": 89}}) as send, \
             patch.object(archive, "telegram_api", return_value={"ok": True, "result": {"message_id": 89}}):
            self.client.get("/login")
            response = self.client.post("/login", data={"csrf_token": self.csrf(), "username": "approval-bypass", "password": "test-pass"})
            self.assertIn(b"Verification code", response.data)
            with self.client.session_transaction() as sess:
                approval_id = sess["pending_login_approval_id"]
                self.assertNotIn("user_id", sess)
            callback_data = send.call_args.args[2]["inline_keyboard"][0][0]["callback_data"]
            archive.handle_telegram_update({"callback_query": {"id": "bypass-2fa", "data": callback_data,
                "message": {"message_id": 89, "chat": {"id": 12345, "type": "private"}}}})
            response = self.client.post("/login/approval-complete", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["ok"])
        with self.client.session_transaction() as sess:
            self.assertTrue(sess.get("user_id"))
            self.assertTrue(sess.get("two_factor_verified"))
        with archive.connect_db() as db:
            status = db.execute("SELECT status FROM login_approval_requests WHERE id=?", (approval_id,)).fetchone()["status"]
        self.assertEqual(status, "success")

    def test_entered_authenticator_code_waits_for_admin_and_is_audited_after_approval(self):
        archive.app.config["LOGIN_APPROVAL_REQUIRED"] = True
        archive.save_secure_setting("telegram_bot_token_enc", "test-bot-token")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        _, secret = self.create_user("approval-code-first")
        calls = []
        def telegram_api_stub(method, payload):
            calls.append((method, payload))
            return {"ok": True, "result": {"message_id": 90}}
        with patch.object(archive, "telegram_send", return_value={"ok": True, "result": {"message_id": 90}}) as send, \
             patch.object(archive, "telegram_api", side_effect=telegram_api_stub):
            self.client.get("/login")
            self.client.post("/login", data={"csrf_token": self.csrf(), "username": "approval-code-first", "password": "test-pass"})
            with self.client.session_transaction() as sess:
                approval_id = sess["pending_login_approval_id"]
                self.assertNotIn("user_id", sess)
            code = pyotp.TOTP(secret).now()
            response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": code})
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"data-login-approval-status", response.data)
            with self.client.session_transaction() as sess:
                self.assertNotIn("user_id", sess)
                self.assertTrue(sess.get("pending_2fa_verified"))
                self.assertNotIn(code, str(dict(sess)))
            callback_data = send.call_args.args[2]["inline_keyboard"][0][0]["callback_data"]
            archive.handle_telegram_update({"callback_query": {"id": "approve-after-code", "data": callback_data,
                "message": {"message_id": 90, "chat": {"id": 12345, "type": "private"}}}})
            response = self.client.post("/login/approval-complete", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["ok"])
        with self.client.session_transaction() as sess:
            self.assertTrue(sess.get("user_id"))
        edited = [payload for method, payload in calls if method == "editMessageText"]
        self.assertTrue(any(f"Code used: {code}" in payload.get("text", "") for payload in edited))
        with archive.connect_db() as db:
            status = db.execute("SELECT status FROM login_approval_requests WHERE id=?", (approval_id,)).fetchone()["status"]
        self.assertEqual(status, "success")

    def test_recovery_code_is_consumed_only_after_admin_approval(self):
        archive.app.config["LOGIN_APPROVAL_REQUIRED"] = True
        archive.save_secure_setting("telegram_bot_token_enc", "test-bot-token")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        user_id, _ = self.create_user("approval-recovery-code")
        recovery_code = "ABCD-1234-EFGH-5678"
        with archive.connect_db() as db:
            db.execute("INSERT INTO user_recovery_codes(user_id,code_hash,created_at) VALUES(?,?,?)",
                       (user_id, archive.recovery_code_hash(user_id, recovery_code), archive.now()))
        with patch.object(archive, "telegram_send", return_value={"ok": True, "result": {"message_id": 91}}) as send, \
             patch.object(archive, "telegram_api", return_value={"ok": True, "result": {"message_id": 91}}):
            self.client.get("/login")
            self.client.post("/login", data={"csrf_token": self.csrf(), "username": "approval-recovery-code", "password": "test-pass"})
            response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": recovery_code})
            self.assertEqual(response.status_code, 200)
            with archive.connect_db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=?", (user_id,)).fetchone()[0], 1)
            with self.client.session_transaction() as sess:
                self.assertNotIn("user_id", sess)
            callback_data = send.call_args.args[2]["inline_keyboard"][0][0]["callback_data"]
            archive.handle_telegram_update({"callback_query": {"id": "approve-recovery", "data": callback_data,
                "message": {"message_id": 91, "chat": {"id": 12345, "type": "private"}}}})
            response = self.client.post("/login/approval-complete", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 200)
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=?", (user_id,)).fetchone()[0], 0)

    def test_telegram_fallback_code_is_consumed_only_after_admin_approval(self):
        archive.app.config["LOGIN_APPROVAL_REQUIRED"] = True
        archive.save_secure_setting("telegram_bot_token_enc", "test-bot-token")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        user_id, _ = self.create_user("approval-telegram-code")
        telegram_code = "654321"
        with archive.connect_db() as db:
            db.execute("INSERT INTO telegram_login_codes(user_id,code_hash,expires_at,created_at,chat_id,message_id) VALUES(?,?,?,?,?,?)",
                       (user_id, archive.telegram_login_code_hash(user_id, telegram_code), "2099-01-01T00:00:00+00:00", archive.now(), "12345", 777))
        with patch.object(archive, "telegram_send", return_value={"ok": True, "result": {"message_id": 92}}) as send, \
             patch.object(archive, "telegram_api", return_value={"ok": True, "result": {"message_id": 92}}):
            self.client.get("/login")
            self.client.post("/login", data={"csrf_token": self.csrf(), "username": "approval-telegram-code", "password": "test-pass"})
            response = self.client.post("/login", data={"csrf_token": self.csrf(), "code": telegram_code})
            self.assertEqual(response.status_code, 200)
            with archive.connect_db() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM telegram_login_codes WHERE user_id=?", (user_id,)).fetchone()[0], 1)
                db.execute("UPDATE telegram_login_codes SET expires_at=? WHERE user_id=?", ("2000-01-01T00:00:00+00:00", user_id))
            callback_data = send.call_args.args[2]["inline_keyboard"][0][0]["callback_data"]
            archive.handle_telegram_update({"callback_query": {"id": "approve-telegram-code", "data": callback_data,
                "message": {"message_id": 92, "chat": {"id": 12345, "type": "private"}}}})
            response = self.client.post("/login/approval-complete", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 200)
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM telegram_login_codes WHERE user_id=?", (user_id,)).fetchone()[0], 0)

    def test_telegram_login_approval_callback_rejects_wrong_chat_or_token(self):
        archive.app.config["LOGIN_APPROVAL_REQUIRED"] = True
        archive.save_secure_setting("telegram_bot_token_enc", "test-bot-token")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        self.create_user("approval-token-check")
        with patch.object(archive, "telegram_send", return_value={"ok": True, "result": {"message_id": 99}}) as send:
            self.client.get("/login")
            self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "approval-token-check", "password": "test-pass",
            })
        callback_data = send.call_args.args[2]["inline_keyboard"][0][0]["callback_data"]
        invalid = callback_data.rsplit(":", 1)[0] + ":invalid-token-123"
        with patch.object(archive, "telegram_api", return_value={"ok": True}):
            archive.handle_telegram_update({"callback_query": {"id": "wrong-chat", "data": callback_data,
                "message": {"message_id": 99, "chat": {"id": 54321, "type": "private"}}}})
            archive.handle_telegram_update({"callback_query": {"id": "wrong-token", "data": invalid,
                "message": {"message_id": 99, "chat": {"id": 12345, "type": "private"}}}})
        with archive.connect_db() as db:
            row = db.execute("SELECT status FROM login_approval_requests ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["status"], "pending")

    def test_telegram_approval_then_first_authenticator_enrollment_updates_original_audit(self):
        archive.app.config["LOGIN_APPROVAL_REQUIRED"] = True
        archive.save_secure_setting("telegram_bot_token_enc", "test-bot-token")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        self.create_user("approval-first-enrollment", secret="")
        calls = []

        def telegram_api_stub(method, payload):
            calls.append((method, payload))
            return {"ok": True, "result": {"message_id": 101}}

        with patch.object(archive, "telegram_send", return_value={"ok": True, "result": {"message_id": 101}}) as send, \
             patch.object(archive, "telegram_api", side_effect=telegram_api_stub):
            self.client.get("/login")
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "approval-first-enrollment", "password": "test-pass",
            })
            self.assertIn(b"Verification code", response.data)
            callback_data = send.call_args.args[2]["inline_keyboard"][0][0]["callback_data"]
            with self.client.session_transaction() as sess:
                approval_id = sess["pending_login_approval_id"]
            archive.handle_telegram_update({"callback_query": {"id": "enroll-approve", "data": callback_data,
                "message": {"message_id": 101, "chat": {"id": 12345, "type": "private"}}}})
            response = self.client.get("/login")
            self.assertEqual(response.status_code, 302)
            self.assertIn("setup-2fa", response.location)
            response = self.client.get("/setup-2fa")
            self.assertEqual(response.status_code, 200)
            with self.client.session_transaction() as sess:
                secret = sess["pending_2fa_secret"]
                self.assertEqual(sess["login_approval_id"], approval_id)
            response = self.client.post("/setup-2fa", data={
                "csrf_token": self.csrf(), "code": pyotp.TOTP(secret).now(),
            })

        self.assertEqual(response.status_code, 302)
        edits = [payload for method, payload in calls if method == "editMessageText"]
        self.assertEqual(len(edits), 2)
        self.assertIn("Administrator approval + Authenticator enrollment", edits[-1]["text"])
        self.assertIn("Code used:", edits[-1]["text"])
        self.assertEqual(edits[-1]["reply_markup"], {"inline_keyboard": []})
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT status FROM login_approval_requests WHERE id=?", (approval_id,)).fetchone()[0], "success")

    def test_telegram_approval_delivery_failure_blocks_login(self):
        archive.app.config["LOGIN_APPROVAL_REQUIRED"] = True
        archive.save_secure_setting("telegram_bot_token_enc", "test-bot-token")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        self.create_user("approval-delivery-failure")
        with patch.object(archive, "telegram_send", return_value={}):
            self.client.get("/login")
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "approval-delivery-failure", "password": "test-pass",
            })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Unable to sign in right now", response.data)
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)
            self.assertNotIn("pending_login_approval_id", sess)
        with archive.connect_db() as db:
            row = db.execute("SELECT status FROM login_approval_requests ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["status"], "delivery_failed")

    def test_telegram_approval_without_second_factor_logs_admin_approval_method(self):
        archive.app.config["LOGIN_APPROVAL_REQUIRED"] = True
        archive.save_secure_setting("telegram_bot_token_enc", "test-bot-token")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        self.create_user("approval-password-only")
        with archive.connect_db() as db:
            db.execute("UPDATE app_settings SET value='off' WHERE key='two_factor_mode'")
        calls = []

        def telegram_api_stub(method, payload):
            calls.append((method, payload))
            return {"ok": True, "result": {"message_id": 121}}

        with patch.object(archive, "telegram_send", return_value={"ok": True, "result": {"message_id": 121}}) as send, \
             patch.object(archive, "telegram_api", side_effect=telegram_api_stub):
            self.client.get("/login")
            response = self.client.post("/login", data={
                "csrf_token": self.csrf(), "username": "approval-password-only", "password": "test-pass",
            })
            self.assertIn(b"Please wait", response.data)
            callback_data = send.call_args.args[2]["inline_keyboard"][0][0]["callback_data"]
            with self.client.session_transaction() as sess:
                approval_id = sess["pending_login_approval_id"]
            archive.handle_telegram_update({"callback_query": {"id": "password-only-approve", "data": callback_data,
                "message": {"message_id": 121, "chat": {"id": 12345, "type": "private"}}}})
            response = self.client.get("/login")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")
        with self.client.session_transaction() as sess:
            self.assertTrue(sess.get("user_id"))
        edits = [payload for method, payload in calls if method == "editMessageText"]
        self.assertEqual(len(edits), 2)
        self.assertIn("Login method: Administrator approval", edits[-1]["text"])
        self.assertNotIn("Code used:", edits[-1]["text"])
        self.assertEqual(edits[-1]["reply_markup"], {"inline_keyboard": []})
        with archive.connect_db() as db:
            self.assertEqual(db.execute("SELECT status FROM login_approval_requests WHERE id=?", (approval_id,)).fetchone()[0], "success")

    def test_telegram_search_results_include_saved_connection_password_for_configured_chat(self):
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
        self.assertIn("Password: <code>do-not-send-device-secret</code>", output)

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

    def test_latest_release_falls_back_to_public_git_refs_when_api_rate_limited(self):
        from urllib.error import HTTPError
        from unittest.mock import MagicMock

        response = MagicMock()
        response.__enter__.return_value = response
        response.geturl.return_value = "https://github.com/AmiRaiZo/IP-Management/releases/tag/v3.0.27"
        commit_sha = "a" * 40
        refs = MagicMock(returncode=0, stdout=f"{commit_sha}\trefs/tags/v3.0.27\n", stderr="")
        with patch.object(archive, "urlopen", side_effect=[HTTPError("https://api.github.com", 403, "rate limit exceeded", {}, None), response]) as mocked_urlopen:
            with patch.object(archive.subprocess, "run", return_value=refs) as git_run:
                release = archive.latest_release()

        self.assertEqual(release, {"version": "3.0.27", "sha": commit_sha, "tag": "v3.0.27"})
        self.assertEqual(git_run.call_args.args[0][1], "ls-remote")
        self.assertEqual(git_run.call_args.kwargs["timeout"], 12)

    def test_latest_release_accepts_two_component_semver_tag_v5_0(self):
        import json

        commit_sha = "b" * 40
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = json.dumps({
            "tag_name": "v5.0", "target_commitish": commit_sha,
        }).encode("utf-8")
        with patch.object(archive, "urlopen", return_value=response):
            release = archive.latest_release()

        self.assertEqual(release, {"version": "5.0", "sha": commit_sha, "tag": "v5.0"})

    def test_installed_version_accepts_two_component_semver(self):
        with tempfile.TemporaryDirectory() as directory:
            version_file = Path(directory) / "version"
            version_file.write_text("5.0\n", encoding="utf-8")
            with patch.object(archive, "VERSION_FILE", version_file):
                self.assertEqual(archive.installed_version(), "5.0")

if __name__ == "__main__":
    unittest.main()


class ReleaseScriptSyntaxTests(unittest.TestCase):
    def test_deployment_shell_scripts_have_valid_bash_syntax(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is not installed on this platform")
        root = Path(__file__).resolve().parent
        for name in ("install.sh", "station-archive-update", "upgrade_existing.sh"):
            with self.subTest(script=name):
                script = root / name
                self.assertTrue(script.is_file(), f"missing deployment script: {name}")
                source = script.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
                result = subprocess.run([bash, "-n"], input=source.encode("utf-8"), capture_output=True)
                self.assertEqual(result.returncode, 0, f"{name}: {result.stderr.decode('utf-8', errors='replace')}")

    def test_in_place_upgrade_embedded_updater_has_valid_bash_syntax(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is not installed on this platform")
        root = Path(__file__).resolve().parent
        upgrade_script = (root / "upgrade_existing.sh").read_text(encoding="utf-8")
        start_marker = "cat > /usr/local/sbin/station-archive-update <<'UPDATER'\n"
        end_marker = "\nUPDATER\n"
        self.assertEqual(upgrade_script.count(start_marker), 1, "expected one embedded updater heredoc")
        start = upgrade_script.index(start_marker) + len(start_marker)
        end = upgrade_script.index(end_marker, start)
        generated_updater = upgrade_script[start:end] + "\n"
        self.assertIn('echo "PROGRESS:84:Validating Nginx configuration"', generated_updater)
        self.assertIn('\n\techo "PROGRESS:84:Validating Nginx configuration"', generated_updater)
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "station-archive-update.generated"
            script.write_text(generated_updater, encoding="utf-8")
            source = script.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
            result = subprocess.run([bash, "-n"], input=source.encode("utf-8"), capture_output=True)
            self.assertEqual(result.returncode, 0, f"generated updater: {result.stderr.decode('utf-8', errors='replace')}")

    def test_updater_bootstraps_before_deploy_and_never_overwrites_its_running_file(self):
        updater = Path(__file__).with_name("station-archive-update").read_text(encoding="utf-8")
        self.assertIn('bash -n "$BOOTSTRAP_TMP/updater.new"', updater)
        self.assertIn('install -o root -g root -m 0750 "$BOOTSTRAP_TMP/updater.new" /usr/local/sbin/station-archive-update', updater)
        self.assertIn("for required in app.py requirements.txt templates static reconfigure_server.sh ip-management-recover-access station-archive-update station_archive_refresh_ip.py", updater)
        bootstrap = updater.index('Refreshing the privileged updater from the verified release')
        deploy = updater.index("rsync -a --delete --exclude='.git/'")
        self.assertLess(bootstrap, deploy, "updater bootstrap must precede deployment")
        self.assertIn('if [[ "${1:-}" != "--bootstrapped" ]]; then', updater)
        self.assertIn('exec /usr/local/sbin/station-archive-update --bootstrapped', updater)
        self.assertNotIn('UPDATER_BOOTSTRAPPED', updater)
        self.assertIn('if ! bash -n "$0"; then', updater)
        self.assertNotIn('install -o root -g root -m 0750 "$TMP/station-archive-update.new" /usr/local/sbin/station-archive-update', updater)
        self.assertIn("Never overwrite the executable currently being interpreted", updater)
