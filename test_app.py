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
        self.client = archive.app.test_client()
        with archive.connect_db() as db:
            db.execute("DELETE FROM user_ip_access")
            db.execute("DELETE FROM user_group_access")
            db.execute("DELETE FROM ips")
            db.execute("DELETE FROM accounts")
            db.execute("DELETE FROM account_groups")
            db.execute("DELETE FROM groups")
            db.execute("INSERT INTO groups(name,description,created_at,sort_order) VALUES('Default','Default group for IP records',?,0)", (archive.now(),))
            db.execute("INSERT INTO account_groups(name,description,created_at,sort_order) VALUES('Default','Default group for saved accounts',?,0)", (archive.now(),))
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

    def test_telegram_menu_includes_display_all_groups_button(self):
        with patch.object(archive, "telegram_send") as send:
            archive.telegram_menu("12345")
        markup = send.call_args.args[2]
        self.assertEqual(markup["inline_keyboard"][1][0]["text"], "📂 Display all groups")
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

    def test_telegram_menu_has_english_2fa_button_and_callback_issues_code(self):
        user_id, _ = self.create_user("telegram-button-admin", role="superadmin")
        archive.save_secure_setting("telegram_chat_id_enc", "12345")
        with patch.object(archive, "telegram_send") as send, patch.object(archive, "telegram_api", return_value={"ok": True}):
            archive.telegram_menu("12345")
            menu_markup = send.call_args.args[2]
            self.assertEqual(menu_markup["inline_keyboard"][2][0]["text"], "🔐 2FA code")
            self.assertEqual(menu_markup["inline_keyboard"][2][0]["callback_data"], "telegram_2fa_code")
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
            start = page.index('data-mobile-ip-list')
            end = page.index('</div>', start)
            mobile_list = page[start:end]
            mobile_records = re.findall(
                r'data-ip-name="([^"]+)"[^>]*data-ip-group="([^"]+)"', mobile_list
            )
            self.assertEqual(
                mobile_records, expected,
                "Mobile IP directory must sort group names A-Z, then IP names A-Z within each group",
            )

            table = page[page.index('<tbody>'):]
            desktop_rows = re.findall(r'<tr data-search-row.*?</tr>', table, re.S)
            desktop_records = []
            for row in desktop_rows:
                name_match = re.search(r'<strong>(.*?)</strong>', row, re.S)
                group_match = re.search(r'<span class="group-tag">(.*?)</span>', row, re.S)
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
        self.assertEqual(db.execute("SELECT COUNT(*) FROM ips WHERE ip_address='amir@example.com'").fetchone()[0], 0)

        response = self.client.get("/accounts?q=amir")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Work Email", response.data)
        self.assertIn(b"amir@example.com", response.data)
        self.assertIn(b'data-copy-value="account-secret-value"', response.data)
        self.assertIn(b"••••••••".decode("utf-8").encode("utf-8"), response.data)

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
        self.assertIn('<th class="name-column">Name</th>', page)
        stylesheet = (archive.BASE_DIR / 'static' / 'style.css').read_text(encoding='utf-8')
        self.assertIn('.inventory-panel .table-scroll table th:first-child{text-align:center;padding-left:18px}', stylesheet)
        self.assertIn('.inventory-panel .table-scroll .record-name{position:relative;display:flex;align-items:center;justify-content:center;width:100%;min-height:32px}', stylesheet)
        self.assertIn('width:calc(100% - 132px);margin-left:132px', stylesheet)
        self.assertIn('.inventory-panel .table-scroll .record-avatar{position:absolute;left:0;top:50%;transform:translateY(-50%);border-radius:50%}', stylesheet)
        self.assertIn('.profile-info{display:grid;gap:3px;min-width:0;flex:1}', stylesheet)
    def test_mobile_ip_directory_uses_name_cards_and_permission_gated_copy_details(self):
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
        self.assertIn('data-mobile-ip-card', page)
        self.assertIn('data-ip-name="Mobile router"', page)
        self.assertIn('data-ip-address="192.0.2.99"', page)
        self.assertIn('data-ip-port="8728"', page)
        self.assertIn('data-ip-username="mobile-user"', page)
        self.assertIn('data-ip-password="mobile-secret"', page)
        self.assertIn('id="mobile-ip-details-modal"', page)
        self.assertIn('id="mobile-ip-details-list"', page)
        self.assertLess(page.index(">Group</th>"), page.index(">IP address / host</th>"))
        script = (archive.BASE_DIR / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("document.querySelectorAll('[data-mobile-ip-card]')", script)
        self.assertLess(script.index("addMobileIpDetail('Group', data.ipGroup, false)"),
                        script.index("addMobileIpDetail('IP address', data.ipAddress, true)"))
        self.assertIn("event.target.closest('[data-copy-value]')", script)
        self.assertIn("mobileRows.forEach(row =>", script)
        stylesheet = (archive.BASE_DIR / "static" / "style.css").read_text(encoding="utf-8")
        self.assertIn(".inventory-panel .table-scroll{display:none!important}", stylesheet)
        self.assertIn(".mobile-ip-list{display:grid;gap:8px", stylesheet)
        self.assertIn(".mobile-ip-list{display:grid;gap:10px;padding:14px 12px 16px}", stylesheet)
        self.assertIn("text-align:center", stylesheet[stylesheet.index("v3.0.7: center and polish mobile IP cards"):])
        self.assertIn("backdrop-filter:blur(8px)", stylesheet)

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
                result = subprocess.run([bash, "-n", str(script)], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, f"{name}: {result.stderr}")

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
            result = subprocess.run([bash, "-n", str(script)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, f"generated updater: {result.stderr}")

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
