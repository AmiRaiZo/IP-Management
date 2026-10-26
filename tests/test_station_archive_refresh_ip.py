import tempfile
import unittest
from pathlib import Path

from station_archive_refresh_ip import (
    NoPublicIPv4,
    choose_public_ipv4,
    rewrite_listener,
)


class PublicIPv4SelectionTests(unittest.TestCase):
    def test_prefers_public_route_source_when_it_is_local(self):
        self.assertEqual(
            choose_public_ipv4(
                "1.1.1.1 via 212.64.210.1 dev ens160 src 212.64.210.74",
                [
                    ("lo", "127.0.0.1"),
                    ("ens160", "212.64.210.74"),
                    ("tun-ovpn-4-u", "10.2.0.1"),
                    ("ppp4", "192.168.36.1"),
                ],
            ),
            "212.64.210.74",
        )

    def test_ignores_private_route_source_when_one_public_address_exists(self):
        self.assertEqual(
            choose_public_ipv4(
                "1.1.1.1 dev tun-ovpn-4-u src 10.2.0.1",
                [("ens160", "212.64.210.74"), ("tun-ovpn-4-u", "10.2.0.1")],
            ),
            "212.64.210.74",
        )

    def test_fails_safe_when_multiple_public_addresses_are_ambiguous(self):
        with self.assertRaises(NoPublicIPv4):
            choose_public_ipv4(
                "1.1.1.1 dev tun0 src 10.2.0.1",
                [("ens160", "212.64.210.74"), ("ens192", "8.8.8.8"), ("tun0", "10.2.0.1")],
            )


class NginxListenerRewriteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / "station-archive-note.example.test"
        self.backups = self.root / "backups"
        self.config.write_text(
            "server {\n"
            "    listen 80;\n"
            "    server_name note.example.test;\n"
            "    location / { return 301 https://$host:443$request_uri; }\n"
            "}\n"
            "server {\n"
            "    listen 212.64.202.199:443 ssl;\n"
            "    server_name note.example.test;\n"
            "    location / {\n"
            "        proxy_pass http://127.0.0.1:443;\n"
            "    }\n"
            "}\n"
            "server {\n"
            "    listen 192.0.2.10:443 ssl;\n"
            "    server_name another.example.test;\n"
            "    location / { return 200; }\n"
            "}\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_updates_only_the_target_proxy_server(self):
        changed, backup = rewrite_listener(
            self.config, "note.example.test", 443, 443, "212.64.210.74", self.backups
        )
        source = self.config.read_text(encoding="utf-8")
        self.assertTrue(changed)
        self.assertIsNotNone(backup)
        self.assertTrue(backup.is_file())
        self.assertIn("listen 212.64.210.74:443 ssl;", source)
        self.assertIn("listen 192.0.2.10:443 ssl;", source)
        self.assertIn("listen 80;", source)

    def test_is_idempotent_when_ip_is_already_current(self):
        rewrite_listener(
            self.config, "note.example.test", 443, 443, "212.64.210.74", self.backups
        )
        changed, backup = rewrite_listener(
            self.config, "note.example.test", 443, 443, "212.64.210.74", self.backups
        )
        self.assertFalse(changed)
        self.assertIsNone(backup)

    def test_does_not_touch_other_listener_when_proxy_port_does_not_match(self):
        with self.assertRaises(RuntimeError):
            rewrite_listener(
                self.config, "note.example.test", 443, 8443, "212.64.210.74", self.backups
            )


if __name__ == "__main__":
    unittest.main()
