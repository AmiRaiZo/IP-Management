import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from station_archive_domain_recovery import (
    atomic_write_text,
    atomic_update_env,
    find_usable_https_port,
    normalize_domain,
    render_nginx_site,
)
from station_archive_refresh_ip import rewrite_listener


class DomainValidationTests(unittest.TestCase):
    def test_normalizes_valid_hostname(self):
        self.assertEqual(normalize_domain(" Panel.Example.COM "), "panel.example.com")

    def test_rejects_url_port_path_and_invalid_labels(self):
        for value in (
            "https://panel.example.com/path", "panel.example.com:443",
            "-bad.example.com", "bad..example.com", "localhost", "192.0.2.1",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)


class DomainRecoveryTests(unittest.TestCase):
    def test_finds_only_matching_https_proxy_with_valid_domain_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cert = root / "fullchain.pem"
            cert.write_text("test certificate")
            config = root / "site.conf"
            config.write_text(
                "server {\n    listen 443 ssl;\n    server_name old.example.com;\n"
                f"    ssl_certificate {cert};\n    location / {{ proxy_pass http://127.0.0.1:8766; }}\n}}\n"
            )
            with patch("station_archive_domain_recovery.subprocess.run") as run:
                run.return_value.returncode = 0
                self.assertEqual(find_usable_https_port("old.example.com", 8766, (root,)), 443)
                run.assert_called_once()

    def test_rejects_certificate_that_does_not_cover_domain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cert = root / "fullchain.pem"
            cert.write_text("test certificate")
            (root / "site.conf").write_text(
                "server {\n    listen 443 ssl;\n    server_name panel.example.com;\n"
                f"    ssl_certificate {cert};\n    location / {{ proxy_pass http://127.0.0.1:8766; }}\n}}\n"
            )
            with patch("station_archive_domain_recovery.subprocess.run") as run:
                run.return_value.returncode = 1
                self.assertIsNone(find_usable_https_port("panel.example.com", 8766, (root,)))

    def test_renders_helper_compatible_ip_specific_https_proxy(self):
        config = render_nginx_site("panel.example.com", "192.0.2.10", 443, 8766)
        self.assertIn("listen 192.0.2.10:443 ssl;", config)
        self.assertIn("server_name panel.example.com;", config)
        self.assertIn("proxy_pass http://127.0.0.1:8766;", config)
        self.assertIn("/etc/letsencrypt/live/panel.example.com/fullchain.pem", config)

    def test_rendered_site_is_accepted_by_public_ip_refresh_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            site = root / "station-archive-panel.example.com"
            site.write_text(render_nginx_site("panel.example.com", "192.0.2.10", 443, 8766))
            changed, backup = rewrite_listener(
                site, "panel.example.com", 443, 8766, "192.0.2.10", root / "backups"
            )
            self.assertFalse(changed)
            self.assertIsNone(backup)

    def test_generated_site_file_is_replaced_atomically_with_private_safe_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "station-archive-panel.example.com"
            atomic_write_text(target, "server {}\n")
            self.assertEqual(target.read_text(), "server {}\n")
            if os.name != "nt":
                self.assertEqual(target.stat().st_mode & 0o777, 0o644)
            self.assertFalse(list(Path(temporary).glob(".station-archive-panel.example.com.*")))

    def test_env_update_is_atomic_in_content_and_preserves_unrelated_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = Path(temporary) / "env"
            env.write_text("SECRET_KEY=keep\nAPP_DOMAIN=old.example.com\nCUSTOM=value\n")
            atomic_update_env(env, {"APP_DOMAIN": "new.example.com", "DOMAIN": "new.example.com"})
            content = env.read_text()
            self.assertIn("SECRET_KEY=keep", content)
            self.assertIn("CUSTOM=value", content)
            self.assertIn("APP_DOMAIN=new.example.com", content)
            self.assertIn("DOMAIN=new.example.com", content)
            self.assertNotIn("APP_DOMAIN=old.example.com", content)


if __name__ == "__main__":
    unittest.main()
