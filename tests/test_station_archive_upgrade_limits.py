import tempfile
import unittest
from pathlib import Path

from station_archive_upgrade_limits import (
    update_existing_limits,
    update_gunicorn_timeout,
    update_nginx_source,
)


SAMPLE_NGINX = """server {
    listen 80;
    server_name panel.example.test;
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 192.0.2.10:443 ssl;
    server_name panel.example.test;
    ssl_certificate /etc/ssl/example/fullchain.pem;
    location / {
        proxy_pass http://127.0.0.1:8766;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
    }
}
"""


class NginxRestoreLimitTests(unittest.TestCase):
    def test_updates_only_the_matching_https_proxy_server(self):
        updated, count = update_nginx_source(SAMPLE_NGINX, "panel.example.test", 443, 8766)
        self.assertEqual(count, 1)
        http_block, https_block = updated.split("server {", 2)[1:]
        self.assertNotIn("client_max_body_size", http_block)
        self.assertIn("client_max_body_size 512m;", https_block)
        self.assertIn("client_body_timeout 900s;", https_block)
        self.assertIn("proxy_read_timeout 900s;", https_block)
        self.assertIn("proxy_send_timeout 900s;", https_block)

    def test_rejects_a_domain_or_port_that_does_not_match(self):
        with self.assertRaisesRegex(ValueError, "Could not find"):
            update_nginx_source(SAMPLE_NGINX, "other.example.test", 443, 8766)

    def test_updates_existing_nginx_file_and_gunicorn_unit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nginx_dir = root / "sites-enabled"
            nginx_dir.mkdir()
            nginx_file = nginx_dir / "station-archive"
            nginx_file.write_text(SAMPLE_NGINX, encoding="utf-8")
            service_unit = root / "station-archive.service"
            service_unit.write_text(
                "[Service]\nExecStart=/opt/app/.venv/bin/gunicorn --workers 2 --timeout 60 app:app\n",
                encoding="utf-8",
            )
            count = update_existing_limits(
                "panel.example.test", 443, 8766,
                nginx_roots=(nginx_dir,), service_unit=service_unit,
            )
            self.assertEqual(count, 1)
            self.assertIn("client_max_body_size 512m;", nginx_file.read_text(encoding="utf-8"))
            self.assertIn("--timeout 900", service_unit.read_text(encoding="utf-8"))

    def test_updates_both_supported_gunicorn_timeout_spellings(self):
        with tempfile.TemporaryDirectory() as temporary:
            for index, argument in enumerate(("--timeout 60", "--timeout=30")):
                unit = Path(temporary) / f"service-{index}.service"
                unit.write_text(f"ExecStart=gunicorn {argument} app:app\n", encoding="utf-8")
                self.assertTrue(update_gunicorn_timeout(unit))
                self.assertIn("--timeout 900", unit.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

