# IP Archive

**Current release: 2.1.0**

IP Archive is an English-language web application for storing and managing IP connection records. It includes a persistent light/dark theme, authenticator-based two-factor authentication (TOTP), searchable IP records, group filtering, superadmin/user roles, group-level visibility, per-IP allow/deny overrides, and an in-site GitHub update action. Public registration is disabled; access is restricted to accounts created by a superadmin.

## Version 2.1.0 release notes

- Added ten one-time 2FA recovery codes per user. They are generated after password and current-authenticator re-authentication, stored only as keyed hashes, shown once with no-store headers, and consumed atomically on use.
- Login accepts an unused recovery code if the authenticator app is unavailable. Regenerating codes invalidates the previous set.
- Recovery codes are deliberately not delivered by Telegram. Sending an OTP from the server to the same Telegram bot/chat would turn that channel into a second-factor bypass; keep recovery codes offline.

## Version 2.0.0 release notes

- Login alerts use a consistent Persian format and include the submitted username, source IP, hostname, Jalali timestamp, and failure reason.
- Failed password guesses are **not** stored as plaintext in the site logs or sent to Telegram. Alerts use a short keyed fingerprint instead; raw authenticator codes are never logged or sent.
- Failed sign-in attempts remain rate-limited to reduce brute-force risk.
- Telegram alerts and the interactive `ربات` menu are supported, including IP record add/search. Webhook requests require Telegram's secret-token header and are restricted to the configured chat ID.
- The readable TXT export requires superadmin access, CSRF protection, and password re-authentication; it redacts account hashes, TOTP seeds, and Telegram credentials. It is a data/source export, not a complete restorable server backup.
- Security review and tests cover protected routes, server-side 2FA enforcement, access controls, webhook authorization, and export protections. A passing test suite is not a substitute for a production penetration test.

## One-command installation on Ubuntu 22.04 or 24.04

1. Create an `A` DNS record for your domain that points to the server's public IPv4 address.
2. Allow inbound TCP port `80` and the HTTPS port you intend to use in both the VPS provider firewall and the Ubuntu firewall.
3. Run the installer from the project's public GitHub repository:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/AmiRaiZo/IP-Management/main/install.sh | sudo bash
   ```

The installer asks for the domain, one HTTPS port (default `443`), superadmin username, and superadmin password. It automatically uses `https://github.com/AmiRaiZo/IP-Management`, so you do not need to enter the repository URL again. The same port number is used publicly and by the application: Nginx binds to the VPS's public IPv4 address, while Gunicorn binds to `127.0.0.1`, so they do not compete for the same socket. The VPS public IPv4 must be assigned directly to a local network interface (not only forwarded through external NAT). Password entry is hidden and confirmed; there is no arbitrary minimum password length, but an empty password is rejected.

The installer installs Python, Nginx, Git, Certbot, and the application dependencies; obtains a Let's Encrypt certificate using the HTTP-01 challenge on port `80`; configures HTTPS on your chosen port; and creates the initial superadmin account. Open the site at `https://your-domain` for port `443`, or `https://your-domain:PORT` for a custom port. If the application service fails to start, the installer prints recent service logs rather than leaving the cause hidden behind a `502 Bad Gateway` page.

## One-time upgrade of an existing installation

For a server that already has an older installation in `/opt/station-archive`, run the in-place upgrader:

```bash
curl -fsSL https://raw.githubusercontent.com/AmiRaiZo/IP-Management/main/upgrade_existing.sh | sudo bash
```

The script detects the current internal application port from systemd (or Nginx as a fallback), and detects the existing domain and public HTTPS port from the active Nginx HTTPS proxy block. It uses the canonical GitHub repository automatically, makes a timestamped root-only backup of the app files, `/etc/station-archive/env`, and `/var/lib/station-archive/archive.sqlite3` (including SQLite sidecar files when present), then updates the code and dependencies in place. It adds or updates repository/domain/port settings while retaining existing secret values and unrelated environment settings. Existing Nginx configuration and SSL certificates are left in place.

The upgrader stops if it cannot identify the existing service or HTTPS proxy configuration. Review the printed backup path after it completes. It does not recreate the database or reinstall the application as a fresh deployment.

## Updating from GitHub

The installer creates a root-owned updater at `/usr/local/sbin/station-archive-update`. The application service account (`www-data`) is granted passwordless sudo permission for that exact command through `/etc/sudoers.d/station-archive-update`. The updater keeps a temporary copy of the current application files and attempts to restore them if an update fails. An application update action can invoke:

```bash
sudo /usr/local/sbin/station-archive-update
```

For a manual update, run the same command as an administrator. The updater fetches the configured repository, checks for required application files, synchronizes the application code, installs updated Python dependencies, validates Nginx configuration, and restarts the service. It does not reinstall Ubuntu packages, regenerate secrets, or intentionally remove runtime data.

## Persistent files and service operations

- Application code: `/opt/station-archive`
- Database and runtime data: `/var/lib/station-archive`
- Secrets and deployment configuration: `/etc/station-archive/env`
- Nginx site configuration: `/etc/nginx/sites-available/`
- Service logs: `sudo journalctl -u station-archive -f`
- Service status: `sudo systemctl status station-archive`
- Certificate renewal check: `sudo certbot renew --dry-run`

The updater preserves `/var/lib/station-archive` and `/etc/station-archive/env`. Back up both securely. The environment file contains encryption and session secrets; losing them may make stored encrypted values unrecoverable. The GitHub repository must contain `app.py`, `setup_admin.py`, `requirements.txt`, `templates/`, and `static/`. Review repository changes before updating production, because the updater executes the application code supplied by that repository.

## Network and TLS notes

Port `80/tcp` must be reachable for certificate issuance and renewal. The selected public HTTPS port must also be reachable. A custom HTTPS port must be included in the URL, for example `https://archive.example.com:8443`. The installer does not change provider-level firewall rules. If certificate issuance fails, verify DNS and port 80, then retry certificate issuance with:

```bash
sudo certbot certonly --webroot -w /var/www/station-archive-acme -d archive.example.com
```

