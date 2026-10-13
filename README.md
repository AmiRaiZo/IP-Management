# IP Archive

IP Archive is an English-language web application for storing and managing IP connection records. It includes a persistent light/dark theme, authenticator-based two-factor authentication (TOTP), searchable IP records, group filtering, superadmin/user roles, group-level visibility, per-IP allow/deny overrides, and an in-site GitHub update action. Public registration is disabled; access is restricted to accounts created by a superadmin.

## One-command installation on Ubuntu 22.04 or 24.04

1. Create an `A` DNS record for your domain that points to the server's public IPv4 address.
2. Allow inbound TCP port `80` and the HTTPS port you intend to use in both the VPS provider firewall and the Ubuntu firewall.
3. Run the installer from your public GitHub repository. Replace `OWNER/REPOSITORY` with the actual repository path:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/OWNER/REPOSITORY/main/install.sh | sudo bash
   ```

The installer asks for the domain, public HTTPS port (default `443`), internal application port (default `8088`), public GitHub repository URL, superadmin username, and superadmin password. Password entry is hidden and confirmed; there is no arbitrary minimum password length, but an empty password is rejected. The repository must be public and hosted on GitHub.

The installer installs Python, Nginx, Git, Certbot, and the application dependencies; obtains a Let's Encrypt certificate using the HTTP-01 challenge on port `80`; configures HTTPS on your chosen public port; and creates the initial superadmin account. The app listens only on `127.0.0.1` at the internal port. Open the site at `https://your-domain` for port `443`, or `https://your-domain:PORT` for a custom port.

## One-time upgrade of an existing installation

For a server that already has an older installation in `/opt/station-archive`, run the in-place upgrader from the new public GitHub repository:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPOSITORY/main/upgrade_existing.sh | sudo bash
```

Replace `OWNER/REPOSITORY` with the repository that contains `upgrade_existing.sh`. The script detects the current internal application port from systemd (or Nginx as a fallback), and detects the existing domain and public HTTPS port from the active Nginx HTTPS proxy block. It asks for the public GitHub repository URL, makes a timestamped root-only backup of the app files, `/etc/station-archive/env`, and `/var/lib/station-archive/archive.sqlite3` (including SQLite sidecar files when present), then updates the code and dependencies in place. It adds or updates repository/domain/port settings while retaining existing secret values and unrelated environment settings. Existing Nginx configuration and SSL certificates are left in place.

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
