# IP Archive

IP Archive is an English-language web application for storing and managing IP connection records. It includes a persistent light/dark theme, authenticator-based two-factor authentication (TOTP), searchable IP records, group filtering, superadmin/user roles, group-level visibility, per-IP allow/deny overrides, and an in-site GitHub update action. Public registration is disabled; access is restricted to accounts created by a superadmin.

## Versioned releases and one-command installation

The project uses GitHub Releases as the source of truth for deployed application code. A successful push to `main` automatically publishes a versioned release with a ZIP package. The version starts from `VERSION` (currently `1.0.0`); subsequent releases automatically increment the patch number. To start a new major/minor series, update `VERSION` (for example, set it to `2.0.0`) before pushing. You can also run the **Publish versioned release** workflow manually and provide an exact semantic version such as `2.0.0`.

The public `install.sh` URL is only a small bootstrap. It fetches the latest published release package; the actual application code and upgrades do not clone `main`.

### Fresh installation on Ubuntu 22.04 or 24.04

1. Create an `A` DNS record for your domain that points to the server's public IPv4 address.
2. Allow inbound TCP port `80` and the HTTPS port you intend to use in both the VPS provider firewall and the Ubuntu firewall.
3. Run the stable command below. There is no commit hash or cache-busting number to change:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/AmiRaiZo/IP-Management/main/install.sh | sudo bash
   ```

The installer asks for the domain, HTTPS port (default `443`), superadmin username, and password. Password entry is hidden and confirmed; empty passwords are rejected. It installs Python, Nginx, Git, Certbot and dependencies, obtains a Let's Encrypt certificate through port `80`, configures HTTPS, and creates the initial superadmin. Open `https://your-domain` for port `443`, or `https://your-domain:PORT` for a custom port.

### Upgrade an existing installation

Run the same stable installer command. It detects an existing installation and offers the in-place upgrade. The upgrader downloads the latest published release package and preserves the current domain, public HTTPS port, Nginx configuration, SSL certificates, secret values and database. It creates a timestamped backup before changing application files.

### Updating from the website (no SSH required)

Sign in as a **superadmin**, open **Updates** in the sidebar, and review the installed version, latest available release and release notes. Select **Install update** to apply a newer published release. The server downloads the release asset, makes a backup of the application, runtime data/database and environment configuration, recreates the Python virtual environment, installs dependencies, checks Nginx and restarts the service. The update log is stored at `/var/lib/station-archive/update.log`. If deployment fails, the updater attempts to restore the previous application and data.

Only published releases are installed; changes on `main` do not go directly to production until the release workflow has packaged them. The release workflow publishes a release for every push to `main`. Review changes before merging or pushing because the updater runs application code from the published release.

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
