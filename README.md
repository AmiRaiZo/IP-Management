## Version 2.9.0 release notes

- Added a Telegram **Display all groups** menu with inline buttons for every group.
- Selecting a group shows only the names of its IP records; selecting a name replaces the current screen with the full connection details.
- Group browsing uses one edited Telegram message for each stage, with back buttons to IP names, all groups, or the main menu instead of stacking old screens.
- Kept the sidebar toggle icon-only and added smooth collapse/expand transitions, with reduced-motion support.
- Updated the stylesheet cache key for the new interface.

## Version 2.6.14 release notes

- Changed the sidebar hide/show control to a three-line hamburger button.
- Hiding the sidebar now collapses the entire navigation, leaving only the floating hamburger control.
- Kept the main content full-width while the sidebar is hidden and preserved the saved collapse preference.
- Bumped the stylesheet cache version to ensure browsers load the updated sidebar styles.

## Version 2.6.1 release notes

- Fixed the IP list `Name` column header alignment so it starts above the IP name text rather than the avatar.

## Version 2.6.0 release notes

- Added a hide/show control for the left navigation sidebar; the preference is remembered in the browser.
- Improved responsive layout behavior for mobile phones and narrow screens while keeping wide tables horizontally scrollable.
- Restored the IP-row avatar to its original rounded-square style and made the avatar in the authentication/login user card circular.

## Version 2.5.9 release notes

- Remember a successful authenticator-code verification on that browser/device for 24 hours using a signed, HTTP-only cookie, while keeping the login session itself as a browser-session cookie.
- Center IP record names under the Name heading and keep a 100px gap between the IP-row avatar and name text.
- Restore the bottom-left signed-in account label to its previous left-aligned layout; these styles are separate from IP-row avatars.

# IP Management

**Current release: 2.9.0**

IP Management is an English-language web application for storing and managing IP connection records. It includes a persistent light/dark theme, authenticator-based two-factor authentication (TOTP), searchable IP records, group filtering, superadmin/user roles, group-level visibility, per-IP allow/deny overrides, and an in-site GitHub update action. Public registration is disabled; access is restricted to accounts created by a superadmin.

## Version 2.5.7 release notes

- Fixed malformed sidebar profile CSS so the account name and role align to the right of the avatar rather than sticking against its left edge.
- Added a 60px left inset to the Name table heading so it aligns with the text after the 32px record avatar and 10px gap; the name text no longer overlays the avatar.
- Telegram search shows the saved password for the configured private chat, prompts for another query after a miss, and cleans up bot messages after two minutes with best-effort deletion of submitted search/add inputs.

## Version 2.5.6 release notes

- Fixed Name-column heading alignment so it begins after the record avatar, and restored the record name text to its normal position instead of overlaying the avatar.
- Telegram search now includes the saved decrypted connection password for the configured private chat, keeps the search flow active after a miss, and prompts for another name or IP.
- Telegram bot messages are scheduled for deletion after two minutes; active conversation inputs are deleted on a best-effort basis to reduce chat clutter and avoid leaving sensitive inputs behind.

## Version 2.5.5 release notes

- Fixed a recurring in-site updater failure by removing the late self-replacement of the currently executing privileged shell script.
- Added regression coverage for early bootstrap ordering and confirmed the updater does not overwrite its running executable.

## Version 2.5.4 release notes

- Prevented the updater from replacing its own executable while the current shell is still running, eliminating a class of mid-update shell parse failures.
- Added regression coverage for early bootstrap ordering and to ensure the running updater is never overwritten during deployment.
- Kept the helper bootstrap syntax-validated before installation.

## Version 2.5.3 release notes

- Added early updater self-refresh from the verified target commit for installations whose privileged helper already supports the bootstrap flow. Legacy helpers with a parse-time/runtime failure may still require one-time recovery.
- Added regression coverage that asserts updater self-refresh happens before application deployment.

## Version 2.5.2 release notes

- Fixed in-site updates on existing installations by refreshing the privileged updater from the verified target commit before legacy update logic runs. This removes the need for a manual SSH bootstrap.

## Version 2.5.1 release notes

- Fixed recurring updater syntax failures on existing servers by shipping the privileged updater as a standalone, syntax-validated script.
- Existing installations now refresh the installed updater from the verified release after a successful health check.
- Added regression coverage that runs `bash -n` on the installer and standalone updater.

- Fixed the IP name layout so each label is centered across the full Name column while the avatar remains anchored at the left.
- Removed the redundant “IP inventory” subtitle beneath each IP name.
- Fixed the generated updater's shell syntax by separating the Gunicorn fallback branch from the Nginx validation progress message.
- Added a regression test that runs `bash -n` against the updater generated by the installer.

## Version 2.3.0 release notes

- Aligned IP record names under the Name column and separated each record's initial avatar from the name text.
- Fixed the two-factor authentication screen label and placeholder; the account avatar now loads the profile image when available and falls back to the user's initial.
- Simplified Telegram sign-in code delivery to a single IP Management label and a formatted six-digit code that is easy to copy, without extra explanatory text.
- Renamed Telegram bot branding from IP Archive to IP Management.
- Updated the Telegram Add IP flow to request the connection password and choose the target group using inline buttons; saved passwords remain encrypted.

## Version 2.2.0 release notes

- Made in-site updates failure-safe: the updater snapshots the exact Python virtual environment before changing dependencies and restores it together with the previous application files if the new version fails.
- Rollback explicitly restarts the prior service and checks readiness; if recovery still fails, it retains the recovery backup and prints actionable diagnostics instead of deleting the only recovery copy.
- Health checks require a successful/redirect response (HTTP 2xx/3xx), rather than treating HTTP 4xx as a healthy deployment.
- Corrected the health-check Host fallback so an unset DOMAIN environment variable cannot abort the updater under strict shell mode.

## Version 2.1.0 release notes

- Added ten one-time 2FA recovery codes per user. They are generated after password and current-authenticator re-authentication, stored only as keyed hashes, shown once with no-store headers, and consumed atomically on use.
- Login accepts an unused recovery code if the authenticator app is unavailable. Regenerating codes invalidates the previous set.
- The configured Telegram chat menu is in English and includes an inline `2FA code` button below `Search`. Pressing it (or sending `/login_code`) issues a separate six-digit superadmin fallback code. It expires after two minutes, is stored only as a keyed hash, works once, and is accepted only after the superadmin password is verified. It is not the authenticator's TOTP value.
- Failed password guesses are never sent as raw text to Telegram; alerts contain security metadata and a keyed fingerprint only.

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

## Recovering access if an IP rule locks you out

If an application allowlist or block rule prevents access to the website, SSH to the VPS (or use the VPS provider's console) and run:

```bash
sudo ip-management-recover-access
```

The tool makes a private SQLite backup first. Option 1 disables only the application allowlist while preserving block rules. Option 2 detects the source IP of the current SSH connection, adds an allow rule for it, and removes any block rule that matches it. Option 3 removes all application IP rules and disables the allowlist; it requires typing `RESET`. The tool changes only IP Management's database policy, not Ubuntu's firewall, SSH settings, or other services. If the command is not installed yet, download it over SSH, then run it:

```bash
sudo curl -fsSL https://raw.githubusercontent.com/AmiRaiZo/IP-Management/main/ip-management-recover-access -o /usr/local/sbin/ip-management-recover-access
sudo chmod 0750 /usr/local/sbin/ip-management-recover-access
sudo /usr/local/sbin/ip-management-recover-access
```

## Persistent files and service operations

- Application code: `/opt/station-archive`
- Database and runtime data: `/var/lib/station-archive`
- Secrets and deployment configuration: `/etc/station-archive/env`
- Nginx site configuration: `/etc/nginx/sites-available/`
- Service logs: `sudo journalctl -u station-archive -f`
- Service status: `sudo systemctl status station-archive`
- Emergency application IP access recovery: `sudo ip-management-recover-access`
- Certificate renewal check: `sudo certbot renew --dry-run`

The updater preserves `/var/lib/station-archive` and `/etc/station-archive/env`. Back up both securely. The environment file contains encryption and session secrets; losing them may make stored encrypted values unrecoverable. The GitHub repository must contain `app.py`, `setup_admin.py`, `requirements.txt`, `templates/`, `static/`, and `ip-management-recover-access`. Review repository changes before updating production, because the updater executes the application code supplied by that repository.

## Network and TLS notes

Port `80/tcp` must be reachable for certificate issuance and renewal. The selected public HTTPS port must also be reachable. A custom HTTPS port must be included in the URL, for example `https://archive.example.com:8443`. The installer does not change provider-level firewall rules. If certificate issuance fails, verify DNS and port 80, then retry certificate issuance with:

```bash
sudo certbot certonly --webroot -w /var/www/station-archive-acme -d archive.example.com
```


## Version 2.5.8 release notes

- Refined the IP inventory table's Name header spacing by shifting it 18px to the right, away from the profile/avatar and closer to the other column headings.
