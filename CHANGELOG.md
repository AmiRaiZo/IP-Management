# Changelog

## 5.0.4 — 2026-11-21
- Add full ZIP backup and restore for the SQLite database and uploaded media, with re-authentication, archive/path/size/schema/constraint validation, cross-worker request draining, durable restore journal and startup recovery, rollback, and global session invalidation.
- Retain the five newest server-side full backups and include Accounts Vault and Notes Vault credentials in the readable TXT export.
- Fix authenticated users being able to fetch other users' profile avatars.
- Make saved branding, login text, inventory labels, navigation labels, accent color and footer settings render throughout the application.
- Show the detected public IPv4 in Settings and refresh its status automatically; persist status from the 30-second systemd IP listener updater.
- Raise the Nginx upload/body and proxy timeouts plus Gunicorn request timeout for large ZIP restores; update existing installations through the upgrade helper.
- Restore the previous Nginx listener configuration if reload/restart fails, and add regression coverage for the new flows.

## 5.0.3 — 2026-11-04
- Show a compact, theme-aware Copied notification with a small green checkmark after successful clipboard actions.
- Cover IP, account, password, Notes, setup URI, and update-log copy flows; failed copy attempts do not show success feedback.
- Add accessible live-region markup and regression coverage, and refresh static asset cache keys.

## 5.0.2 — 2026-11-04
- Allow page scrolling to continue when the IP, account, or Notes card content area has nothing more to scroll or reaches its scroll boundary.
- Keep the card content internally scrollable while restoring normal browser scroll chaining to the main page.
- Add responsive regression coverage and refresh static asset cache keys.

## 5.0.1 — 2026-11-02
- Fix the in-app updater rejecting the two-component `v5.0` release tag; accept both `X.Y` and `X.Y.Z` semantic versions.
- Keep installed-version detection, GitHub API checks, rate-limit fallback, and the privileged updater consistent with the supported version formats.
- Add regression tests for the `v5.0` latest-release tag and two-component installed version detection.

## 5.0 — 2026-11-02
- Equalize the full-width Edit and Delete actions on Notes cards for desktop and mobile.
- Make failed-login counters and lock creation atomic under concurrent requests, and prevent duplicate active lock groups.
- Ensure a lock follows any matching account, IP address, or browser token; normalize IPv4-mapped IPv6 addresses.
- Add regression tests for fresh-browser/IP lock bypass, address normalization, and Notes card action sizing.
- Retain the 3 failures / 15-minute window / 15-minute lock policy and existing administrator unlock mechanisms.
- Document the browser hardware-identification limitation and shared-NAT trade-off.

## 1.0.36 — 2026-10-14
- Fix in-site updates getting stuck at 80% when the Gunicorn service-account verification fails.
- Verify Gunicorn through its actual executable instead of a nested shell/Python import command.
- Automatically rebuild the virtual environment and retry if Gunicorn cannot run as the service account.
- Treat Python tracebacks and import/permission errors in updater logs as terminal failures so the UI stops reconnecting forever and displays the error.

