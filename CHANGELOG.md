# Changelog

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
