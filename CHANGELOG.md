# Changelog

## 1.0.36 — 2026-10-14
- Fix in-site updates getting stuck at 80% when the Gunicorn service-account verification fails.
- Verify Gunicorn through its actual executable instead of a nested shell/Python import command.
- Treat Python tracebacks and import/permission errors in updater logs as terminal failures so the UI stops reconnecting forever and displays the error.
