# Changelog

## 1.0.0 (2026-10-22)

First release.

- Five sections: runtime, logs, sessions, files, system.
- WordPress, Nextcloud, Laravel, Drupal and plain-PHP awareness.
- Runs on hosts or streamed into Docker/Kubernetes containers (`sh -s`).
- Logs from files, `.gz`, or stdin; combined and JSON access-log formats.
- File-based and Redis PHP session checks.
- Read-only, no network, never runs application code, never prints secrets.
- Test suite across BusyBox ash, dash, bash, real PHP, Redis and Git.
