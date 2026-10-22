# Changelog

## 1.1.0 (2026-10-22)

- **Bitnami stacks, including AWS Lightsail's WordPress/LAMP blueprints.** Finds
  PHP, PHP-FPM, the site, Apache/nginx/PHP-FPM logs and sessions under
  `/opt/bitnami`, even when `sudo` has reset `PATH`; treats `daemon` as the web
  user on those stacks. Previously a Bitnami instance run with `sudo` was not
  inspected at all.
- **Never "Clean" after inspecting nothing.** If no PHP binary, log or
  application was found, the run says so and exits 1.
- New `--php PATH` option for PHP installed in unusual places.
- Tests against the real Bitnami WordPress image and a RHEL-family layout.

## 1.0.0 (2026-10-22)

First release.

- Five sections: runtime, logs, sessions, files, system.
- WordPress, Nextcloud, Laravel, Drupal and plain-PHP awareness.
- Runs on hosts or streamed into Docker/Kubernetes containers (`sh -s`).
- Logs from files, `.gz`, or stdin; combined and JSON access-log formats.
- File-based and Redis PHP session checks.
- Read-only, no network, never runs application code, never prints secrets.
- Test suite across BusyBox ash, dash, bash, real PHP, Redis and Git, including
  tests of the safety properties themselves.
- Disposable-container demo (`make demo`) and an asciinema recording of it.
- Releases publish the script with a SHA-256 checksum.
