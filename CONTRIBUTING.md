# Contributing

Thanks for helping. Most valuable contributions:

- **False positives** you hit on a real install, with the path or log line
  (scrubbed) that triggered them.
- **Indicators we miss:** framework-specific upload locations, log formats,
  SAPIs, distro log paths.
- **Shells and platforms** where the script misbehaves.

## Ground rules

These are what make the script safe to run as root on a suspect server. A
change that breaks one won't be merged:

1. **Read-only.** No writes anywhere, temp files included.
2. **No network**, except to a Redis the user names.
3. **Never execute application code** (no `wp`, `occ`, `artisan`, `drush`, no
   `php somefile.php`).
4. **Never print secrets**: session contents, environment, key material.
5. **POSIX sh**, BusyBox-compatible. No bash-isms, no GNU-only flags
   (`find -newermt`, `grep -P`, `sed -i`, `\|` in basic regexes).
6. **No exploit code**, here or in the tests. Fixtures plant *artifacts* (a
   log line, a file that matches a pattern), never anything that triggers the
   vulnerability.

[docs/design.md](docs/design.md) explains the reasoning.

## Workflow

```sh
make lint    # shellcheck -s sh
make test    # full matrix in Docker
sh tests/run.sh logs                         # one case, all images
IMAGES="alpine:3.20|sh" sh tests/run.sh      # all cases, one image
```

Every new check needs a test in `tests/cases/` that shows it fires on a planted
indicator **and** stays quiet on the benign look-alike. Cases are plain POSIX
sh; see `tests/lib.sh` for fixtures and assertions. A case pins itself to
specific images with a first line like `# images: redis:7.4-alpine`.

Keep the inline documentation in `php2shell-ioc.sh` current. People read the
script before they run it, so the comments are part of the product.

## Releasing

1. Bump `VERSION` in the script and add a `CHANGELOG.md` entry.
2. `make check`.
3. Tag `vX.Y.Z`, attach `php2shell-ioc.sh`, and put `make checksum` output in
   the release notes.
