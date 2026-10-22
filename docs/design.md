# Design notes

Why the script is built the way it is. Most of these choices come from one
constraint: people will run it **as root, on a server they suspect may be
compromised, after reading it once**. It has to be safe to do that, and easy to
review.

## One POSIX sh file

No bash-isms, no dependencies beyond what BusyBox provides (`find`, `grep`,
`awk`, `sed`, `stat`, `cksum`), so it runs:

- under BusyBox ash in Alpine-based images (FrankenPHP, many official `-alpine` tags),
- under dash on Debian and Ubuntu,
- under bash everywhere else,

and can be streamed into a container with `sh -s` instead of being copied in.
`shellcheck -s sh` keeps it honest, and the test matrix runs every case under
all three shells.

Lists are newline-separated strings, because POSIX sh has no arrays. Loops read
them from here-documents rather than pipes, so counters updated inside the loop
survive (a pipe would run the loop in a subshell).

## Read-only, provably

The script never writes, not even to `/tmp`. That rules out a few conveniences:

- **No temp files for stdin.** `--log -` can only be read once, so every log
  check happens in a **single awk pass** that classifies each line, keeps a few
  samples and emits a summary.
- **No reference file for "modified since".** `find -newer` needs a file to
  compare against, and creating one would be a write. `-newermt` is GNU-only.
  Instead the script converts `--since` into a day count and uses `-mtime -N`.

`tests/cases/readonly.sh` takes a checksum of every file's path, size, mtime
and inode across the whole container filesystem, does a full run against a
planted system, and checks again.

## No network

Nothing in the script opens a connection, except `redis-cli` when you pass
`--redis`. The entire test suite runs with `docker run --network none`.

## Never execute the application

The obvious deep checks, `wp core verify-checksums` and
`occ integrity:check-core`, load the application's PHP code. On a compromised
install that code may be backdoored, and you'd be running it as whatever user
you invoked the tool as. The script prints those commands with a note and
leaves the decision to you.

The script does execute PHP binaries (`php -v`, `php -r` with a fixed snippet
that reads ini values, `php-fpm -i`, `frankenphp version`), found on `PATH` or
in standard locations. It never runs a PHP *file*.

## `git status` as root is a trap

A Git repository's `.git/config` can set `core.fsmonitor` to a program, and
`git status` runs it. If the web user can write `.git/config` and you run
`git status` as root, the attacker's program runs as root.

Modern Git refuses to operate in a repository owned by another user
(`safe.directory`). A script that discards stderr then sees empty output and
reports "working tree clean": a false all-clear.

The script runs:

```sh
git -c safe.directory="$root" -c core.fsmonitor=false -c core.hooksPath=/dev/null \
    -C "$root" status --porcelain --ignore-submodules
```

Command-line `-c` settings override repository config, so fsmonitor and hooks
are off whatever `.git/config` says. `safe.directory` is passed explicitly so
the status is actually computed. Errors are reported, not swallowed.

`tests/cases/git_hardening.sh` plants an fsmonitor that creates a marker file,
proves that a naive `git status` springs it (the control), then proves the
script doesn't.

## Don't read `/dev/stdout`

Official Docker images symlink `/var/log/nginx/access.log` and friends to
`/dev/stdout`/`/dev/stderr`. A log scanner that opens those reads its own
output, or blocks forever. Auto-detection only accepts regular files (`[ -f ]`
is false for character devices and pipes). A test creates exactly those
symlinks and runs under a timeout.

## Privacy by default

Output goes to terminals and gets pasted into tickets and chats. So:

- sessions: file names, sizes and times only; Redis values go into a pipe that
  only `grep -q` sees;
- SSH keys: counts and paths only;
- no environment variables, and no config values except a fixed list of PHP ini
  settings;
- long lines are clipped.

It does print log lines and process command lines, which can contain IPs, URLs
and occasionally arguments. The README says so.

## Signal over noise

A triage tool that cries wolf gets ignored. Known benign cases are handled
explicitly and covered by tests:

- WordPress's "Silence is golden" `index.php` stubs in upload folders,
- Laravel's `bootstrap/cache` and compiled Blade views in `storage/framework/views`,
- vendor IDE stubs (`.stubs.php`) and vendor directories that happen to be
  called `cache` or `files`,
- Nextcloud users' own uploaded files (backups of old PHP sites are common),
- an app in `/var/www` not being split into `/var/www/app`, `/var/www/public`…

Findings that are usually benign but worth a look (a crontab in Nextcloud's cron
container, `/etc/passwd` changed at image build) are `warn`, with the benign
explanation in the message.

## Network connections include 443

Many host-triage scripts drop connections on ports 80 and 443 to reduce noise.
That hides most real implants, which call home over HTTPS. This script lists
all established non-loopback connections and leaves the judgment to you.
