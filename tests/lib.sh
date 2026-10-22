# shellcheck shell=sh
# tests/lib.sh: helpers sourced by every test case.
#
# Cases run INSIDE a throwaway container (see tests/run.sh), as root, with
# --network none and the repository mounted read-only at /src. That gives each
# case a disposable filesystem it can plant indicators into without touching
# the machine running the tests, and proves the script needs no network.
#
# Output is TAP-like ("ok N - desc" / "not ok N - desc"); tests/run.sh counts
# the lines and fails the run if any case exits non-zero.

IOC=/src/php2shell-ioc.sh
# The shell the script runs under. The matrix sets this to sh (BusyBox ash on
# Alpine, dash on Debian) or bash.
IOC_SHELL=${IOC_SHELL:-sh}

T_NUM=0
T_FAIL=0
OUT=""
RC=0

# run_ioc [args...]: run the script, capturing combined output in $OUT and the
# exit code in $RC. Output stays in a variable: writing it to a file would
# break the read-only assertions in readonly.sh.
run_ioc() {
  OUT=$("$IOC_SHELL" "$IOC" --no-color "$@" 2>&1)
  RC=$?
}

# run_ioc_stdin DATA [args...]: same, with DATA on stdin.
run_ioc_stdin() {
  _in=$1; shift
  OUT=$(printf '%s\n' "$_in" | "$IOC_SHELL" "$IOC" --no-color "$@" 2>&1)
  RC=$?
}

# run_ioc_piped [args...]: run the script the way you would inside a
# container, read from stdin with `sh -s`.
run_ioc_piped() {
  OUT=$("$IOC_SHELL" -s -- "$@" < "$IOC" 2>&1)
  RC=$?
}

_pass() { T_NUM=$((T_NUM + 1)); echo "ok $T_NUM - $1"; }
_fail() {
  T_NUM=$((T_NUM + 1)); T_FAIL=$((T_FAIL + 1))
  echo "not ok $T_NUM - $1"
  [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/#   /'
  printf '%s\n' "$OUT" | sed 's/^/#   | /'
}

assert_rc() { # expected desc
  if [ "$RC" -eq "$1" ]; then _pass "$2"; else _fail "$2" "expected exit $1, got $RC"; fi
}
assert_contains() { # fixed-string desc
  if printf '%s\n' "$OUT" | grep -qF -- "$1"; then _pass "$2"; else _fail "$2" "missing: $1"; fi
}
assert_not_contains() { # fixed-string desc
  if printf '%s\n' "$OUT" | grep -qF -- "$1"; then _fail "$2" "unexpected: $1"; else _pass "$2"; fi
}
assert_match() { # ERE desc
  if printf '%s\n' "$OUT" | grep -qE -- "$1"; then _pass "$2"; else _fail "$2" "no line matches: $1"; fi
}
assert_no_match() { # ERE desc
  if printf '%s\n' "$OUT" | grep -qE -- "$1"; then _fail "$2" "a line matches: $1"; else _pass "$2"; fi
}
assert_true() { # desc command...
  _d=$1; shift
  if "$@"; then _pass "$_d"; else _fail "$_d" "command failed: $*"; fi
}

# finish: last line of every case.
finish() {
  echo "1..$T_NUM"
  [ "$T_FAIL" -eq 0 ]
  exit $?
}

# --- fixtures ---------------------------------------------------------------
# Minimal but realistic application trees. Only the marker files the script
# keys on, plus the benign files known to cause false positives.

mk_wordpress() { # DIR
  mkdir -p "$1/wp-includes" "$1/wp-admin" "$1/wp-content/plugins/akismet" "$1/wp-content/themes/twentytwentysix" \
           "$1/wp-content/uploads/2026/10"
  echo '<?php $wp_version = "7.1.3";' > "$1/wp-includes/version.php"
  echo '<?php require __DIR__ . "/wp-blog-header.php";' > "$1/index.php"
  echo '<?php /* loader */' > "$1/wp-load.php"
  echo '<?php /* akismet */ function akismet_init() {}' > "$1/wp-content/plugins/akismet/akismet.php"
  # WordPress drops these stubs into folders to stop directory listing.
  printf '<?php\n// Silence is golden.\n' > "$1/wp-content/index.php"
  printf '<?php\n// Silence is golden.\n' > "$1/wp-content/uploads/index.php"
  printf '# BEGIN WordPress\nRewriteEngine On\nRewriteRule ^index\\.php$ - [L]\n# END WordPress\n' > "$1/.htaccess"
  echo 'not really a jpeg' > "$1/wp-content/uploads/2026/10/photo.jpg"
  backdate "$1"
}

mk_laravel() { # DIR
  mkdir -p "$1/public" "$1/app/Http" "$1/bootstrap/cache" "$1/storage/framework/views" "$1/storage/app/public" \
           "$1/vendor/filament/tables" "$1/vendor/psr/cache/src"
  echo '#!/usr/bin/env php' > "$1/artisan"
  echo '{"name":"acme/app"}' > "$1/composer.json"
  echo '<?php require __DIR__."/../vendor/autoload.php";' > "$1/public/index.php"
  echo '<?php return [];' > "$1/bootstrap/cache/packages.php"
  echo '<?php echo e($title);' > "$1/storage/framework/views/0f1e2d.php"
  echo '<?php namespace App\Http; class Kernel {}' > "$1/app/Http/Kernel.php"
  echo '<?php // IDE stubs' > "$1/vendor/filament/tables/.stubs.php"
  echo '<?php interface CacheItemInterface {}' > "$1/vendor/psr/cache/src/CacheItemInterface.php"
  backdate "$1"
}

mk_nextcloud() { # DIR
  mkdir -p "$1/config" "$1/data/alice/files/Backups/old-site" "$1/data/appdata_oc123/preview" "$1/lib" "$1/apps/files"
  echo '<?php $OC_Version = [35,0,2,2];' > "$1/version.php"
  echo '#!/usr/bin/env php' > "$1/occ"
  echo '<?php require "lib/base.php";' > "$1/index.php"
  echo '<?php $CONFIG = [];' > "$1/config/config.php"
  echo '<?php $CONFIG = ["memcache.local" => "\\OC\\Memcache\\APCu"];' > "$1/config/apcu.config.php"
  # A user's own uploaded backup of an old PHP site: content, never executed.
  echo '<?php echo "old site";' > "$1/data/alice/files/Backups/old-site/index.php"
  echo '<?php /* files app */' > "$1/apps/files/appinfo.php"
  backdate "$1"
}

# Every file outside the kernel's virtual filesystems, as "path size mtime
# inode" lines. Equal before and after a run means nothing was created,
# removed or modified. (Kept in a variable by the caller, never on disk.)
fs_listing() {
  find / -xdev \( -path /proc -o -path /sys -o -path /dev \) -prune -o -print 2>/dev/null |
    while IFS= read -r f; do stat -c '%n %s %Y %i' "$f" 2>/dev/null; done | sort
}

# assert_same_fs BEFORE AFTER desc: on failure, show the lines that differ.
assert_same_fs() {
  if [ "$1" = "$2" ]; then _pass "$3"; return; fi
  _d=$(printf '%s\n' "$1" | awk 'NR == FNR { a[$0] = 1; next } !($0 in a) { print "+ " $0 } { b[$0] = 1 }
                                END { for (k in a) if (!(k in b)) print "- " k }' - /dev/fd/3 3<<EOF
$2
EOF
)
  _fail "$3" "filesystem changed:
$_d"
}

# backdate DIR: make a fixture look like a long-lived install, so only files
# planted afterwards count as "recently modified".
backdate() {
  find "$1" -exec touch -d '2020-01-01 00:00:00' {} + 2>/dev/null
}
