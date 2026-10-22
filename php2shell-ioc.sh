#!/bin/sh
# =============================================================================
# php2shell-ioc.sh: read-only indicator-of-compromise triage for PHP2Shell
#                   (CVE-2026-109618 / CVE-2026-109619)
# =============================================================================
#
# WHAT THIS IS
#   A triage script, not forensics. It looks for the traces that exploitation of
#   the October 2026 PHP "bailout" vulnerabilities, or follow-on activity, tends
#   to leave behind, and tells you where to look harder. A clean result does
#   NOT prove you were not hit: the memory-disclosure variant can leak data
#   without leaving anything on disk.
#
#   It is framework-agnostic. It knows about WordPress, Nextcloud, Laravel,
#   Drupal and plain PHP, and works on bare-metal hosts, VMs and inside
#   containers (Debian or Alpine, bash or BusyBox).
#
# WHAT IT WILL NEVER DO
#   - Write, modify, create or delete any file (not even a temp file).
#   - Make a network connection. It only talks to Redis if you pass --redis.
#   - Execute your application's code. It never runs wp-cli, occ or artisan,
#     because if the app was backdoored, running its code is exactly what an
#     attacker wants. It prints those commands for you to run deliberately.
#   - Print secrets: no session contents, environment variables, key material
#     or config values beyond a fixed list of PHP ini settings. It does print
#     file paths, log lines (which can contain IPs and URLs) and process
#     command lines, so review the output before pasting it anywhere public.
#
# WHAT IT DOES EXECUTE
#   Standard read-only tools (find, grep, awk, ps-style reads of /proc, ss),
#   `php -v` / `php-fpm -i` / `frankenphp version` from the system paths, and
#   `git status` with repository hooks and fsmonitor forcibly disabled (see
#   the files section for why that matters when you run as root).
#
# HOW TO RUN IT
#   Read it first (you are doing that now, good). Then, on a host:
#       sh php2shell-ioc.sh                       # auto-detect everything
#       sudo sh php2shell-ioc.sh --root /var/www/example --since 2026-10-01
#
#   Inside a container, without copying anything into it:
#       docker exec -i CONTAINER sh -s -- --root /var/www/html < php2shell-ioc.sh
#       kubectl exec -i POD -- sh -s -- --root /app < php2shell-ioc.sh
#
#   Container logs usually go to stdout and live outside the container. Feed
#   them in on stdin (logs only, nothing else):
#       docker logs CONTAINER 2>&1 | sh php2shell-ioc.sh --only logs --log -
#       kubectl logs deploy/web --all-containers | sh php2shell-ioc.sh --only logs --log -
#
#   PHP sessions in Redis (Nextcloud, many Laravel setups): run the sessions
#   check from somewhere redis-cli exists, e.g. the Redis container itself:
#       docker exec -i REDIS sh -s -- --only sessions --redis 127.0.0.1:6379 < php2shell-ioc.sh
#   (Set REDISCLI_AUTH in the environment if Redis needs a password.)
#
# OPTIONS
#   --root DIR         Application root to inspect. Repeatable. Default: auto-
#                      detect common roots (/var/www/html, /var/www/*, /app, /srv/*).
#   --log FILE|-       Log file to scan (.gz is fine). '-' reads stdin. Repeatable.
#                      Default: auto-detect PHP/web server logs under /var/log.
#   --session-dir DIR  PHP session directory to inspect. Repeatable. Default:
#                      PHP's session.save_path plus the usual distro locations.
#   --redis HOST:PORT  Scan PHP sessions stored in Redis (needs redis-cli).
#   --php PATH         A PHP / php-fpm / frankenphp binary to check. Repeatable.
#                      Default: PATH, standard locations, and Bitnami stacks.
#   --since YYYY-MM-DD Start of the window for "recently modified" checks.
#                      Default 2026-10-01. Researchers had working exploits in
#                      August 2026; set it earlier if you want a wider net.
#   --only LIST        Comma-separated sections: runtime,logs,sessions,files,system.
#   --max-samples N    Sample lines shown per finding (default 5).
#   --no-color         Plain output.
#   -h, --help         Show this header.
#
# OUTPUT AND EXIT CODES
#   [FLAG] strong indicator: investigate.       exit 2 if any
#   [warn] worth a look; often benign.          exit 1 if any (and no flags)
#   [ ok ] / [info] context.                    exit 0 otherwise
#
# BACKGROUND: WHAT THE BUGS LOOK LIKE FROM THE OUTSIDE
#   Both bugs are reached before your application code runs, while PHP is
#   still parsing the request (multipart bodies, cookies, superglobals, and
#   session upload progress). An attacker forces a fatal error, usually
#   "Allowed memory size ... exhausted", at a moment that leaves the engine's
#   state corrupt or stale, then uses that state from a later request on the
#   same worker. The traces that can survive are:
#     1. Out-of-memory fatals "in Unknown on line 0" (no script line: the
#        failure happened during request parsing).
#     2. Worker crashes: FPM "exited on signal 11/6", Apache "exit signal
#        Segmentation fault", heap-corruption aborts, and the proxy-side
#        symptom of those ("upstream prematurely closed connection").
#     3. Input-limit and session warnings during parsing (nesting level,
#        input variable count, malformed or oversized session ids).
#     4. Session files or Redis keys holding upload_progress_ data on sites
#        that never show upload progress bars.
#     5. Then the usual post-exploitation: web shells, PHP in upload dirs,
#        .user.ini/.htaccess auto_prepend tricks, odd processes running as
#        the web user, new cron entries or SSH keys.
#
# PROJECT: https://github.com/ericmann/php2shell-ioc (docs, tests, demo, releases)
# LICENSE: MIT (see LICENSE). No warranty. It's triage; use your judgment.
# =============================================================================

set -u
LC_ALL=C
export LC_ALL

VERSION="1.1.0"
SINCE="2026-10-01"
ROOTS=""
LOGS=""
SESSION_DIRS=""
REDIS=""
PHP_BINS=""
ONLY="runtime,logs,sessions,files,system"
MAX_SAMPLES=5
COLOR=1
FLAGS=0
WARNS=0
# What was actually inspected. A run that found no PHP, no logs and no
# application must not end in "Clean": it looked at nothing.
N_BINS=0; N_LOGS=0; N_ROOTS=0

# Patched upstream releases (2026-10-21). Branches not listed here are EOL and
# got no upstream fix; distro packages may still carry a backport.
FLOOR_85="8.5.12"; FLOOR_84="8.4.27"; FLOOR_83="8.3.36"; FLOOR_82="8.2.35"

# Keep a handle on the original stdin: '--log -' is read inside loops whose
# own stdin is a here-document.
exec 3<&0

# -----------------------------------------------------------------------------
# Argument parsing. Lists are newline-separated strings (POSIX sh has no arrays).
# -----------------------------------------------------------------------------
add() { if [ -z "$1" ]; then printf '%s' "$2"; else printf '%s\n%s' "$1" "$2"; fi; }

# Built in rather than read from "$0": when the script is piped into a
# container with `sh -s`, there is no file to read the header from.
usage() {
  cat <<'USAGE'
php2shell-ioc: read-only IOC triage for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

Usage:
  sh php2shell-ioc.sh [options]
  docker exec -i CONTAINER sh -s -- [options] < php2shell-ioc.sh
  kubectl exec -i POD -- sh -s -- [options] < php2shell-ioc.sh
  docker logs CONTAINER 2>&1 | sh php2shell-ioc.sh --only logs --log -

Options:
  --root DIR          application root to inspect (repeatable; default: auto-detect)
  --log FILE|-        log file to scan, .gz ok, '-' = stdin (repeatable; default: auto-detect)
  --session-dir DIR   PHP session directory (repeatable; default: from php.ini + usual paths)
  --redis HOST:PORT   also scan PHP sessions stored in Redis (needs redis-cli)
  --php PATH          a PHP, php-fpm or frankenphp binary to check (repeatable;
                      default: PATH plus standard and Bitnami locations)
  --since YYYY-MM-DD  window start for "recently modified" checks (default 2026-10-01)
  --only LIST         sections: runtime,logs,sessions,files,system (comma-separated)
  --max-samples N     sample lines per finding (default 5)
  --no-color          plain output
  -V, --version       print version
  -h, --help          this help

Exit codes: 0 clean, 1 warnings only, 2 one or more flags, 64 usage error.
The script never writes files, never opens network connections (except to the
Redis you name), and never executes your application's code.
USAGE
}

# need_value OPTION ARGC: every option except the flags takes a value.
# (Checked explicitly: with too few arguments, `shift 2` fails without
# shifting in some shells, and the loop would never end.)
need_value() { [ "$2" -ge 2 ] || { echo "$1 needs a value (try --help)" >&2; exit 64; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --root)        need_value "$1" $#; ROOTS=$(add "$ROOTS" "$2"); shift 2 ;;
    --log)         need_value "$1" $#; LOGS=$(add "$LOGS" "$2"); shift 2 ;;
    --session-dir) need_value "$1" $#; SESSION_DIRS=$(add "$SESSION_DIRS" "$2"); shift 2 ;;
    --redis)       need_value "$1" $#; REDIS="$2"; shift 2 ;;
    --php)         need_value "$1" $#; PHP_BINS=$(add "$PHP_BINS" "$2"); shift 2 ;;
    --since)       need_value "$1" $#; SINCE="$2"; shift 2 ;;
    --only)        need_value "$1" $#; ONLY="$2"; shift 2 ;;
    --max-samples) need_value "$1" $#; MAX_SAMPLES="$2"; shift 2 ;;
    --no-color)    COLOR=0; shift ;;
    -h|--help)     usage; exit 0 ;;
    -V|--version)  echo "php2shell-ioc $VERSION"; exit 0 ;;
    *)             echo "unknown option: $1 (try --help)" >&2; exit 64 ;;
  esac
done

# Validate inputs early: a typo in --only would otherwise silently skip checks.
for sec in $(printf '%s' "$ONLY" | tr ',' ' '); do
  case "$sec" in runtime|logs|sessions|files|system) ;; *) echo "unknown section in --only: $sec" >&2; exit 64 ;; esac
done
case "$SINCE" in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;; *) echo "--since must be YYYY-MM-DD" >&2; exit 64 ;; esac
case "$MAX_SAMPLES" in ''|*[!0-9]*) echo "--max-samples must be a number" >&2; exit 64 ;; esac

# -----------------------------------------------------------------------------
# Output helpers. Every finding goes through flag/warn/ok/info so the verdict
# and the exit code can't disagree with what was printed.
# -----------------------------------------------------------------------------
if [ "$COLOR" -eq 1 ] && [ -t 1 ]; then
  R=$(printf '\033[31m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m')
  B=$(printf '\033[34m'); BOLD=$(printf '\033[1m'); N=$(printf '\033[0m')
else
  R=""; G=""; Y=""; B=""; BOLD=""; N=""
fi
section() { printf '\n%s== %s ==%s\n' "$BOLD" "$1" "$N"; }
flag()  { printf '  %s[FLAG]%s %s\n' "$R" "$N" "$1"; FLAGS=$((FLAGS + 1)); }
warn()  { printf '  %s[warn]%s %s\n' "$Y" "$N" "$1"; WARNS=$((WARNS + 1)); }
ok()    { printf '  %s[ ok ]%s %s\n' "$G" "$N" "$1"; }
info()  { printf '  %s[info]%s %s\n' "$B" "$N" "$1"; }
indent() { sed 's/^/         /'; }
want()  { case ",$ONLY," in *",$1,"*) return 0 ;; esac; return 1; }
have()  { command -v "$1" >/dev/null 2>&1; }
# Trim long lines so a single giant log line can't flood the report.
clip()  { cut -c1-"${1:-200}"; }

# find_php DIR [find-tests...]: files a web server may execute as PHP under
# DIR, skipping node_modules and Nextcloud users' own uploaded files
# (data/<user>/files*, which Nextcloud serves but never executes). Extra
# arguments (e.g. -mtime -7) are applied to the matches.
find_php() {
  fp_dir=$1; shift
  find "$fp_dir" \( -name node_modules -o -name files_versions -o -name files_trashbin -o -path '*/data/*/files' \) -prune -o \
    -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' -o -name '*.phar' -o -name '*.pht' -o -name '*.phps' \) \
    "$@" -print 2>/dev/null
}

# Days between --since and now, for `find -mtime -N`. We compute this instead
# of using `find -newermt` (GNU-only) or a reference file (that would mean
# writing to disk, which this script never does).
since_days() {
  s=$(date -d "$SINCE" +%s 2>/dev/null || date -d "$SINCE 00:00" +%s 2>/dev/null || echo "")
  if [ -z "$s" ]; then echo 30; return; fi
  n=$(date +%s)
  echo $(( (n - s) / 86400 + 1 ))
}
DAYS=$(since_days)

# ver_lt A B: true if version A < version B (major.minor.patch, numeric).
# Suffixes like "-dev" or "+deb12u1" are ignored for the comparison.
ver_lt() {
  IFS=. read -r a1 a2 a3 <<EOF
$1
EOF
  IFS=. read -r b1 b2 b3 <<EOF
$2
EOF
  a3=${a3%%[!0-9]*}; b3=${b3%%[!0-9]*}
  [ "${a1:-0}" -lt "${b1:-0}" ] && return 0; [ "${a1:-0}" -gt "${b1:-0}" ] && return 1
  [ "${a2:-0}" -lt "${b2:-0}" ] && return 0; [ "${a2:-0}" -gt "${b2:-0}" ] && return 1
  [ "${a3:-0}" -lt "${b3:-0}" ]
}

# Context: where are we running? This changes how to read the results (a
# container that was redeployed after the patch has no history to find).
in_container() {
  [ -f /.dockerenv ] || [ -f /run/.containerenv ] && return 0
  grep -qE 'kubepods|docker|containerd|libpod' /proc/1/cgroup 2>/dev/null
}

printf '%sphp2shell-ioc %s%s  (CVE-2026-109618 / CVE-2026-109619)\n' "$BOLD" "$VERSION" "$N"
me=$(id -un 2>/dev/null) || me="uid $(id -u)"
printf 'host: %s   user: %s   date: %s   window: since %s (%s days)\n' \
  "$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)" "$me" \
  "$(date -u '+%Y-%m-%d %H:%M UTC')" "$SINCE" "$DAYS"
if in_container; then
  info "running inside a container. If it was recreated after the patch, logs, /tmp"
  info "and file-based sessions from before the patch are gone. Check the image's"
  info "persistent volumes and your edge/proxy logs as well."
fi
[ "$(id -u)" -ne 0 ] && info "not root: some logs, sessions and other users' processes may be unreadable"

# =============================================================================
# 1. RUNTIME: is this PHP patched, and are the interim mitigations in place?
# =============================================================================
# CLI and FPM are separate binaries with separate ini files. What serves your
# site is FPM, mod_php (apache2handler), FrankenPHP or the built-in server, so
# check the one that matters. Distros (Debian, Ubuntu, RHEL) often backport
# security fixes without bumping the upstream version, so a "below floor"
# result on a distro package means "check the changelog", not "vulnerable".
# Bitnami stacks (AWS Lightsail's WordPress/LAMP blueprints, many marketplace
# images) install everything under /opt/bitnami: PHP, Apache/nginx, logs,
# sessions and the site itself, with Apache and PHP-FPM running as "daemon".
# `sudo` resets PATH, so Bitnami's PHP isn't on it; we look there explicitly.
BITNAMI=0; [ -d /opt/bitnami ] && BITNAMI=1

SAVE_PATHS=""
if want runtime; then
  section "1. PHP runtime"
  bins=""
  for b in "$(command -v php 2>/dev/null)" "$(command -v php-fpm 2>/dev/null)" "$(command -v frankenphp 2>/dev/null)" \
           /usr/local/bin/php /usr/local/sbin/php-fpm /usr/local/bin/frankenphp \
           /usr/bin/php[0-9]* /usr/sbin/php-fpm* /usr/bin/php-fpm* /opt/remi/*/root/usr/sbin/php-fpm \
           /opt/bitnami/php/bin/php /opt/bitnami/php/sbin/php-fpm /opt/*/php/bin/php /opt/*/php/sbin/php-fpm \
           /opt/lampp/bin/php $PHP_BINS; do
    [ -n "$b" ] && [ -x "$b" ] && [ -f "$b" ] || continue
    real=$(readlink -f "$b" 2>/dev/null || echo "$b")
    case "
$bins
" in *"
$real
"*) continue ;; esac
    bins=$(add "$bins" "$real")
  done

  if [ -z "$bins" ]; then
    info "no PHP binary found here (PATH and standard locations). If PHP runs in a"
    info "container, run this inside it; if it's installed somewhere unusual, pass --php PATH."
  else
    while IFS= read -r bin; do
      case "$bin" in
        *frankenphp*) out=$("$bin" version 2>/dev/null) ;;
        *)            out=$("$bin" -v 2>/dev/null) ;;
      esac
      ver=$(printf '%s\n' "$out" | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -n1 | cut -d' ' -f2)
      [ -n "$ver" ] || { info "$bin: could not read version"; continue; }
      N_BINS=$((N_BINS + 1))
      br=$(printf '%s' "$ver" | cut -d. -f1,2)
      case "$br" in
        8.5) floor=$FLOOR_85 ;; 8.4) floor=$FLOOR_84 ;; 8.3) floor=$FLOOR_83 ;; 8.2) floor=$FLOOR_82 ;; *) floor="" ;;
      esac
      if [ -z "$floor" ]; then
        flag "$bin -> PHP $ver: branch $br is end-of-life with no upstream fix (needs a distro backport or an upgrade)"
      elif ver_lt "$ver" "$floor"; then
        flag "$bin -> PHP $ver: below the patched release $floor (if this is a distro package, check its changelog for 109618/109619)"
      else
        ok "$bin -> PHP $ver (patched in $floor)"
      fi

      # The ini settings that mattered as interim mitigations, as THIS binary
      # sees them. `php-fpm -i` prints phpinfo using FPM's own ini files
      # without starting a server. FrankenPHP has no equivalent, so we skip it.
      case "$bin" in
        *frankenphp*) continue ;;
        *fpm*) ini=$("$bin" -i 2>/dev/null | awk -F' => ' '$1 ~ /^(session\.upload_progress\.enabled|session\.use_strict_mode|session\.save_handler|session\.save_path|memory_limit|max_input_nesting_level|display_errors)$/ {print $1 "=" $2}') ;;
        *) ini=$("$bin" -r 'foreach (["session.upload_progress.enabled","session.use_strict_mode","session.save_handler","session.save_path","memory_limit","max_input_nesting_level","display_errors"] as $k) { echo $k, "=", ini_get($k), "\n"; }' 2>/dev/null) ;;
      esac
      [ -n "$ini" ] || continue
      printf '%s\n' "$ini" | sed 's/ *$//' | indent
      up=$(printf '%s\n' "$ini" | sed -n 's/^session\.upload_progress\.enabled=//p' | tr -d ' ')
      case "$up" in
        1|On|on) info "upload progress is enabled. On a patched build that's fine; it was the main pre-patch attack path." ;;
      esac
      # A crash or fatal error during parsing can echo engine state back to the
      # client when errors are displayed. The official Docker images ship no
      # php.ini, so display_errors defaults to on unless something sets it.
      de=$(printf '%s\n' "$ini" | sed -n 's/^display_errors=//p' | tr -d ' ')
      case "$de" in
        1|On|on|stdout|STDOUT) warn "$bin: display_errors is on (set display_errors=Off in a conf.d ini; apps may override it at runtime, but errors during request parsing happen before they can)" ;;
      esac
      sp=$(printf '%s\n' "$ini" | sed -n 's/^session\.save_path=//p' | sed 's/ *$//; s/.*;//')
      sh_=$(printf '%s\n' "$ini" | sed -n 's/^session\.save_handler=//p' | tr -d ' ')
      [ -n "$sp" ] && [ "$sh_" = "files" ] && SAVE_PATHS=$(add "$SAVE_PATHS" "$sp")
      case "$sh_" in
        redis|rediscluster) info "sessions are stored in Redis ($sp): use --redis to check them" ;;
        memcache*) info "sessions are stored in Memcached: this script can't inspect those" ;;
      esac
    done <<EOF
$bins
EOF
  fi
fi

# =============================================================================
# 2. LOGS: crash, out-of-memory and parsing signatures
# =============================================================================
# One awk pass per log source classifies each line. We do it in a single pass
# because stdin ('--log -') can only be read once, and we never buffer it to
# disk. The categories, strongest first:
#   oom_unknown   "Allowed memory size ... exhausted ... in Unknown on line 0".
#                 No script line means PHP died while parsing the request,
#                 before any PHP file ran. This is the trigger's signature.
#   crash         a worker died on a signal or the allocator detected heap
#                 corruption. A dead worker is the patched engine's safe
#                 response and the unpatched engine's warning sign.
#   upstream      nginx/Caddy saw the PHP backend drop the connection
#                 mid-request, which is the proxy-side view of a crash.
#   input         PHP rejected input during parsing (too many variables, too
#                 deep nesting, too many files, body too large). Scanners
#                 trip these too, but so does someone tuning a trigger.
#   session       malformed or oversized session ids, or session data that
#                 failed to decode. The session upload-progress path took
#                 attacker-supplied ids.
#   oom_other     ordinary out-of-memory fatals with a script line: usually a
#                 real bug in the app, listed only for context.
# For access logs (combined format, or JSON with method/status/uri|path), it
# also counts POSTs answered with 5xx, and POSTs to static files, which no
# legitimate client sends and which reach PHP only on catch-all routing.
LOG_AWK='
function keep(cat, line) {
  n[cat]++
  if (n[cat] <= max) s[cat] = s[cat] "\n" substr(line, 1, 220)
}
{
  l = tolower($0)
  if (l ~ /allowed memory size of [0-9]+ bytes exhausted/) {
    if (l ~ /in unknown on line 0/) keep("oom_unknown", $0); else keep("oom_other", $0)
  }
  if (l ~ /exited on signal (4|6|7|11)|exit signal (segmentation fault|aborted|bus error|illegal instruction)|zend_mm_heap corrupted|zend_mm_panic|double free|free\(\): invalid|corrupted size vs|munmap_chunk|segfault at|core dumped/)
    keep("crash", $0)
  if (l ~ /upstream prematurely closed connection|connection reset by peer\) while reading response header from upstream|upstream sent invalid header/)
    keep("upstream", $0)
  if (l ~ /input variables exceeded|input variable nesting level exceeded|maximum number of allowable file uploads|post content-length of [0-9]+ bytes exceeds/)
    keep("input", $0)
  if (l ~ /session id is too long or contains illegal characters|failed to decode session object|failed to read session data|session_start\(\): .*(illegal|too long)/)
    keep("session", $0)

  # Access-log requests: combined format first, then JSON (Caddy, Laravel, etc.).
  path = ""; status = 0
  if (match($0, /"POST [^ "]+ HTTP\/[0-9.]+" [0-9][0-9][0-9]/)) {
    split(substr($0, RSTART, RLENGTH), p, " "); path = p[2]; status = p[4] + 0
  } else if (index($0, "\"method\":\"POST\"")) {
    if (match($0, /"status":[0-9]+/)) status = substr($0, RSTART + 9, RLENGTH - 9) + 0
    if (match($0, /"(uri|path)":"[^"]*"/)) { path = substr($0, RSTART, RLENGTH); sub(/^"(uri|path)":"/, "", path); sub(/"$/, "", path) }
  }
  if (path != "") {
    posts++
    q = path; sub(/\?.*/, "", q)
    if (status >= 500) { p5xx[q]++; keep("post5xx", $0) }
    if (q ~ /\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|txt|xml)$/) keep("post_static", $0)
  }
}
END {
  printf "posts\t%d\n", posts
  for (c in n) printf "count\t%s\t%d\n", c, n[c]
  for (c in s) { gsub(/\n/, "\n\t", s[c]); printf "samples\t%s%s\n", c, s[c] }
  for (q in p5xx) printf "p5xx\t%d\t%s\n", p5xx[q], q
}'

scan_log() { # $1 = path or "-"; prints the findings for one source
  src="$1"
  case "$src" in
    -)    label="stdin"; res=$(awk -v max="$MAX_SAMPLES" "$LOG_AWK") ;;
    *.gz) label="$src"; res=$(gzip -dc "$src" 2>/dev/null | awk -v max="$MAX_SAMPLES" "$LOG_AWK") ;;
    *)    label="$src"; res=$(awk -v max="$MAX_SAMPLES" "$LOG_AWK" "$src" 2>/dev/null) ;;
  esac
  cnt() { printf '%s\n' "$res" | awk -F'\t' -v c="$1" '$1=="count" && $2==c {print $3}'; }
  smp() { printf '%s\n' "$res" | awk -v c="$1" '
            /^samples\t/ { split($0, a, "\t"); on = (a[2] == c); next }
            /^(count|posts|p5xx)\t/ { on = 0 }
            on { sub(/^\t/, ""); print }' | indent; }
  hit=0
  for c in oom_unknown crash; do
    k=$(cnt "$c"); [ -n "$k" ] || continue; hit=1
    case "$c" in
      oom_unknown) flag "$label: $k out-of-memory fatal(s) 'in Unknown on line 0' (died while parsing the request)" ;;
      crash)       flag "$label: $k worker crash / heap-corruption line(s)" ;;
    esac
    smp "$c"
  done
  for c in upstream input session post_static post5xx; do
    k=$(cnt "$c"); [ -n "$k" ] || continue; hit=1
    case "$c" in
      upstream)    warn "$label: $k upstream reset(s): the PHP backend dropped the connection mid-request" ;;
      input)       warn "$label: $k input-limit rejection(s) during request parsing" ;;
      session)     warn "$label: $k malformed session id / session decode warning(s)" ;;
      post_static) warn "$label: $k POST(s) to static-file paths" ;;
      post5xx)     warn "$label: $k POST(s) answered with 5xx. Top paths:"
                   printf '%s\n' "$res" | awk -F'\t' '$1=="p5xx" {print $2 "\t" $3}' | sort -rn | head -n 10 | indent ;;
    esac
    [ "$c" = post5xx ] || smp "$c"
  done
  k=$(cnt oom_other); [ -n "$k" ] && { info "$label: $k ordinary out-of-memory fatal(s) with a script line (app bugs, usually)"; smp oom_other; hit=1; }
  posts=$(printf '%s\n' "$res" | awk -F'\t' '$1=="posts" {print $2}')
  [ "$hit" -eq 0 ] && ok "$label: no crash, OOM or parsing signatures (${posts:-0} POST requests seen)"
  return 0
}

if want logs; then
  section "2. Logs"
  if [ -z "$LOGS" ]; then
    # Only regular files: official Docker images symlink their logs to
    # /dev/stdout and /dev/stderr, and reading those would hang or read our
    # own output.
    for f in /var/log/php*-fpm.log* /var/log/php*fpm*/*.log* /var/log/php*/*.log* /var/log/php_errors.log* \
             /usr/local/var/log/php-fpm.log* /var/opt/remi/*/log/php-fpm/*.log* \
             /var/log/nginx/*.log* /var/log/apache2/*.log* /var/log/httpd/*log* /var/log/caddy/*.log* \
             /opt/bitnami/apache/logs/*log* /opt/bitnami/apache2/logs/*log* /opt/bitnami/nginx/logs/*log* \
             /opt/bitnami/php/logs/*log* /opt/bitnami/php/var/log/*log*; do
      [ -f "$f" ] && [ -r "$f" ] && LOGS=$(add "$LOGS" "$f")
    done
  fi
  if [ -z "$LOGS" ]; then
    info "no log files found. In containers, pipe them in: docker logs C 2>&1 | sh php2shell-ioc.sh --only logs --log -"
  else
    while IFS= read -r lf; do
      [ "$lf" = "-" ] && { N_LOGS=$((N_LOGS + 1)); scan_log - <&3; continue; }
      [ -f "$lf" ] && [ -r "$lf" ] || { info "$lf: not a readable regular file, skipped"; continue; }
      N_LOGS=$((N_LOGS + 1))
      scan_log "$lf"
    done <<EOF
$LOGS
EOF
    info "behind a CDN or tunnel, access-log client IPs may all be the proxy's. Your edge's"
    info "analytics (e.g. Cloudflare GraphQL) can show 5xx and 52x bursts even if logs were lost."
  fi
fi

# =============================================================================
# 3. SESSIONS: upload-progress leftovers and attacker-chosen session ids
# =============================================================================
# Before the fix, any multipart request carrying the upload-progress field
# made PHP open, decode and save the session named in the request's cookie,
# for any script, even one that never uses sessions. So:
#   - a session file containing "upload_progress_" on a site that never shows
#     upload progress bars is a strong sign someone exercised that path;
#   - a session id outside PHP's own alphabet, or far longer than the ids PHP
#     generates, was chosen by a client, not by PHP.
# We print only file names, sizes and times, never contents: sessions hold
# logged-in users' data.
if want sessions; then
  section "3. Sessions"
  dirs=$SESSION_DIRS
  if [ -z "$dirs" ]; then
    dirs=$SAVE_PATHS
    for d in /var/lib/php/sessions /var/lib/php/session /var/lib/php5 /opt/bitnami/php/var/run/session /opt/bitnami/php/tmp /tmp /var/tmp; do dirs=$(add "$dirs" "$d"); done
  fi
  seen=""
  while IFS= read -r d; do
    [ -n "$d" ] && [ -d "$d" ] || continue
    case "
$seen
" in *"
$d
"*) continue ;; esac
    seen=$(add "$seen" "$d")
    if [ ! -r "$d" ] || [ ! -x "$d" ]; then info "$d: not readable (try as root)"; continue; fi
    total=$(find "$d" -maxdepth 1 -type f -name 'sess_*' 2>/dev/null | wc -l | tr -d ' ')
    [ "$total" -gt 0 ] || { info "$d: no PHP session files"; continue; }
    up=$(find "$d" -maxdepth 1 -type f -name 'sess_*' -exec grep -l 'upload_progress_' {} + 2>/dev/null)
    if [ -n "$up" ]; then
      flag "$d: $(printf '%s\n' "$up" | wc -l | tr -d ' ') of $total session file(s) contain upload_progress_ data"
      printf '%s\n' "$up" | head -n "$MAX_SAMPLES" | while IFS= read -r f; do ls -l "$f" 2>/dev/null; done | clip 160 | indent
    else
      ok "$d: $total session file(s), none with upload_progress_ data"
    fi
    # PHP's own ids use [0-9a-zA-Z,-] and are 22-256 chars (default 32).
    # Anything else came from a client.
    odd=$(find "$d" -maxdepth 1 -type f -name 'sess_*' 2>/dev/null | sed 's|.*/sess_||' |
          awk 'length($0) > 128 || length($0) < 22 || $0 ~ /[^0-9A-Za-z,-]/' | head -n "$MAX_SAMPLES")
    if [ -n "$odd" ]; then
      warn "$d: session ids PHP would not generate (odd length or characters):"
      printf '%s\n' "$odd" | clip 80 | indent
    fi
  done <<EOF
$dirs
EOF

  if [ -n "$REDIS" ]; then
    if have redis-cli; then
      rh=${REDIS%:*}; rp=${REDIS##*:}; [ "$rp" = "$REDIS" ] && rp=6379
      keys=$(redis-cli -h "$rh" -p "$rp" --scan --pattern 'PHPREDIS_SESSION:*' 2>/dev/null)
      rt=$(printf '%s' "$keys" | grep -c . | tr -d ' ')
      rhits=0; rodd=0
      # GET returns the session blob into a pipe that only grep sees; it is
      # never printed.
      while IFS= read -r k; do
        [ -n "$k" ] || continue
        redis-cli -h "$rh" -p "$rp" --raw GET "$k" 2>/dev/null | grep -q 'upload_progress_' && rhits=$((rhits + 1))
        printf '%s\n' "${k#PHPREDIS_SESSION:}" | awk 'length($0) > 128 || $0 ~ /[^0-9A-Za-z,-]/ {exit 1}' || rodd=$((rodd + 1))
      done <<EOF
$keys
EOF
      if [ "$rhits" -gt 0 ]; then flag "redis $REDIS: $rhits of $rt session key(s) contain upload_progress_ data"
      else ok "redis $REDIS: $rt session key(s), none with upload_progress_ data"; fi
      [ "$rodd" -gt 0 ] && warn "redis $REDIS: $rodd session key(s) with ids PHP would not generate"
      info "Redis sessions expire (session.gc_maxlifetime), so older evidence may be gone."
    else
      info "--redis given but redis-cli isn't installed here; run it from the Redis container"
    fi
  fi
fi

# =============================================================================
# 4. FILES: code and config that shouldn't be there
# =============================================================================
# Exploitation gives code execution as the web user. The cheapest persistence
# is a PHP file somewhere the web server will execute it, or a one-line change
# to a config that makes PHP include attacker code on every request. Per root:
#   a. PHP files in directories that should only ever hold data/uploads.
#   b. .user.ini / .htaccess that prepend/append code or map other extensions
#      to PHP (e.g. make .jpg execute).
#   c. Content patterns typical of web shells (eval of decoded blobs, request
#      input passed to command execution). Grep heuristics: expect the
#      occasional false positive in vendored libraries; read each hit.
#   d. Hidden or double-extension PHP files (".x.php", "shell.php.jpg").
#   e. PHP files modified within the window (expect noise after a deploy or
#      upgrade; useful on long-lived installs).
#   f. git status, when the root is a checkout. Running git as root in a
#      directory the web user can write is risky: a planted .git/config can set
#      core.fsmonitor to a command, which `git status` runs. We force fsmonitor
#      off and hooks to /dev/null on the command line (which overrides repo
#      config), and pass safe.directory so git doesn't silently refuse a repo
#      owned by another user (which reads as "clean" in scripts that discard
#      stderr).
root_type() {
  r="$1"
  if   [ -f "$r/wp-includes/version.php" ]; then echo wordpress
  elif [ -f "$r/occ" ] && [ -f "$r/version.php" ]; then echo nextcloud
  elif [ -f "$r/artisan" ]; then echo laravel
  elif [ -f "$r/core/lib/Drupal.php" ]; then echo drupal
  else echo php
  fi
}

if want files; then
  section "4. Files"
  if [ -z "$ROOTS" ]; then
    # Parents come before children so an app in /var/www isn't also scanned
    # as /var/www/app, /var/www/public, ... (nested candidates are skipped).
    for c in /var/www /var/www/html /var/www/* /app /srv/* /usr/share/nginx/html /home/*/public_html /home/forge/*/current \
             /opt/bitnami/wordpress /opt/bitnami/apps/*/htdocs /opt/bitnami/*/htdocs /bitnami/wordpress; do
      [ -d "$c" ] || continue
      # Looks like an application root, not just any folder with PHP in it.
      is_app=0
      for m in index.php artisan occ wp-load.php wp-includes/version.php composer.json public/index.php web/index.php; do
        [ -f "$c/$m" ] && { is_app=1; break; }
      done
      [ "$is_app" -eq 1 ] || continue
      c=$(readlink -f "$c" 2>/dev/null || echo "$c")
      # Skip roots already listed, and roots nested inside one (the parent
      # scan already covers them).
      dup=0
      while IFS= read -r e; do
        [ -n "$e" ] || continue
        case "$c/" in "$e"/*) dup=1 ;; esac
      done <<EOR
$ROOTS
EOR
      [ "$dup" -eq 0 ] && ROOTS=$(add "$ROOTS" "$c")
    done
  fi
  if [ -z "$ROOTS" ]; then
    info "no PHP application roots found; pass one with --root DIR"
  fi
  while IFS= read -r root; do
    [ -n "$root" ] || continue
    [ -d "$root" ] || { info "$root: not a directory"; continue; }
    t=$(root_type "$root")
    N_ROOTS=$((N_ROOTS + 1))
    printf '\n  %s%s%s (%s)\n' "$BOLD" "$root" "$N" "$t"

    # a. PHP in data/upload locations, per framework.
    case "$t" in
      wordpress) data="$root/wp-content/uploads" ;;
      laravel)   data="$root/public $root/storage" ;;
      drupal)    data="$root/sites" ;;
      nextcloud) data="$root/data" ;;
      # Plain PHP: folders whose names say "user content". Dependencies are
      # skipped; vendor/ is full of directories called cache or files.
      *)         data=$(find "$root" -maxdepth 3 \( -name vendor -o -name node_modules \) -prune -o -type d \( -name uploads -o -name upload -o -name files -o -name tmp \) -print 2>/dev/null | head -n 20 | tr '\n' ' ') ;;
    esac
    for dd in $data; do
      [ -d "$dd" ] || continue
      hits=$(find_php "$dd" | awk -v t="$t" -v root="$root" '
        t == "laravel" && ($0 == root "/public/index.php" || $0 ~ /\/storage\/framework\/(views|cache)\// || $0 ~ /\/storage\/framework\/maintenance\.php$/) { next }
        t == "drupal" && $0 !~ /\/files\// { next }
        { print }' |
        while IFS= read -r f; do
          # WordPress and many plugins drop a stub index.php ("Silence is
          # golden") into upload folders to stop directory listing. Skip those.
          if [ "$(wc -c < "$f" 2>/dev/null)" -le 200 ] && grep -qi 'silence is golden' "$f" 2>/dev/null; then continue; fi
          printf '%s\n' "$f"
        done)
      ufiles=""
      [ "$t" = nextcloud ] && ufiles=$(find "$dd" -path '*/files*' -type f \( -name '*.php' -o -name '*.phtml' \) 2>/dev/null | wc -l | tr -d ' ')
      [ "$ufiles" = 0 ] && ufiles=""
      if [ -n "$hits" ]; then
        flag "executable PHP in a data/upload location ($dd):"
        printf '%s\n' "$hits" | head -n 25 | clip 200 | indent
      else
        ok "no PHP files in $dd"
      fi
      [ -n "$ufiles" ] && info "$ufiles PHP file(s) inside Nextcloud users' own files (uploaded content; never executed by Nextcloud)"
    done
    if [ "$t" = nextcloud ] && [ -d "$root/config" ]; then
      extra=$(find "$root/config" -type f 2>/dev/null | sed 's|.*/||' | grep -vE '^(config\.php|config\.sample\.php|[a-z0-9_.-]+\.config\.php|\.htaccess|CAN_INSTALL)$')
      [ -n "$extra" ] && { warn "unexpected files in $root/config:"; printf '%s\n' "$extra" | indent; }
    fi

    # b. Config tricks.
    cfg=$(find "$root" \( -name node_modules -prune \) -o \( -name .user.ini -o -name .htaccess -o -name php.ini \) -type f -print 2>/dev/null |
          while IFS= read -r f; do grep -nHiE 'auto_(prepend|append)_file|(AddHandler|AddType|SetHandler)[^#]*php' "$f" 2>/dev/null; done)
    if printf '%s' "$cfg" | grep -qiE 'auto_(prepend|append)_file'; then
      flag "auto_prepend/append_file set in a per-directory config (classic persistence):"
      printf '%s\n' "$cfg" | grep -i 'auto_' | head -n 10 | clip 200 | indent
    fi
    hand=$(printf '%s\n' "$cfg" | grep -iE '(AddHandler|AddType|SetHandler)' | grep -viE '\.php[0-9]?([[:space:]]|$|")' )
    if [ -n "$hand" ]; then
      warn "handler mappings that may execute non-.php files as PHP (review):"
      printf '%s\n' "$hand" | head -n 10 | clip 200 | indent
    fi
    [ -z "$cfg" ] && ok "no auto_prepend/handler tricks in .user.ini/.htaccess/php.ini"

    # c. Web-shell content heuristics.
    shells=$(find "$root" \( -name node_modules -o -name files_versions -o -name files_trashbin -o -path '*/data/*/files' \) -prune -o \
      -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' -o -name '*.phar' -o -name '*.pht' -o -name '*.phps' \) \
      -exec grep -nHE \
          -e 'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|\$_(GET|POST|REQUEST|COOKIE|SERVER))' \
          -e '(assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*(@?\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode)' \
          -e 'preg_replace[[:space:]]*\([[:space:]]*["'"'"'][^"'"'"']*/e["'"'"']' \
          -e 'create_function[[:space:]]*\([^)]*\$_(GET|POST|REQUEST|COOKIE)' \
          -e '\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\(' \
          {} + 2>/dev/null | clip 220)
    if [ -n "$shells" ]; then
      flag "web-shell-like code (read each hit; vendored libraries can false-positive):"
      printf '%s\n' "$shells" | head -n 25 | indent
    else
      ok "no web-shell content patterns"
    fi

    # d. Hidden and double-extension PHP.
    sneaky=$(find "$root" \( -name node_modules -o -name files_versions -o -name files_trashbin -o -path '*/data/*/files' \) -prune -o -type f \( -name '.*.php' -o -name '*.php.*' -o -name '*.phtml.*' \) -print 2>/dev/null |
      grep -vE '\.php\.(dist|sample|example|stub|tpl|twig|bak|orig|txt|md|json|map|lock|xml)$|/\.php-cs-fixer|/\.phpstorm|/\.php_cs|/vendor/.*/\.stubs\.php$' | head -n 15)
    if [ -n "$sneaky" ]; then
      warn "hidden or double-extension PHP files:"
      printf '%s\n' "$sneaky" | clip 200 | indent
    fi

    # e. Recently modified PHP.
    recent=$(find_php "$root" -mtime -"$DAYS" | grep -vE '/storage/framework/|/bootstrap/cache/|/wp-content/cache/')
    nrec=$(printf '%s' "$recent" | grep -c . | tr -d ' ')
    if [ "$nrec" -gt 0 ]; then
      info "$nrec PHP file(s) modified since $SINCE. Expected after a deploy or upgrade; otherwise review."
      info "newest 10:"
      printf '%s\n' "$recent" | while IFS= read -r f; do
        m=$(stat -c '%Y' "$f" 2>/dev/null || date -r "$f" +%s 2>/dev/null || echo 0); printf '%s %s\n' "$m" "$f"
      done | sort -rn | head -n 10 | while read -r m f; do
        printf '%s  %s\n' "$(date -d "@$m" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$m")" "$f"
      done | clip 200 | indent
    else
      ok "no PHP files modified since $SINCE"
    fi

    # f. git status, hardened.
    if [ -d "$root/.git" ] && have git; then
      gs=$(git -c safe.directory="$root" -c core.fsmonitor=false -c core.hooksPath=/dev/null \
               -C "$root" status --porcelain --ignore-submodules 2>&1)
      if [ $? -ne 0 ]; then info "git status failed: $(printf '%s' "$gs" | head -n1 | clip 150)"
      elif [ -n "$gs" ]; then warn "git working tree differs from the last commit:"; printf '%s\n' "$gs" | head -n 25 | clip 200 | indent
      else ok "git working tree clean"; fi
    fi

    # App-level checks we deliberately don't run (they execute app code).
    case "$t" in
      wordpress) info "run deliberately, as the site user: wp core verify-checksums; wp plugin verify-checksums --all;"
                 info "  wp user list --role=administrator --fields=ID,user_login,user_registered" ;;
      nextcloud) info "run deliberately: php occ integrity:check-core; php occ group:list (admin members); php occ user:list" ;;
      laravel)   info "compare against your release artifact or image; check for unexpected admin users in your database" ;;
      drupal)    info "run deliberately: drush pm:security; check for unexpected administrator accounts" ;;
    esac
  done <<EOF
$ROOTS
EOF
fi

# =============================================================================
# 5. SYSTEM: what an attacker does after landing as the web user
# =============================================================================
#   a. Processes running as the web user that aren't the web server or PHP:
#      a shell, interpreter or network tool there is the strongest live signal
#      there is. Read from /proc, so it works without ps.
#   b. Established network connections, INCLUDING ports 443 and 80. Most
#      implants call home over HTTPS; filtering those out hides them.
#   c. Cron entries, SSH keys and account files modified in the window, and any
#      SSH key or crontab belonging to the web user.
#   d. Executables in world-writable temp directories.
if want system; then
  section "5. System"
  # "daemon" only counts on Bitnami stacks, where Apache and PHP-FPM run as it;
  # elsewhere it's an ordinary system account.
  webusers=$(awk -F: -v bn="$BITNAMI" '$1 ~ /^(www-data|apache|nginx|http|httpd|wwwrun|nobody|caddy|frankenphp)$/ || $3 == 33 || $3 == 48 || $3 == 82 || (bn == 1 && $1 == "daemon") {print $3 ":" $1 ":" $6}' /etc/passwd 2>/dev/null)
  uids=$(printf '%s\n' "$webusers" | cut -d: -f1 | tr '\n' ' ' | sed 's/ *$//')

  # a. Processes.
  susp=""; odd=""
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    [ "$pid" = "$$" ] && continue
    st=$(cat "$p/status" 2>/dev/null) || continue
    ppid=$(printf '%s\n' "$st" | awk '/^PPid:/ {print $2}')
    [ "$ppid" = "$$" ] && continue                     # our own pipeline helpers
    uid=$(printf '%s\n' "$st" | awk '/^Uid:/ {print $2}')
    case " $uids " in *" $uid "*) ;; *) continue ;; esac
    comm=$(cat "$p/comm" 2>/dev/null)
    case "$comm" in
      php*|apache2|httpd|nginx|frankenphp|caddy|lsphp*|cron|crond|busybox|rotatelogs|tini|dumb-init|s6-*|supervisord) continue ;;
    esac
    args=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | clip 150)
    case "$comm" in
      sh|bash|dash|ash|zsh|ksh|perl|python*|ruby|node|nc|ncat|netcat|socat|curl|wget|telnet|openssl|php-cgi|base64|xmrig*|kdevtmp*|kinsing*)
        susp=$(add "$susp" "pid $pid uid $uid [$comm] $args") ;;
      *) odd=$(add "$odd" "pid $pid uid $uid [$comm] $args") ;;
    esac
  done
  if [ -n "$susp" ]; then flag "shell/interpreter/network tool running as the web user:"; printf '%s\n' "$susp" | indent
  elif [ -n "$uids" ]; then ok "no shells or network tools running as the web user (uids: $uids)"; fi
  [ -n "$odd" ] && { warn "other processes running as the web user:"; printf '%s\n' "$odd" | head -n 15 | indent; }

  # b. Connections.
  if have ss; then
    est=$( { ss -Htnp state established 2>/dev/null || ss -tnp state established 2>/dev/null | tail -n +2; } | grep -vE '127\.0\.0\.1|\[::1\]|::ffff:127\.' | clip 180)
    if [ -n "$est" ]; then info "established TCP connections (review anything unexpected, on any port):"; printf '%s\n' "$est" | head -n 30 | indent
    else ok "no established non-loopback TCP connections"; fi
  else
    info "ss not available; established connections not listed"
  fi

  # c. Persistence.
  pc=$(find /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron /var/spool/cron/crontabs \
            /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d /etc/ld.so.preload /etc/profile.d \
            -type f -mtime -"$DAYS" 2>/dev/null | sort -u)
  if [ -n "$pc" ]; then
    warn "cron/account/sudo/preload files modified since $SINCE (fine if you or a package did it):"
    printf '%s\n' "$pc" | head -n 20 | indent
  else
    ok "no cron, account, sudoers or ld.so.preload changes since $SINCE"
  fi
  [ -s /etc/ld.so.preload ] && flag "/etc/ld.so.preload is not empty (a common rootkit hook): $(head -c 200 /etc/ld.so.preload | tr '\n' ' ')"
  wcron=""; wkeys=""
  while IFS=: read -r _ wn wh; do
    [ -n "$wn" ] || continue
    for ct in "/var/spool/cron/crontabs/$wn" "/var/spool/cron/$wn"; do [ -f "$ct" ] && wcron=$(add "$wcron" "$ct"); done
    [ -n "$wh" ] && [ -f "$wh/.ssh/authorized_keys" ] && wkeys=$(add "$wkeys" "$wh/.ssh/authorized_keys")
  done <<EOF
$webusers
EOF
  [ -n "$wkeys" ] && { flag "the web user has SSH authorized_keys:"; printf '%s\n' "$wkeys" | indent; }
  [ -n "$wcron" ] && { warn "the web user has a crontab (normal for Nextcloud's cron container; otherwise review):"; printf '%s\n' "$wcron" | indent; }
  ak=$(find /root/.ssh /home -maxdepth 3 -name authorized_keys -type f -mtime -"$DAYS" 2>/dev/null)
  [ -n "$ak" ] && { warn "authorized_keys modified since $SINCE (key count shown, not contents):"; printf '%s\n' "$ak" | while IFS= read -r f; do printf '%s (%s keys)\n' "$f" "$(grep -c . "$f")"; done | indent; }

  # d. Executables in temp dirs.
  tx=$(find /tmp /var/tmp /dev/shm -maxdepth 3 -type f \( -perm -u+x -o -perm -g+x -o -perm -o+x \) 2>/dev/null | head -n 20)
  if [ -n "$tx" ]; then warn "executable files in temp directories:"; printf '%s\n' "$tx" | while IFS= read -r f; do ls -l "$f" 2>/dev/null; done | clip 200 | indent
  else ok "no executables in /tmp, /var/tmp or /dev/shm"; fi
fi

# =============================================================================
# Verdict
# =============================================================================
section "Verdict"
if { want runtime || want logs || want files; } && [ $((N_BINS + N_LOGS + N_ROOTS)) -eq 0 ] && [ -z "$REDIS" ]; then
  warn "found no PHP binary, no logs and no application to inspect: this run says nothing"
  info "about this system. Run it where PHP runs (inside the container), or point it at"
  info "your install with --php, --log and --root."
fi
if [ "$FLAGS" -gt 0 ]; then
  printf '  %s%d flag(s), %d warning(s).%s\n' "$R$BOLD" "$FLAGS" "$WARNS" "$N"
  echo "  Treat this system as suspect until each FLAG is explained. Patching does not"
  echo "  undo a compromise: preserve logs, then rotate secrets the PHP workers could read"
  echo "  (app keys, database and API credentials, session secrets, TLS keys)."
  rc=2
elif [ "$WARNS" -gt 0 ]; then
  printf '  %s0 flags, %d warning(s).%s\n' "$Y$BOLD" "$WARNS" "$N"
  echo "  No strong indicator. Explain each warning before you call it clean."
  rc=1
else
  printf '  %sClean: no flags or warnings from the checks this script can do.%s\n' "$G$BOLD" "$N"
  rc=0
fi
echo "  Limits: memory disclosure leaves almost nothing on disk; redeployed containers"
echo "  lose their history; an attacker with root could hide from any on-host check."
exit "$rc"
