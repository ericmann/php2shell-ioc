# PHP version and ini checks, using stand-in binaries so every branch (patched,
# unpatched, end-of-life, suffixed versions) is exercised without old PHP builds.
. /src/tests/lib.sh

# fake_php PATH VERSION DISPLAY_ERRORS UPLOAD_PROGRESS: a stand-in that answers
# `-v` (version) and `-r` (the script's ini query) like the real CLI does.
fake_php() {
  cat > "$1" <<EOF
#!/bin/sh
case "\$1" in
  -v) echo "PHP $2 (cli) (built: Oct 21 2026 14:00:00) (NTS)"; echo "Copyright (c) The PHP Group" ;;
  -r) printf 'session.upload_progress.enabled=$4\nsession.use_strict_mode=1\nsession.save_handler=files\nsession.save_path=/var/lib/php/sessions\nmemory_limit=128M\nmax_input_nesting_level=64\ndisplay_errors=$3\n' ;;
esac
EOF
  chmod +x "$1"
}

if command -v php >/dev/null 2>&1; then
  # Real PHP image: the official images ship no php.ini, so display_errors is on.
  run_ioc --only runtime
  assert_match '\[ ok \] .*php -> PHP 8\.[0-9]+\.[0-9]+' "real PHP binary is detected and patched"
  assert_contains "display_errors is on" "official image's display_errors default is warned about"
  finish
fi

mkdir -p /usr/local/bin
fake_php /usr/local/bin/php 8.4.27 0 0
run_ioc --only runtime
assert_rc 0 "patched 8.4.27, display_errors off: exit 0"
assert_contains "/usr/local/bin/php -> PHP 8.4.27 (patched in 8.4.27)" "patched version is OK"

fake_php /usr/local/bin/php 8.4.26 0 1
run_ioc --only runtime
assert_rc 2 "8.4.26: exit 2"
assert_contains "PHP 8.4.26: below the patched release 8.4.27" "one patch below the floor is flagged"
assert_contains "upload progress is enabled" "upload progress state is reported"

fake_php /usr/local/bin/php 8.3.100 0 0
run_ioc --only runtime
assert_contains "PHP 8.3.100 (patched in 8.3.36)" "version comparison is numeric, not lexical"

fake_php /usr/local/bin/php 8.5.12-dev On 0
run_ioc --only runtime
assert_contains "PHP 8.5.12-dev (patched in 8.5.12)" "version suffixes are ignored"
assert_contains "display_errors is on" "display_errors=On is a warning"
assert_rc 1 "display_errors alone: exit 1"

fake_php /usr/local/bin/php 8.1.31 0 0
run_ioc --only runtime
assert_contains "branch 8.1 is end-of-life" "EOL branch is flagged"

fake_php /usr/local/bin/php 7.4.33 0 0
run_ioc --only runtime
assert_contains "branch 7.4 is end-of-life" "PHP 7 is flagged as EOL"

# --php points at binaries in unusual places.
mkdir -p /opt/custom/bin
fake_php /opt/custom/bin/php-custom 8.4.27 0 0
run_ioc --only runtime --php /opt/custom/bin/php-custom
assert_contains "/opt/custom/bin/php-custom -> PHP 8.4.27 (patched in 8.4.27)" "--php checks a binary outside the standard locations"

rm -f /usr/local/bin/php /opt/custom/bin/php-custom
run_ioc --only runtime
assert_contains "no PHP binary found here" "no PHP is reported, not an error"
assert_contains "pass --php PATH" "suggests --php"

# Nothing to inspect must never read as "Clean".
run_ioc --only runtime,logs,files
assert_rc 1 "nothing found to inspect: exit 1, not 0"
assert_contains "found no PHP binary, no logs and no application to inspect" "says the run inspected nothing"
assert_not_contains "Clean:" "never says Clean after inspecting nothing"

finish
