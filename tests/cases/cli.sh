# Command-line handling: help, version, and input validation.
. /src/tests/lib.sh

run_ioc --help
assert_rc 0 "--help exits 0"
assert_contains "Usage:" "--help prints usage"
assert_contains "Exit codes:" "--help documents exit codes"

run_ioc --version
assert_rc 0 "--version exits 0"
assert_match '^php2shell-ioc [0-9]+\.[0-9]+\.[0-9]+$' "--version prints a semantic version"

# --help must work when piped in with `sh -s`, where there is no "$0" file.
run_ioc_piped --help
assert_rc 0 "--help works when the script is read from stdin"
assert_contains "Usage:" "piped --help prints usage"

run_ioc --bogus
assert_rc 64 "unknown option exits 64"

run_ioc --only runtime,typo
assert_rc 64 "unknown --only section exits 64"
assert_contains "unknown section in --only: typo" "names the bad section"

run_ioc --since 10/01/2026
assert_rc 64 "malformed --since exits 64"

run_ioc --max-samples lots
assert_rc 64 "non-numeric --max-samples exits 64"

run_ioc --root
assert_rc 64 "option missing its value exits 64 (and doesn't loop)"
assert_contains "--root needs a value" "names the option missing a value"

finish
