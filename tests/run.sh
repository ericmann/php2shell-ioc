#!/bin/sh
# tests/run.sh: run the test suite across a matrix of images and shells.
#
#   tests/run.sh                 # every case, full matrix
#   tests/run.sh logs sessions   # only these cases
#   IMAGES="alpine:3.20|sh" tests/run.sh
#
# Each case is a POSIX sh file in tests/cases/. It runs inside a fresh,
# disposable container:
#   --network none  the script must work with no network at all
#   --rm            nothing a case plants outlives it
#   /src (ro)       the repository, read-only
# A case that needs a specific image says so on its first line:
#   # images: redis:7.4-alpine
# Otherwise it runs once per entry in the default matrix below, which covers
# BusyBox ash (Alpine), dash (Debian), bash, and a real PHP build.
#
# Requires Docker. Exits non-zero if any case fails on any image.

set -u
cd "$(dirname "$0")/.." || exit 1
REPO=$(pwd)

DEFAULT_IMAGES=${IMAGES:-"alpine:3.20|sh debian:bookworm-slim|sh debian:bookworm-slim|bash php:8.4-cli|sh"}

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run the tests" >&2
  exit 1
fi

if [ $# -gt 0 ]; then
  cases=""
  for c in "$@"; do cases="$cases tests/cases/${c%.sh}.sh"; done
else
  cases=$(ls tests/cases/*.sh)
fi

total=0; failed=0; failures=""
for case in $cases; do
  [ -f "$case" ] || { echo "no such case: $case" >&2; exit 1; }
  name=$(basename "$case" .sh)
  pinned=$(sed -n '1s/^# images: *//p' "$case")
  matrix=$DEFAULT_IMAGES
  [ -n "$pinned" ] && matrix=$(for i in $pinned; do printf '%s|sh ' "$i"; done)
  for entry in $matrix; do
    image=${entry%|*}; shell=${entry##*|}
    total=$((total + 1))
    # A case that hangs is a failure, not a stalled CI job.
    cname="php2shell-ioc-test-$$-$total"
    out=$(timeout "${CASE_TIMEOUT:-300}" docker run --rm --name "$cname" --network none -u 0 --entrypoint sh \
            -e IOC_SHELL="$shell" -v "$REPO:/src:ro" "$image" "/src/$case" 2>&1)
    rc=$?
    [ "$rc" -eq 124 ] && { docker kill "$cname" >/dev/null 2>&1; out="$out
# timed out after ${CASE_TIMEOUT:-300}s"; }
    n_ok=$(printf '%s\n' "$out" | grep -c '^ok ')
    n_bad=$(printf '%s\n' "$out" | grep -c '^not ok ')
    if [ "$rc" -eq 0 ] && [ "$n_bad" -eq 0 ] && [ "$n_ok" -gt 0 ]; then
      printf 'PASS  %-26s %-26s %-4s (%d assertions)\n' "$name" "$image" "$shell" "$n_ok"
    else
      printf 'FAIL  %-26s %-26s %-4s (%d ok, %d failed, exit %d)\n' "$name" "$image" "$shell" "$n_ok" "$n_bad" "$rc"
      printf '%s\n' "$out" | sed 's/^/      /'
      failed=$((failed + 1)); failures="$failures $name@$image/$shell"
    fi
  done
done

echo
if [ "$failed" -eq 0 ]; then
  echo "All $total case runs passed."
else
  echo "$failed of $total case runs failed:$failures"
  exit 1
fi
