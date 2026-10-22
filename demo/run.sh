#!/bin/sh
# demo/run.sh: watch php2shell-ioc.sh catch planted indicators.
#
#   demo/run.sh           # clean scan, then plant indicators, then scan again
#   demo/run.sh planted   # skip straight to the planted scan
#
# Everything happens in a disposable Alpine container with no network access
# (--network none, --rm). The repository is mounted read-only; nothing on your
# machine is touched. Requires Docker.
set -eu
cd "$(dirname "$0")/.."
IMAGE=${DEMO_IMAGE:-alpine:3.20}
TTY=""; [ -t 1 ] && TTY="-t"

if [ "${1:-}" != "planted" ]; then
  echo ">>> 1/2: a clean WordPress-shaped site"
  # shellcheck disable=SC2086
  docker run --rm $TTY --network none -v "$(pwd):/src:ro" "$IMAGE" \
    sh -c 'sh /src/demo/plant.sh clean && sh /src/php2shell-ioc.sh --only runtime,logs,sessions,files' || true
  echo
  echo ">>> 2/2: the same site with indicators planted (see demo/plant.sh)"
fi
# shellcheck disable=SC2086
docker run --rm $TTY --network none -v "$(pwd):/src:ro" "$IMAGE" \
  sh -c 'sh /src/demo/plant.sh && sh /src/php2shell-ioc.sh' || true
