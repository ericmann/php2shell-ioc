# images: alpine/git:v2.47.2
# Running `git status` as root in a repository the web user controls is a
# privilege-escalation trap: a planted core.fsmonitor runs as root. This case
# proves the trap is real (control), then that the script doesn't spring it,
# and that it reports the repo state instead of a false "clean".
. /src/tests/lib.sh

R=/var/www/app
mk_laravel "$R"
git -C "$R" init -q
git -C "$R" -c user.email=t@example.test -c user.name=test add -A
git -C "$R" -c user.email=t@example.test -c user.name=test commit -qm init
printf '#!/bin/sh\ntouch /tmp/PWNED\n' > /usr/local/bin/fsmon-trap; chmod +x /usr/local/bin/fsmon-trap
git -C "$R" config core.fsmonitor /usr/local/bin/fsmon-trap
git -C "$R" config core.hooksPath "$R/.githooks"
chown -R nobody "$R"
echo '<?php // modified' >> "$R/app/Http/Kernel.php"

# Control: a naive `git status` as root, once ownership checks are waved through,
# runs the attacker's fsmonitor.
git -c safe.directory='*' -C "$R" status --porcelain >/dev/null 2>&1
assert_true "control: naive git status springs the fsmonitor trap" [ -e /tmp/PWNED ]
rm -f /tmp/PWNED

run_ioc --only files --root "$R"
assert_true "the script does not run the planted fsmonitor" [ ! -e /tmp/PWNED ]
assert_contains "[warn] git working tree differs from the last commit" "reports the modified tree despite foreign ownership"
assert_contains "app/Http/Kernel.php" "names the modified file"
assert_not_contains "git working tree clean" "no false 'clean'"

finish
