# Post-exploitation on the system: processes as the web user, temp-dir
# executables, ld.so.preload, and SSH keys belonging to the web user.
. /src/tests/lib.sh

# Web user: Debian has www-data (uid 33); Alpine's BusyBox images have nobody.
WEBUSER=$(awk -F: '$1 == "www-data" {print $1; exit}' /etc/passwd)
[ -n "$WEBUSER" ] || WEBUSER=nobody
WEBHOME=$(awk -F: -v u="$WEBUSER" '$1 == u {print $6}' /etc/passwd)

# Ran as root in a fresh container with nothing planted: no process or temp findings.
run_ioc --only system --since 2099-01-01
assert_no_match '\[FLAG\]' "fresh container: no flags"
assert_contains "no executables in /tmp, /var/tmp or /dev/shm" "clean temp dirs"

# A reverse-shell-shaped process running as the web user.
su "$WEBUSER" -s /bin/sh -c 'exec sh -c "while :; do sleep 1; done"' &
SPID=$!
sleep 1
printf '#!/bin/sh\n' > /tmp/.x; chmod +x /tmp/.x
echo /lib/libevil.so > /etc/ld.so.preload
mkdir -p "$WEBHOME/.ssh"; echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAM attacker@example' > "$WEBHOME/.ssh/authorized_keys"

run_ioc --only system
assert_rc 2 "planted system artifacts: exit 2"
assert_contains "[FLAG] shell/interpreter/network tool running as the web user" "shell as the web user is flagged"
assert_contains "while :; do sleep 1; done" "shows the process command line"
assert_contains "[warn] executable files in temp directories" "executable in /tmp is a warning"
assert_contains "/tmp/.x" "names the temp executable"
assert_contains "[FLAG] /etc/ld.so.preload is not empty" "ld.so.preload is flagged"
assert_contains "[FLAG] the web user has SSH authorized_keys" "web user's SSH keys are flagged"
assert_not_contains "AAAAC3Nza" "never prints key material"

kill "$SPID" 2>/dev/null
finish
