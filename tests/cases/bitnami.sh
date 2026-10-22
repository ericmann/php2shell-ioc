# images: bitnami/wordpress@sha256:7366e2de7a0db585cbff6c410d56d85531c339d5adfb1845c0019bea4343ef87
# Bitnami stacks: AWS Lightsail's WordPress/LAMP blueprints and many cloud
# marketplace images. Everything lives under /opt/bitnami and Apache/PHP-FPM run
# as "daemon". This is the real Bitnami WordPress image, used as a stand-in for
# a Lightsail VM, so the paths are genuine.
. /src/tests/lib.sh

# On a VM you'd run this with sudo, which resets PATH and drops Bitnami's
# directories. Reproduce that: the script must find PHP anyway.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# On a VM the logs are real files (the image symlinks them to stdout).
for f in /opt/bitnami/apache/logs/access_log /opt/bitnami/apache/logs/error_log /opt/bitnami/php/logs/php-fpm.log; do
  rm -f "$f"; : > "$f"
done

run_ioc --only runtime,logs,sessions,files
assert_rc 0 "clean Bitnami stack under a sudo-style PATH: exit 0"
assert_match '\[ ok \] /opt/bitnami/php/bin/php -> PHP 8\.' "finds Bitnami's PHP CLI without PATH"
assert_match '\[ ok \] /opt/bitnami/php/sbin/php-fpm -> PHP 8\.' "finds Bitnami's PHP-FPM without PATH"
assert_contains "/opt/bitnami/wordpress (wordpress)" "auto-detects the WordPress root"
assert_contains "/opt/bitnami/apache/logs/error_log: no crash" "scans Apache logs"
assert_contains "/opt/bitnami/php/logs/php-fpm.log: no crash" "scans the PHP-FPM log"
assert_contains "/opt/bitnami/php/var/run/session" "checks Bitnami's session directory"
assert_not_contains "found no PHP binary, no logs and no application" "doesn't claim it found nothing"

# Plant indicators where a Bitnami install would have them.
echo '[22-Oct-2026 01:02:03] PHP Fatal error:  Allowed memory size of 268435456 bytes exhausted (tried to allocate 65536 bytes) in Unknown on line 0' >> /opt/bitnami/php/logs/php-fpm.log
echo '[Thu Oct 22 01:02:04.000000 2026] [core:notice] [pid 1:tid 1] AH00052: child pid 4242 exit signal Segmentation fault (11)' >> /opt/bitnami/apache/logs/error_log
printf 'upload_progress_x|a:0:{}' > /opt/bitnami/php/var/run/session/sess_0123456789abcdef0123456789abcdef
mkdir -p /opt/bitnami/wordpress/wp-content/uploads/2026/10
echo '<?php @eval(base64_decode($_POST["x"]));' > /opt/bitnami/wordpress/wp-content/uploads/2026/10/x.php
su daemon -s /bin/sh -c 'exec sh -c "while :; do sleep 1; done"' &
SPID=$!
sleep 1

run_ioc
assert_rc 2 "planted Bitnami stack: exit 2"
assert_contains "/opt/bitnami/php/logs/php-fpm.log: 1 out-of-memory fatal(s) 'in Unknown on line 0'" "OOM in Bitnami's FPM log is flagged"
assert_contains "/opt/bitnami/apache/logs/error_log: 1 worker crash" "Apache child segfault is flagged"
assert_contains "/opt/bitnami/php/var/run/session: 1 of 1 session file(s) contain upload_progress_ data" "upload_progress session is flagged"
assert_contains "/opt/bitnami/wordpress/wp-content/uploads/2026/10/x.php" "PHP in uploads is flagged"
assert_contains "[FLAG] shell/interpreter/network tool running as the web user" "a shell running as daemon is flagged on Bitnami"

kill "$SPID" 2>/dev/null
finish
