# RHEL-family hosts (Amazon Linux, Rocky, Alma; including Lightsail's plain OS
# blueprints with a hand-installed LAMP stack): httpd logs in /var/log/httpd,
# PHP-FPM logs in /var/log/php-fpm, sessions in /var/lib/php/session, and a
# php-fpm binary in /usr/sbin. Only the paths matter, so any image will do.
. /src/tests/lib.sh

mkdir -p /var/log/httpd /var/log/php-fpm /var/lib/php/session /usr/sbin
: > /var/log/httpd/access_log
echo '[Thu Oct 22 01:02:04.000000 2026] [core:notice] [pid 1] AH00052: child pid 4242 exit signal Segmentation fault (11)' > /var/log/httpd/error_log
echo '[22-Oct-2026 01:02:03] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted in Unknown on line 0' > /var/log/php-fpm/www-error.log
printf 'upload_progress_x|a:0:{}' > /var/lib/php/session/sess_0123456789abcdef0123456789abcdef

# A stand-in php-fpm that reports an unpatched 8.3 build.
cat > /usr/sbin/php-fpm <<'EOF'
#!/bin/sh
case "$1" in
  -v) echo "PHP 8.3.30 (fpm-fcgi) (built: Sep  1 2026 00:00:00)" ;;
  -i) printf 'session.save_handler => files => files\nsession.save_path => /var/lib/php/session => /var/lib/php/session\ndisplay_errors => Off => Off\n' ;;
esac
EOF
chmod +x /usr/sbin/php-fpm

run_ioc --only runtime,logs,sessions
assert_rc 2 "RHEL layout with indicators: exit 2"
assert_contains "/usr/sbin/php-fpm -> PHP 8.3.30: below the patched release 8.3.36" "finds and flags /usr/sbin/php-fpm"
assert_contains "/var/log/httpd/error_log: 1 worker crash" "scans /var/log/httpd"
assert_contains "/var/log/php-fpm/www-error.log: 1 out-of-memory fatal(s)" "scans /var/log/php-fpm"
assert_contains "/var/lib/php/session: 1 of 1 session file(s) contain upload_progress_ data" "checks /var/lib/php/session"

finish
