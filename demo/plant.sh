# shellcheck shell=sh
# demo/plant.sh: plant harmless stand-ins for PHP2Shell indicators inside a
# throwaway container, so you can watch php2shell-ioc.sh find them.
#
# Nothing here exploits anything or contains working attack code. The "web
# shell" is a one-line string that matches the detector's pattern; it is never
# served or executed. The log lines are the error messages PHP and nginx print,
# written by hand. Run it ONLY inside a disposable container (demo/run.sh does
# that for you); it writes to /var/www, /var/log, /var/lib/php and /tmp.
set -eu

W=/var/www/html

# A minimal WordPress-shaped site. Only the files the scanner keys on.
mkdir -p "$W/wp-includes" "$W/wp-content/plugins/hello" "$W/wp-content/uploads/2026/10"
echo '<?php $wp_version = "7.1.3";' > "$W/wp-includes/version.php"
echo '<?php require __DIR__ . "/wp-blog-header.php";' > "$W/index.php"
echo '<?php /* Plugin Name: Hello */' > "$W/wp-content/plugins/hello/hello.php"
printf '<?php\n// Silence is golden.\n' > "$W/wp-content/uploads/index.php"   # benign, should NOT be flagged
# Make the site look long-lived, so only what's planted below is "recent".
find "$W" -exec touch -d '2020-01-01 00:00:00' {} +

[ "${1:-}" = "clean" ] && exit 0

# 1. Request-parsing crash signatures in the PHP-FPM / nginx error log.
mkdir -p /var/log/nginx
cat > /var/log/nginx/error.log <<'EOF'
[20-Oct-2026 21:14:01] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[20-Oct-2026 21:14:02] WARNING: [pool www] child 41 exited on signal 11 (SIGSEGV) after 12.3 seconds from start
2026/10/20 21:14:02 [error] 31#31: *88 upstream prematurely closed connection while reading response header from upstream, client: 192.0.2.10, request: "POST /favicon.ico HTTP/1.1"
[20-Oct-2026 21:14:03] PHP Warning:  Unknown: Input variable nesting level exceeded 64. To increase the limit change max_input_nesting_level in php.ini. in Unknown on line 0
EOF
echo '192.0.2.10 - - [20/Oct/2026:21:14:02 +0000] "POST /favicon.ico HTTP/1.1" 502 157 "-" "curl/8.5.0"' > /var/log/nginx/access.log

# 2. A session file holding upload-progress data, and one with an id PHP
#    would never generate (documentation IP range, example values only).
mkdir -p /var/lib/php/sessions
printf 'upload_progress_demo|a:1:{s:4:"done";b:0;}' > /var/lib/php/sessions/sess_0123456789abcdef0123456789abcdef
printf 'a|i:1;' > "/var/lib/php/sessions/sess_<demo>"

# 3. Post-exploitation persistence: PHP in uploads, a web-shell-shaped line,
#    an auto_prepend_file, a .jpg mapped to PHP, and a dotfile PHP script.
echo '<?php @eval(base64_decode($_POST["demo"]));' > "$W/wp-content/uploads/2026/10/thumb.php"
echo 'auto_prepend_file=/tmp/.demo.php' > "$W/.user.ini"
echo 'AddHandler application/x-httpd-php .jpg' > "$W/wp-content/uploads/.htaccess"
echo '<?php // demo' > "$W/wp-content/uploads/2026/10/.cache.php"

# 4. An executable dropped in /tmp.
printf '#!/bin/sh\necho demo\n' > /tmp/.demo-implant && chmod +x /tmp/.demo-implant
