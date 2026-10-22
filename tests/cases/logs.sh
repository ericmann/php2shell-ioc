# Log signatures: files, gzip, stdin, combined and JSON access logs, and the
# Docker-style symlinks to /dev/stdout that must never be read.
. /src/tests/lib.sh

mkdir -p /var/log/nginx /var/log/php
ERR=/var/log/nginx/error.log
cat > "$ERR" <<'EOF'
2026/10/20 21:14:02 [error] 31#31: *88 upstream prematurely closed connection while reading response header from upstream, client: 192.0.2.10, request: "POST / HTTP/1.1"
[20-Oct-2026 21:14:02] WARNING: [pool www] child 41 exited on signal 11 (SIGSEGV) after 12.3 seconds from start
PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
PHP Warning:  Unknown: Input variable nesting level exceeded 64. To increase the limit change max_input_nesting_level in php.ini. in Unknown on line 0
PHP Warning:  session_start(): Session ID is too long or contains illegal characters. Only the A-Z, a-z, 0-9, "-", and "," characters are allowed in Unknown on line 0
EOF

run_ioc --only logs --log "$ERR"
assert_rc 2 "crash + OOM signatures: exit 2"
assert_contains "1 out-of-memory fatal(s) 'in Unknown on line 0'" "OOM during request parsing is flagged"
assert_contains "1 worker crash / heap-corruption line(s)" "worker crash is flagged"
assert_contains "1 upstream reset(s)" "upstream reset is a warning"
assert_contains "1 input-limit rejection(s)" "input-limit rejection is a warning"
assert_contains "1 malformed session id" "malformed session id is a warning"
assert_contains "exited on signal 11" "sample line is shown"

# Compressed rotation.
gzip -c "$ERR" > /var/log/php/old.log.gz
run_ioc --only logs --log /var/log/php/old.log.gz
assert_contains "/var/log/php/old.log.gz: 1 out-of-memory fatal(s)" "reads .gz logs"

# An app bug (OOM with a script line) is context, not an indicator.
run_ioc_stdin 'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted in /app/Report.php on line 88' --only logs --log -
assert_rc 0 "ordinary OOM alone: exit 0"
assert_contains "1 ordinary out-of-memory fatal(s)" "ordinary OOM is reported as info"

# Access logs: combined format and JSON (Caddy / FrankenPHP).
ACCESS='192.0.2.10 - - [20/Oct/2026:21:14:02 +0000] "POST /favicon.ico HTTP/1.1" 502 157 "-" "curl/8"
192.0.2.11 - - [20/Oct/2026:21:14:03 +0000] "POST /contact HTTP/1.1" 200 157 "-" "Mozilla/5.0"
{"level":"error","logger":"http.log.access","request":{"remote_ip":"10.42.0.3","client_ip":"192.0.2.12","method":"POST","uri":"/app.css?v=1"},"status":500}'
run_ioc_stdin "$ACCESS" --only logs --log -
assert_rc 1 "suspicious access-log POSTs: exit 1"
assert_contains "stdin: 2 POST(s) to static-file paths" "POSTs to static files (combined + JSON) are counted"
assert_contains "stdin: 2 POST(s) answered with 5xx" "POSTs answered 5xx are counted"
assert_match '1[[:space:]]+/favicon\.ico' "top 5xx paths listed"
assert_match '1[[:space:]]+/app\.css$' "query strings are stripped from paths"

# Clean input.
run_ioc_stdin '192.0.2.11 - - [20/Oct/2026:21:14:03 +0000] "POST /contact HTTP/1.1" 200 157 "-" "Mozilla/5.0"' --only logs --log -
assert_rc 0 "clean access log: exit 0"
assert_contains "no crash, OOM or parsing signatures (1 POST requests seen)" "clean summary counts POSTs"

# Official Docker images symlink logs to /dev/stdout. Auto-detection must skip
# them; reading one would hang or read our own output.
rm -f "$ERR" /var/log/php/old.log.gz
ln -s /dev/stdout /var/log/nginx/access.log
ln -s /dev/stderr /var/log/nginx/error.log
# shellcheck disable=SC2034  # OUT and RC are read by the lib.sh assertions
OUT=$(timeout 30 "$IOC_SHELL" "$IOC" --no-color --only logs 2>&1); RC=$?
assert_true "log symlinks to /dev/stdout don't hang (finished before timeout)" [ "$RC" -ne 124 ]
assert_contains "no log files found" "symlinked logs are skipped"

finish
