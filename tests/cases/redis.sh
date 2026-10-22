# images: redis:7.4-alpine
# PHP sessions stored in Redis (phpredis' default key prefix).
. /src/tests/lib.sh

redis-server --daemonize yes --save '' --appendonly no >/dev/null
i=0; until redis-cli ping >/dev/null 2>&1 || [ $i -ge 50 ]; do i=$((i + 1)); sleep 0.1; done

redis-cli SET 'PHPREDIS_SESSION:k3r9v0a8b1c2d3e4f5g6h7i8j9' 'user|s:5:"alice";' >/dev/null
run_ioc --only sessions --session-dir /nonexistent --redis 127.0.0.1:6379
assert_rc 0 "ordinary Redis sessions: exit 0"
assert_contains "redis 127.0.0.1:6379: 1 session key(s), none with upload_progress_ data" "ordinary Redis session is OK"

redis-cli SET 'PHPREDIS_SESSION:0123456789abcdef0123456789abcdef' 'upload_progress_x|a:0:{}token|s:6:"SECRET";' >/dev/null
redis-cli SET 'PHPREDIS_SESSION:../../etc/passwd' 'a|i:1;' >/dev/null
run_ioc --only sessions --session-dir /nonexistent --redis 127.0.0.1:6379
assert_rc 2 "upload_progress in Redis: exit 2"
assert_contains "1 of 3 session key(s) contain upload_progress_ data" "upload_progress_ in Redis is flagged"
assert_contains "1 session key(s) with ids PHP would not generate" "odd Redis session id is a warning"
assert_not_contains "SECRET" "never prints Redis session contents"

redis-cli shutdown nosave >/dev/null 2>&1
finish
