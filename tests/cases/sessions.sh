# File-based PHP sessions: upload-progress leftovers and client-chosen ids,
# without ever printing session contents.
. /src/tests/lib.sh

D=/var/lib/php/sessions
mkdir -p "$D"
printf 'user|s:5:"alice";' > "$D/sess_k3r9v0a8b1c2d3e4f5g6h7i8j9"
run_ioc --only sessions --session-dir "$D"
assert_rc 0 "ordinary sessions: exit 0"
assert_contains "$D: 1 session file(s), none with upload_progress_ data" "ordinary session is OK"

printf 'upload_progress_x|a:1:{s:4:"done";b:0;}token|s:21:"SECRET-SESSION-VALUE";' > "$D/sess_0123456789abcdef0123456789abcdef"
printf 'a|i:1;' > "$D/sess_<svg-onload>"
run_ioc --only sessions --session-dir "$D"
assert_rc 2 "upload_progress session: exit 2"
assert_contains "1 of 3 session file(s) contain upload_progress_ data" "upload_progress_ data is flagged"
assert_contains "sess_0123456789abcdef0123456789abcdef" "names the session file"
assert_contains "[warn] $D: session ids PHP would not generate" "odd session id is a warning"
assert_contains "<svg-onload>" "names the odd id"
assert_not_contains "SECRET-SESSION-VALUE" "never prints session contents"
assert_not_contains "alice" "never prints other sessions' contents"

finish
