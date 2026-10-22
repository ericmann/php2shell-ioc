# WordPress: a clean install stays clean; planted persistence is caught.
. /src/tests/lib.sh
W=/var/www/html

mk_wordpress "$W"
run_ioc --only files --root "$W"
assert_rc 0 "clean WordPress tree: exit 0"
assert_contains "$W (wordpress)" "detects WordPress"
assert_contains "[ ok ] no PHP files in $W/wp-content/uploads" "'Silence is golden' stubs are not flagged"
assert_contains "[ ok ] no auto_prepend/handler tricks" "standard WordPress .htaccess is not flagged"
assert_contains "[ ok ] no web-shell content patterns" "no web-shell false positives"
assert_contains "wp core verify-checksums" "suggests (but does not run) wp-cli checks"

# Auto-detection finds the same root without --root, exactly once.
run_ioc --only files
assert_contains "$W (wordpress)" "auto-detects /var/www/html"
assert_true "auto-detected root is scanned once" [ "$(printf '%s\n' "$OUT" | grep -c "$W (wordpress)")" -eq 1 ]

# Plant the usual post-exploitation artifacts.
echo '<?php @eval(base64_decode($_POST["x"]));' > "$W/wp-content/uploads/2026/10/thumb.php"
echo '<?php system($_GET["c"]);' > "$W/wp-content/plugins/akismet/class.helper.php"
echo 'x' > "$W/wp-content/uploads/2026/10/.cache.php"
echo 'auto_prepend_file=/tmp/.x.php' > "$W/.user.ini"
echo 'AddHandler application/x-httpd-php .jpg' > "$W/wp-content/uploads/.htaccess"
echo '<?php' > "$W/wp-content/uploads/2026/10/avatar.php.png"

run_ioc --only files --root "$W"
assert_rc 2 "planted WordPress tree: exit 2"
assert_contains "[FLAG] executable PHP in a data/upload location ($W/wp-content/uploads)" "PHP in uploads is flagged"
assert_contains "$W/wp-content/uploads/2026/10/thumb.php" "names the planted file"
assert_contains "[FLAG] auto_prepend/append_file set" ".user.ini auto_prepend_file is flagged"
assert_contains "[warn] handler mappings" "AddHandler for .jpg is a warning"
assert_contains "[FLAG] web-shell-like code" "web-shell content is flagged"
assert_contains "class.helper.php:1:" "web-shell hit shows file and line"
assert_contains "[warn] hidden or double-extension PHP files" "hidden/double-extension PHP is a warning"
assert_contains "avatar.php.png" "double extension named"
assert_not_contains "uploads/index.php" "silence stub still not reported"

finish
