# Laravel and Nextcloud: framework-specific locations and their known-benign
# files. Also checks auto-detection doesn't split one app into many roots.
. /src/tests/lib.sh

L=/var/www
mk_laravel "$L"
run_ioc --only files
assert_rc 0 "clean Laravel app in /var/www: exit 0"
assert_contains "$L (laravel)" "detects Laravel at /var/www"
assert_not_contains "$L/app (" "does not treat /var/www/app as a separate root"
assert_not_contains "$L/public (" "does not treat /var/www/public as a separate root"
assert_not_contains "bootstrap/cache" "bootstrap/cache is not an upload location"
assert_not_contains "storage/framework/views" "compiled Blade views are not flagged"
assert_not_contains ".stubs.php" "vendor IDE stubs are not flagged"
assert_not_contains "psr/cache" "vendor directories named cache are not upload locations"

echo '<?php passthru($_REQUEST["c"]);' > "$L/public/shell.php"
echo '<?php' > "$L/storage/app/public/avatar.phtml"
run_ioc --only files --root "$L"
assert_rc 2 "planted Laravel app: exit 2"
assert_contains "$L/public/shell.php" "PHP in public/ besides index.php is flagged"
assert_contains "$L/storage/app/public/avatar.phtml" ".phtml in storage is flagged"
assert_not_contains "$L/public/index.php" "public/index.php is expected"

rm -rf "$L"
N=/var/www/html
mk_nextcloud "$N"
run_ioc --only files --root "$N"
assert_rc 0 "clean Nextcloud: exit 0"
assert_contains "$N (nextcloud)" "detects Nextcloud"
assert_contains "[ ok ] no PHP files in $N/data" "users' own files are not flagged"
assert_contains "1 PHP file(s) inside Nextcloud users' own files" "users' PHP files are counted as info"
assert_contains "php occ integrity:check-core" "suggests (but does not run) occ checks"

echo '<?php eval(gzinflate(base64_decode("x")));' > "$N/data/appdata_oc123/preview/p.php"
echo '<?php' > "$N/config/backdoor.inc.php"
run_ioc --only files --root "$N"
assert_rc 2 "planted Nextcloud: exit 2"
assert_contains "$N/data/appdata_oc123/preview/p.php" "PHP in appdata is flagged"
assert_contains "[warn] unexpected files in $N/config" "unexpected config file is a warning"
assert_contains "backdoor.inc.php" "names the unexpected config file"
assert_not_contains "alice/files/Backups/old-site/index.php" "user file still not reported"

finish
