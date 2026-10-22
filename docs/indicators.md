# Indicators

What each check looks for, why it relates to PHP2Shell, how strong a signal it
is, and what else can cause it.

## How the bugs show up from the outside

Both vulnerabilities are reached **before your application code runs**, while
PHP is still turning the raw HTTP request into `$_GET`, `$_POST`, `$_COOKIE`,
`$_FILES` and, for session upload progress, `$_SESSION`.

An attacker makes PHP hit a fatal error, usually running past `memory_limit`,
at a moment when the engine is halfway through updating its own state:

- **CVE-2026-109618**: the out-of-memory "bailout" leaves half-built
  structures behind, and later code trusts them.
- **CVE-2026-109619**: request shutdown frees state without clearing the
  pointers to it, so the *next* request on the same worker finds pointers to
  memory from the previous one.

So the traces that can survive are: fatal errors during request parsing,
crashed workers, odd input during parsing, session data written by the
upload-progress feature, and then whatever the attacker did after landing.

The fixes are in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35.

---

## 1. Runtime

| Finding | Level | Notes |
|---|---|---|
| PHP below the patched release for its branch | FLAG | Distro packages (Debian, Ubuntu, RHEL) often backport fixes without changing the upstream version. Check the package changelog for `109618` / `109619` before concluding you're exposed. |
| End-of-life branch (8.1 and older) | FLAG | No upstream fix. Some distros backported a minimal mitigation. |
| `display_errors` on | warn | The official Docker images ship no `php.ini`, so it defaults to **on**. Frameworks switch it off at runtime, but errors during request parsing happen before your framework boots, and can echo engine state or paths back to the client. Set `display_errors=Off` in a `conf.d` ini. |
| `session.upload_progress.enabled` on | info | Harmless on a patched build. It was the main path to CVE-2026-109619 before the fix, and almost nobody uses it. |

CLI and FPM read separate ini files and can even be different builds. The
script checks each binary separately. What serves your site is FPM,
`apache2handler` (mod_php), FrankenPHP or the built-in server, not the CLI.

## 2. Logs

| Finding | Level | What it means | Also caused by |
|---|---|---|---|
| `Allowed memory size of N bytes exhausted … in Unknown on line 0` | **FLAG** | PHP ran out of memory with **no script line**: it died while parsing the request, before any PHP file ran. This is the trigger's signature. | Very large legitimate uploads with a low `memory_limit`; misconfigured `post_max_size` vs `memory_limit`. Rare. |
| Worker crash: `exited on signal 11` / `6` / `7`, `exit signal Segmentation fault`, `zend_mm_heap corrupted`, `double free`, `free(): invalid` … | **FLAG** | A worker died on a signal or the allocator detected heap corruption. On a patched build, a hard exit is the engine's *safe* response to repeated attempts. On an unpatched one it's the warning sign. | Buggy extensions, opcache/JIT bugs, out-of-memory kills. Look at timing: a burst lined up with odd POSTs is the interesting case. |
| `upstream prematurely closed connection`, `Connection reset by peer … while reading response header from upstream` | warn | The proxy (nginx, Caddy) saw PHP drop the connection mid-request: a crash as seen from the front. | Timeouts, deploys and restarts. |
| `Input variable nesting level exceeded`, `Input variables exceeded`, `Maximum number of allowable file uploads`, `POST Content-Length … exceeds the limit` | warn | PHP rejected input while parsing it. The memory bug is about input that is cheap to send but expensive to parse. | Scanners and fuzzers, and occasionally legitimate large forms. |
| `Session ID is too long or contains illegal characters`, `Failed to decode session object`, `Failed to read session data` | warn | A client sent a session id PHP would never generate, or session data that didn't decode. The upload-progress path accepted attacker-supplied ids. | Broken clients, cookie collisions between apps on the same domain. |
| POSTs to static files (`.css`, `.js`, images, `favicon.ico`…) | warn | Multipart to *any* URL reached the vulnerable code, and static paths are a common choice. Legitimate clients don't POST to images. | Scanners. |
| POSTs answered with 5xx | warn | Requests that made the backend fail. Listed by path. | Ordinary app bugs. Compare against your normal baseline. |
| Out-of-memory **with** a script line | info | An ordinary memory bug in the app. Context only. | — |

**Behind a CDN or tunnel**, your access logs may show the proxy's address for
every request, and container logs disappear on redeploy. Your edge provider's
analytics usually keep a week or more of request metadata (host, path, method,
status, origin status, client IP). Look for bursts of 5xx/52x responses to POSTs
in the window between disclosure and your patch. See [running.md](running.md).

## 3. Sessions

| Finding | Level | What it means |
|---|---|---|
| A session file or Redis session containing `upload_progress_` | **FLAG** | Before the fix, any multipart request carrying the upload-progress field made PHP open, decode and save the session named in the request, for **any** script, even one that never uses sessions. On a site that never shows upload progress bars, this data exists only because someone exercised that path. |
| A session id PHP wouldn't generate (outside `[A-Za-z0-9,-]`, or shorter than 22 / longer than 128 characters) | warn | The id was chosen by a client, not issued by PHP. With `session.use_strict_mode=0` (the default), PHP adopts client-supplied ids. |

Sessions expire (`session.gc_maxlifetime`, 24 minutes by default), so this
evidence is short-lived. The script prints file names, sizes and times, never
contents: sessions hold logged-in users' data.

## 4. Files

| Finding | Level | Notes |
|---|---|---|
| Executable PHP in an upload/data location | **FLAG** | WordPress `wp-content/uploads`; Laravel `public/` (other than `index.php`) and `storage/` (other than compiled views); Drupal `sites/*/files`; Nextcloud `data/` (outside users' own files); plain PHP folders named `uploads`, `upload`, `files`, `tmp`. The "Silence is golden" `index.php` stubs that WordPress and many plugins drop into folders are recognised and skipped. |
| `auto_prepend_file` / `auto_append_file` in `.user.ini`, `.htaccess` or `php.ini` | **FLAG** | Makes PHP include a file on every request. Classic persistence. |
| `AddHandler` / `AddType` / `SetHandler` mapping a non-`.php` extension to PHP | warn | e.g. making `.jpg` files execute. |
| Web-shell content patterns | **FLAG** | `eval()` of decoded or request data; command execution (`system`, `passthru`, `exec`, `shell_exec`, `popen`, `proc_open`, `assert`) fed straight from request input; `preg_replace` with `/e`; calling a function named by request input. Vendored libraries occasionally match. Read each hit. |
| Hidden (`.x.php`) or double-extension (`x.php.png`) PHP files | warn | Common ways to hide a shell or slip it past upload filters. |
| PHP files modified within `--since` | info | Expected after any deploy, update or upgrade. Useful on long-lived installs. |
| `git status` shows changes | warn | Run with fsmonitor and hooks disabled; see [design.md](design.md). |
| Nextcloud: unexpected files in `config/` | warn | Anything besides `config.php`, `*.config.php`, `config.sample.php`, `.htaccess` and `CAN_INSTALL`. |

Nextcloud users' own files (`data/<user>/files`, versions and trash) are
counted but never flagged: Nextcloud stores uploads there and never executes
them, and people do keep backups of old PHP sites in their cloud.

## 5. System

| Finding | Level | Notes |
|---|---|---|
| A shell, interpreter or network tool running as the web user | **FLAG** | `sh`, `bash`, `perl`, `python`, `nc`, `socat`, `curl`, `wget`, cryptominer names. The web user should only ever be running the web server and PHP. |
| Other unexpected processes as the web user | warn | Review them. |
| Established TCP connections | info | Listed **including ports 80 and 443**. Most implants call home over HTTPS, so filtering those out hides exactly what you're looking for. |
| `/etc/ld.so.preload` not empty | **FLAG** | A common rootkit hook. |
| The web user has SSH `authorized_keys` | **FLAG** | |
| The web user has a crontab | warn | Normal for Nextcloud's cron container; unusual elsewhere. |
| Cron, account, sudoers or preload files changed within `--since` | warn | Expected in a freshly built image; investigate on a long-lived host. |
| Executables in `/tmp`, `/var/tmp`, `/dev/shm` | warn | |

## What a clean result means

Nothing more than "none of these traces were found here, now". Rotating secrets
the PHP workers could read is cheap insurance if you were exposed during the
window when exploit details were circulating, whatever this script says.
