# Running it

The script reads from stdin when you run it with `sh -s`, so the usual pattern
is to stream it into wherever PHP lives. Nothing is copied or installed.

Options go after `sh -s --`:

```sh
docker exec -i CONTAINER sh -s -- --since 2026-09-01 --only files,system < php2shell-ioc.sh
```

## Bare metal / VM

```sh
sudo sh php2shell-ioc.sh
sudo sh php2shell-ioc.sh --root /var/www/example.com --root /srv/legacy-app
```

Root is optional but recommended: FPM and auth logs, other users' sessions and
other users' processes are usually root-only. Everything the script runs as
root is read-only, and `git status` is hardened against booby-trapped repos
(see [design.md](design.md)).

Rotated logs are picked up automatically, including `.gz`. If your pool logs
somewhere unusual, name it:

```sh
sudo sh php2shell-ioc.sh --log /var/log/php8.4-fpm-www.log --log /var/log/nginx/example.error.log
```

## AWS Lightsail and other Bitnami stacks

Lightsail's WordPress and LAMP blueprints (and many cloud marketplace images)
are Bitnami stacks: PHP, Apache or nginx, logs, sessions and the site all live
under `/opt/bitnami`, and Apache and PHP-FPM run as `daemon`. There's no Docker
involved; run the script directly on the instance:

```sh
ssh bitnami@your-instance 'sudo sh -s' < php2shell-ioc.sh
```

It finds Bitnami's layout on its own, even though `sudo` drops
`/opt/bitnami/php/bin` from `PATH`:

| What | Where |
|---|---|
| PHP | `/opt/bitnami/php/bin/php`, `/opt/bitnami/php/sbin/php-fpm` |
| Site | `/opt/bitnami/wordpress` (newer stacks), `/opt/bitnami/apps/*/htdocs` (older) |
| Logs | `/opt/bitnami/apache/logs/`, `/opt/bitnami/nginx/logs/`, `/opt/bitnami/php/logs/` |
| Sessions | `/opt/bitnami/php/var/run/session` |
| Web user | `daemon` (only treated as a web user when `/opt/bitnami` exists) |

Lightsail's plain OS blueprints with a hand-installed stack use the usual
distro paths (`/var/log/httpd`, `/var/log/php-fpm`, `/var/lib/php/session` on
Amazon Linux; `/var/log/apache2`, `/var/lib/php/sessions` on Ubuntu), which are
covered too.

If PHP lives somewhere else entirely, point at it:

```sh
sudo sh php2shell-ioc.sh --php /opt/myphp/bin/php --root /srv/site --log /srv/site/logs/error.log
```

If a run finds no PHP, no logs and no application at all, it says so and exits
`1` instead of reporting "Clean". A run that inspected nothing proves nothing.

## Docker

```sh
# Run the scan inside the container, as root inside it
docker exec -i -u 0 CONTAINER sh -s < php2shell-ioc.sh

# Its logs (official images log to stdout, which Docker keeps outside the container)
docker logs CONTAINER 2>&1 | sh php2shell-ioc.sh --only logs --log -

# Since a date only
docker logs --since 2026-10-14T00:00:00 CONTAINER 2>&1 | sh php2shell-ioc.sh --only logs --log -
```

`-u 0` matters for images that run as a non-root user by default.

Over SSH, without copying the script to the server:

```sh
ssh server 'docker exec -i -u 0 CONTAINER sh -s' < php2shell-ioc.sh
ssh server 'docker logs CONTAINER 2>&1' | sh php2shell-ioc.sh --only logs --log -
```

### Docker Compose

```sh
docker compose exec -T -u 0 app sh -s < php2shell-ioc.sh
docker compose logs --no-log-prefix app | sh php2shell-ioc.sh --only logs --log -
```

## Kubernetes

```sh
kubectl exec -i -n NAMESPACE deploy/web -- sh -s < php2shell-ioc.sh
kubectl logs -n NAMESPACE deploy/web --all-containers --since=168h | sh php2shell-ioc.sh --only logs --log -
```

Pods replaced since the incident have lost their logs. `kubectl logs --previous`
gives you the last terminated container's logs, if that's still around.

## Sessions in Redis

Nextcloud and many Laravel deployments store PHP sessions in Redis. The check
needs `redis-cli`, which usually lives in the Redis container, not the app:

```sh
docker exec -i REDIS_CONTAINER sh -s -- --only sessions --redis 127.0.0.1:6379 < php2shell-ioc.sh
```

If Redis needs a password, pass it the way `redis-cli` expects, via the
environment, so it doesn't appear in the process list:

```sh
docker exec -i -e REDISCLI_AUTH="$REDIS_PASSWORD" REDIS_CONTAINER sh -s -- --only sessions --redis 127.0.0.1:6379 < php2shell-ioc.sh
```

The default key prefix is phpredis' `PHPREDIS_SESSION:`.

## Backups and snapshots

If you took a backup before upgrading, its logs predate the redeploy. Stream
them straight out of the archive without extracting anything:

```sh
tar -xOf backup.tar ./data/nextcloud.log | sh php2shell-ioc.sh --only logs --log -
```

## When the logs are gone: edge analytics

If you're behind a CDN or tunnel and your containers were redeployed, the
edge's request analytics may be the only record left. They don't show request
bodies or content types, but they do show the shape of an attempt: POSTs that
made the origin fail, in bursts, from the same clients.

For Cloudflare, the GraphQL Analytics API's `httpRequestsAdaptiveGroups`
dataset keeps about a week on every plan. A query for POSTs that got a 5xx
during a window (replace the zone tag and dates):

```graphql
query ($zone: String!) {
  viewer {
    zones(filter: { zoneTag: $zone }) {
      httpRequestsAdaptiveGroups(
        limit: 100
        orderBy: [count_DESC]
        filter: {
          datetime_geq: "2026-10-20T00:00:00Z"
          datetime_lt: "2026-10-21T14:00:00Z"
          requestSource: "eyeball"
          clientRequestHTTPMethodName: "POST"
          edgeResponseStatus_geq: 500
        }
      ) {
        count
        dimensions {
          clientRequestHTTPHost
          clientRequestPath
          edgeResponseStatus
          originResponseStatus
          clientIP
        }
      }
    }
  }
}
```

What's interesting: clusters of origin `502`/`520`, or of `500` on paths that
normally return `200`, especially to static files or pages that never take
POSTs. What's usually noise: scanners probing paths you don't have (404s),
`xmlrpc.php` and `wp-login.php` brute force, and your own monitoring.

The counts are sampled estimates. A single request can still show up, but
treat small numbers as "at least", not "exactly".
