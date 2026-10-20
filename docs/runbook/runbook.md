# PortReveal operations runbook

This runbook covers production incidents for the Linux Docker Compose deployment
and the Windows host-nmap deployment. Commands assume the repository root and the
default database/user name `netfinder`; substitute values from the production env
file where they differ.

## First five minutes

1. Stop configuration changes and record when the incident began.
2. Check the UI and `GET /api/health`; a degraded database is an application
   outage even if the process is still listening.
3. Preserve logs before restarting:
   - Linux: `docker compose logs --since 2h app db`
   - Windows: `data/logs/production.log` and `data/logs/app.log`
4. Check storage space, Postgres health, and whether a scan or web capture was
   running. Restart once only after collecting evidence.
5. Escalate immediately for suspected credential exposure, unexplained inventory
   deletion, repeated migration failure, or a restore that does not validate.

Treat loss of the UI/database or incorrect inventory as high severity. Treat a
single failed scan as medium unless it affects a critical monitored network.

## Backup set and restore

A recoverable backup set contains all of the following from the same maintenance
window:

- a PostgreSQL `pg_dump` (custom format `-Fc` from `scripts/backup.sh` /
  `scripts/backup.ps1`, or equivalent);
- the app data directory/volume (web-capture files, logs, optional
  `/data/.secret_key`);
- the production env file or secret-manager version, including `APP_SECRET_KEY`
  (required in production; without it the restored SMTP/LDAP passwords cannot be
  decrypted); and
- the deployed Git revision or immutable image tag.

### Schedule, RPO, and RTO

| Item | Target |
|---|---|
| Cadence | Daily (scripts above; copy each `backups/<stamp>/` set off-box) |
| Local retention | 14 days (`KEEP_DAYS`; off-box retention is operator-owned) |
| RPO | ≤ 24 hours with a successful daily run |
| RTO | ≤ 2 hours for a practiced restore onto a spare host |
| Restore drill | Quarterly on an isolated host; never overwrite the only production copy |

Take a set with `./scripts/backup.sh` (Linux Compose) or `.\scripts\backup.ps1`
(Windows). Verify `SHA256SUMS` (Linux) or file sizes before off-box copy. Never
test a restore over the only production copy.

### Linux Docker Compose - restore

1. Enter a maintenance window and stop application writes: `docker compose stop app`.
2. Take a fresh safety dump before replacing anything:
   `docker compose exec -T db pg_dump -U netfinder -d netfinder -Fc > pre-restore.dump`.
3. Restore app data from the **same** backup stamp (do not mix times).
   `docker compose run … app` reuses the Compose `appdata` volume on `/data`:

   ```bash
   docker compose run --rm --no-deps app sh -c 'find /data -mindepth 1 -delete'
   docker compose run --rm --no-deps -v "$PWD/backups/STAMP:/backup:ro" \
     app tar xzf /backup/appdata.tar.gz -C /data
   ```

4. Recreate the database, then restore the selected custom-format dump:

   ```bash
   docker compose exec -T db dropdb -U netfinder --if-exists netfinder
   docker compose exec -T db createdb -U netfinder -O netfinder netfinder
   docker compose exec -T db pg_restore -U netfinder -d netfinder --exit-on-error --no-owner < backups/STAMP/postgres.dump
   ```

5. Restore `.env.production` from the same stamp (or re-apply `APP_SECRET_KEY` from
   the secret manager). Start the app at the recorded Git revision:
   `docker compose up -d --build app`.
6. Confirm `docker compose ps`, review `docker compose logs app`, check
   `/api/health`, sign in, and verify networks, recent scans, and screenshots.

For a plain SQL or gzipped SQL dump, use `psql -v ON_ERROR_STOP=1` instead of
`pg_restore` (for example, `gzip -dc BACKUP.sql.gz | docker compose exec -T db
psql -v ON_ERROR_STOP=1 -U netfinder -d netfinder`).

### Windows host application - restore

1. Stop the host app while leaving Postgres running:
   `.\scripts\run.ps1 -Mode production -Stop`.
2. Copy the current `data`, `.env.production`, and Git revision aside as a safety
   set (or run `.\scripts\backup.ps1` first).
3. Recreate and restore the Compose database with
   `docker compose --env-file .env.production exec -T db` using the same
   `dropdb`/`createdb`/`pg_restore` sequence as Linux, reading
   `backups\STAMP\postgres.dump`.
4. Replace `data` from the matching archive:
   `tar -xzf backups\STAMP\appdata.tar.gz -C data` (after moving the old `data`
   aside). Restore `.env.production` and check out the recorded revision.
5. Start in the foreground so migration errors remain visible:
   `.\scripts\run.ps1 -Mode production -SkipBuild`.
6. Validate health, sign-in, inventory, and screenshots before returning to
   background/Task Scheduler operation.

### Quarterly restore drill

1. Provision a disposable host (or second Compose project name) with the same
   Compose files; do not point it at production volumes.
2. Copy one off-box backup stamp onto that host.
3. Follow the restore section above; time the wall clock (RTO check).
4. Sign in, open a known network, open a web-capture screenshot, and confirm
   SMTP/LDAP settings still decrypt (or re-enter if the drill used a rotated key).
5. Record date, backup stamp, measured RTO, and pass/fail in the ops log; destroy
   the disposable environment.

## Secret rotation

### Application secret

`APP_SECRET_KEY` encrypts stored SMTP and LDAP passwords. Changing it does not
re-encrypt existing values; they become unreadable until an administrator saves
those credentials again.

1. Back up Postgres, app data, and the current secret. Record who approved the
   rotation; never put the old or new value in logs or tickets.
2. Generate a new random value (for example, `openssl rand -hex 32`) and update
   `.env`/`.env.production` or the secret manager.
3. Restart the app.
4. In Settings, re-enter and save the SMTP and LDAP passwords, then test both
   integrations. Check logs for decryption errors.
5. Revoke/delete the old value only after validation. Keep backup copies encrypted
   and access-controlled according to the organization's retention policy.

Production refuses to start without `APP_SECRET_KEY`. Installs that ran without it
before used a generated key in `data/.secret_key` (or the Docker app-data volume):
put that file's contents into `APP_SECRET_KEY` instead of generating a new value,
otherwise the stored SMTP/LDAP passwords become unreadable.

### PostgreSQL password

Change the database role password first from a trusted administrative session,
then update `POSTGRES_PASSWORD` in the production secret/env file and restart the
app. Confirm `/api/health` before closing the maintenance window. Roll back both
the role and env value together if the application cannot reconnect.

## Deployment rollback

Supported rollback is **retarget the previous application revision (or Docker image
tag) and, when the schema changed, restore the pre-upgrade backup set**. Image
tagging and the Windows/Linux upgrade checklists live in `README.md` (Upgrade
sections). Record the Git SHA (and `portreveal:<sha>` / `portreveal:previous`
tags on Linux) with every backup stamp.

| Situation | Action |
|---|---|
| App bug; Alembic revision unchanged | Retag/`checkout` the prior revision or `portreveal:previous`, restart; no DB restore |
| Migration applied or failed mid-upgrade | Restore pre-upgrade Postgres + appdata from the same stamp, then start the prior revision/image |
| Unsure whether schema changed | Treat as migration case: restore backup + prior revision |

After rollback: `GET /api/health` (JSON `status` ok), sign-in, inventory smoke check,
then one controlled scan before re-enabling schedules.

### Alembic downgrade policy

Migration files may define `downgrade()` for local/dev use. **Production rollback
must not use `alembic downgrade`.** Downgrades are not rehearsed as a release path,
can drop or reshape data, and leave the database out of sync with the image that
was running. Prefer restore from the pre-upgrade dump to a matching prior revision.
Forward-fix only: a reviewed corrective migration on a restored copy, then cut
over. Practice the restore+retag path on a disposable host or database copy before
relying on it in an incident.

## Failed migration

The application runs Alembic migrations before it accepts traffic. If startup
reports `DATABASE MIGRATION FAILED`:

1. Leave the app stopped. Do not run `alembic stamp`, edit the version table,
   `alembic downgrade`, or reset the production database.
2. Preserve the complete app/Postgres logs and take a database dump if Postgres is
   reachable.
3. Confirm the app is using the intended production database and revision. Check
   database connectivity, credentials, free disk space, and the Alembic current
   revision versus the code's head revision.
4. Fix environmental failures, then retry once:
   - Linux: `docker compose run --rm app python -m app.cli migrate`
   - Windows: run `.\scripts\run.ps1 -Mode production -SkipBuild` in the
     foreground. Do not use the generic `npm run db:migrate` unless
     `DATABASE_URL` explicitly points at production Postgres.
5. If a migration itself failed or partially applied, stop. Escalate with the
   migration name, database revision, logs, and backup timestamp. Recover with a
   reviewed corrective migration on a copy, or restore the pre-upgrade backup and
   matching prior application revision/image (see Deployment rollback above).
6. After recovery, verify health, sign-in, inventory counts, a read-only search,
   and one controlled scan before resuming schedules.

## Monitoring and alerting

PortReveal does not ship paging or an alert manager. Product email digests
(Settings → Notifications / watches) report inventory and watch matches; they are
**not** a substitute for external ops monitoring. Point an outside probe or
Prometheus/Alertmanager (or equivalent) at the host, and page on the conditions
below.

### Liveness, readiness and degraded database

Two unauthenticated probes answer different questions:

| Probe | Question | Touches the DB | Failure means | Use it for |
|---|---|---|---|---|
| `GET /api/live` | Is the process up and serving HTTP? | No | Process hung or dead | Restart decisions (orchestrator liveness probe, process supervisor) |
| `GET /api/health` | Can the app serve users? | Yes | Database unreachable (HTTP 503) | Readiness / load-balancer membership, paging on outages, the image `HEALTHCHECK` |

Do not restart the app on a failing `/api/health` alone: when the database is
down, a restart does not help and `/api/live` stays `200`. Page on readiness,
restart on liveness. `/api/live` returns `{"status": "ok", "version": "…"}`.

Probe `GET /api/health` for readiness. Example body:

```json
{"status": "ok", "database": "ok", "version": "…"}
```

When the database check fails, the endpoint returns **HTTP 503** with
`"status": "degraded"` and `"database": "error"`. `curl -sf` and the image
`HEALTHCHECK` both fail on that status. Optionally still assert the JSON body:

```bash
# Linux / Git Bash - fail unless HTTP success and status is ok
curl -sf "http://HOST:PORT/api/health" | python -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('status')=='ok' else 1)"
```

```powershell
# Windows PowerShell
$r = Invoke-WebRequest "http://HOST:PORT/api/health"
if ($r.StatusCode -ne 200) { throw "health HTTP $($r.StatusCode)" }
$h = $r.Content | ConvertFrom-Json
if ($h.status -ne 'ok') { throw "health degraded: $($h | ConvertTo-Json -Compress)" }
```

Optional scrape of authenticated `GET /api/metrics` (API token) is documented in
`README.md` (Availability and capacity). Use it for trends; keep the unauthenticated
probes for “is the process up?” (`/api/live`) and “is the app usable?” (`/api/health`).
HTTP metrics are labelled by method, route template (`/api/devices/{uuid}`) and
status, so latency and error rate can be charted per endpoint.

Every API response carries an `X-Request-Id` header, and JSON logs
(`LOG_FORMAT=json`) carry the same `request_id`. When a user reports an error
with a reference id, search the logs for it.

### Container and process restarts

Alert when the app or database keeps coming back up after crashes:

| Deploy | Signal |
|---|---|
| Linux Compose | `docker compose ps` / `docker events` restart storms; Compose `restart: unless-stopped` masking a crash loop; Docker `HEALTHCHECK` failing repeatedly on `app` |
| Windows host | Task Scheduler task failures, missing `data/portreveal-prod.pid`, or unexpected process exit in `data/logs/production.log` |

A single restart after a planned upgrade is normal. Page on repeated restarts in a
short window or on health staying degraded after restart.

### Failed scheduled scans (separate from digests)

Inventory digests and watch emails mean “something changed on the network.” Ops
alerts for **failed scheduled scans** mean “the nightly (or configured) inventory
job did not complete.” Configure them separately so a quiet network does not hide a
broken scanner, and a busy digest does not look like an outage.

Practical signals:

- Prometheus: rising `nf_scans_finished_total{status="failed"}` (from `/api/metrics`)
  while the schedule is enabled - especially after the configured schedule time.
- Authenticated `GET /api/system/status`: `scans.last_failed` newer than
  `scans.last_successful` / `scans.last_completed` when a run was due
  (`scans.next_scheduled` / schedule settings).
- App logs: `scheduled scan` lines followed by scan failure or scanner-unavailable
  errors around the schedule window.

Do not rely on the daily digest SMTP path alone for this: digests only fire when
there are pending notify events, so a failed scan with no inventory changes can
produce no email.

## Geo mismatch (DB-IP Lite)

After each scan, devices on networks with **expected countries** (Settings → Networks)
are checked: published names (hostname, DNS name, TLS CN/SAN, HTTP redirect hosts)
are resolved to public A/AAAA records, those IPs (and a public `current_ip` if any)
are geolocated locally, and a country outside the list raises a `geo_mismatch`
event. Private, loopback, link-local and CGNAT addresses are never geolocated.
When no public IP exists the device shows **geo not checked**, not OK.

### Database files

Default source is **DB-IP Lite Country** and **DB-IP Lite ASN** (MMDB, CC BY 4.0,
no account or API key). Files live under the app data directory:

- `data/geo/dbip-country-lite.mmdb`
- `data/geo/dbip-asn-lite.mmdb`

(Compose: the `appdata` volume mounted at `/data`, so `/data/geo/…`.)

The app downloads them on first need and refreshes about monthly (same inbound-GET
pattern as vulnerability feeds). Settings → Geo shows last update and the
attribution string **IP Geolocation by DB-IP — https://db-ip.com/ (CC BY 4.0)**.
Offline mode skips downloads; place the MMDB files yourself.

Optional **MaxMind GeoLite2 Country**: set a path in Settings → Geo to an
operator-supplied file (relative to the data dir or absolute). MaxMind is never
required and is never downloaded with credentials from this repo.

DNS and MMDB answers are cached (default 24h). Unchanged names are not re-resolved
until the cache expires.

CDN/anycast ASNs (editable list) still flag mismatches, at lower severity, labelled
“behind CDN – location reflects CDN edge, not origin.”
