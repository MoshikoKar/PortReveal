# Network Finder operations runbook

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

### Linux Docker Compose — restore

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

### Windows host application — restore

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

## Failed migration

The application runs Alembic migrations before it accepts traffic. If startup
reports `DATABASE MIGRATION FAILED`:

1. Leave the app stopped. Do not run `alembic stamp`, edit the version table, or
   reset the production database.
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
   migration name, database revision, logs, and backup timestamp. Use a reviewed
   corrective migration, or restore the pre-upgrade backup and matching prior
   application revision; do not improvise a downgrade.
6. After recovery, verify health, sign-in, inventory counts, a read-only search,
   and one controlled scan before resuming schedules.

## Common recovery checks

- Scanner unavailable: verify nmap/Npcap privileges and the route to the target
  network; do not switch production to mock mode to conceal the outage.
- Scan stuck after restart: the app marks interrupted scans failed; start a new
  controlled scan after worker health is confirmed.
- Database unavailable: check Postgres health and disk space before restarting the
  app repeatedly.
- Windows after reboot: confirm an interactive user session, Docker Desktop,
  Task Scheduler history, the PID/log files, and `/api/health`.
