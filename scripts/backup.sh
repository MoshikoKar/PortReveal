#!/usr/bin/env bash
# Backup Compose Postgres + appdata volume (+ production env) for Network Finder.
# Intended for the Linux Docker host. Schedule with cron, for example:
#   15 2 * * * cd /opt/network_finder && ./scripts/backup.sh >> data/logs/backup.log 2>&1
#
# Env overrides:
#   BACKUP_ROOT   destination root (default: ./backups)
#   KEEP_DAYS     delete sets older than this many days (default: 14)
#   COMPOSE_ENV   --env-file path (default: .env.production if present, else .env)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BACKUP_ROOT="${BACKUP_ROOT:-$ROOT/backups}"
KEEP_DAYS="${KEEP_DAYS:-14}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BACKUP_ROOT/$STAMP"
mkdir -p "$OUT"

COMPOSE=(docker compose)
if [[ -n "${COMPOSE_ENV:-}" ]]; then
  COMPOSE=(docker compose --env-file "$COMPOSE_ENV")
elif [[ -f .env.production ]]; then
  COMPOSE=(docker compose --env-file .env.production)
elif [[ -f .env ]]; then
  COMPOSE=(docker compose --env-file .env)
fi

echo "[backup] writing $OUT"

# Custom-format dump (pg_restore-friendly). DB must be healthy.
"${COMPOSE[@]}" exec -T db pg_dump -U "${POSTGRES_USER:-netfinder}" -d "${POSTGRES_DB:-netfinder}" -Fc \
  > "$OUT/postgres.dump"

# Web captures, logs, and optional legacy /data/.secret_key from the app volume.
if "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx app; then
  "${COMPOSE[@]}" exec -T app tar czf - -C /data . > "$OUT/appdata.tar.gz"
else
  # App stopped: mount the named volume read-only via a one-shot helper.
  VOL="$("${COMPOSE[@]}" volume ls -q | grep -E '_appdata$' | head -n1 || true)"
  if [[ -z "$VOL" ]]; then
    echo "[backup] error: app not running and no *_appdata volume found" >&2
    exit 1
  fi
  docker run --rm -v "$VOL:/data:ro" -v "$OUT:/backup" alpine:3.20 \
    tar czf /backup/appdata.tar.gz -C /data .
fi

# Env / secrets that must match the dump (APP_SECRET_KEY decrypts SMTP/LDAP).
if [[ -f .env.production ]]; then
  cp -a .env.production "$OUT/env.production"
elif [[ -f .env ]]; then
  cp -a .env "$OUT/env"
fi

git rev-parse HEAD > "$OUT/git-revision.txt" 2>/dev/null || true
{
  echo "created=$STAMP"
  echo "host=$(hostname 2>/dev/null || echo unknown)"
  echo "compose=${COMPOSE[*]}"
} > "$OUT/MANIFEST.txt"

# Optional local checksums for off-box transfer verification.
( cd "$OUT" && sha256sum postgres.dump appdata.tar.gz > SHA256SUMS 2>/dev/null ) || true

# Retention of local backup sets.
find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -mtime "+$KEEP_DAYS" -exec rm -rf {} +

echo "[backup] done: $OUT"
echo "[backup] copy $OUT off-box; see docs/runbook/runbook.md for restore drill and RPO/RTO"
