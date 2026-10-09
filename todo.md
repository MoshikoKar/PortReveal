# Project TODO (Audit Derived)

---

## 📊 Summary

- **Total findings**: 118
- **Open**: 16
- **Completed**: 102 (91 archived — see index below)
- **Severity distribution:** 🔴 Critical: 4 (1 open), 🟠 High: 32 (15 open), 🟡 Medium: 52 (0 open), 🟢 Low: 30 (0 open)
- **Audits synced:** `docs/audit-ux-flow-2026-10-08.md`, `docs/audit-ui-2026-10-08.md`, `docs/audit-performance-2026-10-08.md`, `docs/audit-ui-2026-10-09.md`, `docs/audit-database-schema-2026-10-09.md`, `docs/audit-ux-flow-2026-10-09.md`, `docs/audit-production-readiness-2026-10-09.md` (PR09-H2/H3 → existing DB09-H1/H2; PR09-H7 → existing UX09/UI09 opens; PR09-M8 verified done as DB09-M2; PR09-M4 dropped — staging out of scope)

---

## 🔴 Critical

### PR09-C2 — No external monitoring or alerting on health / scan failure

Status: Open

#### Subtasks

- [ ] Document external probing of readiness (after PR09-H8) plus alerts for degraded DB / container restarts in `README.md` or `docs/runbook.md`
- [ ] Document alerting for failed scheduled scans separately from inventory digests

---

## 🟠 High

### UX09-H1 — Sign-in from `/login` lands on NotFound

Status: Open

#### Subtasks

- [ ] In `frontend/src/App.tsx` `onLoggedIn`, when `returnTo` is null and pathname is not a known app route, `navigate('/', { replace: true })`

---

### UX09-H2 — Exclusions enable/disable toggle failures are silent

Status: Open

#### Subtasks

- [ ] In `frontend/src/pages/settings/Exclusions.tsx`, surface inline toggle `save` failures via `actionError` (or list banner), not only Modal `saveError`

---

### UX09-H3 — Scans active lists treat fetch errors as empty

Status: Open

#### Subtasks

- [ ] In `frontend/src/pages/Scans.tsx`, render `ErrorBox` + retry when `active.error` instead of Empty
- [ ] In `frontend/src/pages/Scans.tsx`, render `ErrorBox` + retry when `wcActive.error` instead of Empty

---

### UX09-H4 — ScanDialog networks load failure looks like “none configured”

Status: Open

#### Subtasks

- [ ] In `frontend/src/components/ScanDialog.tsx`, show `Loading` while networks are loading
- [ ] In `frontend/src/components/ScanDialog.tsx`, show `networks.error` and only show “No networks configured…” when `data.length === 0`

---

### UX09-H5 — Devices/Changes/Ports filter history uses replace (Search pushes)

Status: Open

#### Subtasks

- [ ] In `frontend/src/pages/Devices.tsx`, push history for discrete filter changes (keep replace only if debounced typing needs it)
- [ ] In `frontend/src/pages/Changes.tsx`, push history for discrete filter changes the same way
- [ ] In `frontend/src/pages/Ports.tsx`, push history for discrete filter/sort changes the same way

---

### UX09-H6 — Search refetch keeps stale results with no busy affordance

Status: Open

#### Subtasks

- [ ] In `frontend/src/pages/Search.tsx`, dim/overlay results and set `aria-busy` when `loading && results`
- [ ] In `frontend/src/pages/Search.tsx`, disable export/bulk actions while `loading`

---

### UI09-H1 — Scans / Web Capture lists show Empty while still loading

Status: Open

#### Subtasks

- [ ] In `frontend/src/pages/Scans.tsx`, gate active-scan Empty on `!active.data` with `Loading` or `SkeletonRows` before treating empty arrays as Empty
- [ ] In `frontend/src/pages/Scans.tsx`, gate WC active Empty on `!wcActive.data` the same way before showing “No Web Capture running or queued.”

---

### UI09-H2 — Lightbox lacks Modal-level focus management

Status: Open

#### Subtasks

- [ ] In `frontend/src/components/WebShots.tsx` `Lightbox`, add `aria-modal="true"` on the dialog root
- [ ] In `frontend/src/components/WebShots.tsx` `Lightbox`, trap Tab focus and move initial focus into the dialog on open; restore focus on close
- [ ] In `frontend/src/components/WebShots.tsx` `Lightbox`, fix the keys/scroll `useEffect` dependency array (include `index`, `onClose`, and related deps)

---

### DB09-H1 — Soft scan references without foreign keys

Status: Open

#### Subtasks

- [ ] In `backend/app/models.py`, add `ForeignKey("scans.id", ondelete="SET NULL")` on `Network.baseline_scan_id` and `Device.last_port_scan_id`
- [ ] Add an Alembic migration creating those FKs (SQLite batch-safe) and clearing dangling IDs before apply
- [ ] Verify `backend/app/core/retention.py` purge still leaves baselines/port-scan refs null (or rely on ON DELETE SET NULL) and add a regression test

---

### DB09-H2 — Unbounded pending-notification event load

Status: Open

#### Subtasks

- [ ] In `backend/app/core/notify.py` `_pending_all`, push allowed `event_type IN (...)` into the SQL filter
- [ ] In `backend/app/core/notify.py` `_pending_all`, add a safety `LIMIT` or chunked fetch/send for pending rows

---

### PR09-H1 — CI does not build, lint, or run the test suite

Status: Open

#### Subtasks

- [ ] Add a GitHub Actions job that runs `pytest` on pull_request and push to `main`
- [ ] Add CI steps for Ruff and frontend `tsc`/eslint (match `package.json` `lint`)
- [ ] Add a CI step for `npm run build` (or Docker image build)

---

### PR09-H4 — Production COOKIE_SECURE defaults to false without TLS

Status: Open

#### Subtasks

- [ ] In `backend/app/config.py`, require `COOKIE_SECURE=true` when `APP_ENV=production` unless an explicit allow-HTTP override is set
- [ ] Update `.env.production.example` comments/defaults for HTTPS termination and `COOKIE_SECURE`

---

### PR09-H5 — OpenAPI docs always exposed unauthenticated

Status: Open

#### Subtasks

- [ ] In `backend/app/main.py`, disable `docs_url` / `openapi_url` when `app_env == "production"` (or gate behind admin auth)

---

### PR09-H6 — No documented/tested deployment rollback path

Status: Open

#### Subtasks

- [ ] Document release image tagging and rollback steps in `README.md` Upgrade sections
- [ ] Document Alembic downgrade / migration rollback policy for failed upgrades in `README.md` or `docs/runbook.md`

---

### PR09-H8 — `/api/health` returns HTTP 200 when database is degraded

Status: Open

#### Subtasks

- [ ] In `backend/app/api/system.py` `health()`, return non-2xx (e.g. 503) when DB check fails, or split `/live` vs `/ready`
- [ ] Update `docker/Dockerfile` HEALTHCHECK to fail when readiness is not ok

---

## 🟡 Medium

### PR09-M1 — Single app process is a deliberate SPOF

Status: Completed (2026-10-09)

#### Subtasks

- [x] Document single-process SPOF / HA non-goal clearly in `README.md`
- [x] Add or extend a test covering in-flight scan recovery after process restart

---

### PR09-M2 — No Compose resource limits or capacity targets

Status: Completed (2026-10-09)

#### Subtasks

- [x] Add memory/CPU limits for `app` (and `db` if appropriate) in `docker-compose.yml`
- [x] Document expected host sizing for full-port + web-capture workloads in `README.md`

---

### PR09-M3 — APP_SECRET_KEY may be empty in production

Status: Completed (2026-10-09)

#### Subtasks

- [x] Fail fast at boot when `APP_ENV=production` and `APP_SECRET_KEY` is empty (`backend/app/config.py` or lifespan)
- [x] Update `.env.production.example` so `APP_SECRET_KEY` is required (not blank)

---

### PR09-M5 — No metrics, tracing, or correlation IDs beyond slow-request logs

Status: Completed (2026-10-09)

#### Subtasks

- [x] Export basic counters (HTTP status, scan duration/outcome, queue depth) from the backend

---

### PR09-M6 — No frontend or end-to-end automated tests

Status: Completed (2026-10-09)

#### Subtasks

- [x] Add a smoke e2e (or Playwright) covering login → dashboard → devices list

---

### PR09-M7 — Privacy/compliance posture is informal

Status: Completed (2026-10-09)

#### Subtasks

- [x] Document data categories (inventory, accounts, screenshots), retention knobs, and access/offboarding in `README.md` or `docs/`

---

### PR09-M9 — Windows production stop force-kills the process

Status: Completed (2026-10-09)

#### Subtasks

- [x] In `scripts/run.ps1`, attempt graceful stop before `Stop-Process -Force`
- [x] Document that `-Stop` may hard-kill and relies on in-flight scan recovery in `README.md`

---

## 🟢 Low

### PR09-L1 — No LICENSE file

Status: Completed (2026-10-09)

#### Subtasks

- [x] Add an explicit `LICENSE` or INTERNAL-USE notice (and align `README.md` License section)

---

### PR09-L2 — Log format is plain text, not structured JSON

Status: Completed (2026-10-09)

#### Subtasks

- [x] In `backend/app/logging_setup.py`, add optional JSON formatting behind `LOG_FORMAT=json`

---

### PR09-L3 — Windows production depends on interactive Task Scheduler session

Status: Completed (2026-10-09)

#### Subtasks

- [x] Document Windows Task Scheduler failure modes and prefer Linux Docker host for unattended uptime in `README.md`

---

### PR09-L4 — No dedicated on-call/runbook beyond README troubleshooting

Status: Completed (2026-10-09)

#### Subtasks

- [x] Add `docs/runbook.md` with restore, secret rotation, and failed-migration steps

---

## ✅ Completed (archived)

Completed findings live in `todo-archive/`. This file keeps an index only — not full history.

| Archive file | Period | Entries | Link |
|--------------|--------|---------|------|
| completed-summary.md | summary | 91 | [open](todo-archive/completed-summary.md) |

**Total completed:** 91

---

*Open tasks derived from audit/review reports in `docs/`. Use `12-todo-sync-orchestrator` to refresh. Completed history: `todo-archive/`.*
