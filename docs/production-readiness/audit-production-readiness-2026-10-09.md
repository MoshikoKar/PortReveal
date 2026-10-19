# Production Readiness Audit Report

## Executive Summary

| Field | Value |
|-------|--------|
| **Audit topic/scope** | Production readiness (architecture, security, reliability, observability, operations, data/compliance, testing, performance) |
| **Date of audit** | 2026-10-09 |
| **Overall score (1-10)** | 6.0 |
| **Production readiness maturity level** | Early Production |
| **Severity distribution** | Critical: 2, High: 8, Medium: 9, Low: 4 |
| **Total number of findings** | 23 |

Network Finder is a coherent single-node inventory/change-detection product with strong session auth, dual Windows-host / Linux-Docker deploy paths, Alembic migrations, local pytest coverage, and an unusually thorough operator README. It is suitable for **controlled early production** on a trusted LAN when an operator owns backups and watches logs, but it is **not** yet ops-hardened for unattended production: backups are manual and untested, there is no external monitoring/alerting, `/api/health` stays HTTP 200 when the database is degraded (so image HEALTHCHECKs and naive probes miss outages), CI does not run the test suite, and a few integrity/scale gaps remain open from the 2026-10-09 database audit.

---

## Audit Scope and Methodology

- **Scope:** FastAPI + React monolith (`backend/app`, `frontend/src`), PostgreSQL (prod) / SQLite (dev), Docker Compose (`docker-compose.yml`, `docker-compose.override.yml`, `docker/Dockerfile`), Windows production runner (`scripts/run.ps1`), CI (`.github/workflows/`), config (`.env.example`, `.env.production.example`, `backend/app/config.py`), observability (logging, `/api/health`), tests (`backend/tests/`), and operational docs (`README.md`). Cross-checked prior audits: `docs/audit-performance-2026-10-08.md`, `docs/audit-database-schema-2026-10-09.md`, `docs/audit-ux-flow-2026-10-09.md`, `docs/audit-ui-2026-10-09.md`, and open items in `todo.md`.
- **Method:** Graphify-oriented discovery, then evidence review of real files/config, cross-checked with parallel explore passes on deploy/ops, security/data, and testing/UX. No source or config modifications. Findings cite project-relative paths only. Several 2026-10-08 performance findings are **verified fixed** in current code and are not re-filed (device list SQL pagination, scoped compare loads, watch chunking, React.lazy, LDAP `finally` unbind, retention commit-then-FS, pool recycle, CheckConstraints + pending index via migration `0007`).
- **Rules referenced:** Skill `09-production-readiness-audit` (CHECKLIST, SEVERITY_GUIDELINES, REPORT_TEMPLATE); shared conventions for severity/scoring; overlap with architecture, security, observability, testing, and database audit expectations.

---

## Readiness Scores by Domain

| Domain | Score (1-10) | Rationale |
|--------|--------------|-----------|
| Architecture & Infrastructure | 7 | Clear monolith + Compose/Windows host models; intentional single-process design; no resource limits or multi-env isolation beyond env files. |
| Security & Access Control | 7 | Argon2, hashed sessions/tokens, CSRF, login rate limit, admin/viewer roles, LDAP, security headers; HTTPS/cookie defaults and open API docs weaken edge posture. |
| Data, Database & Migrations | 6.5 | Linear Alembic + schema-drift CI; retention; soft scan FKs and unbounded digest load still open; backups manual only. |
| Reliability, Resilience & Failover | 5.5 | Lifespan shutdown and scan recovery are solid; HEALTHCHECK/probes can miss DB outages; Windows stop force-kills; single-process SPOF. |
| Observability & Monitoring | 4 | Rotating file logs + slow-request warnings + `/api/health` body; no metrics/traces/alerts; health HTTP status does not reflect DB failure. |
| Deployment, CI/CD & Operations | 5 | Repeatable scripts and Compose; CI is schema-only; no automated CD, rollback drill, or backup job. |
| Testing, Quality & Release Practices | 7 | Broad backend pytest suite locally; no CI test job; no frontend/e2e suite. |
| Performance & Capacity | 6.5 | Major list/compare hotspots fixed; notify backlog and lack of SLOs remain; no capacity baselines. |
| Compliance, Privacy & Data Handling | 5 | Inventory/screenshots are sensitive internal data; retention exists; no formal privacy/DSAR/processor inventory. |
| UX, Supportability & Operational Documentation | 7 | Excellent README/troubleshooting; open UX critical/high items can still cause operator data loss or silent errors. |

---

## Findings

### Critical

| # | Description | Location (file path, line/component) | Impact | Recommendation |
|---|-------------|--------------------------------------|--------|----------------|
| C1 | **No automated backup or tested restore for the primary production datastore.** README documents optional manual `pg_dump` / env copy (`README.md` ~L268-279) but there is no scheduled backup job, retention for dumps, documented restore drill, or coverage for the `appdata` `/data` volume (web captures, optional `.secret_key`). Compose persists `pgdata` / `appdata` (`docker-compose.yml` ~L83-85) with no backup sidecar. | `README.md` (Backup section); `docker-compose.yml` volumes `pgdata`, `appdata`; no backup scripts under `scripts/` | Combined | Schedule encrypted `pg_dump` **and** `/data` (captures + secret key file) off-box; document and periodically test restore into a disposable Postgres; record RPO/RTO. |
| C2 | **No external monitoring or alerting on service health / scan failure.** In-app health exists (`GET /api/health` in `backend/app/api/system.py` ~L26-29; Docker `HEALTHCHECK` in `docker/Dockerfile` ~L77-78) and logs rotate to `data/logs/app.log` (`backend/app/logging_setup.py`), but nothing pages an operator when the process dies, DB degrades, or scheduled scans fail. Product “alerts” are inventory watches/email digests, not ops monitoring. Compounded by H8 (probes that only check HTTP success will not see DB failure). | `backend/app/api/system.py` `health`; `docker/Dockerfile` HEALTHCHECK; `backend/app/logging_setup.py`; absence of metrics/alert config in repo | Combined | Fix health semantics (H8); probe JSON `status` (or non-2xx); alert on degraded DB, container restart loops, and failed scheduled scans; keep digests separate from ops alerts. |

### High

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| H1 | **CI does not build, lint, or run the test suite.** The only workflow is Alembic upgrade + `alembic check` (`.github/workflows/schema-drift.yml`). `package.json` defines `npm test` / `npm run lint` / `npm run build`, but they are not gated on PR/push. | `.github/workflows/schema-drift.yml`; `package.json` scripts `test`, `lint`, `build` | Technical | Add a CI job: Python deps + pytest, Ruff, frontend `tsc`/eslint, and `npm run build` (or Docker build) on PR/`main`. |
| H2 | **Soft scan references without FKs (still open).** `Network.baseline_scan_id` and `Device.last_port_scan_id` remain plain integers; retention deletes scans without clearing them, so baselines/port-diff scope can dangle. Tracked as `DB09-H1` in `todo.md`. | `backend/app/models.py` ~L177, ~L216; `backend/app/core/retention.py` `purge_expired` (~L54); `todo.md` DB09-H1 | Combined | Add FKs `ON DELETE SET NULL` + migration; regression test with retention. |
| H3 | **Daily digest still loads all pending notify events unbounded, then filters in Python.** Index `ix_events_pending` exists (migration `0007`), but `_pending_all` still `.all()` without `event_type` SQL filter or `LIMIT`. Tracked as `DB09-H2`. | `backend/app/core/notify.py` `_pending_all` ~L365-371; `todo.md` DB09-H2 | Technical | Push `event_type IN (...)` into SQL; chunk/LIMIT pending sends. |
| H4 | **Production cookie Secure flag defaults to false; Compose publishes the app on the host network / published port without TLS.** HTTPS is documented as an external reverse-proxy concern (`README.md` ~L261-262; `.env.production.example` `COOKIE_SECURE=false`). Misconfiguration leaves session/CSRF cookies sendable over HTTP on the LAN. | `backend/app/config.py` `cookie_secure` default False (~L60); `docker-compose.yml` `COOKIE_SECURE` default `false` (~L71); `Dockerfile` binds `0.0.0.0` (~L81) | Combined | Require `COOKIE_SECURE=true` when `APP_ENV=production` unless an explicit allow-HTTP override is set; document mandatory TLS termination for any non-localhost clients. |
| H5 | **OpenAPI UI and schema are always exposed unauthenticated.** `docs_url="/api/docs"` and `openapi_url="/api/openapi.json"` are enabled for every environment (`backend/app/main.py` ~L79-80), aiding reconnaissance on a reachable host. | `backend/app/main.py` FastAPI constructor | Technical | Disable docs/openapi when `app_env == "production"` (or gate behind admin auth). |
| H6 | **No documented/tested deployment rollback path for failed upgrades.** Upgrade instructions are `git pull` + rebuild/restart (`README.md` ~L223-224, ~L259). Migrations auto-run at startup (`backend/app/main.py` lifespan ~L57-61). There is no pinned previous image tag strategy, migration downgrade playbook, or rollback verification. | `README.md` Upgrade sections; `backend/app/main.py` `upgrade()`; `docker-compose.yml` `image: network-finder:latest` | Combined | Tag release images; document rollback (previous image + whether Alembic downgrade is supported); practice on a staging DB copy. |
| H7 | **Operator UX defects that can lose settings or hide failures remain open.** `todo.md` still lists Critical `UX09-C1` (settings discard on nav) and High items for silent toggle/scan-list errors (`UX09-H2`-`H4`, `UI09-H1`). These are not security holes but undermine safe day-2 operations. | `todo.md` UX09-C1, UX09-H2-H4, UI09-H1; `docs/audit-ux-flow-2026-10-09.md` | User | Clear Phase-1 UX blockers before wider operator rollout (dirty-form guard; ErrorBox on Scans/Exclusions). |
| H8 | **`/api/health` returns HTTP 200 when the database is degraded**, so Docker `HEALTHCHECK` and URL-only monitors treat a DB outage as healthy. Body sets `"status": "degraded"` / `"database": "error"` but status code stays 200 (`system.py` ~L27-29). Image HEALTHCHECK only opens the URL (`docker/Dockerfile` ~L77-78). | `backend/app/api/system.py` `health` ~L26-29; `docker/Dockerfile` HEALTHCHECK ~L77-78 | Combined | Return non-2xx (e.g. 503) when DB check fails, or split `/live` vs `/ready`; update HEALTHCHECK/monitor to assert readiness. |

### Medium

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| M1 | **Single app process is a deliberate SPOF** (queue + scheduler in-process). Documented in `docker/Dockerfile` ~L80-81 and README (“One app process only”). Restart policy helps (`restart: unless-stopped`), but a crash mid-scan relies on “in-flight marked failed” recovery (`README.md` troubleshooting). | `docker/Dockerfile` CMD comment; `docker-compose.yml` `restart`; `backend/app/main.py` lifespan | Technical | Accept for current scale with monitoring (C2); or document HA non-goal and ensure crash recovery tests cover queued scans. |
| M2 | **No Compose/Kubernetes resource limits or capacity targets.** `docker-compose.yml` has no `mem_limit`/`cpus`/`deploy.resources`. Pool sizing is documented in README (~L180-184) and coded in `backend/app/db.py` (~L49-52, ~L78-84), but host headroom for nmap/Playwright/ffmpeg is unspecified. | `docker-compose.yml`; `backend/app/db.py`; README Database section | Technical | Set memory/CPU limits appropriate to scan concurrency; document expected host sizing for full-port + web-capture workloads. |
| M3 | **`APP_SECRET_KEY` may be empty in production; key is auto-generated into the data volume.** Works for a single volume lifecycle but complicates restore to a new volume (SMTP/LDAP ciphertext becomes undecryptable - logged in `security.py` ~L72). `.env.production.example` allows blank (~L23-25). | `backend/app/security.py` `_fernet` ~L42-57; `.env.production.example` | Combined | Fail fast in production if `APP_SECRET_KEY` is unset; store the key in the same backup set as `pg_dump`. |
| M4 | **No staging / pre-prod environment definition.** Dev uses SQLite + mock scanner; prod uses Postgres + nmap. No compose overlay or docs for a staging Postgres with anonymized inventory. | README env table; absence of staging compose/docs | Business | Add a staging profile (Postgres + mock or limited CIDR) for migration/upgrade rehearsal. |
| M5 | **No metrics, tracing, or correlation IDs beyond slow-request logs.** `slow_request_ms` + `Server-Timing` (`backend/app/main.py` ~L97-114) and text logs exist; no Prometheus/OTel/statsd. | `backend/app/main.py` `request_timing`; `backend/app/config.py` `slow_request_ms` | Technical | Export basic counters (HTTP status, scan duration/outcome, queue depth) even if only scraped locally. |
| M6 | **No frontend or end-to-end automated tests.** Backend has ~25 `backend/tests/test_*.py` modules; frontend has no vitest/playwright suite; quality gate is local `npm test` (pytest only). | `package.json` `test` script; `backend/tests/`; `frontend/` (no test runner config) | Technical | Add smoke e2e for login → dashboard → devices list; keep unit tests for critical React flows if e2e is thin. |
| M7 | **Privacy/compliance posture is informal.** Product stores IPs, MACs, hostnames, optional LDAP identities, audit logs, and web-capture screenshots. Retention defaults exist (`backend/app/core/retention.py`, README ~L310) and export/import is admin-gated, but there is no data-classification note, DSAR/deletion runbook beyond retention, or processor list (SMTP/LDAP). | `backend/app/core/retention.py`; `backend/app/core/data_transfer.py`; README Behaviour notes | Business | Document data categories, retention knobs, and who may access the UI; define delete/export steps for operator offboarding. |
| M8 | **Import path still couples filesystem wipe to the long inventory transaction** (database audit M2; verify if still present). Prior DB audit flagged `_wipe_inventory` FS deletes inside the open import txn. | `docs/audit-database-schema-2026-10-09.md` M2; `backend/app/core/data_transfer.py` | Technical | Align import with retention: commit DB wipe, then FS cleanup (or post-commit orphan pass). |
| M9 | **Windows production stop force-kills the process**, skipping FastAPI lifespan graceful shutdown (scheduler / scan / web-capture stop). `scripts/run.ps1` uses `Stop-Process -Force` (~L150). | `scripts/run.ps1` ~L147-151; contrast `backend/app/main.py` lifespan ~L73-76 | Technical | Prefer Ctrl+Break / graceful signal where possible; document that `-Stop` is hard kill and may leave in-flight scans to recovery-on-restart. |

### Low

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| L1 | **No LICENSE file**; README states proprietary by default (`README.md` ~L376-377). Fine if intentional; unclear for contributors. | `README.md` License section | Business | Add an explicit LICENSE or INTERNAL-USE notice. |
| L2 | **Log format is plain text, not structured JSON**, which slows log shipping/parsing. | `backend/app/logging_setup.py` ~L17 | Technical | Optional JSON formatter behind `LOG_FORMAT=json` for production. |
| L3 | **Windows production path depends on Task Scheduler + Docker Desktop + interactive user session** (README ~L226-237). Operationally workable but fragile vs a service account / always-on host; compounded by hard stop (M9). | `README.md` Task Scheduler; `scripts/run.ps1` | Technical | Document failure modes; prefer Linux Docker host where possible for unattended uptime. |
| L4 | **No dedicated on-call/runbook beyond README troubleshooting.** Troubleshooting table is strong (`README.md` ~L347-366) but lacks severity/escalation, backup restore steps, and “scan stuck” playbooks as a separate ops doc. | `README.md` Troubleshooting | User | Extract a short `docs/runbook.md` with restore, secret rotation, and failed-migration steps. |

---

## Strengths (observed)

- Dual production models (Windows host nmap + Compose Postgres; Linux host networking Compose) documented with concrete commands (`README.md`).
- Auth baseline: Argon2 passwords, hashed session/API tokens, CSRF on unsafe methods, login rate limiting, admin/viewer roles, optional LDAP with connection cleanup (`backend/app/auth/deps.py`, `auth.py`, `ldap_auth.py`, `security.py`).
- Security headers and API `Cache-Control: no-store` (`backend/app/main.py` ~L117-131); secrets from env / `/run/secrets` (`config.py`); `.env*` gitignored with examples allowed.
- Dev seed cannot run in production (`seed.py` gates on `is_dev`); first-admin setup is one-shot (`setup.py`).
- Schema: Alembic chain through `0007` (closed-value CHECKs + pending index); schema-drift workflow; startup migrations; PostgreSQL pool pre-ping/timeout/recycle (`db.py`).
- Reliability patterns: lifespan stops workers; Docker HEALTHCHECK; partial scans do not wipe inventory (README); retention commits before FS cleanup (`retention.py`).
- Testing: substantial backend pytest coverage for change detection, presence, search, intel, web capture, data transfer, LDAP, DB.
- Prior audit remediation: device list SQL paging, scoped compare loads, watch evaluation chunking, React.lazy routes, LDAP unbind, pool recycle - verified in current sources.

---

## Task Consolidation Opportunities

| Group | Finding IDs | Consolidation |
|-------|-------------|----------------|
| Ops safety net (backup + monitor + rollback) | C1, C2, H6, H8, L4 | One ops package: scheduled dump+`/data` restore drill; fix health HTTP semantics; external probes; tagged releases + rollback notes; short runbook. |
| CI quality gate | H1, M6 | Single workflow: schema check + pytest + lint + frontend build (+ optional e2e smoke). |
| Data integrity & digest scale | H2, H3, M8 | Finish open DB09 items: scan FKs, notify SQL filter/chunking, import FS-after-commit. |
| Production edge hardening | H4, H5, M3 | Production boot checks: require secret key, secure cookies (or explicit override), disable OpenAPI. |
| Capacity & SPOF clarity | M1, M2, M5, M9 | Document HA non-goals; resource limits; metrics; Windows graceful stop vs force-kill. |
| Operator UX + privacy docs | H7, M7, L1 | Clear open UX critical/highs; write data-handling note + LICENSE. |

---

## Recommendations

1. **Before unattended production:** scheduled Postgres+`/data` backups with tested restore (C1); fix health readiness HTTP semantics (H8); external health alert (C2).
2. **Gate merges:** run pytest + lint + build in GitHub Actions (H1); keep schema-drift.
3. **Close open data risks:** soft scan FKs (H2) and notify pending chunking (H3) still tracked in `todo.md`.
4. **Harden the edge:** production fail-fast for blank `APP_SECRET_KEY`, secure cookies under HTTPS, disable `/api/docs` in production (H4, H5, M3).
5. **Define rollback:** image tags + migration policy (H6); rehearse on staging (M4).
6. **Finish operator-facing UX blockers** that discard settings or hide errors (H7) before broad handoff.
7. **Treat inventory/screenshots as sensitive:** document retention, access, and offboarding (M7).

---

## Phased Fix Plan

| Phase | Focus | Finding IDs | Notes |
|-------|--------|-------------|--------|
| Phase 1 | Critical fixes | C1, C2, H2, H3, H7, H8 | Backup+`/data` restore; health 503/ready split + alerts; scan FKs; notify bound load; UX blockers. |
| Phase 2 | High-impact improvements | H1, H4, H5, H6, M3, M8, M9 | Full CI; production boot hardening; rollback tags/docs; import txn/FS; Windows graceful stop. |
| Phase 3 | Polish & consistency | M1, M2, M4, M5, M6, M7, L1-L4 | Capacity docs/limits; staging; metrics; e2e smoke; privacy note; LICENSE; structured logs; runbook. |

---

## Checklist coverage (summary)

| Area | Result |
|------|--------|
| 1. Architecture & Infrastructure | Partial: architecture and hosting documented; Compose as IaC; SPOF accepted; no resource limits / formal capacity plan. |
| 2. Security & Access Control | Strong core authz/authn; TLS/cookie defaults and open docs need production hardening. |
| 3. Data, Database & Migrations | Strong migrations/CI drift; backup/restore untested; soft FKs + notify load open. |
| 4. Reliability, Resilience & Failover | Restart + lifespan stop; health HTTP masks DB failure; Windows force-kill; SPOF by design. |
| 5. Observability & Monitoring | Logs + health body only; no metrics/alerts/traces; HEALTHCHECK URL-only; no frontend console.log noise. |
| 6. Deployment, CI/CD & Operations | Scripts/README solid; CI thin; rollback/backup ops incomplete. |
| 7. Testing, Quality & Release Practices | Backend tests strong locally; not enforced in CI; no FE/e2e. |
| 8. Performance & Capacity | Improved vs 2026-10-08; no SLOs/baselines; digest path still risky at scale. |
| 9. Compliance, Privacy & Data Handling | Retention present; formal privacy/DSAR docs absent (internal-tool context). |
| 10. UX, Supportability & Operational Documentation | README excellent; open UX critical/high; no separate runbook. |
