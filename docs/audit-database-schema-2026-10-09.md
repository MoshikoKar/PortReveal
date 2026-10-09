# Database Schema Review Report

## Executive Summary

| Field | Value |
|-------|--------|
| **Audit topic/scope** | Database schema, migrations, query safety, indexing, connection handling, query volume |
| **Date of audit** | 2026-10-09 |
| **Overall score (1–10)** | 7.0 |
| **Database/schema maturity level** | Early Production |
| **Severity distribution** | Critical: 0, High: 2, Medium: 6, Low: 5 |
| **Total number of findings** | 13 |

SQLAlchemy models + a linear Alembic chain (0001–0006) give a coherent dual-engine schema with strong FK coverage, hashed credentials, parameterized ORM queries, and solid session/pool hygiene. List/search paths are generally paginated and batch-loaded. The main gaps are soft (non-FK) scan references that go stale under retention, unbounded pending-event / watch matching loads, weak DB-level enum/range constraints, and a few hot-path index / transaction-scope misses.

---

## Audit Scope and Methodology

- **Scope:** `backend/app/models.py` (logical schema), `backend/alembic/versions/0001`–`0006`, `backend/app/db.py` / `config.py` / `migrate.py`, repositories and query code under `backend/app/api/` and `backend/app/core/` (including scan apply, watches, notify, retention, data transfer).
- **Method:** Graphify-oriented discovery, then review of migrations vs models, FK/index/constraint coverage, raw SQL and parameterization, connection lifecycle, and per-request / per-job query volume. Findings reference real paths only.
- **Rules referenced:** Skill `02-database-schema-review` (CHECKLIST, SEVERITY_GUIDELINES, REPORT_TEMPLATE); DB-001–DB-004 style expectations (schema/migration consistency, parameterized SQL, connection release); injection and performance overlap with security/performance audits.
- **Note:** Prior performance audit (`docs/audit-performance-2026-10-08.md`) called out unbounded device lists, missing retention indexes, and SMTP-held sessions; several of those are already fixed in current code and are **not** re-filed here.

---

## Findings

### Critical

| # | Description | Location (file path, table/query) | Impact | Recommendation |
|---|-------------|--------------------------------------|--------|----------------|
| — | None | — | — | No SQL injection via user-interpolated SQL; every table has a primary key; Alembic head matches `models.py` for applied migrations. |

### High

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| H1 | **Soft scan references without foreign keys.** `networks.baseline_scan_id` and `devices.last_port_scan_id` are plain `Integer` columns (no `ForeignKey` to `scans.id`). Retention deletes old scans (`backend/app/core/retention.py` purge of `scans`) without clearing these columns, so IDs can dangle. Logic treats baseline as “any non-null id” and resolves prior port scope via lookup that silently misses. | `backend/app/models.py` `Network.baseline_scan_id` (~L143), `Device.last_port_scan_id` (~L181); `backend/alembic/versions/0001_initial_schema.py` (~L55, ~L91); `backend/app/core/retention.py` `purge_expired` (~L54); `backend/app/core/compare.py` (~L151, ~L163–168, ~L487–488) | Combined | Add FKs with `ON DELETE SET NULL` (or clear IDs in retention before deleting scans). Prefer FK so the engine enforces integrity. |
| H2 | **Unbounded pending-notification event load.** Daily digest selects all rows with `notify=True` and `notified_at IS NULL` (joined device via `lazy="joined"`), then filters allowed `event_types` in Python. Pending backlog can grow without `LIMIT`; query count/memory scales with backlog size. | `backend/app/core/notify.py` `_pending_all` (~L365–371); `backend/app/models.py` `Event.device` relationship `lazy="joined"` (~L398) | Technical | Push `event_type IN (...)` into SQL; add a safety `LIMIT` / chunked send; consider composite index on `(notify, notified_at)` (see M3). |

### Medium

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| M1 | **Status / role / type / zone values are unconstrained strings.** Invariants such as device `status`, user `role`, scan `status`/`scan_type`/`trigger`, event `event_type`/`severity`, network `zone`, profile `criticality`, and tag `source` are enforced in Python constants/API patterns only—no `CheckConstraint` or DB enum. Invalid rows can be inserted via import, CLI, or bugs. | `backend/app/models.py` (e.g. `User.role` ~L115, `Device.status` ~L177, `Network.zone` ~L142, `Scan.status` ~L346, `Event.event_type` ~L388, `DeviceProfile.criticality` ~L289, `DeviceTag.source` ~L275); import path `backend/app/core/data_transfer.py` | Combined | Add `CheckConstraint`s (or PostgreSQL enums + SQLite checks) for closed value sets used in filters/indexes; validate on import. |
| M2 | **Import wipe performs filesystem deletes inside the open DB transaction.** `_wipe_inventory` runs `delete_capture_files` / `cleanup_capture_dirs` after `flush()` while the caller still holds the import transaction through re-insert. FS I/O extends lock/transaction duration. | `backend/app/core/data_transfer.py` `_wipe_inventory` (~L304–333), `import_inventory` (~L373–391) | Technical | Commit or stage wipe DB deletes first; run capture-file cleanup outside the inventory replace transaction (or after successful commit), with a documented orphan-cleanup pass. |
| M3 | **Missing composite index for digest pending filter.** Hot path filters `Event.notify IS TRUE AND Event.notified_at IS NULL`. Existing indexes are `created_at` and `(event_type, created_at)`, not this pair. | `backend/app/models.py` `Event` (~L381–398); `backend/app/core/notify.py` `_pending_all` (~L366–368) | Technical | Add partial index where supported (e.g. PostgreSQL `WHERE notified_at IS NULL AND notify`) or composite `(notify, notified_at)`. |
| M4 | **Scan apply always full-scans device identity keys.** `load_devices` selects id/ip/mac/hostname/status/last_seen for **every** device to match hosts, then chunk-loads full rows only for matches. Correct for identity matching, but query cost grows with whole inventory on every completed scan. | `backend/app/core/compare.py` `load_devices` (~L202–227) | Technical | Scope key projection by network/target CIDRs when possible; or maintain a narrower identity index/table if inventories grow large. |
| M5 | **Watch/policy evaluation loads all matching device ids unbounded.** `_matching_ids` materializes `set(db.scalars(select(Device.id).where(...)).all())` with no limit; `evaluate_all` runs this per saved search. Broad queries (`*` / empty) load the full device id set. | `backend/app/core/watches.py` `_matching_ids` (~L33–35), `evaluate_all` (~L65–78) | Technical | Cap evaluation set size; stream ids; or evaluate against scan-touched device ids when triggered post-scan. |
| M6 | **Subnet report aggregates in application memory.** `/api/reports/subnets` fetches up to 200k `(ip, status, score)` rows and builds `/24` buckets in Python instead of SQL `GROUP BY`. | `backend/app/api/reports.py` `subnets` (~L109–136), `SUBNET_SCAN_LIMIT` (~L24) | Technical | Compute subnet key in SQL (or dial-limited SQL aggregation) and return grouped counts/scores. |

### Low

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| L1 | **Table naming inconsistency.** ORM class `UserSession` maps to table `sessions`; `AuditLog` maps to singular `audit_log` while most tables are plural. | `backend/app/models.py` `UserSession` (~L122–123), `AuditLog` (~L417–418) | Low | Document as intentional; avoid renaming without a migration plan. |
| L2 | **PostgreSQL pool knobs are minimal.** `pool_pre_ping=True`, `pool_size=10`, `max_overflow=10` only—no `pool_timeout` / `pool_recycle` documented for long-lived workers. | `backend/app/db.py` `init_engine` (~L71) | Low | Set `pool_recycle` (e.g. under idle TCP timeouts) and document sizing vs worker/thread count. |
| L3 | **No single dumped “current schema” artifact beyond models + migration chain.** Fresh installs rely on Alembic head; `models.py` is the documented logical schema. Drift risk if someone edits models without a migration. | `backend/app/models.py`; `backend/alembic/versions/`; `backend/app/migrate.py` | Low | Keep autogenerate/`alembic check` in CI; optionally emit a periodic schema dump for review. |
| L4 | **Device detail issues several independent queries sequentially.** After `selectinload` ports/IPs, `get_device` separately loads network, `PortHttp`, tags, and profile. | `backend/app/api/devices.py` `get_device` (~L179–185) | Low | Optional `selectinload`/`joinedload` for tags/profile/http in `_get`, or parallelize independent reads. |
| L5 | **`evaluate_all` re-fetches each `SavedSearch` by id.** Lists ids then `db.get(SavedSearch, search_id)` per row (small-N admin feature). | `backend/app/core/watches.py` `evaluate_all` (~L68–69) | Low | `select(SavedSearch).order_by(...)` once and iterate. |

---

## Strengths (observed)

- Dual-engine design (`SQLite` + `PostgreSQL`) via one SQLAlchemy model set; Alembic `render_as_batch` for SQLite; `UTCDateTime` rendered as plain `DateTime` in migrations (`backend/alembic/env.py`).
- Primary keys on all tables; unique constraints on natural keys (`users.username`, `devices.uuid`, port/tag/ip uniqueness, snapshot day, token hashes).
- Foreign keys with sensible `ON DELETE` on nearly all relationships (devices↔ports/ips/tags, scans↔hosts/events, web capture cascade, etc.).
- Retention-oriented indexes present (`devices.last_seen`, `sessions.expires_at` via migration `0005`); composite `ix_events_type_created`, `ix_device_ports_open`, web_pages device/captured indexes.
- Query safety: search compiles to SQLAlchemy expressions (`backend/app/core/query/compile.py`); `like_pattern` escapes wildcards (`backend/app/api/common.py`); data-transfer `setval` uses a fixed table allow-list (`backend/app/core/data_transfer.py` ~L336–348).
- Credentials: `password_hash` (argon2/hasher), `api_tokens.token_hash`, session `token_hash`; SMTP/LDAP secrets stored encrypted (`password_enc` / `bind_password_enc`).
- Connection lifecycle: `get_db` / `session_scope` always `close()` in `finally`; SQLite WAL + FK pragmas; digest SMTP runs **outside** the first session (`notify.send_daily_digest`).
- Query volume: device list uses `COUNT` + `ORDER BY` + `LIMIT`/`OFFSET` with `selectinload(ports)`; search hosts/services paginate and batch-load tags/ports; tagging/`refresh_devices` chunk at 500; export pages by id (`BATCH_ROWS=2000`).

---

## Task Consolidation Opportunities

| Group | Finding IDs | Consolidation |
|-------|-------------|----------------|
| Referential integrity for scan links | H1 | One migration: FK `baseline_scan_id` / `last_port_scan_id` → `scans.id` `ON DELETE SET NULL`, plus retention/tests for orphan cleanup. |
| Notify pending path | H2, M3 | SQL filter + index + optional chunking in one notify pass. |
| DB-enforced enums / ranges | M1 | Single constraints migration covering status/role/type/zone/criticality/source closed sets. |
| Long transactions vs FS | M2 | Align import wipe with retention pattern (DB commit, then FS). |
| Inventory-scale scans/watches/reports | M4, M5, M6 | Scope or aggregate in SQL for post-scan and report hot paths. |
| Hygiene / polish | L1–L5 | Naming docs, pool recycle, CI alembic check, small query cleanups. |

---

## Recommendations

1. Fix **soft scan FKs (H1)** before inventories age into retention—dangling baselines silently change alert semantics and port-diff scope.
2. Harden **notify pending selection (H2 + M3)** so digests stay O(pending subset), not O(all unnotified rows).
3. Add **CheckConstraints (M1)** for closed enums already defined as Python constants; import will otherwise bypass app validators.
4. Keep the current strengths: parameterized ORM search compiler, paginated list/search, chunked intel refresh, streaming export, and session close discipline.
5. Feed this report into **12-todo-sync-orchestrator** / score tracking if that pipeline is in use.

---

## Phased Fix Plan

| Phase | Focus | Finding IDs | Notes |
|-------|--------|-------------|--------|
| Phase 1 | Integrity & notify scale | H1, H2, M3 | FKs + SET NULL; SQL event_type filter; pending index |
| Phase 2 | Constraints & transaction scope | M1, M2 | CheckConstraints; move import FS cleanup off the long txn |
| Phase 3 | Scale & hygiene | M4, M5, M6, L1–L5 | Scope compare keys; bound watches; SQL subnets; pool/CI/naming |

---

## Checklist coverage (summary)

| Area | Result |
|------|--------|
| 1. Schema and migration consistency | Pass: linear Alembic 0001→0006 with downgrades; `models.py` reflects head (incl. 0004 absence, 0005 indexes, 0006 intel). No conflicting revisions. L3 notes lack of CI drift check. |
| 2. Query safety | Pass: ORM/parameterized; allow-listed `setval` f-string; no user SQL concatenation found. |
| 3. Schema design & integrity | Mostly pass; H1 soft FKs; M1 weak enum constraints. PKs/uniques otherwise strong. |
| 4. Indexing & performance | Mostly pass after 0005/0006; M3 pending-notify index gap. |
| 5. Connection & pool handling | Pass for release paths; M2 long import txn with FS; L2 pool tuning. |
| 6. Query volume & redundancy | Improved vs 2026-10-08 perf audit; remaining H2/M4/M5/M6/L4/L5. |
