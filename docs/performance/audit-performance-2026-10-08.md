# Performance Audit Report

## Executive Summary

| Field | Value |
|-------|--------|
| **Audit topic/scope** | Performance (resource release, database queries, caching, frontend bundles, latency-sensitive paths) |
| **Date of audit** | 2026-10-08 |
| **Overall score (1–10)** | 5.5 |
| **Performance maturity level** | Early Production |
| **Severity distribution** | Critical: 1, High: 6, Medium: 6, Low: 4 |
| **Total number of findings** | 17 |

Session lifecycle, PostgreSQL pooling, relationship eager-loading on events/devices detail, and bounded scan parallelism are solid foundations. The main gaps are unbounded in-memory device loads (list API and scan compare), aggressive UI polling against `no-store` JSON APIs, LDAP/notify resource-hold issues, and full-table export/import. Frontend deps are lean; route-level splitting is the main client win.

---

## Audit Scope and Methodology

- **Scope:** FastAPI backend (`backend/app` — API, scan/web-capture runners, scheduler, retention, data transfer, LDAP/notify), SQLAlchemy models/migrations, React/Vite frontend (`frontend/src`, `vite.config.ts`).
- **Method:** Graphify-oriented discovery, then code review of resource usage, query patterns, caching, bundles, and latency-sensitive paths. Findings tied to real paths and lines only.
- **Rules referenced:** Skill `08-performance-audit` (CHECKLIST, SEVERITY_GUIDELINES, REPORT_TEMPLATE); project performance expectations (resource release, query optimization).
- **Areas covered:** Resource release & lifecycle; database & query patterns; caching & redundancy; frontend & assets; latency-sensitive paths (device list, dashboard, scans, auth/LDAP, notify, export/import).

---

## Findings

### Critical

| # | Description | Location (file path, line/function) | Impact | Recommendation |
|---|-------------|--------------------------------------|--------|----------------|
| C1 | **Device list loads all matching rows (+ ports), sorts in Python, then slices for pagination.** `GET /api/devices` and shared `_filtered_devices` call `.all()` with `selectinload(Device.ports)` before `page = devices[offset:offset+page_size]`. Large inventories risk high latency, memory pressure, and DB load on every list request (also driven by 15s UI poll). | `backend/app/api/devices.py` `_filtered_devices` (~L78–80), `list_devices` (~L96–101) | Combined | Push filter/sort into SQL (`ORDER BY` / indexed columns); use `COUNT(*)` + `LIMIT`/`OFFSET` (or keyset) so only one page of rows/ports is loaded. |

### High

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| H1 | **Scan compare loads every device with ports and IPs** (`select(Device).options(selectinload(...)).all()`), not scoped to scan targets/network. Runs inside apply after every completed scan. | `backend/app/core/compare.py` `_Applier.run` (~L165–167) | Technical | Scope load to networks/IPs in `outcome.targets` / host set; or batch by network_id. |
| H2 | **Export/import materializes entire inventory tables in memory** (`.all()` → dict lists → ZIP; import loads all JSONL then one long insert txn). Admin path, but OOM/lock risk grows with history. | `backend/app/core/data_transfer.py` `export_inventory` (~L136–138); import payloads (~L296–310); `backend/app/api/data_transfer.py` commit boundary | Combined | Stream JSONL to ZIP; import in chunks with shorter transactions; optional size guard before import. |
| H3 | **SMTP send runs inside `session_scope`.** DB connection held for network I/O while looping `send_email`. | `backend/app/core/notify.py` `notify_events` (~L123–141) | Technical | Load pending events + settings, close/commit session, send mail, then short session to set `notified_at`. |
| H4 | **LDAP service `Connection` not unbound on early returns / exceptions.** User-not-found, invalid credentials, not-in-group, and outer `except` leave `svc` open; failed logins can accumulate sockets. | `backend/app/auth/ldap_auth.py` `ldap_authenticate` (~L69–97); `ldap_test` exception path (~L100–111) | Technical | `try`/`finally: svc.unbind()` (or context manager) for every opened connection. |
| H5 | **Totals via `len(select(id).all())`** on device events/scans history; system queued count same pattern. Materializes all IDs instead of `COUNT(*)`. | `backend/app/api/devices.py` `device_events` / `device_scans` (~L158, L168); `backend/app/api/system.py` `scan_summary` (~L47) | Technical | Use `func.count()` / `select(func.count())` for totals and queued count. |
| H6 | **Aggressive multi-poll against uncached JSON.** App polls `/system/status` every 5s; Scans page polls active scans every 2.5s plus history 5s, snapshots 30s, mock 5s, and web-capture endpoints (initial fetch even when `pollMs` is 0). Global API `Cache-Control: no-store`. | `frontend/src/App.tsx` (~L57–61); `frontend/src/pages/Scans.tsx` (~L69–74); `frontend/src/util.ts` `useApi`; `backend/app/main.py` (~L91–92) | Combined | Gate inactive-tab fetches with `path: null`; slow active poll when no jobs; pause when hidden (already partial); consider SSE/WebSocket for scan progress. |

### Medium

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| M1 | **All routes eagerly imported; no `React.lazy` / Vite chunk strategy.** Warning limit raised to 900 KB. Deps are only React + router, so impact is moderate today but grows with pages. | `frontend/src/App.tsx` (~L7–17, L112–124); `frontend/vite.config.ts` (~L15) | User | Lazy-load page modules; optional `manualChunks` for vendor vs app. |
| M2 | **Scheduler retention runs inside one `session_scope`** wrapping bulk deletes, per-capture FS cleanup, and orphan dir cleanup — long-held connection on retention day. | `backend/app/core/scheduler.py` `tick` (~L86–109); `backend/app/core/retention.py` `run_retention` (~L32–67) | Technical | Commit DB deletes first; do filesystem cleanup outside the session (or separate short scopes). |
| M3 | **Missing indexes on retention filters:** `Device.last_seen`, `UserSession.expires_at` used in deletes without indexes. | `backend/app/models.py` Device (~L150–151), UserSession (~L103); `backend/app/core/retention.py` (~L46–47) | Technical | Add indexes (migration) if retention/tables grow. |
| M4 | **Web-capture concurrency settings unused.** `http_concurrency` / `screenshot_concurrency` exist in settings but runner probes endpoints in a sequential `for` loop. | `backend/app/settings_store.py` (~L162–163); `backend/app/core/web_capture/runner.py` (~L195+) | Technical | Wire bounded concurrency (or remove dead settings). |
| M5 | **Dashboard builds full exposed-port aggregation** via `exposed_ports(db)` with no limit, then truncates to top 12 in Python; also served unbounded at `GET /api/exposed-ports`. | `backend/app/api/dashboard.py` `exposed_ports` / `dashboard` (~L42–63, L103–155) | Technical | Limit aggregation or compute top-N in SQL; paginate Ports API if needed. |
| M6 | **`/api/devices/uuids` shares full-load pattern** (ports skipped, but all matching devices loaded then capped at 4096). | `backend/app/api/devices.py` `list_device_uuids` (~L117–124) | Technical | Same SQL pagination/filter as C1; select only `uuid` column. |

### Low

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| L1 | **`prior_scope` issues one scalar query per distinct `last_port_scan_id`** (cached after first hit). | `backend/app/core/compare.py` (~L132–138) | Low | Prefetch scopes for IDs present on matched devices. |
| L2 | **No performance budgets, query timing, or resource metrics** in app/CI. | N/A (observability gap) | Low | Add slow-query logging / basic latency metrics on list + dashboard. |
| L3 | **Screenshot grids use `loading="lazy"` and 24h `Cache-Control`**, but many parallel image requests possible without size hints. | `frontend/src/components/WebShots.tsx`; `backend/app/api/web_captures.py` FileResponse headers | Low | Optional `decoding="async"` / dimensions; throttle gallery concurrency. |
| L4 | **Settings sections re-read from DB every call** (no TTL); fine for tiny `app_settings`, but frequent on scheduler/runners. | `backend/app/settings_store.py` `get_section` (~L179+) | Low | Optional short process-local cache invalidated on put. |

---

## Strengths (observed)

- `get_db` / `session_scope` always close in `finally`; PostgreSQL `pool_pre_ping` + `pool_size=10` / `max_overflow=10`; SQLite WAL + busy timeout (`backend/app/db.py`).
- Events use `lazy="joined"` on `device`; device detail uses `selectinload` for ports/IPs; events/scans list APIs use proper `offset`/`limit` + `COUNT`.
- Scan runner releases the DB during nmap via short `session_scope` updates and bounded `ThreadPoolExecutor` (`backend/app/core/runner.py`).
- `httpx.Client`, Playwright browser, and SMTP `finally` close patterns are generally sound (LDAP is the exception).
- Frontend runtime deps are minimal (React 19 + react-router); screenshots cached `private, max-age=86400`.

---

## Task Consolidation Opportunities

| Group | Finding IDs | Consolidation |
|-------|-------------|----------------|
| Device query path | C1, M6, H5 | One devices/API pass: SQL sort+page, UUID-only select, `COUNT(*)` totals. |
| Scan apply memory | H1, L1 | Scope device load to targets; batch-prefetch port scopes. |
| Session / I/O separation | H3, M2, H4 | Never hold DB sessions across SMTP/FS/LDAP; LDAP unbind in `finally`. |
| Data transfer scale | H2 | Streaming export + chunked import with size limits. |
| Polling vs load | H6, M1, M5 | Reduce Scans/App poll rates; lazy routes; cap dashboard/ports aggregation. |
| Settings / indexes | M3, M4, L4 | Retention indexes; wire or drop web-capture concurrency; optional settings cache. |
| Observability | L2, L3 | Metrics + light asset hygiene. |

---

## Recommendations

1. Fix **device list pagination in SQL** first — it is the hottest user path and compounds with UI polling.
2. Keep scan nmap work off the DB connection; extend that pattern to **notify**, **retention FS**, and **LDAP**.
3. Treat **export/import** as a bulk job with streaming and size guards before inventories grow.
4. Cut **client poll fan-out** (especially Scans) before adding caches; `no-store` is appropriate for live inventory if polls are sane.
5. Preserve strengths: pool/session close discipline, `selectinload`/`joined` on hot relationships, bounded scan parallelism.

---

## Phased Fix Plan

| Phase | Focus | Finding IDs | Notes |
|-------|--------|-------------|--------|
| Phase 1 | Critical / high load & leaks | C1, M6, H4, H5, H3 | SQL page devices; LDAP unbind; COUNT totals; SMTP outside session |
| Phase 2 | Scan & transfer scale | H1, H2, M2, M3 | Scoped compare load; streaming transfer; retention session split; indexes |
| Phase 3 | UX load & consistency | H6, M1, M4, M5, L1–L4 | Poll gating; lazy routes; web-capture concurrency; dashboard top-N; monitoring |

---

## Checklist coverage (summary)

| Area | Result |
|------|--------|
| 1. Resource release & lifecycle | Strong for DB/httpx/SMTP/Playwright; LDAP leak (H4); DB held across SMTP/retention FS (H3, M2) |
| 2. Database & query patterns | Critical unbounded device list (C1); compare all-devices (H1); good event/scan paging; missing retention indexes (M3) |
| 3. Caching & redundancy | Intentional API `no-store`; screenshot cache OK; settings uncached (L4); polling redundancy (H6) |
| 4. Frontend & assets | Lean deps; eager routes (M1); aggressive polls (H6); lazy images OK (L3) |
| 5. Latency-sensitive paths | Device list + dashboard + Scans polling are the bottlenecks; scan runner parallelism is a strength |
