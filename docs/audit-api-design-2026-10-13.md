# API Design Review Report

## Executive Summary

| Field | Value |
|-------|--------|
| **Audit topic/scope** | API design (endpoints, resources, verbs, status codes, request/response structures, consistency) |
| **Date of audit** | 2026-10-13 |
| **Overall score (1–10)** | 6.5 |
| **API design maturity level** | Early Production |
| **Overall design consistency rating** | Adequate |
| **Severity distribution** | Critical: 0, High: 4, Medium: 7, Low: 5 |
| **Total number of findings** | 16 |

FastAPI routers under `/api` form a coherent internal inventory API: resource nouns dominate CRUD, snake_case is consistent, and shared helpers (`Paging` / `paged`) cover the main list surfaces. Gaps that hurt client reliability are envelope inconsistency (raw arrays vs `{items,total,page,page_size}` vs ad-hoc keys), failures returned as HTTP 200 with `{ok:false}`, no machine-readable error codes, and no versioning strategy. Naming splits (`/api/host` vs `/api/devices`, settings split across modules) add friction for external or multi-client use.

---

## Audit Scope and Methodology

- **Scope:** Backend routers mounted from `backend/app/main.py` (`auth`, `setup`, `system`, `dashboard`, `devices`, `events`, `scans`, `networks`, `exclusions`, `settings`, `users`, `misc`, `web_captures`, `data_transfer`, `search`, `watches`, `reports`, `tokens`, `host`, `webhooks`), shared helpers in `backend/app/api/common.py`, and global exception handlers in `backend/app/main.py`. Frontend consumer patterns in `frontend/src/api.ts` were used only to confirm how error payloads are interpreted—not as findings against UI code.
- **Method:** Graphify-oriented discovery of API modules, then inventory of every `@router.(get|post|put|patch|delete)` route; review of HTTP methods, status usage, error shapes, list envelopes, pagination, and versioning against skill checklist areas A–F.
- **Rules referenced:** Skill `06-api-design-review` (CHECKLIST, SEVERITY_GUIDELINES, REPORT_TEMPLATE); analysis-only—no source changes.

### Endpoint inventory (summary)

| Prefix / area | File | Notes |
|---------------|------|--------|
| `/api/auth/*` | `backend/app/api/auth.py` | login, logout, me |
| `/api/setup/*` | `backend/app/api/setup.py` | first-run wizard |
| `/api/health`, `/api/metrics`, `/api/system/status` | `backend/app/api/system.py` | ops |
| `/api/dashboard`, `/api/exposed-ports` | `backend/app/api/dashboard.py` | aggregates |
| `/api/devices/*` | `backend/app/api/devices.py` | CRUD-ish + nested tags/profile/timeline |
| `/api/events/*` | `backend/app/api/events.py` | list + SSE stream |
| `/api/scans/*` | `backend/app/api/scans.py` | list, create, cancel |
| `/api/networks/*` | `backend/app/api/networks.py` | CRUD + reset-baseline |
| `/api/exclusions/*` | `backend/app/api/exclusions.py` | CRUD |
| `/api/settings/*` | `backend/app/api/settings.py` | schedule, presence, scan, notifications, ldap, retention |
| `/api/settings/web-capture` | `backend/app/api/web_captures.py` | settings colocated with captures |
| `/api/users/*` | `backend/app/api/users.py` | admin user CRUD |
| `/api/*` misc | `backend/app/api/misc.py` | audit, snapshots, mock helpers, ad-sync |
| `/api/web-captures/*`, `/api/web-pages/*`, `/api/web-hosts`, device RTSP/web | `backend/app/api/web_captures.py` | absolute paths (no router prefix) |
| `/api/data/*` | `backend/app/api/data_transfer.py` | export/import |
| `/api/search/*` | `backend/app/api/search.py` | query, facets, export |
| `/api/saved-searches/*` | `backend/app/api/watches.py` | watches/policies |
| `/api/reports/*` | `backend/app/api/reports.py` | exposure, rare-services, etc. |
| `/api/tokens/*` | `backend/app/api/tokens.py` | personal API tokens |
| `/api/host/{ip}` | `backend/app/api/host.py` | Shodan-shaped host document |
| `/api/webhooks/*` | `backend/app/api/webhooks.py` | outbound webhooks |

---

## Findings

### Critical

| # | Description | Location (endpoint, file/controller) | Impact | Recommendation |
|---|-------------|--------------------------------------|--------|----------------|
| — | None | — | — | No GET-with-side-effects or other contract-breaking REST violations observed on reviewed routes. |

### High

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| H1 | **Failure returned as HTTP 200.** `POST /api/settings/notifications/test` catches SMTP errors and returns `{"ok": false, "message": "..."}` with status 200 instead of a 4xx/5xx. Clients that only inspect status codes treat the call as success. | `POST /api/settings/notifications/test` — `backend/app/api/settings.py` (~L140–156) | Combined | On send failure return `502`/`503` (or `422` for bad config) with the same error envelope used elsewhere; reserve 200 for successful delivery. |
| H2 | **Cancel may succeed as HTTP 200 with `ok: false`.** `POST /api/scans/{scan_id}/cancel` always returns 200 and `{"ok": ok}` where `ok` is the boolean from `manager.cancel`. Failed cancel is indistinguishable from success by status code. Sibling `POST /api/web-captures/{id}/cancel` raises `409` when cancel fails. | `POST /api/scans/{scan_id}/cancel` — `backend/app/api/scans.py` (~L126–137); contrast `backend/app/api/web_captures.py` (~L344–365) | Combined | If cancel fails, return `409` (or `500` if unexpected); on success return `200`/`204`. Align scan cancel with web-capture cancel semantics. |
| H3 | **No machine-readable error codes; error shapes vary.** Handlers raise `HTTPException(status, "string")` → FastAPI `{"detail": "..."}`. Validation errors use FastAPI’s array-of-objects `detail`. `QueryError` adds `pos` (`{"detail", "pos"}`). There is no stable `code` (or equivalent) field for clients to branch on. Frontend already special-cases `detail` string vs array (`frontend/src/api.ts` `errorMessage`). | `backend/app/main.py` (~L105–112); widespread `HTTPException` in `backend/app/api/*.py`; `frontend/src/api.ts` (~L31–43) | Technical | Adopt one error envelope (e.g. `{ "code", "message", "details?", "pos?" }`) via exception handlers; map validation errors into the same shape; keep human `message` for UI. |
| H4 | **List response envelopes are inconsistent across collections.** Paginated resources use `paged()` → `{items, total, page, page_size}` (`common.py`). Many collections return a bare JSON array (`users`, `networks`, `exclusions`, `tokens`, `webhooks`, `saved-searches`). Others use custom wrappers (`{"hosts": ...}`, `{"ports","total","truncated"}`, `{"scans": ...}`, `{"capture": ...}`). External clients cannot assume one list contract. | `paged` — `backend/app/api/common.py` (~L26–27); bare arrays — `users.py` (~L49–51), `networks.py` (~L58–62), `exclusions.py` (~L51–53), `tokens.py` (~L42–45), `webhooks.py` (~L33–35), `watches.py` (~L66–68); custom — `web_captures.py` (~L566), `dashboard.py` (~L112–119), `scans.py` (~L123), `web_captures.py` (~L341) | Combined | Standardize: collections → `{items, total, ...}` (paginate or document “unpaged small admin sets”); action creates may keep named keys but document them in OpenAPI as response models. |

### Medium

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| M1 | **Unbounded `GET /api/web-hosts`.** Returns every device with captured pages and nested `services`/`hero` with no `page`/`page_size` or hard cap. Payload grows with inventory × pages. | `GET /api/web-hosts` — `backend/app/api/web_captures.py` (~L507–566) | Technical | Apply `Paging` (or a dedicated limit) and return `paged(...)` (or `{hosts, total, page, page_size}`). |
| M2 | **Search pagination duplicates and diverges from shared `Paging`.** Search uses inline `page` / `page_size` with `MAX_PAGE_SIZE=100`; `Paging` defaults to 50 and allows up to 500. Same param names, different ceilings and wiring. | `GET /api/search` — `backend/app/api/search.py` (~L45–69, `MAX_PAGE_SIZE` ~L36); `Paging` — `backend/app/api/common.py` (~L16–23) | Technical | Reuse `Paging` with a search-specific max, or document intentional divergence and keep one shared type with configurable `le`. |
| M3 | **Scan detail over-embeds events.** `GET /api/scans/{scan_id}` loads up to 500 events into the scan object with no pagination or `?include=events` control. | `GET /api/scans/{scan_id}` — `backend/app/api/scans.py` (~L63–71) | Technical | Return scan metadata alone by default; expose `GET /api/scans/{id}/events` with `Paging`, or require an explicit include flag. |
| M4 | **Update method inconsistency (PUT full body vs PATCH partial).** Users use `PATCH` with optional fields (`UserPatch`). Networks, exclusions, and saved-searches use `PUT` with full `*In` bodies. Device profile uses `PUT` for a full profile replace. Clients must learn per-resource update semantics. | `PATCH /api/users/{id}` — `users.py` (~L67–91); `PUT /api/networks/{id}` — `networks.py` (~L86–108); `PUT /api/exclusions/{id}` — `exclusions.py` (~L67–78); `PUT /api/saved-searches/{id}` — `watches.py` (~L84–99); `PUT /api/devices/{uuid}/profile` — `devices.py` (~L292–304) | Combined | Document the rule (settings/config = PUT replace; users = PATCH) or converge partial updates to PATCH everywhere optional fields are accepted. |
| M5 | **No API versioning strategy.** All routes live under unversioned `/api/...`. OpenAPI is toggled by env (`/api/openapi.json`) but there is no `v1` path/header. Any breaking field change is immediately global. | `backend/app/main.py` (~L91–102); all routers under `/api` | Business | Introduce `/api/v1` (or version header) before exposing the API beyond the bundled UI; freeze response models behind that version. |
| M6 | **Settings resource split across routers.** Most settings use `APIRouter(prefix="/api/settings")` in `settings.py`; web-capture settings are absolute routes on the web-captures router (`/api/settings/web-capture`). Same URL tree, different modules and auth wiring patterns. | `backend/app/api/settings.py` (~L28); `GET/PUT /api/settings/web-capture` — `web_captures.py` (~L224–235) | Technical | Mount web-capture settings from `settings.py` (or a shared settings package) so `/api/settings/*` is one contract surface. |
| M7 | **Singular `/api/host` vs plural `/api/devices`.** Host lookup by IP is intentionally Shodan-shaped (`/api/host/{ip}`) while inventory CRUD is plural `/api/devices`. Pluralization is inconsistent for “device/host” as a resource. | `backend/app/api/host.py` (~L24–28); `backend/app/api/devices.py` (~L38) | Combined | Keep Shodan alias if needed, but document it; prefer `/api/hosts/{ip}` or `/api/devices/by-ip/{ip}` as the canonical path and deprecate the singular form later. |

### Low

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| L1 | **Creates always return 200, never 201.** No route sets `status_code=201` for resource creation (users, networks, scans, tokens, webhooks, etc.). | e.g. `POST /api/users` — `users.py` (~L54–64); `POST /api/networks` — `networks.py` (~L73–83); `POST /api/tokens` — `tokens.py` (~L48–61) | Low | Use `status_code=201` (and optional `Location`) for successful creates. |
| L2 | **Deletes/actions return 200 `{ok: true}` instead of 204.** Widespread pattern for DELETE and many POST actions. | e.g. `users.py` (~L111), `networks.py` (~L133), `exclusions.py` (~L90), `watches.py` (~L109), `webhooks.py` (~L60) | Low | Prefer `204 No Content` for deletes with empty body; keep `{ok:true}` only where a payload is required. |
| L3 | **Host document duplicates service list as `ports` and `data`.** Same array assigned twice for Shodan aliasing. | `GET /api/host/{ip}` — `host.py` (~L113–114) | Low | Document `data` as deprecated alias; eventually drop one field under a versioned API. |
| L4 | **Token “DELETE” is soft-revoke.** Endpoint is `DELETE /api/tokens/{id}` but sets `revoked=True` rather than removing the row; response is still `{ok:true}`. | `tokens.py` (~L64–72) | Low | Rename semantics in docs to “revoke”; optionally expose `POST .../revoke` or return the updated token resource. |
| L5 | **RPC-style verb paths mixed with CRUD.** Examples: `POST .../reset-baseline`, `POST .../cancel`, `POST /api/inventory/ad-sync`, `POST /api/settings/retention/run`, `POST .../notifications/test`. Acceptable for actions, but density is high without a documented “actions” convention. | `networks.py` (~L111); `scans.py` (~L126); `misc.py` (~L25); `settings.py` (~L140, ~L242) | Low | Document action endpoints as RPC under the parent resource; avoid new top-level verb paths outside `/api/{resource}/...`. |

---

## Strengths (observed)

- Consistent **snake_case** field naming in serializers (`user_out`, `device_summary`, `scan_out`, `event_out` in `backend/app/api/common.py`).
- Shared **offset pagination** helper (`Paging` / `paged`) used by devices, events, scans, audit, snapshots, web-captures.
- Sensible use of **409** for conflicts (duplicate user, active scan, last admin, disabled web capture) and **422** for validation/target errors.
- **Auth/setup** enforce JSON content-type where appropriate (`require_json`); login/rate-limit return proper **401/429**.
- **Health** correctly uses **503** when the database is down (`system.py` ~L27–35).
- Search export and data export use streaming responses with clear `Content-Disposition` filenames.
- OpenAPI available outside production (`docs_url=/api/docs`, `openapi_url=/api/openapi.json` in `main.py`).

---

## Task Consolidation Opportunities

| Group | Finding IDs | Consolidation |
|-------|-------------|---------------|
| Status-code honesty | H1, H2, L1, L2 | One pass: never encode failure in 200 bodies; align create→201 and delete→204 where empty. |
| Error contract | H3 | Single exception-handler + typed error model; update `frontend/src/api.ts` once. |
| List/pagination contract | H4, M1, M2, M3 | Mandate `paged` (or documented small-admin arrays); paginate web-hosts and scan events; unify search `Paging`. |
| Resource naming & versioning | M5, M6, M7, L3, L4, L5 | Introduce `/api/v1`, relocate web-capture settings, document host alias and action verbs. |
| Update semantics | M4 | Short style guide: PUT = full settings/config replace; PATCH = partial entity update. |

---

## Recommendations

1. Fix **200-with-failure** endpoints (notifications test, scan cancel) before treating the API as a stable integration surface.
2. Publish a **single error + list envelope** (even if admin-only arrays stay unpaged) and generate response models so OpenAPI matches runtime.
3. Add **`/api/v1`** (or freeze the current `/api` as v1 in docs) before any external consumer depends on field shapes.
4. Bound **web-hosts** and trim **scan detail** event embedding to avoid silent payload growth.
5. Keep current strengths: conflict codes, snake_case serializers, and shared `Paging` for inventory-scale lists.

---

## Phased Fix Plan

| Phase | Focus | Finding IDs | Notes |
|-------|--------|-------------|--------|
| Phase 1 | Critical / correctness of HTTP status | H1, H2 | Clients must trust status codes for success vs failure. |
| Phase 2 | Contract consistency | H3, H4, M1, M2, M3 | Error envelope + list/pagination conventions; bound large GETs. |
| Phase 3 | Naming, versioning, polish | M4, M5, M6, M7, L1–L5 | Versioned path, settings consolidation, 201/204, docs for aliases and actions. |
