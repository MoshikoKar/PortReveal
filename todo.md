# Project TODO (Audit Derived)

---

## 📊 Summary

- **Total findings**: 158
- **Open**: 40
- **Completed**: 118 (archived — see index below)
- **Severity distribution:** 🔴 Critical: 4 (0 open), 🟠 High: 41 (9 open), 🟡 Medium: 70 (18 open), 🟢 Low: 43 (13 open)
- **Audits synced:** prior set + `docs/audit-api-design-2026-10-13.md` + `docs/audit-observability-2026-10-13.md` + `docs/audit-testing-coverage-2026-10-13.md` (TEST13-H1–H2, M1–M5, L1–L4 → open)

---

## 🔴 Critical

*(none open)*

---

## 🟠 High

### API13-H1: Notifications test returns HTTP 200 on SMTP failure

Status: Open

#### Subtasks

- [ ] In `backend/app/api/settings.py` `test_notifications`, raise `HTTPException` (502/503 or 422) on send failure instead of `{"ok": false}` with 200
- [ ] Keep successful test response as 200 with a clear success body
- [ ] Confirm Settings UI still surfaces the error via status/`ApiError`

---

### API13-H2: Scan cancel returns HTTP 200 with `ok: false`

Status: Open

#### Subtasks

- [ ] In `backend/app/api/scans.py` `cancel_scan`, raise `HTTPException(409)` when `manager.cancel` returns false
- [ ] Align success response with web-capture cancel (`{"ok": true}` or 204)
- [ ] Adjust any frontend that reads `ok` from the cancel body if needed

---

### API13-H3: No machine-readable API error codes / inconsistent error shape

Status: Open

#### Subtasks

- [ ] Define a shared error envelope (`code`, `message`, optional `details`/`pos`) in the backend API layer
- [ ] Map `HTTPException`, validation errors, `QueryError`, and `TargetError` through handlers in `backend/app/main.py`
- [ ] Update `frontend/src/api.ts` `errorMessage` to read the new envelope while remaining backward-compatible during rollout

---

### API13-H4: Inconsistent list response envelopes across collections

Status: Open

#### Subtasks

- [ ] Document the list contract: prefer `paged()` `{items, total, page, page_size}` for collections
- [ ] Wrap bare-array list endpoints (`users`, `networks`, `exclusions`, `tokens`, `webhooks`, `saved-searches`) in a consistent envelope (or document unpaged admin sets explicitly in OpenAPI)
- [ ] Align custom wrappers (`web-hosts`, create responses) with documented response models

---

### OBS13-H1: Internal exception text stored and returned via scan/web-capture `error`

Status: Open

#### Subtasks

- [ ] In `backend/app/core/runner.py`, stop persisting `f"internal error: {exc}"` on unexpected crash; store a stable safe message and keep detail in `log.exception` only
- [ ] In `backend/app/core/web_capture/runner.py`, apply the same safe client-facing error on unexpected crash
- [ ] Confirm `scan_out` / web-capture serializers still expose `error` without leaking exception internals

---

### OBS13-H2: Webhook delivery failures logged only at debug

Status: Open

#### Subtasks

- [ ] In `backend/app/core/webhooks.py` `deliver_event`, log per-hook HTTP/network failures at `warning` (hook id + host/status or exception type; no secrets)
- [ ] Optionally add a Prometheus counter for webhook delivery outcomes in `backend/app/metrics.py` and increment it from `deliver_event`

---

### OBS13-H3: Login rate-limit lockouts produce no audit or application log

Status: Open

#### Subtasks

- [ ] In `backend/app/api/auth.py` login lockout path, `audit` and/or `log.warning` with username + client IP when returning 429
- [ ] Optionally add `nf_login_rate_limited_total` (or equivalent) in `backend/app/metrics.py` and observe it from the lockout path

---

### TEST13-H1: Nmap process invocation contract is untested

Status: Open

#### Subtasks

- [ ] Add `backend/tests/test_nmap_command_integrity.py` with a docstring listing invariants (list argv, no shell, `-iL` only, deny-list flags)
- [ ] Monkeypatch `subprocess.Popen` in that module and run `NmapScanner.discover` / `scan_ports` with crafted targets (`;`, `$(...)`, newlines) via stubs so CI stays offline
- [ ] Assert `Popen` receives a `list` argv, `shell` is not true, `-iL` is present, and target-file contents match the validated IP list
- [ ] Assert composed argv never includes `--script`, `-A`, or `-iR`

---

### TEST13-H2: Scan settings API lacks injection / closed-set tests

Status: Open

#### Subtasks

- [ ] In `backend/tests/test_api.py` (or the integrity module), add a valid `PUT /api/settings/scan` timing round-trip for `polite`/`normal`/`fast`
- [ ] Assert invalid `timing` (`--script`, `-T5;id`, unknown strings) and out-of-range `top_ports` return 422
- [ ] Assert unknown raw-nmap JSON fields are rejected and stored settings never contain free-form nmap argv

---

## 🟡 Medium

### API13-M1: Unbounded `GET /api/web-hosts`

Status: Open

#### Subtasks

- [ ] Add `Paging` (or an explicit limit) to `web_hosts` in `backend/app/api/web_captures.py`
- [ ] Return a paginated envelope (`paged(...)` or `{hosts, total, page, page_size}`)
- [ ] Update the Web Hosts / Remote Hosts frontend fetch to pass page params

---

### API13-M2: Search pagination diverges from shared `Paging`

Status: Open

#### Subtasks

- [ ] Reuse or parameterize `Paging` in `backend/app/api/common.py` so search can set `le=100`
- [ ] Wire `GET /api/search` in `backend/app/api/search.py` to that shared helper (keep max 100 if intentional)
- [ ] Document the search page-size ceiling next to other list endpoints

---

### API13-M3: Scan detail over-embeds up to 500 events

Status: Open

#### Subtasks

- [ ] Stop embedding a fixed 500-event list in `GET /api/scans/{scan_id}` by default (`backend/app/api/scans.py`)
- [ ] Add `GET /api/scans/{scan_id}/events` with `Paging`, or gate events behind an explicit query flag
- [ ] Update the Scans UI to load events from the new contract if it relied on the embedded list

---

### API13-M4: PUT vs PATCH update semantics inconsistent

Status: Open

#### Subtasks

- [ ] Document the API rule: PUT = full replace (settings/config); PATCH = partial entity update
- [ ] Either convert partial-friendly resources to PATCH or keep PUT and document full-body requirements in OpenAPI for networks/exclusions/saved-searches/profile

---

### API13-M5: No API versioning strategy

Status: Open

#### Subtasks

- [ ] Choose path (`/api/v1`) or header versioning and document it
- [ ] Mount or alias existing routers under the chosen version scheme in `backend/app/main.py` without breaking the bundled UI
- [ ] Note the freeze policy for breaking response changes in README or OpenAPI description

---

### API13-M6: Web-capture settings split from other `/api/settings` routes

Status: Open

#### Subtasks

- [ ] Move `GET/PUT /api/settings/web-capture` handlers from `backend/app/api/web_captures.py` into `backend/app/api/settings.py` (or a shared settings module)
- [ ] Keep URL paths stable; remove duplicate absolute routes from the web-captures router
- [ ] Verify Settings UI still loads/saves web-capture settings

---

### API13-M7: Singular `/api/host` vs plural `/api/devices`

Status: Open

#### Subtasks

- [ ] Document `/api/host/{ip}` as the Shodan-shaped alias in OpenAPI/README
- [ ] Add a canonical plural (or by-ip) path such as `/api/hosts/{ip}` or `/api/devices/by-ip/{ip}` in `backend/app/api/host.py`
- [ ] Prefer the canonical path from new frontend callers; keep the singular alias for compatibility

---

### OBS13-M1: No request / correlation identifiers

Status: Open

#### Subtasks

- [ ] Add middleware in `backend/app/main.py` that accepts or generates `X-Request-Id` and echoes it on the response
- [ ] Attach the request id to a contextvar / log `extra` so subsequent log lines can carry it
- [ ] Optionally send/echo the same id from `frontend/src/api.ts` fetch headers

---

### OBS13-M2: Structured logging optional and shallow

Status: Open

#### Subtasks

- [ ] Prefer `LOG_FORMAT=json` in production examples (`.env.example` / `.env.production.example` notes)
- [ ] Extend `JsonFormatter` in `backend/app/logging_setup.py` to emit an allowlisted set of extras (`request_id`, `user`, etc.)

---

### OBS13-M3: HTTP metrics lack route/path labels

Status: Open

#### Subtasks

- [ ] Pass a low-cardinality route template from `request_timing` in `backend/app/main.py` into `observe_request`
- [ ] Update `backend/app/metrics.py` counters/summary labels to include route (not raw URLs with IDs)

---

### OBS13-M4: Admin SMTP/LDAP diagnostics return raw exception strings

Status: Open

#### Subtasks

- [ ] In `backend/app/api/settings.py` SMTP test, return a short classified message to the client; log full detail server-side
- [ ] Truncate/redact exception text stored in `audit(...)` details for SMTP test failures
- [ ] In `backend/app/auth/ldap_auth.py` / LDAP test path, return classified messages instead of raw `str(exc)` to the UI

---

### OBS13-M5: No frontend error reporting or shared request id UX

Status: Open

#### Subtasks

- [ ] Surface response `X-Request-Id` (when present) in `frontend/src/api.ts` `ApiError` or support reference text
- [ ] Optionally add a React error boundary that shows a reference id for uncaught UI failures

---

### OBS13-M6: Health is DB-coupled with no separate liveness probe

Status: Open

#### Subtasks

- [ ] Add a cheap `/api/live` (process up, no DB) in `backend/app/api/system.py`, or document that `/api/health` is readiness-only
- [ ] Update `docs/runbook/runbook.md` monitoring section to distinguish live vs ready probe roles

---

### TEST13-M1: Web-capture helper subprocess argv integrity is untested

Status: Open

#### Subtasks

- [ ] Add unit assertions for VNC argv construction in `backend/tests/test_web_capture.py` (or a dedicated module): list tokens only, no shell operators, no credential files
- [ ] Add the same style of argv asserts for FreeRDP (`backend/app/core/web_capture/rdp.py`) with invalid IP/port rejected upstream
- [ ] Add the same style of argv asserts for RTSP/ffmpeg (`backend/app/core/web_capture/rtsp.py`)

---

### TEST13-M2: No frontend unit/component tests

Status: Open

#### Subtasks

- [ ] Add a Vitest (or project-chosen) harness under `frontend/` for unit tests
- [ ] Cover `frontend/src/api.ts` CSRF header attachment and `errorMessage` / `ApiError` mapping
- [ ] Wire the frontend unit script into `.github/workflows/ci.yml` (or a dedicated npm script invoked by CI)

---

### TEST13-M3: E2E smoke is opt-in and not run in CI

Status: Open

#### Subtasks

- [ ] Add a CI job (or scheduled workflow) that builds the frontend, installs Chromium, and runs `pytest -m e2e`, or document an explicit non-goal if M2 unit coverage is the chosen gate
- [ ] Keep default local `npm test` / pytest free of e2e so offline contributors are unaffected

---

### TEST13-M4: LDAP auth coverage is narrow

Status: Open

#### Subtasks

- [ ] Extend `backend/tests/test_ldap_auth.py` with a successful `ldap_authenticate` path that maps to a user/role
- [ ] Add an API login test with LDAP mocked enabled covering `/api/auth/login` success vs local-disabled routing

---

### TEST13-M5: Scan-command safety tests are fragmented

Status: Open

#### Subtasks

- [ ] Point existing builder/VPN/API injection cases at `backend/tests/test_nmap_command_integrity.py` (or expand `test_scanner.py`) with one threat-model docstring
- [ ] Cross-link H1/H2 cases from that module so review sees one integrity entrypoint

---

## 🟢 Low

### API13-L1: Resource creates return 200 instead of 201

Status: Open

#### Subtasks

- [ ] Set `status_code=201` on primary create routes (`users`, `networks`, `tokens`, `webhooks`, exclusions, saved-searches) where a new resource is created
- [ ] Optionally add `Location` headers for created resource URLs

---

### API13-L2: Deletes return 200 `{ok: true}` instead of 204

Status: Open

#### Subtasks

- [ ] Change empty-body DELETE successes to `204 No Content` for resources that currently return only `{ok: true}`
- [ ] Update frontend `del()` callers that expect a JSON body on those endpoints

---

### API13-L3: Host document duplicates `ports` and `data`

Status: Open

#### Subtasks

- [ ] Document `data` as a deprecated Shodan alias on `GET /api/host/{ip}` in `backend/app/api/host.py`
- [ ] Plan removal of the duplicate field under a future API version

---

### API13-L4: Token DELETE is soft-revoke without documented semantics

Status: Open

#### Subtasks

- [ ] Document `DELETE /api/tokens/{id}` as revoke (soft) in OpenAPI/docstring (`backend/app/api/tokens.py`)
- [ ] Optionally return the updated token resource or add an explicit `POST .../revoke` alias

---

### API13-L5: RPC-style action paths lack a documented convention

Status: Open

#### Subtasks

- [ ] Document allowed action/RPC patterns under parent resources (`…/cancel`, `…/reset-baseline`, settings tests/runs)
- [ ] Avoid introducing new top-level verb paths outside `/api/{resource}/…`

---

### OBS13-L1: Playwright settle path uses empty `except Exception: pass`

Status: Open

#### Subtasks

- [ ] Decide keep-as-is vs count settle timeouts in `backend/app/core/web_capture/screenshot.py`
- [ ] If counting, add a debug counter or gated debug log for settle timeout / destroyed-context cases

---

### OBS13-L2: Optional enrichers fail closed without INFO visibility

Status: Open

#### Subtasks

- [ ] In `backend/app/core/intel.py`, rate-limit a `warning` when TLS/SSH enrich failures exceed a per-scan threshold (or keep debug and emit a metric)
- [ ] In `backend/app/core/image_intel.py`, optionally log/metric soft-fail decode/OCR paths when failures are systemic

---

### OBS13-L3: JSON logs omit service/host/process identity fields

Status: Open

#### Subtasks

- [ ] Add static identity fields (`service`, `version`, optional hostname) to `JsonFormatter` in `backend/app/logging_setup.py` when `log_format=json`

---

### OBS13-L4: Slow-request logs include the full query string

Status: Open

#### Subtasks

- [ ] In `backend/app/main.py` `request_timing`, truncate or omit query strings on slow-request warnings (path + safe params only)

---

### TEST13-L1: No coverage reporting or thresholds in CI

Status: Open

#### Subtasks

- [ ] Add optional `pytest-cov` (or equivalent) to the backend CI job in `.github/workflows/ci.yml` as a report artifact without a hard gate initially
- [ ] Optionally set a modest fail-under later for `app/scanner` and `app/auth` once the integrity suite lands

---

### TEST13-L2: Interface bind values trusted into nmap argv without sanitizer test

Status: Open

#### Subtasks

- [ ] In the integrity Popen spy suite, include a bind with a malicious `device`/`source` string
- [ ] Assert either rejection/validation in `backend/app/scanner/nmap_iface.py` / `_run`, or that unsafe bind values never reach argv

---

### TEST13-L3: Frontend CI is typecheck/lint/build only (no behavioral tests)

Status: Open

#### Subtasks

- [ ] Note in `.github/workflows/ci.yml` or README that the frontend job does not run behavioral tests until TEST13-M2/M3 land
- [ ] Ensure CSRF header and scan-dialog cases are explicitly listed under TEST13-M2 or TEST13-M3 when those are implemented

---

### TEST13-L4: Test run docs are brief

Status: Open

#### Subtasks

- [ ] Add a short Testing subsection to `README.md`: mock scanner default, when e2e runs, how to run pytest locally
- [ ] Point contributors at `backend/tests/test_nmap_command_integrity.py` (or the integrity entrypoint) once TEST13-H1 lands

---

## ✅ Completed (archived)

Completed findings live in `todo-archive/`. This file keeps an index only — not full history.

| Archive file | Period | Entries | Link |
|--------------|--------|---------|------|
| completed-summary.md | summary | 118 | [open](todo-archive/completed-summary.md) |

**Total completed:** 118

---

*Open tasks derived from audit/review reports in `docs/`. Use `22-todo-sync-orchestrator` to refresh. Completed history: `todo-archive/`.*
