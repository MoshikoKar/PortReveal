# Observability & Logging Review Report

## Executive Summary

| Field | Value |
|-------|--------|
| **Audit topic/scope** | Observability, logging, metrics, tracing, and error visibility |
| **Date of audit** | 2026-10-13 |
| **Overall score (1–10)** | 6.5 |
| **Observability maturity level** | Early Production |
| **Severity distribution** | Critical: 0, High: 3, Medium: 6, Low: 4 |
| **Total number of findings** | 13 |

Network Finder already has a usable ops baseline: stdlib logging with optional JSON (`backend/app/logging_setup.py`), unauthenticated `GET /api/health` with DB degradation → 503, authenticated Prometheus text at `GET /api/metrics`, slow-request logging + `Server-Timing`, and worker loops that `log.exception` on unexpected failures. The main blind spots are correlation (no request IDs), silent webhook/login-lockout paths at default INFO, and raw exception strings persisted into scan/web-capture records that the API returns to clients. Maturity is early production—monitorable for a single-process deploy, not yet well-instrumented for multi-hop incident tracing.

---

## Audit Scope and Methodology

- **Scope:** Backend logging setup and usage (`backend/app/logging_setup.py`, `backend/app/main.py`, core workers/scanners), health/metrics (`backend/app/api/system.py`, `backend/app/metrics.py`), auth rate limiting (`backend/app/auth/ratelimit.py`, `backend/app/api/auth.py`), outbound webhooks/notify (`backend/app/core/webhooks.py`, `backend/app/core/notify.py`), error surfaces returned by the API (`backend/app/api/common.py`, scan/web-capture runners, settings test endpoints), frontend fetch wrapper (`frontend/src/api.ts`), and ops docs (`docs/runbook/runbook.md`, `README.md` monitoring notes). Config keys: `LOG_LEVEL`, `LOG_FORMAT`, `SLOW_REQUEST_MS` (`.env.example`, `backend/app/config.py`).
- **Method:** Graphify-oriented discovery of logging/health/metrics/middleware nodes, then file-level review of handlers, catch blocks, metrics export, and client-facing error fields. Analysis only—no source changes.
- **Rules referenced:** Skill `09-observability-review` (CHECKLIST, SEVERITY_GUIDELINES, REPORT_TEMPLATE); shared `CONVENTIONS.md` severity/scoring.

### Strengths observed

- Consistent `logging.getLogger(__name__)` across backend modules; noisy libraries quieted at WARNING.
- Optional JSON formatter + rotating `data/logs/app.log`; tests cover JSON shape (`backend/tests/test_logging_setup.py`).
- Health + Prometheus metrics + runbook guidance for external probing/alerting.
- Scan / web-capture / scheduler managers log unexpected failures with `log.exception`.
- Admin actions go through `backend/app/core/audit.py` (DB + `audit` logger).
- Frontend has no `console.*` noise; API errors map to user-facing messages without dumping stacks.

---

## Findings

### Critical

| # | Description | Location (file/service, line/component) | Impact | Recommendation |
|---|-------------|-----------------------------------------|--------|----------------|
| — | None | — | — | No passwords/tokens found in log messages; FastAPI is not run with `debug=True` and there is no handler that returns `exc.stack` to clients. Worker critical paths generally log failures. |

### High

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| H1 | **Internal exception text is stored and returned to API clients.** On unexpected crash, scan and web-capture runners persist `error=f"internal error: {exc}"`. `scan_out` / web-capture serializers expose `error` to authenticated callers. That leaks exception messages (paths, driver text, library internals) without needing a stack trace. | `backend/app/core/runner.py` (~L349–352); `backend/app/core/web_capture/runner.py` (~L549–557); `backend/app/api/common.py` `scan_out` (~L143); `backend/app/api/web_captures.py` (~L215) | Combined | Persist a stable code + short safe message for the API/UI; keep the full exception only in server logs via `log.exception`. Never round-trip `str(exc)` from unexpected paths into client-visible fields. |
| H2 | **Outbound webhook delivery failures are effectively silent at default INFO.** `deliver_event` records `hook.last_error` but logs only at `debug`. Ops running `LOG_LEVEL=INFO` (default) will not see SIEM/automation delivery failures in the app log unless they scrape webhook settings. | `backend/app/core/webhooks.py` (~L50–59); contrast `deliver_event_ids` which does `log.exception` on outer failure (~L69–70) | Technical | Log per-hook failures at `warning` (include hook id/url host, status or exception type—not secrets). Optionally increment a Prometheus counter (e.g. `nf_webhook_deliveries_total{result=...}`). |
| H3 | **Login rate-limit lockouts produce no audit or application log.** When `limiter.blocked(...)` is true, the handler raises HTTP 429 and returns immediately—no `audit(...)`, no `log.warning`. Failed logins before the threshold are audited (`auth.login_failed`); once locked, continued brute-force attempts are invisible in the audit trail (metrics still count HTTP 429 via `observe_request`). | `backend/app/api/auth.py` (~L40–41); `backend/app/auth/ratelimit.py` | Combined | Audit (or at least `log.warning`) lockout hits with username + client IP; consider a dedicated metric `nf_login_rate_limited_total`. |

### Medium

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| M1 | **No request / correlation identifiers.** HTTP middleware times requests and may log method/path/status/latency, but never assigns or propagates an `X-Request-Id` (or equivalent). `JsonFormatter` only emits timestamp/level/logger/message/exception—no request or user fields. Frontend→backend log correlation is impossible. | `backend/app/main.py` `request_timing` (~L115–134); `backend/app/logging_setup.py` `JsonFormatter` (~L14–29); `frontend/src/api.ts` | Technical | Generate or accept `X-Request-Id` in middleware; attach to a contextvar / `extra`; include in JSON logs and echo on the response. Optionally pass the same id from the UI fetch wrapper. |
| M2 | **Structured logging is optional and shallow.** Default `LOG_FORMAT=text` (`.env.example`). Even with `json`, custom `extra` attributes and context fields are not merged into the payload, so adopting request IDs later would not appear without formatter changes. | `backend/app/config.py` (`log_format` default `"text"`); `.env.example` (~L8–10); `backend/app/logging_setup.py` | Technical | Prefer `LOG_FORMAT=json` in production examples; extend `JsonFormatter` to include a allowlisted set of `record.__dict__` extras (e.g. `request_id`, `user`). |
| M3 | **HTTP metrics lack route/path labels.** `observe_request` counts only `(method, status)` and a global latency summary. Slow endpoints still appear in `app.perf` logs, but Prometheus cannot chart latency or error rate per route. | `backend/app/metrics.py` `observe_request` / `render` (~L37–41, ~L100–103); `backend/app/main.py` (~L127) | Technical | Label with a low-cardinality route template (FastAPI `request.scope["route"].path` or similar), not raw URLs with IDs. Keep status + method. |
| M4 | **Admin diagnostic endpoints return raw exception strings (and SMTP audits them).** SMTP test returns `Sending failed: {exc}` and stores `error: str(exc)` in the audit log. LDAP test returns `LDAP test failed: {exc}` / `failed ({res.error})` including underlying LDAP exception text. Useful for admins, but noisy/sensitive for shared audit retention. | `backend/app/api/settings.py` (~L147–153, ~L213–224); `backend/app/auth/ldap_auth.py` (~L106–127) | Combined | Return a short classified message to the UI; log full detail server-side; redact or truncate exception text in `audit(...)` details. |
| M5 | **No frontend error reporting or shared request id.** The UI maps API failures to `ApiError` messages only; there is no Error Boundary, no client telemetry, and no header correlation with backend logs. | `frontend/src/api.ts`; frontend tree (no ErrorBoundary / reporting hooks found) | User | At minimum, propagate `X-Request-Id` from responses into user-visible “reference” text for support; optionally report uncaught UI errors to the same log pipeline. |
| M6 | **Health is DB-coupled with no separate liveness probe.** `GET /api/health` runs `check_db()` and returns 503 when the DB is down. That is correct readiness for “app usable,” but a process that is up while DB is down cannot be distinguished from a dead process by a pure liveness check. Runbook currently treats `/api/health` as both. | `backend/app/api/system.py` (~L27–35); `docs/runbook/runbook.md` (~L202–229) | Technical | Keep `/api/health` as readiness; add a cheap `/api/live` (or document that container HEALTHCHECK vs external probe roles differ) if orchestrators need non-DB liveness. |

### Low

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| L1 | **Playwright settle path uses empty `except Exception: pass`.** Timeouts / destroyed execution contexts during screenshot settling are intentionally ignored; failures later surface via the outer `take_screenshot` warning. Noisy if promoted to logs, but local soft-fails are invisible. | `backend/app/core/web_capture/screenshot.py` (~L110–133) | Technical | Leave as-is, or count a debug counter for settle timeouts if blank-page skips become common. |
| L2 | **Optional enrichers fail closed without INFO visibility.** Image hash/OCR soft-fail with bare `return None`. TLS/SSH enrich failures log only at `debug` with `exc_info`. Systemic probe breakage stays quiet at default INFO. | `backend/app/core/image_intel.py` (~L17–40); `backend/app/core/intel.py` (~L64–71) | Technical | Rate-limit a `warning` when enrich failures exceed a threshold per scan, or expose a metric for enrich failures. |
| L3 | **JSON logs omit service/host/process identity fields.** Collectors must infer source from the transport. Fine for a single host; weaker when aggregating multiple instances. | `backend/app/logging_setup.py` `JsonFormatter` | Technical | Add static fields (`service=network-finder`, `version`, optional hostname) when `log_format=json`. |
| L4 | **Slow-request logs include the full query string.** Useful for debugging search, but can retain sensitive filter text in rotating logs. | `backend/app/main.py` (~L131–133) | Technical | Log path + selected safe params, or truncate/hash the query on slow warnings. |

---

## Task Consolidation Opportunities

| Group | Finding IDs | Shared remediation |
|-------|-------------|-------------------|
| Client-safe errors | H1, M4 | Sanitize unexpected exception text for API/audit; keep full detail in server logs only. |
| Correlation baseline | M1, M2, M5 | Request ID middleware + JsonFormatter extras + frontend echo. |
| Ops signal gaps | H2, H3, M3 | Raise webhook/login-lockout log levels; add counters; optional route labels on HTTP metrics. |
| Probe shape | M6 | Document or split live vs ready health checks. |
| Soft-fail hygiene | L1, L2, L3, L4 | Threshold warnings, JSON identity fields, query truncation. |

---

## Recommendations

1. Treat **correlation IDs + JSON production logs** as the next observability milestone; metrics and health already exist.
2. Align **SIEM webhook** and **login lockout** visibility with the care already given to scan worker crashes (`log.exception` / audit).
3. Stop returning **raw `str(exc)`** from unexpected failure paths into inventory records and admin audit rows.
4. Keep external alerting on `/api/health` and scrape `/api/metrics` as documented in `docs/runbook/runbook.md`—product email digests are not ops monitoring.
5. Defer full OpenTelemetry until correlation IDs and route-labeled metrics are in place; this is a single-process app and does not need a tracing stack to reach Production-ready observability.

---

## Phased Fix Plan

| Phase | Focus | Finding IDs | Notes |
|-------|--------|-------------|--------|
| Phase 1 | Critical fixes / high visibility | H1, H2, H3 | Sanitize persisted errors; warn on webhook failures; audit login lockouts |
| Phase 2 | High-impact improvements | M1, M2, M3, M4 | Request IDs, richer JSON logs, route metrics, safer admin diagnostics |
| Phase 3 | Maturity & consistency | M5, M6, L1–L4 | Frontend reference ids, live/ready split, soft-fail thresholds, log field hygiene |
