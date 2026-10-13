# Completed tasks (summary)

> One line per finding. Full detail: `todo-archive/.backup/`

**Entries:** 158  
**Prettified:** 2026-10-13  
**Format:** `severity` `id` — outcome (≤72 chars)

### 🔴 Critical (4)

- 🔴 `Perf-C1` — SQL COUNT/LIMIT device list; ports loaded per page only
- 🔴 `PR09-C1` — Scheduled pg_dump+appdata backup scripts; RPO/RTO drill
- 🔴 `PR09-C2` — Runbook: external health probes + scan-fail ops alerts
- 🔴 `UX09-C1` — Settings tabs/leave confirm before discarding dirty forms

### 🟠 High (41)

- 🟠 `API13-H1` — Notifications test returns non-200 on SMTP failure
- 🟠 `API13-H2` — Scan cancel returns 409 when cancel fails
- 🟠 `API13-H3` — Shared API error envelope with code/message
- 🟠 `API13-H4` — Consistent paged list envelopes across collections
- 🟠 `DB09-H1` — FK baseline/last_port_scan → scans ON DELETE SET NULL
- 🟠 `DB09-H2` — Pending digest filters event_type in SQL; LIMIT 500
- 🟠 `OBS13-H1` — Safe client-facing errors on scan/WC crash
- 🟠 `OBS13-H2` — Webhook delivery failures logged at warning
- 🟠 `OBS13-H3` — Login lockouts audited/logged (+ optional metric)
- 🟠 `PR09-H1` — CI runs pytest, Ruff, frontend lint, and npm build
- 🟠 `PR09-H4` — Require COOKIE_SECURE in prod; COOKIE_ALLOW_HTTP override
- 🟠 `PR09-H5` — Disable /api/docs and openapi.json when APP_ENV=production
- 🟠 `PR09-H6` — Document image tags, rollback, no prod alembic downgrade
- 🟠 `PR09-H8` — /api/health returns 503 when DB check fails; HEALTHCHECK asserts ok
- 🟠 `Perf-H1` — Scoped device load in scan compare Applier
- 🟠 `Perf-H2` — Streamed export JSONL; chunked import with guards
- 🟠 `Perf-H3` — SMTP send outside session_scope before notify
- 🟠 `Perf-H4` — LDAP unbind on early returns and exceptions
- 🟠 `Perf-H5` — COUNT(*) replaces len(select(id).all()) totals
- 🟠 `Perf-H6` — Gated/slowed multi-poll on Scans and App status
- 🟠 `TEST13-H1` — Nmap Popen argv integrity suite in CI
- 🟠 `TEST13-H2` — Scan settings closed-set / injection API tests
- 🟠 `UI-H1` — Destructive Delete/Reset use btn danger styling
- 🟠 `UI-H2` — Collapsible sidebar drawer under 900px
- 🟠 `UI-H3` — Modal Escape, focus trap, and aria-modal
- 🟠 `UI-H4` — Shared :focus-visible rings for buttons/links/tabs
- 🟠 `UI-H5` — Setup step pills meet AA contrast on panel-3
- 🟠 `UI09-H1` — Active scan/WC lists show SkeletonRows until data loads
- 🟠 `UI09-H2` — Lightbox aria-modal, focus trap, restore; fixed key deps
- 🟠 `UX-H1` — Session expiry shows message; restores prior route on login
- 🟠 `UX-H2` — Setup wizard step persisted and restored via ?step=
- 🟠 `UX-H3` — Dirty Setup Next/Skip auto-saves or confirms discard
- 🟠 `UX-H4` — Setup finish shows ErrorBox; busy state on Finish
- 🟠 `UX-H5` — Device/network/exclusion delete try/catch + feedback
- 🟠 `UX-H6` — Retention cleanup confirm, error handling, busy state
- 🟠 `UX09-H1` — Post-login redirects unknown paths (e.g. /login) to /
- 🟠 `UX09-H2` — Exclusion list toggle failures surface via actionError
- 🟠 `UX09-H3` — Active scan/WC fetch errors show ErrorBox + Retry
- 🟠 `UX09-H4` — ScanDialog networks: Loading/error vs empty configured
- 🟠 `UX09-H5` — Devices/Changes/Ports push filter history; q uses replace
- 🟠 `UX09-H6` — Search dims stale results; blocks export/bulk while loading

### 🟡 Medium (70)

- 🟡 `API13-M1` — Paginated GET /api/web-hosts with page params
- 🟡 `API13-M2` — Search reuses shared Paging (max 100)
- 🟡 `API13-M3` — Scan events via separate paged endpoint
- 🟡 `API13-M4` — Documented PUT vs PATCH update semantics
- 🟡 `API13-M5` — Added /api/v1 versioning alias without UI break
- 🟡 `API13-M6` — Moved web-capture settings into settings routes
- 🟡 `API13-M7` — Documented /api/host; added canonical hosts path
- 🟡 `DB09-M1` — Closed-value CHECKs on enums + import validation
- 🟡 `DB09-M2` — Import FS cleanup after inventory wipe commit
- 🟡 `DB09-M3` — Composite pending digest index on events
- 🟡 `DB09-M4` — Scoped identity key projection in load_devices
- 🟡 `DB09-M5` — Chunked watch evaluation (no full id materialize)
- 🟡 `DB09-M6` — SQL subnet report aggregation
- 🟡 `OBS13-M1` — X-Request-Id middleware + log contextvar
- 🟡 `OBS13-M2` — JSON logs allowlist extras; prod LOG_FORMAT note
- 🟡 `OBS13-M3` — HTTP metrics label low-cardinality route template
- 🟡 `OBS13-M4` — SMTP/LDAP tests return classified client messages
- 🟡 `OBS13-M5` — ApiError surfaces X-Request-Id reference
- 🟡 `OBS13-M6` — Added /api/live; documented live vs ready probes
- 🟡 `Perf-M1` — Lazy-loaded routes with React.lazy + Suspense
- 🟡 `Perf-M2` — Retention DB deletes finish before FS cleanup
- 🟡 `Perf-M3` — Indexed Device.last_seen and UserSession.expires_at
- 🟡 `Perf-M4` — Wired web-capture concurrency into parallel work
- 🟡 `Perf-M5` — Limited exposed_ports aggregation; paginated API
- 🟡 `Perf-M6` — UUID list selects only uuid with SQL LIMIT 4096
- 🟡 `PR09-M1` — Documented single-process SPOF; scan restart recovery test
- 🟡 `PR09-M2` — Compose CPU/memory limits; host sizing documented
- 🟡 `PR09-M3` — Fail fast when production APP_SECRET_KEY empty
- 🟡 `PR09-M5` — Export HTTP/scan/queue basic metrics counters
- 🟡 `PR09-M6` — Smoke e2e: login → dashboard → devices list
- 🟡 `PR09-M7` — Documented data categories, retention, offboarding
- 🟡 `PR09-M9` — Graceful stop before force-kill in run.ps1
- 🟡 `TEST13-M1` — VNC/RDP/RTSP argv integrity unit asserts
- 🟡 `TEST13-M2` — Vitest harness; CSRF/ApiError; CI npm unit
- 🟡 `TEST13-M3` — CI/scheduled e2e or documented non-goal
- 🟡 `TEST13-M4` — LDAP success path + mocked API login tests
- 🟡 `TEST13-M5` — Consolidated nmap integrity test entrypoint
- 🟡 `UI-M1` — Added --space-* tokens; mapped layout utilities
- 🟡 `UI-M2` — Raised body line-height to ≥1.5
- 🟡 `UI-M3` — Switched chrome labels toward sentence case
- 🟡 `UI-M4` — Added prefers-reduced-motion for UI animations
- 🟡 `UI-M5` — Increased icon button and checkbox hit areas
- 🟡 `UI-M6` — Moved secondary diagnostics into System control
- 🟡 `UI-M7` — Defined --radius-sm/md/lg/pill tokens
- 🟡 `UI-M8` — Restyled Changes filters to outline/selected chips
- 🟡 `UI09-M1` — table-wrap on Ports/Scans wide tables
- 🟡 `UI09-M10` — Search port labels use text-2 not accent
- 🟡 `UI09-M2` — Modal locks body scroll while open
- 🟡 `UI09-M3` — Mobile nav backdrop dismiss + body lock
- 🟡 `UI09-M4` — Sortable headers use button + aria-sort
- 🟡 `UI09-M5` — Filter chips aligned to toggle/pressed pattern
- 🟡 `UI09-M6` — Superseded by UX09-H6 (search refetch busy affordance)
- 🟡 `UI09-M7` — Settings create/save required-field gating
- 🟡 `UI09-M8` — Admin Disable styled as warn not Edit
- 🟡 `UI09-M9` — See-all bars use shared ghost btn class
- 🟡 `UX-M1` — Confirmed before stop scan / cancel web capture
- 🟡 `UX-M2` — Confirmed before user Disable and role change
- 🟡 `UX-M3` — Blocked Network-step Next until ≥1 network
- 🟡 `UX-M4` — Added busy/disabled submit on Setup and settings
- 🟡 `UX-M5` — Added Ports nav link to sidebar
- 🟡 `UX-M6` — try/catch scan detail opens into ErrorBox
- 🟡 `UX-M7` — Dirty/discard confirm on Modal settings drafts
- 🟡 `UX09-M1` — Settings link/redirect to /settings/networks
- 🟡 `UX09-M2` — Web preview highlights Web in sidebar
- 🟡 `UX09-M3` — Setup wizard step pushes history
- 🟡 `UX09-M4` — Viewer admin-tab redirect shows notice
- 🟡 `UX09-M5` — Destructive list actions in-flight disable
- 🟡 `UX09-M6` — Users Create and LDAP Test busy UI
- 🟡 `UX09-M7` — Scans page/WebHosts filters in URL
- 🟡 `UX09-M8` — Run again confirm; mock reset error handling

### 🟢 Low (43)

- 🟢 `API13-L1` — Create routes return 201 on resource create
- 🟢 `API13-L2` — Empty DELETE successes return 204 No Content
- 🟢 `API13-L3` — Documented host `data` as deprecated Shodan alias
- 🟢 `API13-L4` — Documented token DELETE as soft revoke
- 🟢 `API13-L5` — Documented RPC action path conventions
- 🟢 `DB09-L1` — Documented sessions/audit_log naming as intentional
- 🟢 `DB09-L2` — Set pool_recycle (and pool docs) in init_engine
- 🟢 `DB09-L3` — Added alembic check / schema-drift to CI
- 🟢 `DB09-L4` — selectinload/joinedload on get_device relations
- 🟢 `DB09-L5` — evaluate_all selects SavedSearch once
- 🟢 `OBS13-L1` — Playwright settle: keep-as-is or counted timeouts
- 🟢 `OBS13-L2` — Rate-limited enricher failure warnings/metrics
- 🟢 `OBS13-L3` — JSON logs include service/version identity fields
- 🟢 `OBS13-L4` — Slow-request logs omit/truncate query strings
- 🟢 `Perf-L1` — Prefetch Scan.port_scope for matched device scan ids
- 🟢 `Perf-L2` — Added latency logging for device list and dashboard
- 🟢 `Perf-L3` — Added decoding=async / size hints on shot images
- 🟢 `Perf-L4` — Added short process-local cache for get_section
- 🟢 `PR09-L1` — Added LICENSE / INTERNAL-USE notice
- 🟢 `PR09-L2` — Optional JSON logging via LOG_FORMAT=json
- 🟢 `PR09-L3` — Documented Task Scheduler limits; prefer Linux host
- 🟢 `PR09-L4` — Added runbook for restore, rotation, migrations
- 🟢 `TEST13-L1` — Optional pytest-cov artifact in backend CI
- 🟢 `TEST13-L2` — Integrity suite asserts bind iface sanitization
- 🟢 `TEST13-L3` — Documented frontend CI lacks behavioral tests
- 🟢 `TEST13-L4` — README Testing subsection for pytest/e2e/mocks
- 🟢 `UI-L1` — Normalized font-weights to standard 400/600/700
- 🟢 `UI-L2` — Added skeleton row pattern for primary list tables
- 🟢 `UI-L3` — Documented native title tooltips as accepted pattern
- 🟢 `UI-L4` — Added --accent-ink token for primary button text
- 🟢 `UI09-L1` — Documented brand-sub uppercase as intentional exception
- 🟢 `UI09-L2` — Added title on Modal/Lightbox close icon buttons
- 🟢 `UI09-L3` — Ports/settings lists use Empty / SkeletonRows
- 🟢 `UI09-L4` — Mock Reset scenario uses danger + confirm
- 🟢 `UI09-L5` — Facets sticky offset fixed under mobile topbar
- 🟢 `UI09-L6` — chip.suppressed uses muted token (≥3:1)
- 🟢 `UX-L1` — Soft 404 for unknown URLs instead of silent home redirect
- 🟢 `UX-L2` — Disabled Scan now shows scanner unavailable reason
- 🟢 `UX-L3` — Ports search/sort persisted in URL query params
- 🟢 `UX09-L1` — Scan/WebCapture dialogs dirty Modal confirm
- 🟢 `UX09-L2` — Disabled Start buttons have reason hints
- 🟢 `UX09-L3` — Search export/bulk busy labeling
- 🟢 `UX09-L4` — Brand home link; clear setup step on complete
