# Completed tasks (summary)

> One line per finding. Full detail: `todo-archive/.backup/`

**Entries:** 92  
**Prettified:** 2026-10-08  
**Format:** `severity` `id` — outcome (≤72 chars)

### 🔴 Critical (4)

- 🔴 `Perf-C1` — SQL COUNT/LIMIT device list; ports loaded per page only
- 🔴 `PR09-C1` — Scheduled pg_dump+appdata backup scripts; RPO/RTO drill
- 🔴 `PR09-C2` — Runbook: external health probes + scan-fail ops alerts
- 🔴 `UX09-C1` — Settings tabs/leave confirm before discarding dirty forms

### 🟠 High (17)

- 🟠 `Perf-H1` — Scoped device load in scan compare Applier
- 🟠 `Perf-H2` — Streamed export JSONL; chunked import with guards
- 🟠 `Perf-H3` — SMTP send outside session_scope before notify
- 🟠 `Perf-H4` — LDAP unbind on early returns and exceptions
- 🟠 `Perf-H5` — COUNT(*) replaces len(select(id).all()) totals
- 🟠 `Perf-H6` — Gated/slowed multi-poll on Scans and App status
- 🟠 `UI-H1` — Destructive Delete/Reset use btn danger styling
- 🟠 `UI-H2` — Collapsible sidebar drawer under 900px
- 🟠 `UI-H3` — Modal Escape, focus trap, and aria-modal
- 🟠 `UI-H4` — Shared :focus-visible rings for buttons/links/tabs
- 🟠 `UI-H5` — Setup step pills meet AA contrast on panel-3
- 🟠 `UX-H1` — Session expiry shows message; restores prior route on login
- 🟠 `UX-H2` — Setup wizard step persisted and restored via ?step=
- 🟠 `UX-H3` — Dirty Setup Next/Skip auto-saves or confirms discard
- 🟠 `UX-H4` — Setup finish shows ErrorBox; busy state on Finish
- 🟠 `UX-H5` — Device/network/exclusion delete try/catch + feedback
- 🟠 `UX-H6` — Retention cleanup confirm, error handling, busy state

### 🟡 Medium (45)

- 🟡 `DB09-M1` — Closed-value CHECKs on enums + import validation
- 🟡 `DB09-M2` — Import FS cleanup after inventory wipe commit
- 🟡 `DB09-M3` — Composite pending digest index on events
- 🟡 `DB09-M4` — Scoped identity key projection in load_devices
- 🟡 `DB09-M5` — Chunked watch evaluation (no full id materialize)
- 🟡 `DB09-M6` — SQL subnet report aggregation
- 🟡 `Perf-M1` — Lazy-loaded routes with React.lazy + Suspense
- 🟡 `Perf-M2` — Retention DB deletes finish before FS cleanup
- 🟡 `Perf-M3` — Indexed Device.last_seen and UserSession.expires_at
- 🟡 `Perf-M4` — Wired web-capture concurrency into parallel work
- 🟡 `Perf-M5` — Limited exposed_ports aggregation; paginated API
- 🟡 `Perf-M6` — UUID list selects only uuid with SQL LIMIT 4096
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

### 🟢 Low (26)

- 🟢 `DB09-L1` — Documented sessions/audit_log naming as intentional
- 🟢 `DB09-L2` — Set pool_recycle (and pool docs) in init_engine
- 🟢 `DB09-L3` — Added alembic check / schema-drift to CI
- 🟢 `DB09-L4` — selectinload/joinedload on get_device relations
- 🟢 `DB09-L5` — evaluate_all selects SavedSearch once
- 🟢 `Perf-L1` — Prefetch Scan.port_scope for matched device scan ids
- 🟢 `Perf-L2` — Added latency logging for device list and dashboard
- 🟢 `Perf-L3` — Added decoding=async / size hints on shot images
- 🟢 `Perf-L4` — Added short process-local cache for get_section
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
