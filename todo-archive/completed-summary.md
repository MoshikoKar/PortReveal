# Completed tasks (summary)

> One line per finding. Full detail: `todo-archive/.backup/`

**Entries:** 50  
**Prettified:** 2026-10-08  
**Format:** `severity` `id` — outcome (≤72 chars)

### 🔴 Critical (1)

- 🔴 `Perf-C1` — SQL COUNT/LIMIT device list; ports loaded per page only

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

### 🟡 Medium (21)

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
- 🟡 `UX-M1` — Confirmed before stop scan / cancel web capture
- 🟡 `UX-M2` — Confirmed before user Disable and role change
- 🟡 `UX-M3` — Blocked Network-step Next until ≥1 network
- 🟡 `UX-M4` — Added busy/disabled submit on Setup and settings
- 🟡 `UX-M5` — Added Ports nav link to sidebar
- 🟡 `UX-M6` — try/catch scan detail opens into ErrorBox
- 🟡 `UX-M7` — Dirty/discard confirm on Modal settings drafts

### 🟢 Low (11)

- 🟢 `Perf-L1` — Prefetch Scan.port_scope for matched device scan ids
- 🟢 `Perf-L2` — Added latency logging for device list and dashboard
- 🟢 `Perf-L3` — Added decoding=async / size hints on shot images
- 🟢 `Perf-L4` — Added short process-local cache for get_section
- 🟢 `UI-L1` — Normalized font-weights to standard 400/600/700
- 🟢 `UI-L2` — Added skeleton row pattern for primary list tables
- 🟢 `UI-L3` — Documented native title tooltips as accepted pattern
- 🟢 `UI-L4` — Added --accent-ink token for primary button text
- 🟢 `UX-L1` — Soft 404 for unknown URLs instead of silent home redirect
- 🟢 `UX-L2` — Disabled Scan now shows scanner unavailable reason
- 🟢 `UX-L3` — Ports search/sort persisted in URL query params
