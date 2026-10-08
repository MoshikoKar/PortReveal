# Completed Tasks — Migrated 2026-10-08

> Cut from `todo.md` Medium section (`Status: Completed`). Raw migration dump for `todo-archive-organize`.

**Period:** 2026-10  
**Entries:** 21  
**Source:** todo.md ## 🟡 Medium (inline completed)

---

### [UX-M1] Stop scan / Cancel web capture without confirmation

Status: Completed

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Scans.tsx`

#### Subtasks

- [x] Confirm before `stopScan` posts cancel.
- [x] Confirm before `wcCancel` posts cancel.

---

### [UX-M2] Users – Disable / role change without confirmation

Status: Completed

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/settings/Admin.tsx`

#### Subtasks

- [x] Confirm before Disable/Enable user patch in `UsersSettings`.
- [x] Confirm before role change patch (especially admin → viewer).

---

### [UX-M3] Setup – Next allowed with zero networks

Status: Completed

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Setup.tsx`

#### Subtasks

- [x] Block Network-step Next until ≥1 network exists, or relabel as Skip and warn that baseline/schedule need a network.

---

### [UX-M4] Setup / settings forms – double-submit risk

Status: Completed

Source: `docs/audit-ux-flow-2026-10-08.md` · Setup and settings save actions

#### Subtasks

- [x] Add busy/disabled submit on `AdminStep` create in `Setup.tsx`.
- [x] Add busy/disabled Save on network modal in `Networks.tsx`.
- [x] Add busy/disabled Save on exclusion modal in `Exclusions.tsx`.
- [x] Add busy/disabled Save on settings forms that still lack it in `Forms.tsx`.

---

### [UX-M5] Ports page missing from sidebar nav

Status: Completed

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/components/Layout.tsx`

#### Subtasks

- [x] Add Ports nav link to sidebar in `Layout.tsx` (or add a clear back affordance on `Ports.tsx` if nesting under Dashboard is preferred).

---

### [UX-M6] Scan / web-capture detail open failures are silent

Status: Completed

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Scans.tsx`

#### Subtasks

- [x] try/catch `openDetail` and set the shared `err` ErrorBox channel.
- [x] try/catch `openWcDetail` and set the shared `err` ErrorBox channel.

---

### [UX-M7] Edit modals discard dirty drafts without warning

Status: Completed

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/components/ui.tsx`, settings modals

#### Subtasks

- [x] Support dirty/discard confirm (or disable backdrop dismiss while dirty) on `Modal` or its settings consumers.
- [x] Wire dirty-check for network/exclusion/user draft modals on Cancel and backdrop close.

---

### [UI-M1] Spacing not tokenized; many inline gaps

Status: Completed

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [x] Add `--space-*` tokens (4/8/12/16/24) to `:root` in `styles.css`.
- [x] Map core layout utilities (`.row`, `.stack`, `.content`, `.grid`) to space tokens where practical.

---

### [UI-M2] Body line-height below 1.5

Status: Completed

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [x] Raise `body` (and long-form `p`) line-height to ≥1.5; keep denser line-height only for table cells if needed.

---

### [UI-M3] Heavy uppercase on UI chrome labels

Status: Completed

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [x] Switch `h3`, `.kpi .label`, and `th` toward sentence case (keep brand eyebrow uppercase only if intentional).

---

### [UI-M4] Motion without prefers-reduced-motion

Status: Completed

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [x] Add `@media (prefers-reduced-motion: reduce)` to disable/shorten spinner, pulse, host-card, and shot-image motion.

---

### [UI-M5] Small hit targets on icon buttons and checkboxes

Status: Completed

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [x] Increase `.btn.icon` hit area toward ≥40px (padding/min-size) in `styles.css`.
- [x] Increase checkbox hit area / label padding for easier targeting.

---

### [UI-M6] Topbar status badge cluster competes with hierarchy

Status: Completed

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/components/Layout.tsx`

#### Subtasks

- [x] Move secondary diagnostics (DEV/DB/Scanner/nmap/read-only) into a compact System control; keep scan progress + critical banners inline.

---

### [UI-M7] Radius levels undocumented / inconsistent naming

Status: Completed

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [x] Define `--radius-sm/md/lg/pill` (or equivalent) in `:root` and map card/control/modal/chip/badge radii to them.

---

### [UI-M8] Changes filters overuse filled primary buttons

Status: Completed

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/pages/Changes.tsx`

#### Subtasks

- [x] Restyle range/type filter chips to outline/selected (not filled primary); reserve `.btn.primary` for page CTAs.

---

### [Perf-M1] All routes eagerly imported; no React.lazy / Vite chunks

Status: Completed

Source: `docs/audit-performance-2026-10-08.md` · `frontend/src/App.tsx`, `frontend/vite.config.ts`

#### Subtasks

- [x] Convert page imports in `App.tsx` to `React.lazy` + `Suspense`.
- [x] Optionally add Vite `manualChunks` for vendor vs app in `vite.config.ts`.

---

### [Perf-M2] Scheduler retention holds one long DB session across FS cleanup

Status: Completed

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/core/scheduler.py`, `backend/app/core/retention.py`

#### Subtasks

- [x] Commit/finish DB deletes in `run_retention` before filesystem cleanup.
- [x] Run capture-dir / raw cleanup outside the scheduler `session_scope` (or in a separate short scope).

---

### [Perf-M3] Missing indexes on retention filters (`last_seen`, `expires_at`)

Status: Completed

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/models.py`, `backend/app/core/retention.py`

#### Subtasks

- [x] Add index on `Device.last_seen` in `backend/app/models.py`.
- [x] Add index on `UserSession.expires_at` in `backend/app/models.py`.
- [x] Add Alembic migration for the new indexes.

---

### [Perf-M4] Web-capture concurrency settings unused (sequential probes)

Status: Completed

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/settings_store.py`, `backend/app/core/web_capture/runner.py`

#### Subtasks

- [x] Wire `http_concurrency` / `screenshot_concurrency` into bounded parallel work in `web_capture/runner.py`, or remove the unused settings fields.

---

### [Perf-M5] Dashboard/exposed-ports builds unbounded port aggregation

Status: Completed

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/api/dashboard.py`

#### Subtasks

- [x] Limit `exposed_ports` aggregation to top-N in SQL (or early cut) for dashboard.
- [x] Paginate or cap `GET /api/exposed-ports` instead of returning the full ranked set.

---

### [Perf-M6] `/api/devices/uuids` full-loads matching devices then caps at 4096

Status: Completed

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/api/devices.py` (`list_device_uuids`)

#### Subtasks

- [x] Select only `uuid` (and sort keys) with SQL filter/sort shared with the list path.
- [x] Apply the 4096 cap in SQL (`LIMIT`) before materializing the full match set.
