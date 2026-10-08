# Project TODO (Audit Derived)

---

## 📊 Summary

- **Total findings**: 50
- **Open**: 37
- **Completed** (archived — see index below): 13
- **Severity distribution:** 🔴 Critical: 1 (0 open), 🟠 High: 17 (16 open), 🟡 Medium: 21 (21 open), 🟢 Low: 11 (0 open)
- **Audits synced:** `docs/audit-ux-flow-2026-10-08.md`, `docs/audit-ui-2026-10-08.md`, `docs/audit-performance-2026-10-08.md`

---

## 🔴 Critical

*(none open)*

---

## 🟠 High

### [UX-H2] First-run setup – step lost on refresh

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Setup.tsx`

#### Subtasks

- [ ] Persist wizard `step` in URL query or `sessionStorage` in `frontend/src/pages/Setup.tsx`.
- [ ] Restore step on mount when setup is incomplete (`!setup_completed`).

---

### [UX-H3] First-run setup – Next/Skip discards unsaved form edits

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Setup.tsx`, `frontend/src/pages/settings/Forms.tsx`

#### Subtasks

- [ ] Detect dirty Schedule/SMTP/LDAP/Recipients form state when Setup footer Next/Skip is clicked.
- [ ] On dirty Next/Skip: auto-save, block until Save, or confirm discard before advancing in `Setup.tsx`.

---

### [UX-H4] First-run setup – complete failure has no UI feedback

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Setup.tsx`

#### Subtasks

- [ ] Wrap `finish` (`post('/setup/complete')`) in try/catch and show `ErrorBox` on failure.
- [ ] Add busy/disabled state on Finish / Skip–finish while the request is in flight.

---

### [UX-H5] Device delete – silent failure after confirm

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/DeviceDetail.tsx`

#### Subtasks

- [ ] Wrap `remove` `del` in try/catch and show error feedback in `DeviceDetail.tsx`.
- [ ] Navigate to `/devices` only after successful delete.
- [ ] Add the same try/catch + error feedback pattern to network delete in `frontend/src/pages/settings/Networks.tsx`.
- [ ] Add the same try/catch + error feedback pattern to exclusion delete in `frontend/src/pages/settings/Exclusions.tsx`.

---

### [UX-H6] Retention – Run cleanup now without confirm or error handling

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/settings/Forms.tsx` (`RetentionForm`)

#### Subtasks

- [ ] Add confirmation dialog before `post('/settings/retention/run')` with clear copy of what will be deleted.
- [ ] Catch API errors and show failure message in `RetentionForm`.
- [ ] Disable the cleanup button and show busy label while the request runs.

---

### [UI-H1] Destructive Delete/Reset styled as ghost (same as Edit)

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · settings tables

#### Subtasks

- [ ] Change network Delete and Reset baseline to `btn danger` (keep Edit as ghost) in `frontend/src/pages/settings/Networks.tsx`.
- [ ] Change exclusion Delete to `btn danger` in `frontend/src/pages/settings/Exclusions.tsx`.
- [ ] Change user Delete to `btn danger` in `frontend/src/pages/settings/Admin.tsx` (`UsersSettings`).

---

### [UI-H2] Narrow viewport sidebar stacks with no collapse/drawer

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`, `frontend/src/components/Layout.tsx`

#### Subtasks

- [ ] Add collapsible drawer or compact top-nav behavior for `.sidebar` under 900px in `Layout.tsx` + `styles.css`.
- [ ] Preserve visible active nav state when the mobile nav is collapsed or open.

---

### [UI-H3] Modal missing Escape, focus trap, and aria-modal

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/components/ui.tsx` (`Modal`)

#### Subtasks

- [ ] Close `Modal` on Escape (mirror Lightbox in `WebShots.tsx`).
- [ ] Trap focus inside `Modal` while open and restore focus on close.
- [ ] Set `aria-modal="true"` (and initial focus) on the dialog element.

---

### [UI-H4] No shared `:focus-visible` styles for buttons/links/tabs

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [ ] Add a shared `:focus-visible` ring (≥3:1) for `.btn`, `.tabs a/button`, and `.nav a` in `styles.css`.
- [ ] Strengthen input focus ring (keep `outline: none` only where the ring replaces it).

---

### [UI-H5] Setup step pill labels fail AA contrast on `--panel-3`

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css` (`.steps span`)

#### Subtasks

- [ ] Adjust `.steps span` text/background tokens so idle step labels meet ≥4.5:1 contrast.
- [ ] Verify done/current step styles still meet AA after the change.

---

### [Perf-H1] Scan compare loads every device with ports and IPs

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/core/compare.py` (`_Applier.run`)

#### Subtasks

- [ ] Scope the device load in `_Applier.run` to scan targets / network IPs instead of `select(Device).all()`.
- [ ] Keep `selectinload` for ports/IPs only on the scoped device set.

---

### [Perf-H2] Export/import materializes entire inventory tables in memory

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/core/data_transfer.py`, `backend/app/api/data_transfer.py`

#### Subtasks

- [ ] Stream export JSONL to ZIP per table instead of buffering all rows in `export_inventory`.
- [ ] Import inventory in chunked inserts with shorter transactions in `data_transfer.py`.
- [ ] Add a size/row guard before import accepts a ZIP in `backend/app/api/data_transfer.py`.

---

### [Perf-H3] SMTP send runs inside `session_scope`

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/core/notify.py` (`notify_events`)

#### Subtasks

- [ ] Load pending events + notification settings, then exit `session_scope` before calling `send_email`.
- [ ] Open a short follow-up session to set `notified_at` after successful sends.

---

### [Perf-H4] LDAP connections not unbound on early returns / exceptions

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/auth/ldap_auth.py`

#### Subtasks

- [ ] Wrap `ldap_authenticate` service connection in `try`/`finally` with `svc.unbind()`.
- [ ] Ensure `ldap_test` unbinds on exception paths after a successful open/bind.

---

### [Perf-H5] Totals via `len(select(id).all())` instead of `COUNT(*)`

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/api/devices.py`, `backend/app/api/system.py`

#### Subtasks

- [ ] Replace `len(...select(Event.id)...all())` with `func.count()` in `device_events`.
- [ ] Replace `len(...select(ScanHost.id)...all())` with `func.count()` in `device_scans`.
- [ ] Replace queued-scan `len(select(Scan.id)...all())` with `func.count()` in `scan_summary`.

---

### [Perf-H6] Aggressive multi-poll against uncached JSON APIs

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `frontend/src/App.tsx`, `frontend/src/pages/Scans.tsx`, `frontend/src/util.ts`

#### Subtasks

- [ ] Gate Scans web-capture fetches with `path: null` when the web-captures tab is inactive (avoid initial load with `pollMs: 0`).
- [ ] Slow or pause `/scans/active` polling when no jobs are running/queued in `Scans.tsx`.
- [ ] Revisit App `/system/status` 5s interval (lengthen when idle or when Scans is not visible).

---

## 🟡 Medium

### [UX-M1] Stop scan / Cancel web capture without confirmation

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Scans.tsx`

#### Subtasks

- [ ] Confirm before `stopScan` posts cancel.
- [ ] Confirm before `wcCancel` posts cancel.

---

### [UX-M2] Users – Disable / role change without confirmation

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/settings/Admin.tsx`

#### Subtasks

- [ ] Confirm before Disable/Enable user patch in `UsersSettings`.
- [ ] Confirm before role change patch (especially admin → viewer).

---

### [UX-M3] Setup – Next allowed with zero networks

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Setup.tsx`

#### Subtasks

- [ ] Block Network-step Next until ≥1 network exists, or relabel as Skip and warn that baseline/schedule need a network.

---

### [UX-M4] Setup / settings forms – double-submit risk

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · Setup and settings save actions

#### Subtasks

- [ ] Add busy/disabled submit on `AdminStep` create in `Setup.tsx`.
- [ ] Add busy/disabled Save on network modal in `Networks.tsx`.
- [ ] Add busy/disabled Save on exclusion modal in `Exclusions.tsx`.
- [ ] Add busy/disabled Save on settings forms that still lack it in `Forms.tsx`.

---

### [UX-M5] Ports page missing from sidebar nav

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/components/Layout.tsx`

#### Subtasks

- [ ] Add Ports nav link to sidebar in `Layout.tsx` (or add a clear back affordance on `Ports.tsx` if nesting under Dashboard is preferred).

---

### [UX-M6] Scan / web-capture detail open failures are silent

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Scans.tsx`

#### Subtasks

- [ ] try/catch `openDetail` and set the shared `err` ErrorBox channel.
- [ ] try/catch `openWcDetail` and set the shared `err` ErrorBox channel.

---

### [UX-M7] Edit modals discard dirty drafts without warning

Status: Open

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/components/ui.tsx`, settings modals

#### Subtasks

- [ ] Support dirty/discard confirm (or disable backdrop dismiss while dirty) on `Modal` or its settings consumers.
- [ ] Wire dirty-check for network/exclusion/user draft modals on Cancel and backdrop close.

---

### [UI-M1] Spacing not tokenized; many inline gaps

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [ ] Add `--space-*` tokens (4/8/12/16/24) to `:root` in `styles.css`.
- [ ] Map core layout utilities (`.row`, `.stack`, `.content`, `.grid`) to space tokens where practical.

---

### [UI-M2] Body line-height below 1.5

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [ ] Raise `body` (and long-form `p`) line-height to ≥1.5; keep denser line-height only for table cells if needed.

---

### [UI-M3] Heavy uppercase on UI chrome labels

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [ ] Switch `h3`, `.kpi .label`, and `th` toward sentence case (keep brand eyebrow uppercase only if intentional).

---

### [UI-M4] Motion without prefers-reduced-motion

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [ ] Add `@media (prefers-reduced-motion: reduce)` to disable/shorten spinner, pulse, host-card, and shot-image motion.

---

### [UI-M5] Small hit targets on icon buttons and checkboxes

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [ ] Increase `.btn.icon` hit area toward ≥40px (padding/min-size) in `styles.css`.
- [ ] Increase checkbox hit area / label padding for easier targeting.

---

### [UI-M6] Topbar status badge cluster competes with hierarchy

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/components/Layout.tsx`

#### Subtasks

- [ ] Move secondary diagnostics (DEV/DB/Scanner/nmap/read-only) into a compact System control; keep scan progress + critical banners inline.

---

### [UI-M7] Radius levels undocumented / inconsistent naming

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [ ] Define `--radius-sm/md/lg/pill` (or equivalent) in `:root` and map card/control/modal/chip/badge radii to them.

---

### [UI-M8] Changes filters overuse filled primary buttons

Status: Open

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/pages/Changes.tsx`

#### Subtasks

- [ ] Restyle range/type filter chips to outline/selected (not filled primary); reserve `.btn.primary` for page CTAs.

---

### [Perf-M1] All routes eagerly imported; no React.lazy / Vite chunks

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `frontend/src/App.tsx`, `frontend/vite.config.ts`

#### Subtasks

- [ ] Convert page imports in `App.tsx` to `React.lazy` + `Suspense`.
- [ ] Optionally add Vite `manualChunks` for vendor vs app in `vite.config.ts`.

---

### [Perf-M2] Scheduler retention holds one long DB session across FS cleanup

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/core/scheduler.py`, `backend/app/core/retention.py`

#### Subtasks

- [ ] Commit/finish DB deletes in `run_retention` before filesystem cleanup.
- [ ] Run capture-dir / raw cleanup outside the scheduler `session_scope` (or in a separate short scope).

---

### [Perf-M3] Missing indexes on retention filters (`last_seen`, `expires_at`)

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/models.py`, `backend/app/core/retention.py`

#### Subtasks

- [ ] Add index on `Device.last_seen` in `backend/app/models.py`.
- [ ] Add index on `UserSession.expires_at` in `backend/app/models.py`.
- [ ] Add Alembic migration for the new indexes.

---

### [Perf-M4] Web-capture concurrency settings unused (sequential probes)

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/settings_store.py`, `backend/app/core/web_capture/runner.py`

#### Subtasks

- [ ] Wire `http_concurrency` / `screenshot_concurrency` into bounded parallel work in `web_capture/runner.py`, or remove the unused settings fields.

---

### [Perf-M5] Dashboard/exposed-ports builds unbounded port aggregation

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/api/dashboard.py`

#### Subtasks

- [ ] Limit `exposed_ports` aggregation to top-N in SQL (or early cut) for dashboard.
- [ ] Paginate or cap `GET /api/exposed-ports` instead of returning the full ranked set.

---

### [Perf-M6] `/api/devices/uuids` full-loads matching devices then caps at 4096

Status: Open

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/api/devices.py` (`list_device_uuids`)

#### Subtasks

- [ ] Select only `uuid` (and sort keys) with SQL filter/sort shared with the list path.
- [ ] Apply the 4096 cap in SQL (`LIMIT`) before materializing the full match set.

---

## 🟢 Low

*(none open)*

---

## ✅ Completed (archived)

Completed findings live in `todo-archive/`. This file keeps an index only — not full history.

| Archive file | Period | Entries | Link |
|--------------|--------|---------|------|
| completed-summary.md | summary | 13 | [open](todo-archive/completed-summary.md) |

**Total completed:** 13

---

*Open tasks derived from audit/review reports in `docs/`. Use `22-todo-sync-orchestrator` to refresh. Completed history: `todo-archive/`.*
