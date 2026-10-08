# Completed Tasks — Migrated 2026-10-08

> Cut from `todo.md` High section (`Status: Done`). Raw migration dump for archive integrity fix.

**Period:** 2026-10  
**Entries:** 15  
**Source:** todo.md ## High (inline completed)

---
### [UX-H3] First-run setup – Next/Skip discards unsaved form edits

Status: Done

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Setup.tsx`, `frontend/src/pages/settings/Forms.tsx`

#### Subtasks

- [x] Detect dirty Schedule/SMTP/LDAP/Recipients form state when Setup footer Next/Skip is clicked.
- [x] On dirty Next/Skip: auto-save, block until Save, or confirm discard before advancing in `Setup.tsx`.

---

### [UX-H4] First-run setup – complete failure has no UI feedback

Status: Done

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Setup.tsx`

#### Subtasks

- [x] Wrap `finish` (`post('/setup/complete')`) in try/catch and show `ErrorBox` on failure.
- [x] Add busy/disabled state on Finish / Skip–finish while the request is in flight.

---

### [UX-H5] Device delete – silent failure after confirm

Status: Done

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/DeviceDetail.tsx`

#### Subtasks

- [x] Wrap `remove` `del` in try/catch and show error feedback in `DeviceDetail.tsx`.
- [x] Navigate to `/devices` only after successful delete.
- [x] Add the same try/catch + error feedback pattern to network delete in `frontend/src/pages/settings/Networks.tsx`.
- [x] Add the same try/catch + error feedback pattern to exclusion delete in `frontend/src/pages/settings/Exclusions.tsx`.

---

### [UX-H6] Retention – Run cleanup now without confirm or error handling

Status: Done

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/settings/Forms.tsx` (`RetentionForm`)

#### Subtasks

- [x] Add confirmation dialog before `post('/settings/retention/run')` with clear copy of what will be deleted.
- [x] Catch API errors and show failure message in `RetentionForm`.
- [x] Disable the cleanup button and show busy label while the request runs.

---

### [UI-H1] Destructive Delete/Reset styled as ghost (same as Edit)

Status: Done

Source: `docs/audit-ui-2026-10-08.md` · settings tables

#### Subtasks

- [x] Change network Delete and Reset baseline to `btn danger` (keep Edit as ghost) in `frontend/src/pages/settings/Networks.tsx`.
- [x] Change exclusion Delete to `btn danger` in `frontend/src/pages/settings/Exclusions.tsx`.
- [x] Change user Delete to `btn danger` in `frontend/src/pages/settings/Admin.tsx` (`UsersSettings`).

---

### [UI-H2] Narrow viewport sidebar stacks with no collapse/drawer

Status: Done

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`, `frontend/src/components/Layout.tsx`

#### Subtasks

- [x] Add collapsible drawer or compact top-nav behavior for `.sidebar` under 900px in `Layout.tsx` + `styles.css`.
- [x] Preserve visible active nav state when the mobile nav is collapsed or open.

---

### [UI-H3] Modal missing Escape, focus trap, and aria-modal

Status: Done

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/components/ui.tsx` (`Modal`)

#### Subtasks

- [x] Close `Modal` on Escape (mirror Lightbox in `WebShots.tsx`).
- [x] Trap focus inside `Modal` while open and restore focus on close.
- [x] Set `aria-modal="true"` (and initial focus) on the dialog element.

---

### [UI-H4] No shared `:focus-visible` styles for buttons/links/tabs

Status: Done

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [x] Add a shared `:focus-visible` ring (≥3:1) for `.btn`, `.tabs a/button`, and `.nav a` in `styles.css`.
- [x] Strengthen input focus ring (keep `outline: none` only where the ring replaces it).

---

### [UI-H5] Setup step pill labels fail AA contrast on `--panel-3`

Status: Done

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css` (`.steps span`)

#### Subtasks

- [x] Adjust `.steps span` text/background tokens so idle step labels meet ≥4.5:1 contrast.
- [x] Verify done/current step styles still meet AA after the change.

---

### [Perf-H1] Scan compare loads every device with ports and IPs

Status: Done

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/core/compare.py` (`_Applier.run`)

#### Subtasks

- [x] Scope the device load in `_Applier.run` to scan targets / network IPs instead of `select(Device).all()`.
- [x] Keep `selectinload` for ports/IPs only on the scoped device set.

---

### [Perf-H2] Export/import materializes entire inventory tables in memory

Status: Done

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/core/data_transfer.py`, `backend/app/api/data_transfer.py`

#### Subtasks

- [x] Stream export JSONL to ZIP per table instead of buffering all rows in `export_inventory`.
- [x] Import inventory in chunked inserts with shorter transactions in `data_transfer.py`.
- [x] Add a size/row guard before import accepts a ZIP in `backend/app/api/data_transfer.py`.

---

### [Perf-H3] SMTP send runs inside `session_scope`

Status: Done

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/core/notify.py` (`notify_events`)

#### Subtasks

- [x] Load pending events + notification settings, then exit `session_scope` before calling `send_email`.
- [x] Open a short follow-up session to set `notified_at` after successful sends.

---

### [Perf-H4] LDAP connections not unbound on early returns / exceptions

Status: Done

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/auth/ldap_auth.py`

#### Subtasks

- [x] Wrap `ldap_authenticate` service connection in `try`/`finally` with `svc.unbind()`.
- [x] Ensure `ldap_test` unbinds on exception paths after a successful open/bind.

---

### [Perf-H5] Totals via `len(select(id).all())` instead of `COUNT(*)`

Status: Done

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/api/devices.py`, `backend/app/api/system.py`

#### Subtasks

- [x] Replace `len(...select(Event.id)...all())` with `func.count()` in `device_events`.
- [x] Replace `len(...select(ScanHost.id)...all())` with `func.count()` in `device_scans`.
- [x] Replace queued-scan `len(select(Scan.id)...all())` with `func.count()` in `scan_summary`.

---

### [Perf-H6] Aggressive multi-poll against uncached JSON APIs

Status: Done

Source: `docs/audit-performance-2026-10-08.md` · `frontend/src/App.tsx`, `frontend/src/pages/Scans.tsx`, `frontend/src/util.ts`

#### Subtasks

- [x] Gate Scans web-capture fetches with `path: null` when the web-captures tab is inactive (avoid initial load with `pollMs: 0`).
- [x] Slow or pause `/scans/active` polling when no jobs are running/queued in `Scans.tsx`.
- [x] Revisit App `/system/status` 5s interval (lengthen when idle or when Scans is not visible).

---

