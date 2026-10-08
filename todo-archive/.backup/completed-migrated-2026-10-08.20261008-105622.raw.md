# Completed findings migrated from todo.md

Migrated: 2026-10-08
Source: todo.md Low section (Status: Completed blocks)
Count: 11

---

## 🟢 Low

### [UX-L1] Unknown URL silently redirects to home

Status: Completed

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/App.tsx`

#### Subtasks

- [x] Replace silent `Navigate` catch-all with a soft 404 message or brief toast before redirect.

---

### [UX-L2] Disabled “Scan now” lacks adjacent reason

Status: Completed

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Scans.tsx`

#### Subtasks

- [x] Add `title`/tooltip on disabled Scan now mirroring `system.scanner.message`.

---

### [UX-L3] Ports search/sort not in URL

Status: Completed

Source: `docs/audit-ux-flow-2026-10-08.md` · `frontend/src/pages/Ports.tsx`

#### Subtasks

- [x] Persist Ports search and sort in query params (alongside existing `network_id`).

---

### [UI-L1] Non-standard font-weights (550 / 650)

Status: Completed

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [x] Normalize `.btn` / `.kpi .value` / related weights to 400/600 (or 500/700) only.

---

### [UI-L2] Spinner-only loading; no table skeletons

Status: Completed

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/components/ui.tsx`

#### Subtasks

- [x] Optional: add skeleton row pattern for primary list tables (Devices/Scans/Changes) when loading.

---

### [UI-L3] Native title-only tooltips

Status: Completed

Source: `docs/audit-ui-2026-10-08.md`

#### Subtasks

- [x] Document acceptance of native `title` tooltips, or add a small tooltip primitive for icon-only controls.

---

### [UI-L4] Hardcoded primary ink `#04201d`

Status: Completed

Source: `docs/audit-ui-2026-10-08.md` · `frontend/src/styles.css`

#### Subtasks

- [x] Add `--accent-ink` (or equivalent) token and use it for `.btn.primary` and `.steps span.current` text.

---

### [Perf-L1] `prior_scope` one scalar query per distinct scan id

Status: Completed

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/core/compare.py`

#### Subtasks

- [x] Prefetch `Scan.port_scope` for IDs present on matched devices instead of per-id scalars in `prior_scope`.

---

### [Perf-L2] No performance budgets, query timing, or resource metrics

Status: Completed

Source: `docs/audit-performance-2026-10-08.md`

#### Subtasks

- [x] Add slow-query or request-latency logging for device list and dashboard endpoints.

---

### [Perf-L3] Screenshot gallery parallel requests without size hints

Status: Completed

Source: `docs/audit-performance-2026-10-08.md` · `frontend/src/components/WebShots.tsx`

#### Subtasks

- [x] Add `decoding="async"` and/or width/height hints on shot `<img>` elements in `WebShots.tsx`.

---

### [Perf-L4] Settings sections re-read from DB every call (no TTL)

Status: Completed

Source: `docs/audit-performance-2026-10-08.md` · `backend/app/settings_store.py`

#### Subtasks

- [x] Optional: add a short process-local cache for `get_section` invalidated on put.
