# Completed findings migrated from todo.md

Migrated: 2026-10-18
Source: todo.md Critical-Low sections (Status: Completed blocks)
Count: 26

---

## 🔴 Critical

### [UX18-C1] Settings unsaved-work barrier incomplete (history + entity drafts)

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Settings.tsx`, block browser Back/Forward while `dirty` (`confirmDiscard` / `useBlocker`); restore URL if cancelled
- [x] In `frontend/src/pages/settings/Networks.tsx`, report draft-modal dirty into Settings leave barrier
- [x] In `frontend/src/pages/settings/Exclusions.tsx`, report draft-modal dirty into Settings leave barrier
- [x] In `frontend/src/pages/settings/Tokens.tsx`, report create-modal dirty into Settings leave barrier
- [x] In `frontend/src/pages/settings/Admin.tsx` (`UsersSettings`), report create/password modal dirty into Settings leave barrier

---

## 🟠 High

### [UI18-H1] Vulnerabilities filters use badge buttons; KEV not a clear control

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Vulnerabilities.tsx`, render active filter removals as `btn sm toggle on` with `aria-pressed` (not `badge outline`)
- [x] In `frontend/src/pages/Vulnerabilities.tsx`, restyle KEV summary as `Kpi` or toggle card using `.kpi.active` affordance

### [UX18-H1] Setup browser Back/Forward discards dirty step without confirm

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Setup.tsx`, block history-driven step changes while `formDirty` (confirm or `useBlocker`); keep footer `leave()` behavior

### [UX18-H2] WebHosts rows use `window.location.href` instead of SPA navigation

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/WebHosts.tsx`, replace row `window.location.href` navigations (~L182, ~L239) with `useNavigate` or `Link` to `/devices/:uuid/web`

### [UX18-H3] Devices vuln-check success shown via ErrorBox (error styling)

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Devices.tsx`, show vuln-queue success in `alert ok` (or separate success state); keep failures in `ErrorBox`
- [x] In `frontend/src/pages/Devices.tsx`, clear success message on next bulk action or filter change

---

## 🟡 Medium

### [UI18-M1] WebHosts “no application” tables omit `.table-wrap`

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/WebHosts.tsx`, wrap nested no-app host `<table>` elements in `.table-wrap`

### [UI18-M2] Reports SeeAll bypasses `.btn.see-all`

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Reports.tsx`, switch `SeeAll` to `className="btn see-all"` (drop inline button styles)

### [UI18-M3] Accent washes hardcode old teal instead of `--accent`

Status: Completed

#### Subtasks

- [x] In `frontend/src/styles.css`, replace `rgba(45, 212, 191, …)` washes with `color-mix` / `--accent-bg` / `--accent-ring` derived from `--accent`

### [UI18-M4] VulnFacets/Dashboard bar-row buttons use per-row inline chrome resets

Status: Completed

#### Subtasks

- [x] In `frontend/src/styles.css`, add `.bar-row` button/link styles (reset, cursor, focus)
- [x] In `frontend/src/components/VulnFacets.tsx`, remove per-row inline button reset styles
- [x] In `frontend/src/pages/Dashboard.tsx`, drop redundant `bar-row` inline color/chrome resets where CSS covers them

### [UI18-M5] Content links rely on accent color alone until hover

Status: Completed

#### Subtasks

- [x] In `frontend/src/styles.css`, add a persistent non-color cue for body/content links (e.g. underline); keep nav/buttons undecorated

### [UI18-M6] RemoteHosts section headings use undefined `.section-title` + inline type

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/RemoteHosts.tsx`, use plain `h2` (or a token-mapped `.section-title` rule) and remove inline font sizing

### [UI18-M7] Pages still use magic inline gaps instead of `--space-*`

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/WebHosts.tsx`, replace one-off inline `gap`/`padding` with `--space-*` or `.row`/`.stack` where practical
- [x] In `frontend/src/pages/Vulnerabilities.tsx`, replace filter/KPI row magic gaps with `--space-*` utilities

### [UI18-M8] Ports/Scans tabular cards still use spinner Loading instead of SkeletonRows

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Ports.tsx`, use `SkeletonRows` while ports data is loading
- [x] In `frontend/src/pages/Scans.tsx`, use `SkeletonRows` for WC history and snapshots tabular loading states

### [UX18-M1] Scans WC history / snapshots page not in URL

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Scans.tsx`, persist Web Capture history page in search params
- [x] In `frontend/src/pages/Scans.tsx`, persist snapshots page in search params

### [UX18-M2] Scans tab switch wipes `page` / `scan` URL params

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Scans.tsx`, change tab buttons to preserve or namescope params (only clear incompatible keys)

### [UX18-M3] Settings denied-tab banner lost on refresh (`location.state`)

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Settings.tsx`, persist denied notice via query flag (e.g. `?denied=…`) or dismissible durable notice

### [UX18-M4] CveDetail API errors lack Retry

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/CveDetail.tsx`, add Retry control calling `reload` beside non-404 `ErrorBox`

### [UX18-M5] Devices clears selection on filter change with no notice

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Devices.tsx`, show brief “Selection cleared” cue when filters clear selection (or keep selection when only page changes)

---

## 🟢 Low

### [UI18-L2] Checkbox / icon hit targets still under common 44px guidance

Status: Completed

#### Subtasks

- [x] In `frontend/src/styles.css`, optionally enlarge table checkbox hit area and/or document denser-vs-touch density tokens

### [UI18-L3] Dashboard / VulnTrend use raw `div.empty` instead of `<Empty>`

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Dashboard.tsx`, use shared `<Empty>` for ports empty state
- [x] In `frontend/src/components/VulnTrend.tsx` (and `Trend.tsx` if needed), use shared `<Empty>` for empty trend copy

### [UI18-L4] Stale accent fallback hexes (`#5b8def` / `#4a90d9`)

Status: Completed

#### Subtasks

- [x] In `frontend/src/styles.css` `.chip.on`, drop or update `--accent` fallback to `#0ed0d9`
- [x] In `frontend/src/components/DeviceIntel.tsx` sparkline, drop outdated `--accent` fallbacks

### [UI18-L5] `.brand-name` hardcodes `#f7f7f7`

Status: Completed

#### Subtasks

- [x] In `frontend/src/styles.css`, tokenize `.brand-name` color (e.g. `--brand-ink` / `--text`)

### [UX18-L1] Scan/WebCapture dialog dirty ignores type/mode-only changes

Status: Completed

#### Subtasks

- [x] In `frontend/src/components/ScanDialog.tsx`, treat any change from initial preset (including type) as dirty
- [x] In `frontend/src/components/WebCaptureDialog.tsx`, treat mode/target changes from initial preset as dirty

### [UX18-L2] Scans WC detail modal not URL-backed

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Scans.tsx`, optionally mirror scan detail with `?capture=` for WC detail modal

### [UX18-L3] Reports expand “See all” state not URL-backed

Status: Completed

#### Subtasks

- [x] In `frontend/src/pages/Reports.tsx`, optionally persist expanded section flags in URL only if shareable expanded views are needed

### [UX18-L4] ErrorBoundary offers Reload only (no dashboard exit)

Status: Completed

#### Subtasks

- [x] In `frontend/src/components/ErrorBoundary.tsx`, add secondary “Go to dashboard” recovery path after clearing error state
