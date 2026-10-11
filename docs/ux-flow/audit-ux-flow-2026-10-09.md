# UX Flow Review Report

## Executive Summary

| Field | Value |
|-------|--------|
| **Audit topic/scope** | UX flows (navigation, multi-step flows, error & recovery paths, loading and state transitions, destructive actions, persistence) |
| **Date of audit** | 2026-10-09 |
| **Overall score (1–10)** | 6.0 |
| **UX flow maturity level** | Early Production |
| **Severity distribution** | Critical: 1, High: 6, Medium: 8, Low: 4 |
| **Total number of findings** | 19 |

Primary journeys (login with session-return, setup with `?step=` + dirty leave, scan/web-capture dialogs, devices/search URL filters, destructive confirms on delete/stop/retention/import) are coherent. Compared with `docs/audit-ux-flow-2026-10-08.md`, several prior High items are fixed (session expiry copy + return path, setup step URL, setup dirty leave, retention confirm, device-delete errors, stop/cancel confirms, modal discard, NotFound page). Remaining breaks center on **silent settings data loss**, operator-facing **error-as-empty** on Scans, and **inconsistent browser-Back / history** across list pages.

---

## Audit Scope and Methodology

- **Scope:** Entry and navigation flows, first-run setup wizard, inventory/search/scan/web-capture journeys, settings and admin actions, error/recovery paths, loading states, and destructive actions.
- **Method:** Walkthrough against the UX flow checklist; review of routing (`frontend/src/App.tsx`, `frontend/src/components/Layout.tsx`), UI logic, and state handling. Findings tied to real routes, components, and screens only. Graphify used for orientation before file review.
- **Rules referenced:** 05-ux-flow-review skill (CHECKLIST, SEVERITY_GUIDELINES, REPORT_TEMPLATE); Laws of UX where they justify friction (Jacob’s Law, Zeigarnik, Doherty Threshold, Gestalt continuity).

### Mapped entry points and routes

| Route | Screen | Notes |
|-------|--------|--------|
| (boot) | Loading / Backend unavailable + Retry | `App.tsx` via `/setup/status` |
| (unauth) | Login | Gate; URL unchanged; mid-session 401 sets `returnTo` |
| (setup) | Setup wizard | `needs_admin` or admin + `!setup_completed`; steps via `?step=` |
| `/` | Dashboard | |
| `/search` | Search | Query/view/sort/at/page in URL (push history) |
| `/devices`, `/devices/:uuid`, `/devices/:uuid/web` | Devices, DeviceDetail, WebPreview | Filters use `replace` |
| `/web` | WebHosts | Filter state mostly local |
| `/changes` | Changes | Filters use `replace` |
| `/ports`, `/ports/:proto/:port` | Ports, PortDetail | Filters use `replace` |
| `/watches` | Watches | |
| `/reports` | Reports | |
| `/scans` | Scans | `?tab=web-captures`; page/detail local |
| `/settings`, `/settings/:tab` | Settings | Viewer-forbidden tabs → Networks |
| `*` | NotFound + link to Dashboard | Authenticated shell only |

---

## Findings

### Critical

| # | Flow | Description | Location (route/component) | Impact | Recommendation |
|---|------|-------------|---------------------------|--------|----------------|
| C1 | Settings configuration | Schedule / Scan profiles / Web capture / Notifications / LDAP / Retention / Presence forms compute `dirty` (and Setup wires `onDirtyChange` + confirm). Settings mounts forms via tab `NavLink` with **no dirty guard** — switching tabs or leaving Settings discards unsaved edits without warning. | `/settings/:tab` — `frontend/src/pages/Settings.tsx`; `frontend/src/pages/settings/Forms.tsx` (`useForm` / `useReportDirty`); contrast `Setup.tsx` `leave()` | User — silent configuration data loss (Zeigarnik / unexpected reset) | Lift dirty to Settings (or block nav when dirty); reuse Setup `leave()` / `confirmDiscard` before unmounting a dirty form |

**Reproduction (C1):** Open Settings → Schedule (or LDAP). Change a field without Save. Click another settings tab or sidebar Devices. Edits are gone; no confirm.

### High

| # | Flow | Description | Location | Impact | Recommendation |
|---|------|-------------|----------|--------|----------------|
| H1 | Login → app | Login is not a route. Unauthenticated `/login` (or any unknown path) shows Login while keeping the URL. After login with no `returnTo`, `<Routes>` mounts on that path → NotFound. (Jacob’s Law.) | `frontend/src/App.tsx` (`onLoggedIn`, `path="*"`) | User — successful sign-in lands on “Page not found” | After login with no `returnTo`, `navigate('/', { replace: true })` when pathname is not a known app route; or rewrite unauth URLs to `/` |
| H2 | Settings → Exclusions toggle | Inline enable/disable calls `save()`, which sets `saveError`, but list page only shows `error \|\| actionError`. `saveError` is rendered only inside the draft Modal. Failed toggle snaps checkbox back with no message. | `/settings/exclusions` — `frontend/src/pages/settings/Exclusions.tsx` | User — silent failure; unclear whether exclusion is active | Surface toggle failures via `actionError` (or shared banner); optional optimistic UI with rollback + message |
| H3 | Scans / Web captures — active lists | `active.error` / `wcActive.error` are never rendered. Missing data falls through to empty arrays → “No scan running or queued.” History does show errors. | `/scans`, `/scans?tab=web-captures` — `frontend/src/pages/Scans.tsx` | User/Business — operator believes system is idle when polling failed | Show `ErrorBox` + retry when active fetch errors; do not treat error as empty |
| H4 | Scan now — Networks targets | `useApi('/networks')` loading/error unused. Empty list shows “No networks configured…” even on API failure; no spinner while loading. | `frontend/src/components/ScanDialog.tsx` (opened from Scans, Devices, Search, DeviceDetail) | User — cannot distinguish misconfig vs outage | Show `networks.error` / `Loading` while loading; keep empty copy only when `data.length === 0` |
| H5 | Devices / Changes / Ports filters vs Search | Devices, Changes, Ports call `setSp(..., { replace: true })` so browser Back leaves the page instead of undoing the last filter. Search pushes history and Back restores prior query. | `Devices.tsx`, `Changes.tsx`, `Ports.tsx` vs `Search.tsx` | User — unexpected navigation; filters feel non-undoable (Jacob’s Law) | Push history for meaningful filter changes; keep replace only for debounced typing if needed |
| H6 | Search — refetch | `setLoading(true)` runs on query/page/sort change, but UI shows `<Loading />` only when `loading && !results`. Prior results stay fully interactive with no busy cue. | `/search` — `frontend/src/pages/Search.tsx` | User — may export/scan/capture against stale hosts mid-refresh (Doherty) | Overlay/dim list when `loading && results`; disable bulk actions while loading |

**Reproduction (H1):** Sign out → open `/login` → sign in → see NotFound for `/login`.  
**Reproduction (H3):** Force `/scans/active` to fail → open Scans → empty active card, no error.

### Medium

| # | Flow | Description | Location | Impact | Recommendation |
|---|------|-------------|----------|--------|----------------|
| M1 | Settings entry | Sidebar links to `/settings`. Content defaults to Networks, but tab `NavLink`s are `/settings/{id}`, so none match `/settings` — no tab appears active. | `Layout.tsx` NAV; `Settings.tsx` | User — unclear which section is selected | Link sidebar to `/settings/networks`, or redirect `/settings` → `/settings/networks` |
| M2 | Web preview nav cue | Active nav uses first prefix match. `/devices/:uuid/web` matches Devices before Web; breadcrumb starts with Web. | `Layout.tsx` `activeNav`; `WebPreview.tsx` | User — location cue disagrees with breadcrumb | Prefer longest match, or special-case `/devices/*/web` as Web |
| M3 | Setup wizard — browser Back | Steps use `setSp(..., { replace: true })`. In-app Back changes `?step=`; browser Back does not undo steps the same way. Refresh still restores step (good). | `frontend/src/pages/Setup.tsx` `goTo` | User — Back ≠ previous step (Jacob’s Law) | Push step changes into history, or document that only footer Back moves steps |
| M4 | Viewer settings deep link | Forbidden/unknown tab → `<Navigate to="/settings/networks" replace />` with no message. | `Settings.tsx` | User — shared admin URL looks like a soft failure | Show “Admin only” / access notice before or instead of silent redirect |
| M5 | Destructive list actions — double-submit | Confirms exist for network/exclusion/token/watch delete and scan stop/cancel, but buttons stay enabled during the request (unlike DeviceDetail delete / form `saving`). | `Networks.tsx`, `Exclusions.tsx`, `Tokens.tsx`, `Watches.tsx`, `Scans.tsx` | User/Technical — duplicate cancel/delete requests | Disable action buttons while in flight |
| M6 | Users create / LDAP Test | Create user and LDAP “Test connection” lack busy/disabled-while-pending (forms Save already guarded). | `Admin.tsx` `UsersSettings`; `Forms.tsx` `LdapForm` | User — possible duplicate creates / parallel tests | Mirror Networks modal: `disabled={saving}` + “Creating…” / “Testing…” |
| M7 | Scans / WebHosts persistence | Scans history page and detail modals are local state (only `tab` in URL). WebHosts `q` / “no app” filters are `useState` only. Refresh loses place. | `Scans.tsx`; `WebHosts.tsx` | User — lost place; views not shareable | Put `page` / optional `scan=` in params (pattern: WebPreview `?capture=`); persist WebHosts `q` in URL |
| M8 | Run again / Mock reset | History “Run again” starts a new scan with no confirm (`rerunBusy` only). Dev “Reset scenario” posts with no confirm and no error handling. | `Scans.tsx` `runAgain`; mock reset button | User — accidental deep/full rescans; silent mock reset failure | Confirm for `full` (optionally all types); confirm + try/catch for mock reset |

### Low

| # | Flow | Description | Location | Impact | Recommendation |
|---|------|-------------|----------|--------|----------------|
| L1 | Scan / Web Capture dialogs | Cancel / backdrop close without `dirty` / `confirmDiscard` (settings modals use it). | `ScanDialog.tsx`; `WebCaptureDialog.tsx` | User — minor loss of typed targets | Pass `dirty` when selection/targets differ from initial |
| L2 | Start scan / capture disabled | Primary CTA disabled when `!ready` with no title/hint (unavailable case does explain on Scans page). | `ScanDialog.tsx`; `WebCaptureDialog.tsx` | User — unclear why Start is dead | Hint: “Select at least one network” / “Enter targets” |
| L3 | Search export / bulk labels | Export has no busy state; bulk disables buttons but labels stay “Scan results” / “Capture web”. | `Search.tsx` | User — weak in-progress feedback | “Exporting…” / “Loading hosts…” |
| L4 | Brand / leftover setup query | Brand block is not a home link. After setup finish, `?step=N` can remain on the landing URL (harmless but noisy). | `Layout.tsx`; `Setup.tsx` / `App` post-boot | User — minor convention gap | Make brand a Link to `/`; clear `step` on setup complete |

---

## Task Consolidation Opportunities

| Cluster | Finding IDs | Remediation theme |
|---------|-------------|-------------------|
| Dirty navigation | C1, L1 | Settings-level (and dialog) dirty barrier; reuse Setup / `confirmDiscard` |
| Silent empties / errors | H2, H3, H4 | Never present API failure as empty success; banner + retry |
| History & URL consistency | H1, H5, M1, M3, M7, L4 | Normalize post-login landing; align push vs replace; persist list/filter state in URL |
| Nav / location cues | M2, M4 | Correct active nav for web preview; explain forbidden settings redirect |
| Busy / double-submit | M5, M6, L2, L3 | In-flight guards and labels on destructive and test actions |
| Accidental job starts | M8 | Confirm before re-run / mock reset |

---

## Recommendations

1. **Ship C1 first** — settings dirty barrier is the only Critical and reuses patterns already proven in Setup.
2. **Treat “error as empty” as an operator-safety theme** — Scans active lists and ScanDialog networks can hide outages during incidents.
3. **Standardize history policy** — pick one rule (e.g. push for discrete filter changes, replace for debounced search typing) and apply across Devices, Changes, Ports, Search, Setup.
4. **Keep strengths** — session-expired Login + `returnTo`, Setup `?step=` + dirty leave, NotFound with Dashboard CTA, modal `confirmDiscard`, retention/import confirms, DeviceDetail delete busy+error.

---

## Phased Fix Plan

| Phase | Focus | Finding IDs | Notes |
|-------|--------|-------------|--------|
| Phase 1 | Critical + operator-visible failures | C1, H2, H3, H4 | Dirty settings guard; surface exclusion toggle / active-scan / networks-load errors |
| Phase 2 | High-friction navigation & stale UI | H1, H5, H6, M1, M2, M3 | Post-login landing; history consistency; search loading cue; settings/web nav cues |
| Phase 3 | Polish & consistency | M4–M8, L1–L4 | Busy guards, URL persistence, confirms, microcopy |

---

## Prior audit delta (2026-10-08 → 2026-10-09)

Fixed / no longer reported: session expiry without message or return path; setup step only in React state; setup dirty Next/Skip without confirm; setup finish silent failure; device delete silent failure; retention cleanup without confirm; stop/cancel without confirm; Ports missing from sidebar; silent `*` redirect to `/`; several modal discard gaps.

New or newly prioritized: Settings dirty discard (C1); login URL → NotFound (H1); exclusions toggle silent fail (H2); scans active error-as-empty (H3); ScanDialog networks load gap (H4); replace vs push filter history (H5); search stale results (H6).
