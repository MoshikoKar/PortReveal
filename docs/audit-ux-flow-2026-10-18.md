# UX Flow Review Report

## Executive Summary

| Field | Value |
|-------|--------|
| **Audit topic/scope** | UX flows (navigation, multi-step flows, error & recovery paths, loading and state transitions, destructive actions, persistence) |
| **Date of audit** | 2026-10-18 |
| **Overall score (1-10)** | 7.5 |
| **UX flow maturity level** | Production-ready |
| **Severity distribution** | Critical: 1, High: 3, Medium: 5, Low: 4 |
| **Total number of findings** | 13 |

Primary journeys (login + session `returnTo`, post-login known-path landing, setup `?step=` with footer dirty leave, scan/web-capture dialogs with discard/busy hints, Devices/Search URL filters, Scans active error+retry, settings form dirty on tab/sidebar click) are coherent. Compared with `docs/ux-flow/audit-ux-flow-2026-10-09.md`, the prior Critical and most Highs are remediated. Remaining breaks center on **incomplete Settings unsaved-work coverage** (entity draft modals + history Back), **Setup browser-Back dirty bypass**, **WebHosts hard navigations**, and **success feedback styled as error** on Devices.

---

## Audit Scope and Methodology

- **Scope:** Entry and navigation flows, first-run setup wizard, inventory/search/scan/web-capture/vulnerabilities journeys, settings and admin actions, error/recovery paths, loading states, and destructive actions.
- **Method:** Walkthrough against the UX flow checklist; review of routing (`frontend/src/App.tsx`, `frontend/src/components/Layout.tsx`), UI logic, and state handling. Findings tied to real routes, components, and screens only. Graphify used for orientation before file review. Prior report used only to mark remediations.
- **Rules referenced:** 05-ux-flow-review skill (CHECKLIST, SEVERITY_GUIDELINES, REPORT_TEMPLATE); Laws of UX where they justify friction (Jacob’s Law, Zeigarnik, Doherty Threshold, Gestalt continuity).

### Mapped entry points and routes

| Route | Screen | Notes |
|-------|--------|--------|
| (boot) | Loading / Backend unavailable + Retry | `App.tsx` via `/setup/status` |
| (unauth) | Login | Gate; URL unchanged; mid-session 401 sets `returnTo`; unknown paths → `/` after login |
| (setup) | Setup wizard | `needs_admin` or admin + `!setup_completed`; steps via `?step=` (history push) |
| `/` | Dashboard | |
| `/search` | Search | Query/view/sort/at/page in URL; refetch dims results (`aria-busy`) |
| `/devices`, `/devices/:uuid`, `/devices/:uuid/web` | Devices, DeviceDetail, WebPreview | Discrete filters push; debounced `q` uses `replace`; web preview maps nav to Web |
| `/web`, `/remote` | WebHosts, RemoteHosts | Filters largely in URL |
| `/changes`, `/ports`, `/ports/:proto/:port` | Changes, Ports, PortDetail | Discrete filters push; typing `replace` |
| `/vulnerabilities`, `/vulnerabilities/:cve_id` | Vulnerabilities, CveDetail | Filters in URL |
| `/watches`, `/reports` | Watches, Reports | |
| `/scans` | Scans | `?tab=`, `?page=`, `?scan=`; WC history page still local |
| `/settings`, `/settings/:tab` | Settings | `/settings` → networks; dirty guard on tab/sidebar; forbidden → networks + warn |
| `*` | NotFound + link to Dashboard | Authenticated shell only |

### Remediations since 2026-10-09 (not re-filed)

| Prior ID | Status |
|----------|--------|
| C1 Settings form dirty discard | Mostly fixed - tab `confirmDiscard`, sidebar click capture, `beforeunload`; gaps remain (this report C1) |
| H1 Login `/login` → NotFound | Fixed - `isKnownAppPath` + `navigate('/')` |
| H2 Exclusions toggle silent fail | Fixed - `actionError` on list + `ErrorBox` |
| H3 Scans active error-as-empty | Fixed - `ErrorBox` + Retry; skeletons while loading |
| H4 ScanDialog networks load/error | Fixed - `Loading` / `ErrorBox` / empty only when data empty |
| H5 Filter history replace-only | Fixed - Devices/Changes/Ports push discrete filters; `replace` for debounced typing |
| H6 Search stale refetch | Fixed - opacity + `aria-busy`; bulk/export disabled while loading |
| M1 Settings bare `/settings` active tab | Fixed - redirect to `/settings/networks` |
| M2 Web preview nav cue | Fixed - `Layout` maps `/devices/:uuid/web` to Web |
| M3 Setup step history | Fixed - `goTo` pushes; finish clears `step` |
| M4 Viewer forbidden redirect silent | Fixed - `deniedTab` warn banner |
| M5-M8 / L1-L3 (partial) | Double-submit `pending`, run-again/mock confirm, dialog dirty/hints, export busy labels, brand home link |

---

## Findings

### Critical

| # | Flow | Description | Location (route/component) | Impact | Recommendation |
|---|------|-------------|---------------------------|--------|----------------|
| C1 | Settings - unsaved work | Form dirty is guarded for **tab clicks**, **in-app sidebar links**, and **beforeunload**, but (1) **browser Back/Forward** between `/settings/:tab` entries changes `tab` and the effect clears dirty **without** `confirmDiscard`; (2) **Networks / Exclusions / Tokens / Users** draft modals keep their own `dirty` and never report into Settings `formDirty` - leaving via sidebar or another tab unmounts the modal and drops edits with no warning. (Zeigarnik / unexpected reset.) | `/settings/:tab` - `frontend/src/pages/Settings.tsx` (~L36-83, L93-96); `Networks.tsx` / `Exclusions.tsx` / `Tokens.tsx` / `Admin.tsx` `UsersSettings` draft modals | User - silent configuration / draft data loss | Lift entity-modal dirty into Settings (or a shared “block leave” flag); on `popstate`/location change while dirty, `confirmDiscard` and `preventDefault`/restore URL if cancelled |

**Reproduction (C1a):** Settings → Schedule → change a field → browser Back to a prior settings tab (or Forward). Edits gone; no confirm.  
**Reproduction (C1b):** Settings → Networks → Edit → change name → click Devices in sidebar. Modal closes; edits gone; no confirm.

### High

| # | Flow | Description | Location | Impact | Recommendation |
|---|------|-------------|----------|--------|----------------|
| H1 | Setup wizard - browser history | Footer Back/Next uses `leave()` with dirty confirm. Step changes from **browser Back/Forward** update `?step=` directly; `useEffect` clears `formDirty` with no confirm - same silent discard as Settings history. (Jacob’s Law: Back should not trash work quietly.) | `frontend/src/pages/Setup.tsx` (~L124-137) | User - lost SMTP/LDAP/schedule edits mid-setup | Before accepting a history-driven step change while dirty, confirm or block (e.g. `useBlocker` / popstate handler); keep footer `leave()` as today |
| H2 | Web → device web preview | Clickable “no app” / service rows set `window.location.href = /devices/:uuid/web` instead of client `navigate`/`Link`. Full document load; breaks SPA continuity vs RemoteHosts `Link` cards and Devices `nav()`. (Doherty / Jacob’s Law.) | `/web` - `frontend/src/pages/WebHosts.tsx` (~L182, L239) | User - slower transition; loses in-memory Web list scroll/context | Use `useNavigate` or row `Link` (same pattern as Devices table) |
| H3 | Devices - bulk vulnerability check | Success copy (“Vulnerability check queued…”) is passed into `<ErrorBox>` (`alert error`). Failures and successes look the same (red error). Setup/Search use `alert ok` for success. | `/devices` - `frontend/src/pages/Devices.tsx` (~L181-194) | User - thinks the action failed when it succeeded | Split success (`alert ok`) vs error (`ErrorBox`); clear success on next action |

**Reproduction (H1):** Setup → Notifications → edit SMTP without Save → browser Back. Form remounts clean.  
**Reproduction (H2):** Web → expand No web application → click a host row (not the inner link). Full reload to preview.  
**Reproduction (H3):** Devices → select hosts → Check vulnerabilities → red error-styled banner with queue message.

### Medium

| # | Flow | Description | Location | Impact | Recommendation |
|---|------|-------------|----------|--------|----------------|
| M1 | Scans - Web Capture history / snapshots paging | Network scan history `page` and detail `scan` live in the URL. **Web Capture history `wcPage` and snapshots `snapPage` are React state only** - refresh or share loses place. | `/scans`, `/scans?tab=web-captures` - `frontend/src/pages/Scans.tsx` (~L67, L82) | User - lost place; views not bookmarkable | Put `wc_page` / `snap_page` (or reuse `page` per tab) in search params |
| M2 | Scans - tab switch clears URL state | “Network scans” calls `setSearchParams({})`, wiping `page`, `scan`, and any other params. Switching away from a deep-linked scan detail cannot be restored by Back to the same tab URL. | `Scans.tsx` (~L259-261) | User - unexpected reset of scan list/detail context | Preserve or namescope params per tab (`tab` + `page` / `scan`); only clear incompatible keys |
| M3 | Settings - viewer forbidden deep link | Denied admin tab redirects to Networks with `state.deniedTab` warn. **Refresh on Networks clears `location.state`** - banner disappears; user may not recall why they landed there. | `Settings.tsx` (~L87-113) | User - ephemeral explanation | Persist a short query flag (e.g. `?denied=users`) or keep a dismissible local notice |
| M4 | CVE detail - fetch failure | Unknown CVE gets a clear Empty. Other API errors show `ErrorBox` **without Retry** (contrast Scans active lists). | `/vulnerabilities/:cve_id` - `frontend/src/pages/CveDetail.tsx` (~L53-57) | User - weaker recovery | Add Retry calling `reload` beside `ErrorBox` |
| M5 | Devices - selection vs filters | Changing filters clears selection via `useEffect` with no notice. Reasonable, but bulk actions can vanish mid-intent if the user tweaks a filter. | `Devices.tsx` (~L82-86) | User - minor surprise | Optional: toast “Selection cleared” or keep selection when only page changes |

### Low

| # | Flow | Description | Location | Impact | Recommendation |
|---|------|-------------|----------|--------|----------------|
| L1 | Web Capture dialog dirty | `dirty` tracks targets text vs preset only - switching mode or editing then reverting may not prompt; ScanDialog similarly ignores type-only changes. | `WebCaptureDialog.tsx` (~L42-43); `ScanDialog.tsx` (~L51-52) | User - rare silent discard of type/mode choice | Broaden dirty to any change from initial preset |
| L2 | Scans - WC detail modal | `wcDetail` is local state; refresh closes the modal (scan detail uses `?scan=`). | `Scans.tsx` (~L68) | User - minor persistence gap | Optional `?capture=` mirror of `?scan=` |
| L3 | Reports - expand “See all” | Expanded sections are local; refresh collapses. Acceptable for density. | `Reports.tsx` | User - minor | Optional URL flags only if sharing expanded views matters |
| L4 | Error boundary recovery | Render failures offer Reload only (full page), not “Go to dashboard” while staying signed in. | `frontend/src/components/ErrorBoundary.tsx` (~L34) | User - heavier recovery than needed | Secondary link to `/` after reset error state if router is available |

---

## Task Consolidation Opportunities

| Cluster | Finding IDs | Remediation theme |
|---------|-------------|-------------------|
| Unsaved-work / history | C1, H1, L1 | Shared leave-blocker (`confirmDiscard` + popstate/`useBlocker`); report all draft sources into one dirty flag |
| Navigation continuity | H2, M2 | Client-side routing everywhere; preserve namespaced URL params across tabs |
| Feedback honesty | H3, M4 | Success ≠ ErrorBox; errors get Retry |
| URL persistence | M1, M2, L2, L3 | Put pager/detail ids in search params consistently |
| Soft expectations | M3, M5, L4 | Durable denied notice; selection clear cue; softer error-boundary exit |

---

## Recommendations

1. **Close C1 completely** - Settings leave-blocker must cover history and entity draft modals; reuse the same pattern for Setup (H1).
2. **Replace `window.location.href` on WebHosts** with SPA navigation (H2) - small change, high perceived quality.
3. **Fix Devices success styling** (H3) - stop teaching operators that “queued” means failure.
4. **Finish Scans URL model** - WC/snapshot pages and tab switches should not wipe shareable state (M1, M2).
5. **Preserve strengths** - session `returnTo`, login path normalize, Scans active error+retry, ScanDialog networks/load, filter push vs typing replace, modal discard, destructive confirms + `pending`.

---

## Phased Fix Plan

| Phase | Focus | Finding IDs | Notes |
|-------|--------|-------------|--------|
| Phase 1 | Data-loss barriers | C1, H1 | Settings + Setup history/modal dirty coverage |
| Phase 2 | Navigation & feedback | H2, H3, M2, M4 | SPA WebHosts rows; Devices success alert; Scans tab params; CVE retry |
| Phase 3 | Persistence polish | M1, M3, M5, L1-L4 | WC/snap URL pages; denied query; selection cue; dirty breadth; ErrorBoundary |

---

## Checklist coverage (summary)

| Area | Result |
|------|--------|
| 1. Entry & navigation | Strong: NotFound, login landing, Web nav cue, brand home; WebHosts hard nav (H2); Scans tab wipe (M2) |
| 2. Multi-step flows | Setup progress + footer dirty good; history dirty bypass (H1); Settings incomplete (C1) |
| 3. Error & recovery | Scans/Exclusions/ScanDialog solid; Devices success-as-error (H3); CVE retry gap (M4) |
| 4. Loading & transitions | Skeletons/busy cues on major lists; Search refetch dimmed |
| 5. Destructive actions | Confirms + in-flight disable widely present |
| 6. State persistence | Many lists URL-backed; WC/snap pages and entity drafts still leak (M1, C1, L2) |

---

## Prior audit delta (2026-10-09 → 2026-10-18)

Fixed / no longer reported as open: login path NotFound; exclusions toggle silent fail; scans active error-as-empty; ScanDialog networks gap; list filter replace-only history; search stale refetch; settings bare URL / web nav cue / setup step push / viewer denied silence; most double-submit and dialog dirty gaps.

New or newly prioritized: incomplete Settings dirty (entity modals + history) as C1; Setup history dirty (H1); WebHosts `window.location` (H2); Devices vuln success via ErrorBox (H3); Scans WC/snap URL and tab wipe (M1-M2).
