# UX Flow Review Report

## Executive Summary

| Field | Value |
|-------|--------|
| **Audit topic/scope** | UX flows (navigation, multi-step flows, error & recovery paths, loading and state transitions, destructive actions, persistence) |
| **Date of audit** | 2026-10-08 |
| **Overall score (1-10)** | 6.5 |
| **UX flow maturity level** | Early Production |
| **Severity distribution** | Critical: 0, High: 6, Medium: 7, Low: 3 |
| **Total number of findings** | 16 |

Primary journeys (login, dashboard → devices/scans, scan/web-capture dialogs, settings tabs, data import confirmation) are coherent and usually provide loading, empty, and error surfaces. The largest friction clusters are first-run setup state persistence, silent session expiry, and several destructive or irreversible actions that run without confirmation or without failure feedback after confirm. URL-backed filters on Devices and Changes are a strength; the setup wizard and many modals are not.

---

## Audit Scope and Methodology

- **Scope:** Entry and navigation flows, first-run setup wizard, primary inventory/scan/web-capture journeys, settings and admin actions, error/recovery paths, loading states, and destructive actions.
- **Method:** Walkthrough of key flows using the UX flow checklist; review of routing (`frontend/src/App.tsx`, `frontend/src/components/Layout.tsx`), UI logic, and state handling in the pages/components listed below. Findings tied to real routes, components, and screens only.
- **Rules referenced:** 11-ux-flow-review skill (CHECKLIST, SEVERITY_GUIDELINES, REPORT_TEMPLATE); Laws of UX applied where they justify friction (Zeigarnik, Jacob’s Law, Doherty Threshold, Hick’s Law, Gestalt continuity).

### Mapped entry points and routes

| Route | Screen | Notes |
|-------|--------|--------|
| (boot) | Loading / Backend unavailable | `App.tsx` boot via `/setup/status` |
| (unauth) | Login | Shown when `!user && !setup.needs_admin` |
| (setup) | Setup wizard | When `needs_admin` or admin + `!setup_completed` |
| `/` | Dashboard | |
| `/devices`, `/devices/:uuid`, `/devices/:uuid/web` | Devices, DeviceDetail, WebPreview | |
| `/web` | WebHosts | |
| `/changes` | Changes | Filters in query string |
| `/ports` | Ports | Linked from Dashboard; not in sidebar |
| `/scans` | Scans (+ `?tab=web-captures`) | |
| `/settings`, `/settings/:tab` | Settings | Viewer sees only viewer-safe tabs |
| `*` | Redirect to `/` | Silent |

---

## Findings

### Critical

| # | Flow | Description | Location (route/component) | Impact | Recommendation |
|---|------|-------------|---------------------------|--------|----------------|
| - | - | No critical flow breaks identified (no dead-end with zero exit, no irrecoverable app state). | - | - | - |

### High

| # | Flow | Description | Location | Impact | Recommendation |
|---|------|-------------|----------|--------|----------------|
| H1 | Session expiry → Login | Any non-login `401` dispatches `nf:unauthorized`; `App` sets `user` to `null` and replaces the whole tree with `Login` with no “session expired” message and no recovery hint. Unsaved settings edits are dropped. (Jacob’s Law / unexpected reset.) | `frontend/src/api.ts`; `frontend/src/App.tsx` | User | Show a clear session-expired message on Login (or a toast before redirect). Optionally preserve `location` and return after re-login. |
| H2 | First-run setup - step persistence | Wizard `step` lives only in `useState`. Refresh mid-wizard remounts at step 0 (no user) or step 1 (logged-in admin). Progress indicator resets; user must re-walk steps. (Zeigarnik / state persistence.) | `frontend/src/pages/Setup.tsx`; gate in `frontend/src/App.tsx` | User | Persist step in URL (`?step=`) or sessionStorage; restore on mount when `!setup_completed`. |
| H3 | First-run setup - unsaved form on Next/Skip | Schedule / SMTP / LDAP / Recipients steps embed forms whose Save advances via `onSaved`, but the footer **Next** / **Skip / next** calls `next()` without saving. Edited fields are discarded with no leave warning. | `frontend/src/pages/Setup.tsx` + `ScheduleForm` / `NotificationsForm` / `LdapForm` in `frontend/src/pages/settings/Forms.tsx` | User | On Next, either auto-save, require Save before advance, or confirm discard of dirty form state. |
| H4 | First-run setup - complete failure | `finish` awaits `post('/setup/complete')` then `onDone()` with no `try/catch` or `ErrorBox`. API failure yields no UI feedback (promise rejection only); user may click Finish repeatedly with no explanation. | `frontend/src/pages/Setup.tsx` (`finish`, `BaselineStep`) | User/Technical | Catch errors, show message, keep Finish enabled for retry; disable while busy. |
| H5 | Device delete - silent failure after confirm | After `confirm(...)`, `del` has no error handling. Failure leaves the user on the detail page with no message. | `frontend/src/pages/DeviceDetail.tsx` (`remove`) | User | Wrap in try/catch; show `ErrorBox` / alert; only navigate on success. Same pattern for network/exclusion deletes. |
| H6 | Retention - Run cleanup now | Irreversible history deletion runs on click with **no confirmation** and no error handling on `post('/settings/retention/run')`. | `frontend/src/pages/settings/Forms.tsx` (`RetentionForm`) | User/Business | Confirm with explicit copy (what will be deleted); handle errors; busy state on the button. |

### Medium

| # | Flow | Description | Location | Impact | Recommendation |
|---|------|-------------|----------|--------|----------------|
| M1 | Stop scan / Cancel web capture | Active scan stop and web-capture cancel fire immediately (`post .../cancel`) with no confirmation. A mis-click can abort a long-running job. | `frontend/src/pages/Scans.tsx` (`stopScan`, `wcCancel`) | User | Confirm (“Stop scan #N?” / “Cancel web capture?”) before cancel. |
| M2 | Users - Disable / role change | Disable/Enable and role `<select>` apply immediately via `patch` with no confirmation. Delete has confirm; disable and demote do not. Inconsistent destructive safeguards. | `frontend/src/pages/settings/Admin.tsx` (`UsersSettings`) | User | Confirm disable and role demotion (especially admin → viewer). |
| M3 | Setup - skip networks | Network step allows **Next** with zero networks. Baseline step then errors (“Add at least one network first”) or user finishes with no scope. Complexity pushed to a later step (Tesler’s Law). | `frontend/src/pages/Setup.tsx` + `NetworksSettings` | User | Block Next until ≥1 network, or make Next label “Skip” and warn that baseline/schedule need a network. |
| M4 | Setup / settings forms - double submit | Admin create, network/exclusion Save, and several settings saves lack busy/disabled-while-submitting guards (Login and ScanDialog do this well). | `Setup.tsx` `AdminStep`; `Networks.tsx` / `Exclusions.tsx` modals; parts of `Forms.tsx` | User/Technical | Disable primary actions while request in flight; show “Saving…” / “Creating…”. |
| M5 | Ports discovery | `/ports` is a real route and linked from Dashboard (“See all”), but absent from sidebar `Layout` nav. Users who leave Ports have no persistent nav item for return (browser back only). | `frontend/src/components/Layout.tsx`; `frontend/src/pages/Dashboard.tsx`; `frontend/src/App.tsx` | User | Add Ports to sidebar, or nest under Devices/Dashboard with a clear back affordance on the page. |
| M6 | Scan / web-capture detail open | `openDetail` / `openWcDetail` await GET with no try/catch; failure is silent (no ErrorBox for that action). | `frontend/src/pages/Scans.tsx` | User | Catch and set `err` (same channel as stop/rerun errors). |
| M7 | Edit modals - discard without warning | Network/exclusion/user draft modals close via backdrop click or Cancel with no dirty check; in-progress edits are lost. | `frontend/src/components/ui.tsx` (`Modal`); settings modals | User | Dirty-state confirm on close, or disable backdrop dismiss while dirty. |

### Low

| # | Flow | Description | Location | Impact | Recommendation |
|---|------|-------------|----------|--------|----------------|
| L1 | Unknown URL | `path="*"` navigates to `/` with replace; no “page not found” feedback. | `frontend/src/App.tsx` | User | Soft 404 or toast before redirect. |
| L2 | Disabled “Scan now” | Button disabled when scanner unavailable; reason is in top banner, not next to the control. | `frontend/src/pages/Scans.tsx`; `Layout.tsx` banners | User | Title/tooltip on disabled button mirroring scanner message. |
| L3 | Ports filters not shareable | Search/sort on Ports are local state; network filter is in URL. Refresh loses q/sort. | `frontend/src/pages/Ports.tsx` | User | Mirror Devices: put filter/sort in query params if bookmarking matters. |

---

## Detailed findings (High)

### H1 - Session expiry → Login
**Reproduction:** Stay signed in until session cookie expires (or force a 401 on a polled endpoint such as `/system/status` or `/devices`). Observe UI swap to Login with no explanation; any open settings form edits are gone.  
**Problem:** Unauthorized handling only clears `user`; no user-facing reason.  
**Impact:** Feels like a crash or random logout; trust and task completion suffer.  
**Recommendation:** Message on Login + optional post-login return to prior route.

### H2 - Setup step lost on refresh
**Reproduction:** Start first-run setup, reach Schedule (or later), refresh.  
**Problem:** Step index is not in URL/storage.  
**Impact:** User re-enters earlier steps; unclear whether prior Saves persisted (server may have them; UI does not say).  
**Recommendation:** URL or sessionStorage step + “already configured” hints per step.

### H3 - Wizard Next discards unsaved edits
**Reproduction:** On Schedule (or SMTP/LDAP/Recipients), change fields, click footer **Next** / **Skip / next** without **Save**. Re-open that settings area later (or go Back).  
**Problem:** Footer navigation does not sync with form save.  
**Impact:** Silent loss of configuration work mid-wizard.  
**Recommendation:** Dirty-guard or save-on-next.

### H4 - Finish setup silent failure
**Reproduction:** On Baseline step, click Finish / Skip while `/setup/complete` fails (network/backend error).  
**Problem:** No UI error path on `finish`.  
**Impact:** User cannot tell if setup completed; may leave wizard stuck or retry blindly.  
**Recommendation:** ErrorBox + busy state.

### H5 - Device delete silent failure
**Reproduction:** Confirm delete on Device Detail when DELETE fails (403/network).  
**Problem:** No catch after confirm.  
**Impact:** User believes delete succeeded or sees no feedback.  
**Recommendation:** Surface error; navigate only on success.

### H6 - Retention cleanup without confirm
**Reproduction:** Settings → Retention → **Run cleanup now**.  
**Problem:** Immediate irreversible delete of aged history; no confirm; errors unhandled.  
**Impact:** Accidental data loss; failed runs look like no-ops.  
**Recommendation:** Confirm + error + busy.

---

## Task Consolidation Opportunities

| Group | Finding IDs | Consolidation |
|-------|-------------|----------------|
| Setup wizard reliability | H2, H3, H4, M3, M4 | One setup hardening pass: step persistence, dirty/next semantics, complete error handling, network gate, submit busy states. |
| Auth / session messaging | H1 | Single session-expiry UX on Login + optional return URL. |
| Destructive-action confirmations | H6, M1, M2 | Shared confirm pattern for cancel scan, disable user, role change, retention run (delete already confirms in several places). |
| Mutation error surfacing | H5, M6 | Standard try/catch → `ErrorBox` / shared `err` after confirm or detail fetch. |
| Modal discard | M7 | Optional dirty flag on `Modal` consumers. |
| Navigation completeness | M5, L1, L3 | Ports nav + soft 404 + optional Ports query persistence. |

---

## Recommendations

1. Treat **setup completion and session expiry** as the highest-leverage UX reliability work-they affect every new install and every idle admin session.
2. Align **destructive / irreversible** actions to the existing `confirm()` pattern already used for device/network/exclusion/user delete and web-capture delete.
3. Keep the strong patterns: Login busy state, ScanDialog/WebCaptureDialog busy + errors, DataTransfer explicit confirm checkbox, Devices/Changes URL filters, Layout scan progress link to `/scans`, boot **Retry** on backend unavailable.
4. Prefer **URL or durable state** for multi-step and shareable views (setup step; Ports filters) so refresh and Back behave as users expect (Gestalt continuity / Jacob’s Law).

---

## Phased Fix Plan

| Phase | Focus | Finding IDs | Notes |
|-------|--------|-------------|--------|
| Phase 1 | Critical reliability | H1, H4, H5, H6 | Session message; setup complete errors; delete/cleanup safety and feedback |
| Phase 2 | High-friction flows | H2, H3, M1, M2, M3 | Setup persistence + dirty Next; confirm stop/cancel and user disable/role |
| Phase 3 | Polish & consistency | M4, M5, M6, M7, L1-L3 | Busy states, Ports nav, detail fetch errors, modal discard, soft 404 |

---

## Checklist coverage (summary)

| Area | Result |
|------|--------|
| 1. Entry & Navigation | Mostly sound; Ports off-nav (M5); silent `*` redirect (L1); session kick (H1) |
| 2. Multi-Step Flows | Setup progress UI present; step/state gaps H2-H4, M3 |
| 3. Error & Recovery | Good `ErrorBox`/`Empty`/`Loading` coverage; gaps on finish, delete, detail open, retention |
| 4. Loading & State | Strong on list pages and scan dialogs; weaker on some Save buttons (M4) |
| 5. Destructive Actions | Deletes often confirmed; stop/cancel/disable/cleanup gaps (H6, M1, M2) |
| 6. State Persistence | Devices/Changes/Settings tabs good; Setup/modals/Ports weaker (H2, M7, L3) |
