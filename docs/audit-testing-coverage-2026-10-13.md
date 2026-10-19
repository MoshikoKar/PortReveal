# Testing & Coverage Review Report

## Executive Summary

| Field | Value |
|-------|--------|
| **Audit topic/scope** | Testing strategy, independence, test data isolation, coverage of critical paths (including scan-command integrity / injection resistance), test quality |
| **Date of audit** | 2026-10-13 |
| **Overall score (1-10)** | 7.0 |
| **Testing maturity level** | Early Production |
| **Severity distribution** | Critical: 0, High: 2, Medium: 5, Low: 4 |
| **Total number of findings** | 11 |

Backend testing is a real strength: ~231 pytest cases under `backend/tests/`, per-test SQLite isolation via `conftest.py`, mock scanner by default, and CI that runs `pytest` + Ruff on every PR. Auth, change detection, scan pipeline (mock), intel, and data-transfer paths are well exercised. The main gaps are a missing **nmap invocation-contract** regression (list argv / no shell / targets only via `-iL`), no coverage of **scan-settings injection rejection** at the API, no frontend unit tests, and no coverage reporting or e2e in CI. Maturity is early production-solid for domain logic, not yet locked down for security-regression on subprocess surfaces.

---

## Audit Scope and Methodology

- **Scope:** Test roots (`backend/tests/`, opt-in e2e), runners/config (`backend/pyproject.toml`, root `package.json`, `.github/workflows/ci.yml`), fixtures (`backend/tests/fixtures/`, `helpers.py`, `conftest.py`), and critical paths: auth/CSRF/roles, scan start + nmap argument builders, target validation, compare/change detection, web capture, LDAP, data transfer.
- **Method:** Graphify discovery of scanner/test/auth nodes, then review of real test files and production command-building code. Analysis only-no source or test changes.
- **Rules referenced:** Skill `10-testing-coverage-review` (CHECKLIST, SEVERITY_GUIDELINES, REPORT_TEMPLATE); TEST-001 / TEST-002 / TEST-003 intent (tests for critical paths, independence, isolated test data).
- **User focus:** Integrity of the scan command so injected / malicious arguments cannot reach the nmap (or related) process.

### Strengths observed

- **Isolation (TEST-002 / TEST-003):** `backend/tests/conftest.py` forces `APP_ENV=test`, `SCANNER_MODE=mock`, `BACKGROUND_JOBS=false`, synthetic `APP_SECRET_KEY`, and a fresh SQLite copy per test from a migrated template-no production DB or live nmap required.
- **Auth / API critical path:** `backend/tests/test_api.py` covers setup wizard, login/logout, cookie flags, CSRF, rate limit, viewer read-only, network/exclusion validation (including `cidr` with `; rm -rf`), and scan flow through the API (including refusal of `targets: "10.0.0.1; reboot"`).
- **Domain coverage:** Change detection (`test_change_detection.py`), identity matching, intel/tags/watches, presence, snapshots/retention, data transfer, query language, ops/boot checks, VPN S2S rate caps (`test_vpn_s2s.py`).
- **Partial scan-command safety already tested:**
  - `test_nmap_arguments_are_fixed_and_safe` (`backend/tests/test_scanner.py`) asserts discovery/port arg shapes, no `-PU`, no `-A`, no `--script`.
  - `test_invalid_targets_rejected` parametrizes `$(reboot)` and `1.2.3.4;rm` through `AddressSet.from_specs`.
  - `test_vpn_discovery_args_are_capped_and_serial` / `test_port_args_carry_vpn_max_rate` lock VPN profiles.
  - Module contract in `backend/app/scanner/nmap_scanner.py`: fixed allow-list args, `subprocess` list form, targets via temp `-iL` file; `ScanSettings` documents “no raw nmap arguments” with `timing: Literal["polite","normal","fast"]`.
- **CI:** `.github/workflows/ci.yml` runs backend pytest + Ruff; frontend typecheck/eslint/build. Root `npm test` → pytest.

---

## Findings

### Critical

| # | Description | Location (file path, test/code) | Impact | Recommendation |
|---|-------------|--------------------------------------|--------|----------------|
| - | None | - | - | Test suite does not point at production DB/secrets; `conftest.py` and CI env use isolated SQLite + mock scanner. |

### High

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| H1 | **Nmap process invocation contract is untested.** Builders (`build_discovery_args` / `build_port_args` / `build_fixed_port_args`) are unit-tested for flag *content*, but nothing asserts that `NmapScanner._run` always invokes `subprocess.Popen` with a **list** argv, never `shell=True`, always passes targets only via `-iL` + temp file (not interpolated into a shell string), and that the composed `cmd` contains no shell metacharacters or unsafe optional flags (`--script`, `-oA` with attacker paths, etc.). A future refactor that concatenates CIDR/hostname into a shell command would not be caught by today’s builder-only tests. | Code: `backend/app/scanner/nmap_scanner.py` `NmapScanner._run` (~L368-385). Related tests: `backend/tests/test_scanner.py` `test_nmap_arguments_are_fixed_and_safe`; no Popen spy. | Combined (security regression) | Add a focused integrity suite (e.g. monkeypatch `subprocess.Popen`) that: (1) runs discover/scan_ports with crafted targets including `;`, `$(...)`, newlines; (2) asserts `Popen` first arg is a `list`, `shell` not true; (3) asserts `-iL` present and target file contents equal the validated IP list; (4) asserts deny-list of flags (`--script`, `-A`, `-iR`, `--privileged` misuse paths as designed). Keep using mock/bind stubs so CI stays offline. |
| H2 | **Scan settings API does not have injection / closed-set tests.** `ScanSettings.timing` is a Pydantic `Literal`, and numeric fields are bounded, but there is no API test that `PUT` scan settings rejects `timing` values like `--script` / `-T5;id` / unknown strings, rejects out-of-range `top_ports`, or rejects unexpected raw-nmap fields. Notifications/schedule get validation tests in `test_api.py`; scan settings do not. | Schema: `backend/app/settings_store.py` `ScanSettings` (~L88-102). API: `backend/app/api/settings.py` `put_scan_settings`. Tests: schedule `time: "25:00"` → 422 in `test_api.py`; no analogous scan-settings cases. | Combined | Add API cases: valid `timing` round-trip; invalid timing / out-of-range ports / unknown JSON fields → 422; assert stored settings never contain free-form nmap argv. |

### Medium

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| M1 | **Web-capture helper subprocess argv integrity is untested.** VNC/RDP/RTSP build argv lists with `ip`/`port` interpolated into strings (`f"{ip}::{port}"`, `f"/v:{ip}:{port}"`, ffmpeg `-i`). Production code uses list form (no `shell=True` found under `backend/`), but tests mock `_run_freerdp` / tools rather than asserting the constructed argv cannot be twisted by a malicious hostname/IP string that somehow bypassed earlier validation. | `backend/app/core/web_capture/vnc.py` (~L72-107); `rdp.py` (~L107+); `rtsp.py`; mocks in `backend/tests/test_web_capture.py` (~L766+). | Technical | Unit-test argv builders with invalid IP/port (expect rejection upstream) and assert final arg lists are structured tokens only-no shell operators, no credential files. |
| M2 | **No frontend unit/component tests.** Frontend CI runs `tsc`, eslint, and production build only. There is no Vitest/Jest (or similar) for React pages/hooks (`frontend/src/pages/*`, `api.ts`, `context.tsx`). Regressions in client auth/CSRF header handling or scan dialog validation rely on manual QA or opt-in e2e. | `.github/workflows/ci.yml` `frontend` job; `frontend/package.json`; no `*.test.*` / `*.spec.*` under `frontend/`. | User / Technical | Add a minimal Vitest (or project-chosen) suite for `api.ts` CSRF/error mapping and one critical form validator; wire `npm test` or a dedicated script into CI. |
| M3 | **E2E smoke is opt-in and not run in CI.** `backend/tests/test_e2e_smoke.py` is marked `e2e` and excluded by default (`pyproject.toml` `addopts = ... -m 'not e2e'`). `npm run test:e2e` is documented in README for contributors but `.github/workflows/ci.yml` never runs it-so “sign in → dashboard → devices” can break without failing PRs. | `backend/pyproject.toml` (~L6-10); `backend/tests/test_e2e_smoke.py`; `package.json` `test:e2e`; CI workflow. | Technical | Add a CI job (or scheduled workflow) that builds frontend, installs Chromium, runs `-m e2e`, or document an explicit non-goal and keep M2 unit coverage for the critical UI paths. |
| M4 | **LDAP auth coverage is narrow.** `backend/tests/test_ldap_auth.py` only asserts connections are unbound on failure paths (`FakeConn`). There is no test that successful LDAP bind maps to a session/user role, or that LDAP-disabled vs enabled login routing behaves correctly through `/api/auth/login`. | `backend/tests/test_ldap_auth.py`; `backend/app/auth/ldap_auth.py`; `backend/app/api/auth.py`. | Technical | Extend with success-path authenticate + one API login test with LDAP mocked enabled. |
| M5 | **Scan-command safety tests are split and incomplete vs. the stated security design.** Existing checks are good but fragmented (`test_scanner.py`, `test_vpn_s2s.py`, `test_identify_ai.py`, API target 422). There is no single named “command integrity” module that documents the threat model (injection via targets, settings, bind device, nmap path) and locks the invariants in one place-making regressions easy to miss in review. | `backend/tests/test_scanner.py` L62-90; `test_vpn_s2s.py` L33-57; `test_api.py` L108-154. | Technical | Consolidate H1/H2 into `backend/tests/test_nmap_command_integrity.py` (or expand `test_scanner.py`) with an explicit docstring listing invariants. |

### Low

| # | Description | Location | Impact | Recommendation |
|---|-------------|----------|--------|----------------|
| L1 | **No coverage reporting or thresholds in CI.** Pytest runs quietly (`-q`) without `--cov` / coverage upload. Hard to enforce “critical modules stay covered” as the suite grows. | `.github/workflows/ci.yml` backend job; `backend/requirements-dev.txt` (no cov gate observed in workflow). | Technical | Optional: add `pytest-cov` with a modest fail-under for `app/scanner` + `app/auth`, or generate a report artifact without gating initially. |
| L2 | **Interface bind values from `nmap --iflist` are trusted into argv (`-e`, `-S`) without a dedicated sanitizer test.** `choose_bind` is well unit-tested for selection logic (`test_nmap_iface.py`), but there is no assert that device/source strings are constrained (e.g. alphanumeric / known iface set) before `_run` appends them. Risk is low if iflist is only from local nmap, but it is still an argv surface. | `backend/app/scanner/nmap_scanner.py` (~L374-381); `backend/app/scanner/nmap_iface.py`; `backend/tests/test_nmap_iface.py`. | Technical | When adding H1 Popen spy, include a bind with a malicious `device` and assert either rejection or safe quoting/validation. |
| L3 | **Frontend lint/typecheck ≠ behavioral tests.** CI catches type errors but not wrong CSRF header names or broken scan dialog state machines. | `.github/workflows/ci.yml` frontend job. | Technical | Covered under M2/M3. |
| L4 | **Test run docs are brief.** README Contributing mentions `npm test` / `npm run test:e2e` but does not spell out mock-scanner isolation or how to add a scanner integrity test. | `README.md` Contributing (~L564-570). | Technical | One short “Testing” subsection: mock default, when e2e runs, pointer to command-integrity tests once added. |

---

## Task Consolidation Opportunities

| Group | Finding IDs | Shared remediation |
|-------|-------------|-------------------|
| Scan / subprocess integrity | H1, H2, M1, M5, L2 | One `test_nmap_command_integrity.py` (+ light web-capture argv tests) covering builders, settings API closed set, Popen contract, bind sanitization. |
| Frontend / e2e gate | M2, M3, L3 | Decide: Vitest critical paths in CI **or** Playwright e2e in CI (or both, thin). |
| Auth completeness | M4 | Extend LDAP success path beside existing local-auth tests in `test_api.py`. |
| Visibility | L1, L4 | Coverage artifact + README testing subsection. |

---

## Recommendations

1. **Treat scan-command integrity as a first-class security regression suite** (addresses the audit ask directly). Prefer testing the *invocation contract* (H1) over only re-checking known-good flag lists-builders already have solid unit coverage.
2. **Keep the current design invariants in tests:** list argv only; no `shell=True`; no user-supplied raw nmap flags; targets only via validated `AddressSet` + `-iL` file; `timing`/`top_ports`/timeouts only from `ScanSettings` closed fields.
3. **Do not weaken isolation:** continue mock scanner + temp SQLite in default CI; integrity tests should monkeypatch `Popen`, not call a real nmap.
4. **Close the frontend behavioral hole** with either unit tests or CI e2e so auth/CSRF UI cannot drift silently.
5. **Optional coverage gate** on `app/scanner` and `app/auth` once the integrity suite lands.

---

## Phased Fix Plan

| Phase | Focus | Finding IDs | Notes |
|-------|--------|-------------|--------|
| Phase 1 | Scan-command integrity | H1, H2, M5 | Popen contract + scan-settings API closed-set tests; consolidate under one module/docstring. |
| Phase 2 | Adjacent subprocess + auth | M1, M4, L2 | Web-capture argv asserts; LDAP success path; bind sanitization in integrity suite. |
| Phase 3 | Frontend / CI quality | M2, M3, L1, L3, L4 | Vitest and/or e2e in CI; coverage report; README testing notes. |

---

## Appendix: Scan-command integrity map (current state)

| Invariant | Implemented in code? | Covered by automated test? |
|-----------|----------------------|----------------------------|
| Args built from fixed helpers, not free-form user nmap CLI | Yes (`nmap_scanner.py`, `ScanSettings`) | Partial (`test_nmap_arguments_are_fixed_and_safe`, VPN tests) |
| No `--script` / `-A` on standard port scan | Yes | Yes (`test_scanner.py`) |
| Targets with `;` / `$(...)` rejected | Yes (`AddressSet` / CIDR validation) | Yes (unit + API) |
| `subprocess` list argv, not shell | Yes (`Popen(cmd, ...)`; no `shell=True` in backend) | **No** (H1) |
| Targets passed only via `-iL` file | Yes (`_run`) | **No** (H1) |
| `timing` closed set only | Yes (`Literal[...]`) | **No API test** (H2) |
| VPN rate caps cannot be bypassed via timing alone | Yes (`vpn_s2s` profile) | Yes (`test_vpn_s2s.py`) |
| Web-capture tools list argv | Yes | **No integrity assert** (M1) |
