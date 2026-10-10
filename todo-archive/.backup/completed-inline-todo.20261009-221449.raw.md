# Completed inline blocks extracted from todo.md (2026-10-09)

Source: todo.md Medium + Low Status: Completed findings before archive-organize.

## ðŸŸ¡ Medium

### PR09-M1 â€” Single app process is a deliberate SPOF

Status: Completed (2026-10-09)

#### Subtasks

- [x] Document single-process SPOF / HA non-goal clearly in `README.md`
- [x] Add or extend a test covering in-flight scan recovery after process restart

---

### PR09-M2 â€” No Compose resource limits or capacity targets

Status: Completed (2026-10-09)

#### Subtasks

- [x] Add memory/CPU limits for `app` (and `db` if appropriate) in `docker-compose.yml`
- [x] Document expected host sizing for full-port + web-capture workloads in `README.md`

---

### PR09-M3 â€” APP_SECRET_KEY may be empty in production

Status: Completed (2026-10-09)

#### Subtasks

- [x] Fail fast at boot when `APP_ENV=production` and `APP_SECRET_KEY` is empty (`backend/app/config.py` or lifespan)
- [x] Update `.env.production.example` so `APP_SECRET_KEY` is required (not blank)

---

### PR09-M5 â€” No metrics, tracing, or correlation IDs beyond slow-request logs

Status: Completed (2026-10-09)

#### Subtasks

- [x] Export basic counters (HTTP status, scan duration/outcome, queue depth) from the backend

---

### PR09-M6 â€” No frontend or end-to-end automated tests

Status: Completed (2026-10-09)

#### Subtasks

- [x] Add a smoke e2e (or Playwright) covering login â†’ dashboard â†’ devices list

---

### PR09-M7 â€” Privacy/compliance posture is informal

Status: Completed (2026-10-09)

#### Subtasks

- [x] Document data categories (inventory, accounts, screenshots), retention knobs, and access/offboarding in `README.md` or `docs/`

---

### PR09-M9 â€” Windows production stop force-kills the process

Status: Completed (2026-10-09)

#### Subtasks

- [x] In `scripts/run.ps1`, attempt graceful stop before `Stop-Process -Force`
- [x] Document that `-Stop` may hard-kill and relies on in-flight scan recovery in `README.md`

---

## ðŸŸ¢ Low

### PR09-L1 â€” No LICENSE file

Status: Completed (2026-10-09)

#### Subtasks

- [x] Add an explicit `LICENSE` or INTERNAL-USE notice (and align `README.md` License section)

---

### PR09-L2 â€” Log format is plain text, not structured JSON

Status: Completed (2026-10-09)

#### Subtasks

- [x] In `backend/app/logging_setup.py`, add optional JSON formatting behind `LOG_FORMAT=json`

---

### PR09-L3 â€” Windows production depends on interactive Task Scheduler session

Status: Completed (2026-10-09)

#### Subtasks

- [x] Document Windows Task Scheduler failure modes and prefer Linux Docker host for unattended uptime in `README.md`

---

### PR09-L4 â€” No dedicated on-call/runbook beyond README troubleshooting

Status: Completed (2026-10-09)

#### Subtasks

- [x] Add `docs/runbook.md` with restore, secret rotation, and failed-migration steps

---
