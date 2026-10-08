# Network Finder

Lightweight internal web application for **continuous network discovery, service inventory and change detection**.
It answers one question: *what is on the network, what does each device expose, and what changed since the last scan?*

Nmap does the scanning. This application orchestrates it, stores normalized results, compares scans, shows a
SOC-style dashboard and sends concise email alerts on state changes.

It is **not** a vulnerability scanner, EDR, SIEM, CMDB or performance monitor. No exploits, brute force, authentication
attempts or intrusive NSE scripts are ever run.

| | Development | Production |
|---|---|---|
| Start | `npm install && npm run dev` | `docker compose up -d` |
| Database | SQLite `./data/dev.db` (auto-created) | PostgreSQL (container) |
| Scanner | mock (default) or local nmap | nmap inside the app container |
| Docker needed | no | yes |

---

## Development

Requirements: **Node.js 20.19+** and **Python 3.10+** on PATH. Nmap is optional (only for real scans).

```bash
git clone https://github.com/MoshikoKar/network_finder.git && cd network_finder
npm install          # Node dependencies (root + frontend workspace)
npm run dev          # first run also creates .env, backend/.venv, installs Python deps, migrates the DB
```

Open **http://localhost:5173** and log in with **admin / admin** (development seed). The seed also creates the
network *Mock Lab* (`10.99.0.0/24`) and queues a baseline scan, so the dashboard fills within seconds.

| Task | Command |
|---|---|
| Install | `npm install` (optionally `npm run setup` to prepare Python/DB explicitly) |
| Configure | edit `.env` (created from `.env.example`; every value has a safe default) |
| Start everything (hot reload) | `npm run dev` |
| Start one side | `npm run dev:backend` / `npm run dev:frontend` |
| Stop | `Ctrl+C` in the `npm run dev` terminal (stops backend and frontend) |
| Tests | `npm test` |
| Lint / type-check | `npm run lint` (ruff + tsc + eslint) |
| Production frontend build | `npm run build` |
| Reset the dev database | stop the app, then `npm run db:reset` (deletes `data/dev.db`; the seed runs again on next start) |
| Run migrations | `npm run db:migrate` (also runs automatically on every start) |
| Reset the mock scenario | `npm run mock:reset` |

- Backend: FastAPI on `127.0.0.1:8000` with auto-reload (`uvicorn --reload`). API docs: http://localhost:8000/api/docs
- Frontend: Vite on `:5173` with hot module reload; `/api` is proxied to the backend.
- Logs: printed to the terminal and written to `data/logs/app.log`.
- Setup is idempotent and non-interactive. Python requirements are reinstalled only when `backend/requirements*.txt` change.

### Headless / AI-agent usage

Everything is scriptable; no prompts, no GUI, no Docker:

```bash
npm install && npm test                      # full test suite, no network or nmap needed
npm run cli -- status                        # env, database, scanner mode, nmap detection (JSON)
npm run cli -- scan --type standard --network "Mock Lab"   # run a scan synchronously, prints a JSON summary
npm run cli -- scan --type full --targets 10.99.0.10
npm run cli -- create-user alice 'S3cret-pass' --role viewer
curl -s localhost:8000/api/health
```

To exercise the first-run wizard instead of the seed: `DEV_SEED=false npm run dev` with a fresh DB (`npm run db:reset`).

---

## Scanner modes

Set `SCANNER_MODE` in `.env`:

| Value | Behaviour |
|---|---|
| `mock` | **Development default.** Simulated, Nmap-like results. No network traffic. The UI shows a permanent *SIMULATED DATA* banner and every mock scan is labelled. |
| `nmap` | Real scans with the `nmap` executable (`NMAP_PATH`, default `nmap`). If nmap is missing the app still runs and shows the scanner as *unavailable*. |
| `auto` | nmap when found, otherwise mock (clearly labelled). |

**Enable real scanning in development:** install nmap (`sudo apt-get install nmap`, `brew install nmap`, or the Windows
installer), set `SCANNER_MODE=nmap`, restart `npm run dev`. Without root/raw-socket privileges nmap uses TCP connect
probes (no ARP/ICMP, no MAC addresses). Running the backend as root, or setting `NMAP_PRIVILEGED=true` with the
appropriate capabilities, enables full discovery.

**Mock scenario.** Mock results flow through the *same* orchestration, identity matching, comparison, alerting and
snapshot code as real results; only the data source differs. Each completed network scan advances a deterministic scenario:

| Step | Change |
|---|---|
| 0 | baseline (13 hosts) - no alerts |
| 1 | srv-web01 opens TCP/8080; ws-finance07 closes TCP/3389; new host ws-temp25 (TCP/445) |
| 2 | srv-intranet Apache → nginx; srv-db01 OpenSSH 8.9p1 → 9.6p1; ws-dev12 changes IP (same MAC); cam-lobby missing (1st miss) |
| 3 | srv-web01 opens TCP/9000; cam-lobby confirmed *not detected* |
| 4 | cam-lobby reappears; TCP/9000 closes |
| 5 | TCP/9000 opens again (new alert, by design) |
| 6+ | no changes - verifies no duplicate events |

Full-port mock scans additionally reveal a few high ports (e.g. 49664/msrpc).

### Web Capture (optional)

On-demand inventory enrichment for known HTTP(S) and RTSP services on selected devices/IPs. Not part of nmap scans.
Requires Chromium for HTTP screenshots and **ffmpeg** for RTSP still frames / live MJPEG viewing:

```bash
cd backend
.\.venv\Scripts\playwright.exe install chromium   # Windows
# or: playwright install chromium

# ffmpeg (RTSP capture + live Watch)
# Windows: install from https://ffmpeg.org and ensure ffmpeg is on PATH
# macOS: brew install ffmpeg
# Linux: sudo apt-get install ffmpeg
```

Any inventory port whose service is identified as **rtsp** (any port number, not only 554) is captured as a stream page. Open the host’s web preview and click **Watch live** to view the feed in the browser (server-side RTSP→MJPEG proxy).

Toggle and limits: **Settings → Web capture**. Start jobs from Device details, Devices multi-select, or **Scans → Web captures**.

---

## Database

One SQLAlchemy model and one Alembic migration history serve both engines; there is no engine-specific business logic.

- **SQLite (development):** `DATABASE_URL=sqlite:///./data/dev.db`. Relative paths resolve from the repo root. Created
  and migrated automatically. Disposable - `npm run db:reset`.
- **PostgreSQL (production):** `DATABASE_URL=postgresql+psycopg://user:pass@host:5432/db` (`postgresql://` is accepted),
  or the `POSTGRES_HOST/PORT/DB/USER/PASSWORD` variables (used by Docker Compose; avoids URL-escaping passwords).
  Migrations run automatically at startup.

To try PostgreSQL in development, point `DATABASE_URL` at any PostgreSQL server and restart `npm run dev`.

---

## Production (Docker Compose)

Requirements: a Linux VM inside the monitored network with Docker Engine + Compose plugin.

```bash
git clone <repo> network_finder && cd network_finder
cp .env.production.example .env
#   edit .env: set POSTGRES_PASSWORD (required), APP_SECRET_KEY (openssl rand -hex 32), TZ, APP_PORT
docker compose up -d --build
docker compose ps            # app should become "healthy"
docker compose logs -f app
```

Open `http://<vm-ip>:8080` and complete the **first-run wizard**: administrator → network scope(s) → exclusions →
schedule → SMTP → optional LDAP → email recipients → baseline scan.

What Compose provides:

- `db`: PostgreSQL 16, data in the `pgdata` volume, listening on `127.0.0.1` only.
- `app`: built frontend + FastAPI + **nmap** (installed in the image), data in the `appdata` volume (`/data`).
  It uses **host networking** and the `NET_RAW`/`NET_ADMIN` capabilities so nmap can do ARP/ICMP/SYN discovery and see
  MAC addresses on the local segment. The process runs as a non-root user; nmap gets raw-socket access through file
  capabilities. Host networking requires a Linux Docker host (not Docker Desktop on Windows or macOS).
- One application process by design: the scan queue and the scheduler live inside it. Do not run several replicas.

Upgrade: `git pull && docker compose up -d --build` (migrations run automatically).

**HTTPS / reverse proxy.** Put nginx, Caddy or Traefik in front, set `COOKIE_SECURE=true`, and set
`FORWARDED_ALLOW_IPS` to the proxy IP. Example Caddy: `netfinder.corp.local { reverse_proxy 127.0.0.1:8080 }`.

**Secrets.** Keep them in `.env` (never committed). Docker secrets mounted under `/run/secrets/<setting_name>` (e.g.
`postgres_password`, `app_secret_key`) are also read automatically. SMTP and LDAP passwords entered in the UI are
stored encrypted with `APP_SECRET_KEY` and are never returned by the API.

**Backup.** Back up PostgreSQL and the configuration:

```bash
docker compose exec -T db pg_dump -U netfinder netfinder | gzip > netfinder-$(date +%F).sql.gz
cp .env /secure/backup/location/
```

Restore: `gunzip -c backup.sql.gz | docker compose exec -T db psql -U netfinder netfinder`. If `APP_SECRET_KEY` was
empty, also back up `/data/.secret_key` from the `appdata` volume (otherwise re-enter SMTP/LDAP passwords). Temporary
scan files need no backup.

**Migrate inventory from dev to production.** To copy scan results (networks, devices, ports, scans, events,
snapshots, exclusions) without re-running nmap, use the portable ZIP export. Users, app settings, and web-capture
screenshots are not included — re-run web captures on production after import.

```bash
# On the development machine (SQLite):
npm run cli -- export-data .\inventory.zip

# Copy inventory.zip to the production host, then:
docker compose cp inventory.zip app:/tmp/inventory.zip
docker compose exec app python -m app.cli import-data /tmp/inventory.zip --yes
```

The same actions are available in the UI under **Settings → Data** (admin only). Import **replaces** inventory on
the target; production admin users and SMTP/LDAP settings are kept. Both environments must be on the same database
schema revision (normal after `git pull` / migrate).

---

## How it works

```
backend/app/
  scanner/          NmapScanner + MockScanner (same interface), nmap XML parser, scanner status
  core/runner.py    orchestration: targets -> discovery chunks -> service-scan batches -> compare -> notify -> snapshot
  core/compare.py   the single change-detection engine
  core/identity.py  device identity matching
  core/manager.py   persistent scan queue (one scan at a time)
  core/scheduler.py daily schedule + retention (re-reads settings every tick)
  api/              REST endpoints;  auth/  sessions, CSRF, LDAP;  alembic/  migrations
frontend/src/       React UI (Dashboard, Devices, Device details, Changes, Scans, Settings, first-run wizard)
scripts/            npm helpers (setup, dev runner, venv python launcher)
docker/Dockerfile, docker-compose.yml
```

**Scan profiles** (fixed argument lists; no raw nmap options are accepted from the UI or API):

| Profile | nmap | When |
|---|---|---|
| Discovery | `-sn -PE -PP -PS<22 common ports> -PA80,443,3389` (+ ARP on local segments) | part of every scan, or alone |
| Standard | discovery, then `-Pn -sV --top-ports N` (default 3000) on live hosts only | daily schedule / manual |
| Full port | discovery, then `-Pn -sV -p 1-65535` on live hosts | manual only, for hosts/ranges/networks |

**/16 networks.** Exclusions are subtracted *before* nmap runs. The remaining addresses are split into discovery
chunks (default 1,024 addresses = 64 chunks for a /16) that run with bounded parallelism (default 4 nmap processes),
each with a hard timeout. Only live hosts get the service scan, in batches (default 32 hosts) with `--host-timeout`
(default 15 min). One unresponsive host or chunk can never block the scan. Rough expectation for a /16 with 2,000 live
hosts at default settings: discovery 15-30 min, service scan 1-2 h. Tune it under *Settings → Scan profiles*.

**Device identity.** Each device has a permanent `uuid`. Matching order: MAC (if unique in the scan) → same IP
without contradicting MAC or hostname → unique non-generic hostname (detects IP changes without MAC) → otherwise a
**new** device. When in doubt, the engine creates a new device rather than merging two machines.

**Change rules.**
- The first complete standard scan of a network is its **baseline**: no events, no alerts.
- Only *transitions* create events: port opened/closed (re-opening alerts again), service/version changed, device
  discovered/disappeared/reappeared, IP changed. Unchanged state never creates duplicates.
- Ports are reported as *opened* only if a previous port scan covered that port. A new device's ports go into its
  *new device* event, and a device's first full-port scan records high ports silently. Standard scans never close
  ports that only a full scan can see.
- A device is *not detected* only after N consecutive **complete** scans missed it (default 2; *Unconfirmed* in
  between). A failed host ping alone never means offline.
- **Failed or partial scans never remove anything.** A failed scan changes nothing. A partial scan (a chunk or
  batch failed) may add or refresh, but never closes ports or marks devices gone, and it creates no snapshot or
  baseline. A **mass-change guard** skips removals when an implausible share of devices or ports vanishes at once.
- Devices outside every configured network (ad-hoc target scans) are recorded but never emailed.

**History.** Per-scan host observations, all events, and one compressed daily snapshot per network (a few KB) are
kept for the retention period (default **365 days**). Raw nmap XML is not stored, except optionally for N days
for troubleshooting.

**Email.** Uses an internal SMTP relay (port 25, no auth by default; STARTTLS/SSL and auth are optional). One short
email per change, e.g. `[Network Monitor] New port detected` / `Device: server01` / `IP: 10.20.15.22` /
`Port: TCP/8080` / `Service: HTTP` / `Detected: 2026-10-05 14:04`. Above a threshold (default 10 changes per scan)
a single short digest is sent instead.

**Security.** Argon2 password hashing; server-side sessions (HttpOnly, SameSite=Lax, optional Secure cookie, idle +
absolute expiry); CSRF token required on every state-changing request; login rate limiting; two roles (admin / viewer);
admin-only scans and configuration; local admin fallback is always kept when LDAP is enabled; strict validation of
IPs, CIDRs, ranges and hostnames; nmap always runs with a fixed argument list (`subprocess`, no shell; targets via
`-iL`); audit log for user, network, exclusion, scan, SMTP and LDAP changes.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| **nmap missing** - banner *Scanner unavailable* / *nmap not detected* | Install nmap and restart, or use `SCANNER_MODE=mock`. The app itself keeps working. In Docker it is preinstalled. |
| Real scans find hosts but no MAC addresses / ping probes | nmap runs unprivileged. In Docker keep `network_mode: host` + `cap_add`. In dev, run as root or use mock mode. |
| **Database migration failure** at startup | Read the error in the log (`data/logs/app.log`). Dev: `npm run db:reset` recreates the SQLite DB. Prod: check `docker compose logs db` and the `POSTGRES_*` values. |
| **Port already in use** (`8000` / `5173` / `8080`) | Stop the other process, or set `BACKEND_PORT` / `FRONTEND_PORT` in `.env` (dev) or `APP_PORT` (prod). |
| **Backend unavailable** - UI shows *Backend unavailable* / Vite logs `ECONNREFUSED 127.0.0.1:8000` | The backend crashed or is still starting; check the `[backend]` lines in the `npm run dev` output. Try `npm run dev:backend` alone. `curl localhost:8000/api/health` must return `ok`. |
| **Frontend unavailable** - `localhost:5173` does not load | Check the `[frontend]` output; run `npm install` (Node 20.19+ required). Production serves the UI from the app on `APP_PORT`. |
| `python -m venv` fails (Debian/Ubuntu) | `sudo apt-get install -y python3-venv`, then `npm run setup`. |
| Python deps out of date | `npm run setup -- --force` |
| Scan stuck after a restart | Scans running during a restart are marked *failed* automatically (state preserved); start a new one. |
| Login blocked (HTTP 429) | Too many failed attempts; wait 15 minutes (`LOGIN_WINDOW_MINUTES`). |
| Lost admin password | `npm run cli -- create-user rescue 'New-pass-123' --role admin` (prod: `docker compose exec app python -m app.cli create-user ...`). |
