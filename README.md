# Network Finder

Continuous network discovery, service inventory, and change detection for internal
networks. Nmap does the scanning; this app orchestrates it, stores normalized
results, compares scans, shows a dashboard, and can email a daily change summary.

It is **not** a vulnerability scanner, EDR, SIEM, CMDB, or performance monitor.
No exploits, brute force, authentication attempts, or intrusive NSE scripts are run.

| | Development | Production (Windows host) | Production (Linux Docker) |
|---|---|---|---|
| Start | `npm install && npm run setup` then Playwright Chromium, then `npm run dev` | `.\scripts\run.ps1 -Mode production -Background` | `docker compose up -d` |
| Database | SQLite `./data/dev.db` | PostgreSQL (Compose `db` only) | PostgreSQL (container) |
| Scanner | mock (default) or local nmap | host nmap + Npcap | nmap in the app image |
| Docker | not required | Postgres only | app + db |

## Description

Network Finder is for operators who need a clear answer to: *what is on the
network, what does each device expose, and what changed since the last scan?*

Use it on a machine that can see the LAN you care about. Development defaults to
a safe mock scanner (no network traffic). Production uses real nmap with fixed
argument profiles — the UI and API never accept raw nmap options.

## Installation

Requirements: **Node.js 20.19+** and **Python 3.10+** on `PATH`. Nmap is optional
in development (required for real scans).

```bash
git clone https://github.com/MoshikoKar/network_finder.git
cd network_finder
npm install
npm run setup
npm run dev
```

`npm run setup` creates `.env` from `.env.example`, sets up `backend/.venv`,
installs Python dependencies, and migrates the database. On **Windows** it also
runs `scripts/install-capture-tools.ps1` (Playwright Chromium, ffmpeg via winget,
FreeRDP via Scoop) with soft-fail so missing optional tools do not block setup.
Skip that step with `npm run setup -- --skip-capture-tools` or
`NF_SKIP_CAPTURE_TOOLS=1`. Re-run tools alone with `npm run setup:capture-tools`.

Open **http://localhost:5173** and sign in with **admin / admin** (development
seed). The seed also creates the network *Mock Lab* (`10.99.0.0/24`) and queues a
baseline scan so the dashboard fills within seconds.

| Task | Command |
|---|---|
| Install | `npm install` + `npm run setup` (Windows also installs capture tools) |
| Capture tools only (Windows) | `npm run setup:capture-tools` |
| Configure | edit `.env` (safe defaults; created from `.env.example`) |
| Start both sides | `npm run dev` |
| Backend / frontend only | `npm run dev:backend` / `npm run dev:frontend` |
| Tests | `npm test` |
| Lint / type-check | `npm run lint` |
| Production frontend build | `npm run build` |
| Reset SQLite DB | stop the app, then `npm run db:reset` |
| Migrations | `npm run db:migrate` (also runs on every start) |
| Reset mock scenario | `npm run mock:reset` |

- Backend: FastAPI on `127.0.0.1:8000` (`uvicorn --reload`). Docs:
  http://localhost:8000/api/docs (disabled when `APP_ENV=production`)
- Frontend: Vite on `:5173`; `/api` is proxied to the backend
- Logs: terminal and `data/logs/app.log`

## Usage

### CLI and headless checks

```bash
npm install && npm test
npm run cli -- status
npm run cli -- scan --type standard --network "Mock Lab"
npm run cli -- scan --type full --targets 10.99.0.10
npm run cli -- create-user alice 'S3cret-pass' --role viewer
curl -s localhost:8000/api/health
```

To walk the first-run wizard instead of the seed:
`DEV_SEED=false npm run dev` with a fresh DB (`npm run db:reset`).

### Scanner modes

Set `SCANNER_MODE` in `.env`:

| Value | Behaviour |
|---|---|
| `mock` | Development default. Simulated results; no network traffic. UI shows a *SIMULATED DATA* banner. |
| `nmap` | Real scans via `NMAP_PATH` (default `nmap`). App still runs if nmap is missing (scanner *unavailable*). |
| `auto` | nmap when found, otherwise labelled mock. |

For real scans in development: install nmap, set `SCANNER_MODE=nmap`, restart
`npm run dev`. Without raw-socket privileges, nmap uses TCP connect probes (no
ARP/ICMP, no MACs). `NMAP_PRIVILEGED=true` (or root) enables full discovery.

**Mock scenario.** Mock results use the same orchestration and change pipeline as
real scans. Each completed network scan advances a fixed scenario (baseline →
port/service/IP/absence changes → quiet steps). Reset with `npm run mock:reset`.

### Web capture (optional)

Post-scan stills of remote UIs found in inventory: **HTTP(S)** (Playwright),
**RTSP** (ffmpeg), **RDP** (FreeRDP), and **VNC** (ffmpeg or `vncsnapshot`).
One Web Capture job; galleries are split — **Web** (HTTP/RTSP) and **Remote**
(RDP/VNC). Not an nmap stage. Auto-queue after standard/full scans is under
**Settings → Web capture**. Manual jobs from Device details, Devices multi-select,
or **Scans → Web captures**.

| Target | Tool on `PATH` | Install |
|---|---|---|
| HTTP(S) screenshots | Playwright Chromium | Windows: included in `npm run setup` / `npm run setup:capture-tools`. Manual: `backend\.venv\Scripts\python.exe -m playwright install chromium` |
| RTSP stills / live MJPEG, VNC stills | `ffmpeg` | Windows: `npm run setup:capture-tools` (winget) or `winget install ffmpeg` then ensure the `bin` folder is on `PATH`. Linux: `sudo apt-get install -y ffmpeg`. **Preinstalled in Docker.** |
| RDP stills | `wfreerdp` / `sdl-freerdp` (Windows) or `xfreerdp` (Linux) | Windows: `npm run setup:capture-tools` (Scoop `freerdp-nightly` + `wfreerdp` shim). Official FreeRDP does not ship Windows release zips. Linux: `sudo apt-get install -y freerdp2-x11`. **Preinstalled in Docker.** |

Empty credentials only — no password guessing. RDP stills use FreeRDP `/sec:tls`
first so hosts **without NLA** yield a Shodan-style Windows logon-screen bitmap.
Hosts that **require NLA** never draw a desktop before CredSSP, so there is no
frame to capture (shown as auth required). VNC stills need no-auth RFB; password
VNC and non-RFB/`tcpwrapped` ports stay without a frame. Confirm tools with
`ffmpeg -version` and `wfreerdp /version` (or `sdl-freerdp` / `xfreerdp --version`),
then restart the app.

Any inventory port identified as **rtsp** is treated as a stream page; use
**Watch live** on the host preview for the server-side RTSP→MJPEG proxy.

### Search

**Search** queries the stored inventory (nmap results and Web Capture metadata)
with Shodan-style `field:value` terms. Searching never sends traffic to the
network. The Devices search box accepts the same syntax.

- Terms separated by spaces must all match; `OR` (or `|`) and parentheses group;
  a leading `-` or `NOT` negates.
- Numbers: `port:22`, `port:1-1024`, `port:22,80,443`, `score:>=60`.
- Text: substring by default, `*` wildcards, `=` for exact, quotes for spaces
  (`network:"Office LAN"`). Times: `first_seen:<7d`, `last_seen:>30d`.
- A bare word matches IP, hostname, MAC, vendor, OS, tags, service, product,
  version and HTTP title.
- Port terms in one AND group must match the same service:
  `port:22 product:openssh` means OpenSSH on port 22.

```text
port:3389 net:10.0.0.0/8          RDP inside 10/8
tag:camera -zone:iot              cameras outside the IoT zone
http.login:true http.status:200   web login pages
has:tls ssl.cert.expired:true     expired TLS certificates
has:screenshot product:OpenSSH    hosts with a captured still
product:nginx -version:1.25*      nginx not on 1.25.x
score:>=60 new:7d                 high-exposure hosts first seen this week
before:2026-09-01 port:22         point-in-time (daily snapshots)
```

The full field list is under **Search → Show field reference** and
`GET /api/search/fields`. Pick a past date (**As of**) or use `before:YYYY-MM-DD`
to search the daily snapshots instead of current data.

Post-scan enrichment (open services only; no credential guessing) stores
searchable **banners**, **TLS cert** fields, SSH host keys, and **CPE** with
provenance (TCP only; previously stored SNMP sys\* data stays searchable). Web Capture also covers **RDP/VNC** stills when
FreeRDP / VNC tools are available and the service accepts empty auth; browser
VNC gateways (noVNC, Guacamole) are classified as `web-vnc`.

Rule-based **tags** and a **device type** (printer, camera, nas, hypervisor,
domain-controller, database, …) are recomputed after every scan and web
capture; admins can add or pin manual tags. Each device gets an **exposure
score** (0–100) with the factors behind it, weighted by the network **zone**.
Save a query as a **watch** (alert when a new host matches) or **policy** (every
new match is a violation); matches appear in the daily digest.

API (session cookie, or a read-only token from **Settings → API tokens** sent as
`Authorization: Bearer nf_…`; tokens allow GET only):

| Endpoint | Purpose |
|---|---|
| `GET /api/search?q=&view=hosts\|services&sort=&page=&page_size=&at=` | Results |
| `GET /api/search/facets?q=&facets=port,product,tag` | Value counts |
| `GET /api/search/count?q=` | Host and service counts |
| `GET /api/search/export?q=&format=csv\|ndjson` | Streaming export |
| `GET /api/search/fields` | Field reference |
| `GET /api/host/{ip}` | One host document (services, TLS, HTTP, screenshots) |
| `GET /api/reports/exposure` · `rare-services` · `version-skew` · `subnets` · `heatmap` | Reports |
| `/api/saved-searches` | Watches and policies (CRUD) |
| `/api/webhooks` | Outbound event webhooks (admin) |
| `GET /api/events/stream` | SSE event feed |

```bash
npm run cli -- search "port:22 product:openssh"
curl -H "Authorization: Bearer $NF_TOKEN" "localhost:8000/api/search/export?q=tag:camera&format=csv"
curl -H "Authorization: Bearer $NF_TOKEN" "localhost:8000/api/host/10.0.0.5"
```

### Database

One SQLAlchemy model and one Alembic history for both engines.

- **SQLite (dev):** `DATABASE_URL=sqlite:///./data/dev.db` (repo-root relative).
  Disposable via `npm run db:reset`.
- **PostgreSQL (prod):** `DATABASE_URL=postgresql+psycopg://…` or
  `POSTGRES_HOST` / `PORT` / `DB` / `USER` / `PASSWORD` (Compose-friendly).
- **Naming exceptions:** `UserSession` intentionally maps to the concise plural
  table `sessions`, while append-only `AuditLog` intentionally maps to the
  singular table `audit_log`. Do not rename either without a staged migration
  plan that preserves existing data and foreign-key references.
- **PostgreSQL pooling:** each app process keeps 10 base connections and may open
  10 overflow connections, waits up to 30 seconds for a checkout, recycles
  connections after 30 minutes, and verifies connections before use. Size the
  database limit for `(pool_size + max_overflow) × app worker processes` plus
  migration and administrative connections.

Migrations run automatically at startup. GitHub Actions runs pytest and Ruff,
frontend typecheck/eslint, `npm run build`, and (separately) Alembic upgrade +
`alembic check` so regressions and model/migration drift fail the build.

### Production on Windows (host nmap)

Recommended when the scanner is a **Windows PC on the LAN** (Npc + Npcap).
Docker Desktop runs **Postgres only**; the app and nmap stay on the host.

Requirements: Node.js 20.19+, Python 3.10+, nmap+Npc, Docker Desktop, and on
`PATH`: **ffmpeg** (RTSP/VNC) plus **FreeRDP** (`wfreerdp` / `sdl-freerdp`) if you
want RDP stills. Copy `.env.production.example` → `.env.production` and set at
least `POSTGRES_PASSWORD` and `APP_SECRET_KEY`.

`npm run setup` (and production `run.ps1` when tools are missing) installs
Playwright Chromium, ffmpeg, and Scoop FreeRDP for the **same Windows user**
that runs the app:

```powershell
npm install
npm run setup
# or only capture tools:
npm run setup:capture-tools
ffmpeg -version
wfreerdp /version
```

| Task | Command |
|---|---|
| Start (foreground) | `.\scripts\run.ps1 -Mode production` or `npm start` |
| Start (background) | `.\scripts\run.ps1 -Mode production -Background` |
| Skip frontend rebuild | add `-SkipBuild` |
| Force restart | add `-ForceRestart` |
| Stop app (graceful, then forced) | `.\scripts\run.ps1 -Stop` or `npm run stop` |
| Stop app + Postgres | `.\scripts\run.ps1 -Stop -StopDb` |
| Dev via same script | `.\scripts\run.ps1 -Mode dev` or `npm run start:dev` |

Production start loads `.env.production`, starts Compose `db` only, builds the
frontend, migrates, and serves on `APP_PORT` (default **8081**). Background mode
logs to `data/logs/production.log`.

The production host **supervises** uvicorn: app stderr is teed into the log without
killing the PowerShell process (a Windows PowerShell 5.1 pitfall with
`$ErrorActionPreference = Stop`), and if uvicorn or Docker Postgres exits
unexpectedly the script brings Postgres back up and restarts the app until you
`-Stop`. For boot/logon survival, also register Task Scheduler as noted in
`scripts/run.ps1`.

`-Stop` (and `-ForceRestart`) first asks the app to shut down gracefully by creating
`data/network-finder.stop` (and a no-restart marker so the supervisor does not
bring the app back); the app stops its scheduler, scan worker and web-capture
worker and exits. If it has not exited within 45 seconds (hung, or a build older than
this feature), the script falls back to `Stop-Process -Force`. A hard kill is safe for
data: an interrupted scan or capture is marked failed on the next start, its partial
results are discarded, and queued jobs run as normal (see
[Availability and capacity](#availability-and-capacity)).

Set `LOG_FORMAT=json` for newline-delimited JSON application logs suitable for a
log collector; the default is human-readable `text`.

Open `http://localhost:8081` and complete the first-run wizard (admin → networks →
exclusions → schedule → SMTP → optional LDAP → recipients → baseline scan).

**Upgrade**

1. Take a backup set (`.\scripts\backup.ps1`) and record the current Git revision
   (`git rev-parse HEAD`) with the stamp.
2. `git pull`, `npm run setup` (reinstalls capture tools / Chromium when needed), then
   `.\scripts\run.ps1 -Mode production -ForceRestart`.
3. Confirm `/api/health`, sign-in, and a smoke check of inventory before closing the
   window. Migrations run automatically on start.

**Rollback (Windows):** stop the app (`.\scripts\run.ps1 -Stop`). If the new revision
applied a schema migration (or startup failed mid-migration), restore the matching
pre-upgrade backup set and check out the recorded prior revision, then start with
`-SkipBuild` in the foreground — see [docs/runbook/runbook.md](docs/runbook/runbook.md)
(Deployment rollback / Failed migration). If the failure was app-only and the database
schema did not change, `git checkout <prior-sha>` and restart is enough. Do **not** run
`alembic downgrade` against production.

**Task Scheduler** (same Windows user as Docker Desktop / Npcap):

1. Create Task → **Run only when user is logged on**
2. Trigger: At log on (optional 1–2 minute delay)
3. Action: `powershell.exe` with arguments:

```text
-NoProfile -ExecutionPolicy Bypass -File "<repo-root>\scripts\run.ps1" -Mode production -Background -SkipBuild
```

Set **Start in** to `<repo-root>`. Prefer **Do not start a new instance** if already
running.

This Task Scheduler setup is a convenience launcher, not a Windows service. It
does not start until that user logs on; a password/account change can invalidate
the task; Docker Desktop, Npcap, and Chromium must be available to the same user;
and sleep, logout, Windows Update, or a closed interactive session can interrupt
the app. A successful task launch also does not prove that Postgres or the API is
healthy, so monitor the health endpoint and `data/logs/production.log` separately.
For unattended 24×7 operation, prefer the Linux Docker Compose deployment on an
always-on host. If Windows is required, verify the task, Docker Desktop, and API
after every reboot.

### Production (Linux Docker Compose)

Linux Docker host with host networking (not Docker Desktop on Windows/macOS).
Allow build egress to `storage.googleapis.com:443` (Playwright Chromium) plus the
usual package indexes. Inbound TCP `APP_PORT` (default `8081`).

```bash
git clone https://github.com/MoshikoKar/network_finder.git
cd network_finder
cp .env.production.example .env
# Set POSTGRES_PASSWORD, APP_SECRET_KEY (openssl rand -hex 32), TZ, APP_PORT
docker compose up -d --build
docker compose ps
docker compose logs -f app
```

Compose provides PostgreSQL 16 (`pgdata`) and the app image (frontend + FastAPI +
nmap + Playwright Chromium + ffmpeg + FreeRDP) with host networking and
`NET_RAW` / `NET_ADMIN`. One app process only (queue + scheduler live inside it);
see [Availability and capacity](#availability-and-capacity).

`APP_SECRET_KEY` is required in production: the app refuses to start while it is
empty or still the example placeholder. Installs that previously ran without it
used a key generated into the app data volume (`/data/.secret_key`); copy that
file's contents into `APP_SECRET_KEY` so stored SMTP/LDAP passwords stay readable.

**Upgrade and image tags**

Compose builds `network-finder:latest`. Before each upgrade, keep a rollback handle:

```bash
./scripts/backup.sh                                          # Postgres + appdata + env + revision
docker tag network-finder:latest network-finder:previous     # keep last good image
git pull
SHA=$(git rev-parse --short HEAD)
docker compose build
docker tag network-finder:latest "network-finder:${SHA}"     # immutable release tag
docker compose up -d
# Confirm /api/health (JSON status ok), sign-in, smoke inventory
```

**Rollback (Linux):** stop the app (`docker compose stop app`). If a migration ran or
failed, restore the pre-upgrade backup set (Postgres + `appdata`) from the same stamp,
then retag and start the prior image:

```bash
docker tag network-finder:previous network-finder:latest
docker compose up -d --no-build app
```

If the schema did not change, retagging/starting `network-finder:previous` alone is
enough. Full restore steps and migration policy:
[docs/runbook/runbook.md](docs/runbook/runbook.md) (Deployment rollback / Failed migration). Do **not**
run `alembic downgrade` against production. Practice the path on a disposable host or
DB copy before you need it.

**HTTPS:** reverse-proxy to the app, set `COOKIE_SECURE=true` and
`FORWARDED_ALLOW_IPS` to the proxy IP. Production refuses to start with
`COOKIE_SECURE=false` unless `COOKIE_ALLOW_HTTP=true` (trusted plain-HTTP LAN only).

**Secrets:** keep them in `.env` / `.env.production` (never commit). Docker secrets
under `/run/secrets/<setting_name>` are also read. SMTP/LDAP passwords from the UI
are encrypted with `APP_SECRET_KEY` and never returned by the API.

**Backup.** A recoverable set is Postgres + app data (`appdata` / `data/`: web
captures and optional `.secret_key`) + the production env (`APP_SECRET_KEY`) +
the deployed Git revision. Without the matching secret, restored SMTP/LDAP
passwords cannot be decrypted.

| Target | RPO | RTO |
|---|---|---|
| Daily scheduled backup (default) | ≤ 24 hours | ≤ 2 hours (restore drill on a spare host) |

Schedule the script on the production host and copy each set **off-box**:

```bash
# Linux Docker Compose (cron example: 02:15 daily)
chmod +x scripts/backup.sh
./scripts/backup.sh
# 15 2 * * * cd /opt/network_finder && ./scripts/backup.sh >> data/logs/backup.log 2>&1
```

```powershell
# Windows host production (Task Scheduler daily)
.\scripts\backup.ps1
# Keeps ./backups/<timestamp>/{postgres.dump,appdata.tar.gz,env.production,…} for KEEP_DAYS (default 14)
```

Manual one-shot (Linux) if you prefer not to use the script:

```bash
docker compose exec -T db pg_dump -U netfinder -d netfinder -Fc > postgres.dump
docker compose exec -T app tar czf - -C /data . > appdata.tar.gz
cp .env.production /secure/backup/location/
```

Restore steps, validation checklist, and quarterly restore drill:
[operations runbook — Backup set and restore](docs/runbook/runbook.md#backup-set-and-restore).

**Migrate inventory from dev to production** (ZIP export; users/settings/web-capture
screenshots are not included):

```bash
npm run cli -- export-data .\inventory.zip
# Linux Docker:
docker compose cp inventory.zip app:/tmp/inventory.zip
docker compose exec app python -m app.cli import-data /tmp/inventory.zip --yes
# Windows host production:
npm run cli -- import-data .\inventory.zip --yes
```

Also available under **Settings → Data** (admin). Import **replaces** inventory on
the target; keep environments on the same schema revision.

### Availability and capacity

**Single process by design.** One app process holds the scan queue, the scheduler,
and the web-capture worker. High availability (several replicas, failover) is a
non-goal: two processes would run the same schedule and queue twice. The process is
therefore a single point of failure, mitigated by:

- **Automatic restart:** `restart: unless-stopped` (Docker); on Windows, rerun the
  Task Scheduler task or `run.ps1`.
- **Restart recovery:** on start, scans and web captures that were running are marked
  failed ("Interrupted by an application restart") and their partial results are
  discarded, so inventory stays at the last completed scan. Queued jobs are kept and
  run normally. Covered by `backend/tests/test_ops.py`.
- **Monitoring:** watch `/api/health` and `/api/metrics` (below) from outside the host.

**Metrics.** `GET /api/metrics` returns Prometheus text format: API requests by method
and status, request latency, scans finished by type and status, scan duration, scan
and web-capture queue depth, and devices by status. Counters reset when the process
restarts. It requires authentication, so scrape it with a read-only API token
(Settings → API tokens):

```yaml
scrape_configs:
  - job_name: network-finder
    metrics_path: /api/metrics
    authorization: { credentials: nf_xxxxxxxx }   # API token
    static_configs: [{ targets: ["netfinder-host:8081"] }]
```

**Host sizing.** Work runs one scan at a time, with up to `parallelism` concurrent
nmap processes (Settings → Scan profiles, default 4), plus one web-capture job using
up to `http_concurrency` HTTP probes and `screenshot_concurrency` headless Chromium
pages (defaults 3 and 1).

| Workload | CPU | RAM (app) | RAM (Postgres) | Disk |
|---|---|---|---|---|
| Up to a few /24s, default settings | 2 cores | 2 GB | 512 MB | 5 GB |
| /16 inventory, full-port scans, web capture (Compose defaults) | 4 cores | 3 GB | 1 GB | 20 GB |
| Parallelism 8–16, screenshot concurrency 2 | 8 cores | 6 GB | 2 GB | 40 GB+ |

Disk grows mainly with web-capture screenshots and event history, both bounded by the
retention period. Linux Compose enforces `APP_MEM_LIMIT` / `APP_CPUS` (defaults `3g` /
`4`) and `DB_MEM_LIMIT` / `DB_CPUS` (`1g` / `2`); raise them together with parallelism or
screenshot concurrency. An out-of-memory kill behaves like a crash: the restart policy
starts the app again and restart recovery applies.

### Behaviour notes

**Scan profiles** (fixed argument lists):

| Profile | Role |
|---|---|
| Discovery | Host discovery (`-sn` + common probes; ARP on local segments) |
| Standard | Discovery, then `-Pn -sV --top-ports N` (default 3000) on live hosts |
| Full port | Discovery, then `-Pn -sV -p 1-65535` on live hosts (manual) |

Daily schedule (optional discovery then standard), daytime presence scans, and
correlated absence thresholds are configured under **Settings → Schedule**.
The daily schedule is deferred (within its catch-up window) while any scan is
still queued or running, so a long scan never stacks the next day's jobs.
Large CIDRs are chunked with bounded parallelism; failed/partial scans never
remove inventory. Discovery caps probe RTT, uses one retry, and bounds probe
rate (min and max) on both local and routed/VPN paths so silent ranges finish
without flooding a remote site — duration follows live hosts, not CIDR size.
Discovery uses ICMP/TCP (rate-capped ARP on local segments). No scan or
enrichment stage sends UDP. Service detection runs `--version-light` and never
probes telephony signaling ports (H.323 1720, SCCP 2000/2443, CTI 2748, SIP
5060/5061), which can crash Cisco CUCM and similar call managers. Device identity prefers unique MAC, then IP/hostname rules.
History and compressed daily snapshots are retained (default 365 days). What is
stored, for how long, and how to remove it: [data and privacy](docs/data-and-privacy/data-and-privacy.md).

Layout overview:

```
backend/app/
  scanner/          NmapScanner + MockScanner, XML parser, NIC bind, status
  core/             runner, compare, identity, queue, scheduler, presence, web_capture
  api/              REST; auth/ sessions, CSRF, LDAP; alembic/ migrations
frontend/src/       React UI (Dashboard, Devices, Ports, Changes, Web, Scans, Settings)
scripts/            setup, dev runner, Windows production runner
docker/Dockerfile, docker-compose.yml
```

## Features

- Continuous discovery and service inventory via nmap (or labelled mock data)
- Change detection for devices, ports, services, versions, and IP moves
- Inventory search (`field:value` queries, facets, export), tags, exposure scores, watches and reports
- Enrichment: banners, TLS certs, SNMP sys*, CPE provenance, SSH host keys, subnet heatmap
- SOC-style dashboard with devices, ports, changes, scans, and settings
- Daily categorized HTML email summary of pending changes; optional webhooks and SSE
- Optional web capture (HTTP / RTSP / RDP / VNC stills; live RTSP Watch)
- Scheduled night scans plus daytime presence / correlated absence
- Admin / viewer roles, sessions, CSRF, optional LDAP, audit log
- CLI for status, scans, users, DB reset, and inventory import/export
- SQLite in development; PostgreSQL in production

## Tech Stack

- **Frontend:** React 19, React Router, TypeScript, Vite 7
- **Backend:** Python 3.10+, FastAPI, Uvicorn, SQLAlchemy 2, Alembic, Pydantic
- **Database:** SQLite (dev) or PostgreSQL 16 (prod)
- **Scanner:** Nmap (production); MockScanner (development default)
- **Enrichment:** Playwright (Chromium), ffmpeg (RTSP/VNC), FreeRDP (RDP; optional on host, in Docker image)
- **Auth:** Argon2, server-side sessions, optional LDAP (`ldap3`)
- **Tooling:** Node.js 20.19+ workspaces, Ruff, pytest, Docker Compose

## Troubleshooting

For incident triage, database restore, secret rotation, and failed-migration
recovery, see the [operations runbook](docs/runbook/runbook.md).

| Symptom | Fix |
|---|---|
| Scanner unavailable / nmap missing | Install nmap or use `SCANNER_MODE=mock`. Preinstalled in the Docker app image. |
| Hosts found but no MACs | Unprivileged nmap. Docker: keep host networking + caps. Dev: root or mock. |
| `"unk0" is not an ethernet device` | Tunnel stole the LAN route; scanner auto-binds `-e` when a local ethernet overlaps. Restart after updates. |
| Standard/full scans report 0 ports (VPN on Windows) | Scanner passes `-e` and `-S` for the LAN NIC. Restart production and re-run Standard. |
| Background start OK but UI down | Check `data/logs/production.log`, Docker Desktop, and `APP_PORT`. Use `-ForceRestart` or foreground mode. |
| Migration failure | Read `data/logs/app.log`. Dev: `npm run db:reset`. Prod: `docker compose logs db` and `POSTGRES_*`. |
| Port in use | Free it, or set `BACKEND_PORT` / `FRONTEND_PORT` (dev) or `APP_PORT` (prod). |
| Backend unavailable in Vite | Check `[backend]` output; `curl localhost:8000/api/health` should return `ok`. |
| Frontend not loading | `npm install` (Node 20.19+). Production serves UI on `APP_PORT`. |
| `python -m venv` fails (Debian/Ubuntu) | `sudo apt-get install -y python3-venv`, then `npm run setup`. |
| Stale Python deps | `npm run setup -- --force` |
| Browser unavailable at capture time | Windows: `npm run setup:capture-tools` as the app user, then restart. Manual: `backend\.venv\Scripts\python.exe -m playwright install chromium`. |
| ffmpeg unavailable | Windows: `npm run setup:capture-tools` (fixes winget PATH). Confirm `ffmpeg -version`, then restart. Preinstalled in Docker. |
| freerdp unavailable | Windows: `npm run setup:capture-tools` (Scoop + `wfreerdp` shim from `sdl-freerdp`). Linux: `sudo apt-get install -y freerdp2-x11`. Confirm on `PATH`, then restart. Preinstalled in Docker. |
| Scan stuck after restart | In-flight scans are marked failed; start a new one. |
| App exits at start: `APP_SECRET_KEY must be set` | Production needs an explicit key. Set it in `.env.production` / `.env` (`openssl rand -hex 32`), or copy `data/.secret_key` from an earlier run to keep stored SMTP/LDAP passwords. |
| Login HTTP 429 | Wait out the login window (`LOGIN_WINDOW_MINUTES`, default 15). |
| Lost admin password | `npm run cli -- create-user rescue 'New-pass-123' --role admin` (Docker: `docker compose exec app python -m app.cli create-user …`). |

## Contributing

Pull requests are welcome. For substantial changes, open an issue first to discuss
the approach. Prefer matching existing patterns; run `npm test` and `npm run lint`
before submitting. UI changes should also pass `npm run test:e2e` (builds the frontend,
then signs in and opens the dashboard and devices list in headless Chromium; needs
`python -m playwright install chromium` once).

## License

See [LICENSE](LICENSE). Network Finder is proprietary software intended only for
authorized internal use; no open-source license is granted.
