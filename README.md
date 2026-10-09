# Network Finder

Continuous network discovery, service inventory, and change detection for internal
networks. Nmap does the scanning; this app orchestrates it, stores normalized
results, compares scans, shows a dashboard, and can email a daily change summary.

It is **not** a vulnerability scanner, EDR, SIEM, CMDB, or performance monitor.
No exploits, brute force, authentication attempts, or intrusive NSE scripts are run.

| | Development | Production (Windows host) | Production (Linux Docker) |
|---|---|---|---|
| Start | `npm install && npm run dev` | `.\scripts\run.ps1 -Mode production -Background` | `docker compose up -d` |
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
npm run dev
```

The first `npm run dev` creates `.env` from `.env.example`, sets up
`backend/.venv`, installs Python dependencies, and migrates the database.

Open **http://localhost:5173** and sign in with **admin / admin** (development
seed). The seed also creates the network *Mock Lab* (`10.99.0.0/24`) and queues a
baseline scan so the dashboard fills within seconds.

| Task | Command |
|---|---|
| Install | `npm install` (or `npm run setup` for Python/DB only) |
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
  http://localhost:8000/api/docs
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

Enrichment for known HTTP(S) and RTSP services (not part of nmap). Auto-queue
after standard/full scans is toggled under **Settings → Web capture**. Manual jobs
from Device details, Devices multi-select, or **Scans → Web captures**.

Needs Chromium (Playwright) for HTTP screenshots and **ffmpeg** for RTSP stills /
live MJPEG:

```bash
cd backend
.\.venv\Scripts\playwright.exe install chromium   # Windows
# or: playwright install chromium
```

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
product:nginx -version:1.25*      nginx not on 1.25.x
score:>=60 new:7d                 high-exposure hosts first seen this week
```

The full field list is under **Search → Show field reference** and
`GET /api/search/fields`. Pick a past date (**As of**) to search the daily
snapshots instead of current data.

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
| `GET /api/reports/exposure` · `rare-services` · `version-skew` · `subnets` | Reports |
| `/api/saved-searches` | Watches and policies (CRUD) |

```bash
npm run cli -- search "port:22 product:openssh"
curl -H "Authorization: Bearer $NF_TOKEN" "localhost:8000/api/search/export?q=tag:camera&format=csv"
```

### Database

One SQLAlchemy model and one Alembic history for both engines.

- **SQLite (dev):** `DATABASE_URL=sqlite:///./data/dev.db` (repo-root relative).
  Disposable via `npm run db:reset`.
- **PostgreSQL (prod):** `DATABASE_URL=postgresql+psycopg://…` or
  `POSTGRES_HOST` / `PORT` / `DB` / `USER` / `PASSWORD` (Compose-friendly).

Migrations run automatically at startup.

### Production on Windows (host nmap)

Recommended when the scanner is a **Windows PC on the LAN** (Npc + Npcap).
Docker Desktop runs **Postgres only**; the app and nmap stay on the host.

Requirements: Node.js 20.19+, Python 3.10+, nmap+Npc, Docker Desktop, ffmpeg
on `PATH`. Copy `.env.production.example` → `.env.production` and set at least
`POSTGRES_PASSWORD` and `APP_SECRET_KEY`.

Install Chromium for the same user that runs the app (Playwright pip package
does not download the browser):

```powershell
npm run setup
backend\.venv\Scripts\python.exe -m playwright install chromium
```

| Task | Command |
|---|---|
| Start (foreground) | `.\scripts\run.ps1 -Mode production` or `npm start` |
| Start (background) | `.\scripts\run.ps1 -Mode production -Background` |
| Skip frontend rebuild | add `-SkipBuild` |
| Force restart | add `-ForceRestart` |
| Stop app | `.\scripts\run.ps1 -Stop` or `npm run stop` |
| Stop app + Postgres | `.\scripts\run.ps1 -Stop -StopDb` |
| Dev via same script | `.\scripts\run.ps1 -Mode dev` or `npm run start:dev` |

Production start loads `.env.production`, starts Compose `db` only, builds the
frontend, migrates, and serves on `APP_PORT` (default **8081**). Background mode
logs to `data/logs/production.log`.

Open `http://localhost:8081` and complete the first-run wizard (admin → networks →
exclusions → schedule → SMTP → optional LDAP → recipients → baseline scan).

Upgrade: `git pull`, `npm run setup`, reinstall Chromium, then
`.\scripts\run.ps1 -Mode production -ForceRestart`.

**Task Scheduler** (same Windows user as Docker Desktop / Npcap):

1. Create Task → **Run only when user is logged on**
2. Trigger: At log on (optional 1–2 minute delay)
3. Action: `powershell.exe` with arguments:

```text
-NoProfile -ExecutionPolicy Bypass -File "<repo-root>\scripts\run.ps1" -Mode production -Background -SkipBuild
```

Set **Start in** to `<repo-root>`. Prefer **Do not start a new instance** if already
running.

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
nmap + Playwright Chromium + ffmpeg) with host networking and `NET_RAW` /
`NET_ADMIN`. One app process only (queue + scheduler live inside it).

Upgrade: `git pull && docker compose up -d --build`.

**HTTPS:** reverse-proxy to the app, set `COOKIE_SECURE=true` and
`FORWARDED_ALLOW_IPS` to the proxy IP.

**Secrets:** keep them in `.env` / `.env.production` (never commit). Docker secrets
under `/run/secrets/<setting_name>` are also read. SMTP/LDAP passwords from the UI
are encrypted with `APP_SECRET_KEY` and never returned by the API.

**Backup:**

```bash
docker compose exec -T db pg_dump -U netfinder netfinder | gzip > netfinder-$(date +%F).sql.gz
cp .env /secure/backup/location/
```

Windows host production (Postgres-only Compose):

```powershell
docker compose --env-file .env.production exec -T db pg_dump -U netfinder netfinder | Out-File -Encoding utf8 netfinder-backup.sql
```

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

### Behaviour notes

**Scan profiles** (fixed argument lists):

| Profile | Role |
|---|---|
| Discovery | Host discovery (`-sn` + common probes; ARP on local segments) |
| Standard | Discovery, then `-Pn -sV --top-ports N` (default 3000) on live hosts |
| Full port | Discovery, then `-Pn -sV -p 1-65535` on live hosts (manual) |

Daily schedule (optional discovery then standard), daytime presence scans, and
correlated absence thresholds are configured under **Settings → Schedule**.
Large CIDRs are chunked with bounded parallelism; failed/partial scans never
remove inventory. Device identity prefers unique MAC, then IP/hostname rules.
History and compressed daily snapshots are retained (default 365 days).

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
- SOC-style dashboard with devices, ports, changes, scans, and settings
- Daily categorized HTML email summary of pending changes
- Optional web capture (HTTP screenshots + RTSP stills / live Watch)
- Scheduled night scans plus daytime presence / correlated absence
- Admin / viewer roles, sessions, CSRF, optional LDAP, audit log
- CLI for status, scans, users, DB reset, and inventory import/export
- SQLite in development; PostgreSQL in production

## Tech Stack

- **Frontend:** React 19, React Router, TypeScript, Vite 7
- **Backend:** Python 3.10+, FastAPI, Uvicorn, SQLAlchemy 2, Alembic, Pydantic
- **Database:** SQLite (dev) or PostgreSQL 16 (prod)
- **Scanner:** Nmap (production); MockScanner (development default)
- **Enrichment:** Playwright (Chromium), ffmpeg (RTSP)
- **Auth:** Argon2, server-side sessions, optional LDAP (`ldap3`)
- **Tooling:** Node.js 20.19+ workspaces, Ruff, pytest, Docker Compose

## Troubleshooting

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
| Browser unavailable at capture time | `backend\.venv\Scripts\python.exe -m playwright install chromium` as the app user, then restart. |
| ffmpeg unavailable | Install ffmpeg; confirm `ffmpeg -version`, then restart. Preinstalled in Docker. |
| Scan stuck after restart | In-flight scans are marked failed; start a new one. |
| Login HTTP 429 | Wait out the login window (`LOGIN_WINDOW_MINUTES`, default 15). |
| Lost admin password | `npm run cli -- create-user rescue 'New-pass-123' --role admin` (Docker: `docker compose exec app python -m app.cli create-user …`). |

## Contributing

Pull requests are welcome. For substantial changes, open an issue first to discuss
the approach. Prefer matching existing patterns; run `npm test` and `npm run lint`
before submitting.

## License

No `LICENSE` file is present in this repository. Treat the project as proprietary
unless the owner publishes license terms.
