# דוח ביקורת (Read-Only): Network Finder

**מאגר:** `MoshikoKar/network_finder` (ענף `main`, commit `7631020`)  
**תאריך:** 2026-10-08  
**היקף:** קוד בלבד — **לא** נקראו `docs/` וקבצי audit/review/critique קיימים.  
**פעולות:** אין שינויים במאגר, אין commit/push/PR/branch/issue.

---

## סיכום מנהלים

**Network Finder** הוא אפליקציית web פנימית לגילוי רשת רציף, מלאי שירותים וזיהוי שינויים. **Nmap** מבצע סריקה; האפליקציה מתזמרת, מנרמלת ל-DB, משווה לסריקות קודמות, מציגה דשבורד בסגנון SOC ושולחת סיכום מייל יומי. זה **אינו** סורק פגיעויות (CVE) — במכוון.

| שכבה | טכנולוגיה |
|------|-----------|
| Backend | FastAPI + SQLAlchemy + Alembic (`backend/app/`) |
| DB | SQLite (dev) / PostgreSQL (prod) |
| Frontend | React + Vite (`frontend/src/`) |
| Scanner | nmap (subprocess argv) או mock |
| העשרה | Web Capture: Playwright (HTTP) + ffmpeg (RTSP) |
| Auth | Cookie session + CSRF + Argon2; LDAP אופציונלי |
| Deploy | Docker Compose, `network_mode: host`, `NET_RAW`/`NET_ADMIN` |

**זרימת סריקה:** תור בטבלת `scans` → worker סריאלי (`ScanManager`) → discovery ב-chunks מקבילים → port/service scan ב-batches → `compare.apply_outcome` → snapshot (standard) → web capture אוטומטי אופציונלי.

**חוזקות:** ארגומנטים קבועים ל-nmap (לא shell), targets ב-`-iL`, `defusedxml`, הגנת partial/mass-change, ביטול סריקה, identity לפי MAC/IP/hostname, UI עשיר יחסית (KPI, שינויים, ports, web).

**פערים עיקריים:** סריקה כבדה (`--top-ports 3000` + `-sV` + pass נוסף), תור סריקות סריאלי בלבד, אין UDP/IPv6, אין risk/CVE, polling תכוף ב-UI במקום SSE, ופרופילי nmap שלא מותאמים ל-"מהיר מול עמוק".

---

## Top-10 פעולות מומלצות (לפי עדיפות)

| # | עדיפות | פעולה |
|---|--------|--------|
| 1 | Critical | פרופילי סריקה מפורשים: **fast discovery** מול **deep inventory** (דגלים למטה) + ברירת מחדל פחות אגרסיבית ל-`top_ports` / `-sV` |
| 2 | Critical | אבטחת פרודקשן: `COOKIE_SECURE=true` מאחורי HTTPS, `APP_SECRET_KEY` חובה, הגבלת `/api/docs` בפרודקשן |
| 3 | High | אינטגרציית **masscan/rustscan** לשלב discovery מהיר של פורטים, ואז nmap `-sV` רק על פורטים פתוחים |
| 4 | High | הפחתת עומס UI: SSE/WebSocket ל-progress; האטת poll כשאין עבודה |
| 5 | High | סינון רשת בדשבורד + ווידג'טים: התפלגות OS/vendor, hosts חדשים/נעלמים, השוואת סריקה |
| 6 | High | מידע host: סיכון פשוט (פורטים רגישים), first/last port-scope, diff ויזואלי בין סריקות |
| 7 | Medium | כתיבת XML לדיסק/stream במקום `communicate()` מלא בזיכרון; `--max-output-rate` / `--version-intensity` |
| 8 | Medium | כלים קלים: `fping`/`arp-scan`, `httpx`/`whatweb`, `sslscan`/`testssl.sh`, `ssh-audit` (ראה סעיף 5) |
| 9 | Medium | תמיכת UDP ממוקדת (DNS/SNMP/NTP) בפרופיל נפרד — לא full UDP |
| 10 | Low | תגיות/הערות על device, ייצוא diff, מפת רשת פשוטה |

---

## 1. ארכיטקטורה ומוצר (מהקוד)

### מחסנית והרצה
- כניסה: `backend/app/main.py` — lifespan מריץ migrations, seed, `manager` / `web_capture_manager` / `scheduler`.
- תור סריקות: `backend/app/core/manager.py` — **סריקה אחת בכל רגע**; מקביליות *בתוך* סריקה.
- אורקסטרציה: `backend/app/core/runner.py` — discovery → ports → compare → snapshot → auto web capture.
- Nmap: `backend/app/scanner/nmap_scanner.py` + parser `nmap_parser.py`.
- השוואה: `backend/app/core/compare.py` — baseline שקט, partial לא מוחק, mass-change guard.
- מודל: `backend/app/models.py` — Device / DevicePort / Scan / Event / Snapshot / WebCapture.
- הגדרות runtime: `backend/app/settings_store.py` (`ScanSettings`, schedule, presence, …).
- UI: Dashboard, Devices, DeviceDetail, Ports, Changes, Scans, WebHosts, Settings.

### איך סריקה מופעלת
1. API `POST /api/scans` (`backend/app/api/scans.py`) — admin, `network_ids` **או** `targets` **או** `device_uuids`.
2. `create_scan` → סטטוס `queued` → `manager.wake()`.
3. Scheduler (`backend/app/core/scheduler.py`): לילה = discovery+standard; יום = presence discovery; digest מייל; retention.
4. CLI: `npm run cli -- scan …`.

### אחסון ותצוגה
- מצב נוכחי ב-`devices` / `device_ports`; היסטוריה ב-`events`, `scan_hosts`, `snapshots` (JSON דחוס).
- דשבורד: `GET /api/dashboard` → `frontend/src/pages/Dashboard.tsx` (poll ~10s).
- פרטי host: `DeviceDetail.tsx` — פורטים, OS, MAC/vendor, first/last seen, web shots, אירועים.

---

## 2. ביצועים

### Critical / High

**H-P1 — פרופיל standard כבד לרשתות גדולות**  
`ScanSettings.top_ports` ברירת מחדל **3000** (`settings_store.py` ~L91) + תמיד `-sV` (`nmap_scanner.py` `build_port_args` L100–115) + pass שני ל-`STANDARD_EXTRA_TCP_PORTS` (L178–188). על /16 עם מאות hosts זה שעות של `-sV`.  
**המלצה:** ברירת מחדל 1000 או 1500; עומק גרסה בפרופיל "deep" בלבד; או `-sV` רק על פורטים "מעניינים".

**H-P2 — תור סריקות סריאלי גלובלי**  
`ScanManager` מריץ סריקה אחת (`manager.py` L1–4, `_loop` L123–143). רשתות מרובות מחכות בתור.  
**המלצה:** מקביליות לפי `network_id` (2–3 workers) עם מגבלה על מספר nmap כולל.

**H-P3 — XML מלא בזיכרון**  
`_run` קורא את כל stdout דרך `proc.communicate` (`nmap_scanner.py` L209–212) ואז `parse_nmap_xml`. Full scan / chunks גדולים = spike זיכרון.  
**המלצה:** `-oX` לקובץ זמני + parse streaming/incremental, או מגבלת גודל.

**H-P4 — Discovery עם רשימת SYN ארוכה**  
`_DISCOVERY_TCP` כולל בסיס + AI/LLM ports (`nmap_scanner.py` L36–37, `known_ports.py`). על טווחים ריקים `--min-rate` עוזר (L42–43, L78–79) אבל עדיין הרבה probes.  
**המלצה:** פרופיל "fast discovery" עם `-PE`/`-PS80,443,22,445` בלבד; רשימה מורחבת ל-"thorough".

### Medium / Low

**M-P5 — Polling אגרסיבי ב-frontend**  
`App.tsx` L75–86: `/system/status` כל 5s כשיש סריקה; Dashboard 10s; Devices/Changes 15s; Cache-Control `no-store` (`main.py` L113–114).  
**המלצה:** SSE ל-progress; backoff כשאין שינוי; כיבוי poll בטאב מוסתר (חלקית כבר ל-system).

**M-P6 — מיון `open_ports` עם subquery מתואם**  
`devices.py` `_open_port_count_expr` L88–94 בכל ORDER BY. על אלפי devices ב-SQLite — איטי.  
**המלצה:** עמודה מחושבת / join ל-aggregate / אינדקס מורכב.

**M-P7 — Dashboard: שאילתות רבות בכל רענון**  
`dashboard.py` L117–207 — ספירות, events, top services/ports, trend, networks.  
**המלצה:** cache קצר (כמו settings 5s) או materialized summary.

**L-P8 — Web capture סידורי ל-screenshots**  
`WebCaptureSettings.screenshot_concurrency` שמור אך "Not used yet" (`settings_store.py` L218–221).

**L-P9 — SQLite ב-dev על מלאי גדול** — לעבור ל-Postgres מוקדם לבדיקות עומס.

---

## 3. דשבורד ו-UX

### מה קיים (טוב)
- KPI: hosts, active, not_detected, open ports, שינויים 24h/7d (`Dashboard.tsx` L71–81).
- Recent changes, scan progress, bars לפי סוג אירוע, trend 30 יום, top ports/services, טבלת networks + baseline.
- Filters ב-Devices/Changes/Ports; multi-select לסריקה/web capture.

### פערים מומלצים

| עדיפות | פער | המלצה |
|--------|-----|--------|
| High | אין סינון רשת גלובלי בדשבורד | `?network_id=` על כל ווידג'ט (API כבר תומך חלקית ב-`exposed-ports`) |
| High | אין תצוגת "מה השתנה בסריקה האחרונה" | כרטיס diff: host±, port± לסריקה `last_completed` |
| Medium | אין התפלגות OS / vendor / subnet | pie/bar מ-`devices.os_name` / `vendor` |
| Medium | Progress גס (לפי chunk/batch) | שלבים: discovery N/M, ports N/M, ETA |
| Medium | אין live push | SSE `/api/scans/stream` |
| Low | 10 KPI צפופים | קיבוץ Exposure / Presence / Change |
| Low | אין מפת רשת / timeline host | אופציונלי בהמשך |
| Low | אין ייצוא מהיר מהדשבורד | CSV של top ports / changes 7d |

---

## 4. מידע שמוצג למשתמש

### קיים במודל/UI
| שדה | מקור | UI |
|-----|------|-----|
| IP, hostname, DNS | nmap / PTR | DeviceDetail |
| MAC + vendor | ARP (privileged L2) | כן; בלי privilege: "not on L2" |
| OS guess | `-O` (אופציונלי, כבוי כברירת מחדל) או `ostype` משירות | כן |
| Service / product / version / confidence | `-sV` | טבלת פורטים |
| first_seen / last_seen / opened_at / closed_at | DB | כן |
| שינויים | Event types ב-`models.py` L49–68 | Changes + feed |
| Web title/server/TLS/screenshot | Web Capture | כן |
| Missed scans / absence | presence | חלקי |

### חסר / מבלבל

| עדיפות | נושא | פירוט |
|--------|------|--------|
| High | **Risk scoring** | אין ניקוד. מומלץ score פשוט מבוסס פורטים רגישים (445, 3389, 23, DB, admin UIs) ללא CVE DB |
| High | **CVE hints** | מחוץ לסקאופ המוצר — אם רוצים: שכבה אופציונלית מ-CPE/`product+version` (NVD offline) או nuclei templates ממוקדים |
| High | **השוואת סריקות** | יש events אבל אין side-by-side "scan #12 vs #11" |
| Medium | **UDP / non-TCP** | `protocol` במודל תומך, הסורק סורק TCP בלבד |
| Medium | **IPv6** | `netutils.py` L48–49 דוחה IPv6 |
| Medium | **CPE / banner גולמי** | לא נשמר מעבר ל-product/version/extrainfo |
| Medium | **הסבר MAC חסר** | ברור יחסית; כדאי tooltip בדשבורד כש-% hosts בלי MAC גבוה |
| Low | **תגיות / owner / criticality** | אין על Device |
| Low | **port_scope ב-UI** | נשמר ב-`scans.port_scope` — לא בולט למשתמש ("מה נסרק באמת") |

---

## 5. Nmap: מהירות, אמינות, דגלים מומלצים

### מצב נוכחי (קוד)

**Discovery** — `build_discovery_args` (`nmap_scanner.py` L71–80):
```
-sn
[--privileged -PE -PP -PS<long> -PA80,443,3389 | --unprivileged -PS<long>]
-T2|-T3|-T4
--max-retries 2
--min-rate 100|300|600
```
Timeout דינמי: `discovery_timeout` L87–97; רצפה 30 דקות.

**Port scan** — `build_port_args` L100–115:
```
-Pn -n -sV
[--privileged -sS | --unprivileged -sT]
--top-ports N | -p 1-65535
-T*
--max-retries 2
--host-timeout Nm
--min-hostgroup batch_size
[-O --osscan-limit --max-os-tries 1]  # אם os_detection+privileged
```

**אמינות / תפעול:**
- Parallelism: `ThreadPoolExecutor` עד `parallelism` (1–16), chunk/batch (`runner.py` L112–143).
- ביטול: `ScanContext.cancel` → `proc.kill` (`types.py` L109–120).
- Progress: יחס chunks/hosts (`runner.py` L179–218) — לא hosts-per-second מ-nmap.
- Partial: כשל chunk לא מוחק state (`compare.py` docstring L13–15).
- XML: `defusedxml`, דורש `runstats/finished` (`nmap_parser.py` L39–46).
- אין NSE / `-A` (נבדק ב-tests `test_scanner.py` L47).
- Scheduling: לילה + presence (`scheduler.py`).
- Re-scan/diff: דרך compare events, לא diff UI.

### בעיות
1. אין הבחנה UX בין "גילוי מהיר" ל-"מלאי עמוק" — רק discovery/standard/full + timing.
2. `-sV` תמיד על כל פורט פתוח ב-standard/full.
3. אין `--version-intensity`, אין `--max-rate` על port stage.
4. Full scan מקטין batch ל-16 (`runner.py` L209) — טוב — אבל עדיין כבד.
5. Unprivileged: אין ARP/MAC/ICMP — צפוי; כדאי לזהור בדשבורד.

### דגלי nmap מומלצים

#### A) Fast discovery (נוכחות / לפני standard)
מטרה: מי חי, מהר, רעש נמוך.

**Privileged (LAN):**
```bash
nmap -sn --privileged -PE -PP -PS21,22,23,80,139,443,445,3389,8080 -PA80,443 \
  -T4 --max-retries 1 --min-rate 1000 --max-rtt-timeout 500ms \
  -iL targets.txt -oX -
```

**Unprivileged:**
```bash
nmap -sn --unprivileged -PS22,80,443,445,3389,8080 \
  -T4 --max-retries 1 --min-rate 500 \
  -iL targets.txt -oX -
```

#### B) Fast port map (אחרי live hosts; בלי גרסאות)
```bash
nmap -Pn -n --privileged -sS --top-ports 1000 -T4 \
  --max-retries 1 --host-timeout 5m --min-hostgroup 64 --min-rate 500 \
  -iL live.txt -oX -
```
או עם masscan/rustscan (סעיף 6) ואז רק `-p <open>` ל-nmap.

#### C) Deep inventory (מה שהמערכת עושה היום, מכוונן)
```bash
nmap -Pn -n --privileged -sS -sV --version-intensity 5 \
  --top-ports 3000 -T3 --max-retries 2 --host-timeout 15m \
  --min-hostgroup 32 \
  -iL live.txt -oX -
# אופציונלי: -O --osscan-limit --max-os-tries 1
```

#### D) Deep single-host / incident
```bash
nmap -Pn -n --privileged -sS -sV -p 1-65535 --version-intensity 7 \
  -T3 --max-retries 2 --host-timeout 120m \
  --reason -oX - <ip>
```

**שילוב מומלץ באפליקציה:**  
`presence`/`discovery` → פרופיל A;  
`standard` יומי → B ואז C רק על פורטים חדשים/לא מוכרים;  
`full` → D על hosts נבחרים.

---

## 6. כלים קלים מומלצים לאינטגרציה

עקרון: subprocess + parse JSON/XML/טקסט; לא להחליף את nmap כמקור אמת למלאי — להשלים.

| עדיפות | כלי | פער שסוגר | למה קל | אינטגרציה | רישוי |
|--------|-----|-----------|--------|-----------|--------|
| High | **rustscan** או **masscan** | גילוי פורטים מהיר לפני `-sV` | בינארי אחד / מהיר מאוד | subprocess → רשימת ports → nmap `-sV -p …` | rustscan: GPL-3.0; masscan: AGPL-3.0 (**זהירות AGPL**) |
| High | **fping** | discovery מהיר ל-ICMP | קל מאוד | parse alive list → אותו pipeline | BSD-like |
| High | **arp-scan** | MAC/vendor ב-L2 כש-nmap חלש | קטן, root/CAP_NET_RAW | XML/text → merge ל-HostObservation | GPL-3.0 |
| Medium | **httpx** (projectdiscovery) | כותרות/title/tech על HTTP בלי Chromium | Go binary, JSONL | אחרי open 80/443/8080… | MIT |
| Medium | **whatweb** | fingerprint אפליקציות | Ruby/CLI | JSON → העשרת service | GPL-2.0 |
| Medium | **sslscan** או **testssl.sh** | TLS issues בלי "vuln scanner" מלא | sslscan קל יותר | JSON/text על 443 | sslscan: GPL; testssl: GPL |
| Medium | **ssh-audit** | חוזק SSH | Python CLI | JSON על :22 | MIT |
| Medium | **nbtscan** / **enum4linux-ng** (read-only) | שם מחשב/shares ברשת Windows | קל יחסית | רק מצב enum לא פולשני | GPL |
| Medium | **onesixtyone** + **snmpwalk** | SNMP community/sysDescr | קטנים | רק עם community רשימה מוגבלת | GPL |
| Medium | **dnsrecon** | רשומות DNS פנימיות | Python | scope מוגבל ל-zones מורשים | GPL |
| Low | **nuclei** (templates curated) | רמזי CVE/misconfig | Go, templates | רק templates informational/ssl/http-default; כבוי כברירת מחדל | MIT |
| Low | **ncat/netcat** | בדיקת connect נקודתית / banner | בכל מקום | health check ידני, לא bulk | Nmap license / OpenBSD |
| Avoid as default | **nikto**, **sslyze** כבד | כפילות עם httpx/sslscan | — | אופציונלי למקרים | nikto GPL; sslyze Apache-2.0 |

**לא מומלץ כברירת מחדל:** כלי brute-force / exploit — מנוגד למוצר (README + Scan profile UI).

---

## 7. אבטחת האפליקציה עצמה

### חוזקות
- Nmap: argv list, לא shell; targets ב-`-iL`; ארגומנטים מ-allowlist (`nmap_scanner.py` L1–6, L200–205).
- אין `--script` / `-A` (test L47).
- Sessions: HttpOnly cookie, CSRF header (`auth/deps.py`).
- סיסמאות Argon2; rate limit login (`auth/ratelimit.py`, `auth.py` L40–41).
- סודות SMTP/LDAP ב-Fernet (`security.py`).
- XML עם `defusedxml`.
- Headers: nosniff, frame deny, CSP ל-SPA (`main.py` L107–121).
- Import: אישור מפורש + מגבלות גודל (`data_transfer.py` API).
- LDAP: escape ל-filter (`ldap_auth.py` L14, L68).

### ממצאים

| עדיפות | ממצא | מיקום | המלצה |
|--------|------|-------|--------|
| Critical | `COOKIE_SECURE` ברירת מחדל `false` גם ב-prod example | `.env.production.example` L31; `docker-compose.yml` L71 | חובה `true` מאחורי HTTPS |
| Critical | `APP_SECRET_KEY` יכול להיות ריק → מפתח אוטומטי ב-volume | `security.py` L44–57; `.env.production.example` L25 | לחייב בפרודקשן; סיבוב מפתח שובר decrypt |
| High | `/api/docs` + OpenAPI חשופים | `main.py` L74–75 | לכבות בפרודקשן או להגן ב-auth |
| High | Host networking + NET_RAW/NET_ADMIN | `docker-compose.yml` L51–54 | צפוי ל-nmap; להקשיח firewall ל-UI port בלבד |
| Medium | Dev seed `admin`/`admin` | `.env.example` L37–38 | לוודא `DEV_SEED` לא בפרודקשן (כבר ignored לפי README) |
| Medium | RTSP URL ל-ffmpeg כ-argv | `rtsp.py` L121–130 | לא shell — טוב; לוודא host רק מ-inventory IP (לא SSRF ל-metadata cloud) |
| Medium | Import מחליף מלאי שלם | `api/data_transfer.py` | כבר דורש confirm; להוסיף הרשאת "backup role" / audit בולט ב-UI |
| Low | Session idle עד 480 דק׳ | config | להקטין בסביבות רגישות |
| Low | אין MFA | — | אופציונלי דרך IdP/LDAP |

**הזרקת פקודות ל-nmap:** לא נמצאה נתיב סביר — משתמש לא מעביר raw args; `ScanSettings` במכוון בלי raw nmap (`settings_store.py` L88–89). Targets עוברים `AddressSet`/`TargetError`.

---

## 8. איכות קוד ואמינות

| עדיפות | נושא | הערות |
|--------|------|--------|
| High | Worker יחיד + restart | סריקה `running` עוברת ל-`failed` ב-`recover_interrupted` — state לא מיושם באמצע (טוב), אבל אין resume |
| Medium | `os_detection` כבוי כברירת מחדל | OS בדשבורד לרוב ריק עד שמפעילים |
| Medium | `screenshot_concurrency` dead setting | מבלבל ב-UI |
| Medium | Progress לא מייצג היטב שלב `-sV` ארוך על host בודד | host-timeout עוזר אך UI "תקוע" |
| Low | IPv4 only | מגביל ארגונים dual-stack |
| Low | בדיקות טובות יחסית | `tests/test_scanner.py`, change detection, presence — לשמור כרגרסיה לפרופילי nmap חדשים |

---

## מפת דרכים קצרה

### Quick wins (שינויים קטנים, השפעה גבוהה)
1. ברירת מחדל: `top_ports=1000`, timing `fast` ל-discovery/presence.
2. פרופיל discovery "lean" (פחות `-PS` ports).
3. `COOKIE_SECURE` + השבתת OpenAPI בפרודקשן.
4. סינון `network_id` בדשבורד.
5. האטת polling כשאין סריקה פעילה.

### Medium
1. שני-שלבי standard: port-map מהיר → `-sV` ממוקד.
2. SSE ל-progress.
3. Risk score פשוט + ווידג'ט "risky ports".
4. אינטגרציית fping/arp-scan או rustscan (זהירות AGPL ל-masscan).
5. כתיבת XML לקובץ במקום buffer מלא.

### Larger
1. מקביליות סריקות בין רשתות.
2. שכבת העשרה pluggable (httpx, sslscan, ssh-audit) עם תור נפרד כמו web capture.
3. תצוגת diff סריקה-לסריקה + ייצוא.
4. אופציית CVE/nuclei כבויה כברירת מחדל.
5. IPv6 + UDP ממוקד.

---

## נספח: מפת קבצים מרכזיים

| תפקיד | נתיב |
|-------|------|
| Nmap args / run | `backend/app/scanner/nmap_scanner.py` |
| XML parse | `backend/app/scanner/nmap_parser.py` |
| Orchestration | `backend/app/core/runner.py` |
| Queue | `backend/app/core/manager.py` |
| Diff/state | `backend/app/core/compare.py` |
| Settings | `backend/app/settings_store.py` |
| Dashboard API | `backend/app/api/dashboard.py` |
| Dashboard UI | `frontend/src/pages/Dashboard.tsx` |
| Device UI | `frontend/src/pages/DeviceDetail.tsx` |
| Auth | `backend/app/auth/deps.py`, `api/auth.py` |
| Compose | `docker-compose.yml`, `docker/Dockerfile` |

---

## אישור תהליך

- **לא בוצעו שינויים במאגר** (`git status` נקי בזמן הביקורת).
- **לא** נוצרו branches / commits / pushes / PRs / issues.
- **לא** נסרקו רשתות חיצוניות; nmap לא היה זמין ב-VM לריצה מקומית.
- **לא** נקראו קבצים תחת `docs/` או קבצי audit/review/critique קיימים (רק זוהו בשמם כדי להימנע מהם).
- הדוח נשמר ב: `/opt/cursor/artifacts/network_finder_audit_he.md`
