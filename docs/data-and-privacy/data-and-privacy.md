# Data and privacy

What PortReveal stores, where, for how long, who can see it, and how to remove it.
It is an internal tool; this note gives the operator what a data-protection review or an
offboarding checklist needs. It is not legal advice; map it onto your organization's own
classification and retention policy.

## Data categories

| Category | What | Where | Classification hint |
|---|---|---|---|
| Network inventory | IP and MAC addresses, hostnames/DNS names, vendor, OS guess, open ports, service product/version, tags, exposure scores, device owner/location/notes (entered by admins) | Database (`devices`, `device_ports`, `device_ips`, `device_tags`, `device_profiles`) | Internal / confidential: a map of the network and its weak spots |
| Scan and change history | Scans, per-scan host observations, change events, daily compressed snapshots | Database (`scans`, `scan_hosts`, `events`, `snapshots`) | Same as inventory |
| Web captures | Screenshots and titles of web interfaces and RTSP camera stills found on the network. Pages are loaded passively; no credentials are submitted, but a screenshot can show whatever the page displays (dashboards, camera images of people or premises) | Data directory `web-captures/` + database (`web_captures`, `web_pages`, `port_http`) | Potentially sensitive; camera stills may be personal data |
| Raw scanner output | nmap XML, only when "Keep raw nmap XML temporarily" is enabled (Settings → Scan profiles) | Data directory `raw/` | Same as inventory |
| User accounts | Username, display name, role, source (local/LDAP), Argon2 password hash (local accounts only), last login | Database (`users`) | Personal data (employees) |
| Sessions and API tokens | Session token hash, client IP, timestamps; API token hash, name, last use | Database (`sessions`, `api_tokens`) | Personal data (employees) |
| Audit log | Who did what, when, and from which IP (logins, failed logins, settings and inventory changes, deletions) | Database (`audit_log`) | Personal data (employees); security record |
| Application logs | Startup, scan and capture summaries, errors, slow requests (path and query string) | Data directory `logs/app.log` (rotated, 4 × 5 MB) | Internal |
| Integration settings | SMTP host/user/recipients, LDAP server/bind DN; passwords encrypted with `APP_SECRET_KEY` | Database (`app_settings`) | Confidential |

No data leaves the host except through the integrations below.

## External processors and recipients

| Integration | Data sent | When |
|---|---|---|
| SMTP server (Settings → Notifications) | Daily digest: device labels, IPs, ports, services, change descriptions | Daily, when changes are pending; test emails on demand |
| LDAP / Active Directory (Settings → Authentication) | Username and password of the person signing in; group lookups | Each LDAP sign-in |
| Scanned networks | nmap probes and HTTP/RTSP requests; OS detection (`-O`) sends one UDP probe to a closed port (U1 fingerprint) when privileged | Scans and web captures |
| Local discovery (optional) | mDNS/SSDP multicast listen/query and NetBIOS unicast to already-known device IPs - stays on the LAN | After scans, when Settings → Local discovery is enabled |
| NVD / CISA KEV / FIRST EPSS (Settings → Vulnerabilities) | **Inbound only**: HTTP GET of public vulnerability data files/API pages. No device, port, CPE, or network inventory is included in any request. Matching and scoring run locally against the downloaded cache. An optional NVD API key only raises the public rate limit. | On first enable / empty cache, then on the configured weekly schedule (or Sync now) |

Whoever operates those systems (mail relay, directory, public feed hosts) can see that data. List them in
your processing records if your organization keeps them.

## Retention

| Data | Default | Setting |
|---|---|---|
| Events, scan history, per-scan observations, daily snapshots, web captures and their screenshots, audit log | 365 days | Settings → Retention (`days`, 7-3650) |
| Devices not seen for the whole retention period (and not currently active) | 365 days | same |
| Expired sessions | removed when they expire | `SESSION_IDLE_MINUTES`, `SESSION_MAX_HOURS` |
| Raw nmap XML | 7 days | Settings → Scan profiles (`raw_retention_days`, 1-90) |
| Application log files | about 20 MB total, rotated | fixed |
| User accounts, API tokens, settings | until deleted | manual |

Retention runs daily from the scheduler, and on demand from Settings → Retention (**Run cleanup now**) or with
`npm run cli -- retention`. Backups (`pg_dump`, data-volume snapshots, inventory export
ZIPs) are outside this retention; delete them according to your backup policy.

## Who can access what

- **Viewer:** reads inventory, history, reports, screenshots, and Settings pages in
  read-only form. Cannot see SMTP/LDAP passwords (never returned by the API).
- **Administrator:** everything a viewer can, plus scans, settings, users, the audit log,
  inventory export/import, and deletion.
- **API tokens:** act with their owner's role but read-only (GET only); revoked
  immediately when deleted.
- **Host operators:** anyone with shell access to the host or the database can read all
  of the above directly. Restrict host, database, backup, and `APP_SECRET_KEY` access
  accordingly.

## Removing data

| Need | Steps |
|---|---|
| Offboard a person | Settings → Users → Delete (or Disable to keep the account for the record). Their sessions and API tokens are deleted with the account. Disable the LDAP account in the directory too; an LDAP user who can still sign in is re-created on the next login. Audit log entries keep the username until retention removes them. |
| Remove one device and its history | Device page → Delete (admin). Removes the device with its ports, IPs, tags, profile, events and scan observations. Its web-capture pages stay until their capture job is deleted or expires. |
| Remove screenshots | Scans → Web captures → Delete the job (removes its pages and files), or wait for retention. |
| Shorten what is kept | Lower Settings → Retention, save, then **Run cleanup now**. |
| Hand over or move the inventory | Settings → Data → Export (admin). The ZIP contains inventory and history only, no users, settings, audit log, or screenshots. Treat the file as confidential. |
| Decommission the installation | Delete the database (or `pgdata` volume), the data directory (or `appdata` volume), the env file holding `APP_SECRET_KEY`, and backups/exports per policy. |

Every deletion made through the UI is recorded in the audit log.
