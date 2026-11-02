# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary: in-house IT generalists and sysadmins at small and mid-size organizations, often one person or a small team. They own the network but are not dedicated security staff. Each deployment has two roles: **admin** (configures networks, runs scans, manages settings, users and wordlists) and **viewer** (read-only).

They use it in four situations, all confirmed:

- **Morning change check.** Read the daily email digest or the Changes and Dashboard pages to see what is new, gone, moved or newly exposed since the last scan.
- **Investigation lookup.** Look up one IP, host, MAC, port, service, CVE or subdomain while chasing an issue.
- **Wall / NOC display.** Leave the dashboard open on a shared screen.
- **Reports for others.** Hand exposure and vulnerability reports (on screen or printed) to management or auditors.

## Product Purpose

PortReveal provides continuous network discovery, service inventory and change detection for internal networks. Nmap does the scanning. PortReveal runs it with fixed profiles, stores normalized results, compares scans, shows a dashboard, and sends change summaries by email or webhook.

It answers three questions: *what is on the network, what does each device expose, and what changed since the last scan?*

Success means an operator learns about a new device, a newly opened port, a newly matched CVE or a leaked internal DNS name from PortReveal, before it turns into an incident.

## Positioning

It is open source and self-hosted, and people besides the author deploy it.

- **Change-first inventory.** Every scan is diffed against the last one. Change events are what the product leads with, not a static asset list.
- **Deliberately non-intrusive.** It is not a vulnerability scanner, EDR, SIEM, CMDB or performance monitor. It runs no exploits, brute force, credential attempts or intrusive NSE scripts. CVE matching is passive: it compares service CPEs against a local NVD/KEV/EPSS cache.
- **Outsider view vs. ground truth for DNS.** Domain scans compare what an unprivileged outsider can find (passive sources, brute force, public resolvers) with the operator's own authorized zone transfer. They flag internal names that leak and zone transfers left open.
- **Sees what the services show.** It captures stills of the web, RTSP, RDP and VNC interfaces it finds, using empty credentials only.

## Operating Context

- Runs on a host that can see the target LAN: Windows (host nmap + Npcap, Postgres in Docker), Linux Docker Compose, or development (SQLite, mock scanner).
- Daily rhythm: scheduled scans, then a change pipeline, then a digest email to recipient groups. Critical events (zone transfer open, internal name exposed, new external subdomain pointing inside a network, CVE watchlist match) are delivered immediately.
- Main areas: Dashboard (customizable widget grid), Search, Changes, Devices, Ports, Vulnerabilities, CVE watchlist, Watches (saved searches and monitors), Web and Remote galleries, Domains and subdomain detail, Reports (exposure, rare services, version skew, subnets, heatmap, printable vulnerability report), Scans, Settings, first-run Setup wizard, and Login (local or LDAP/AD).
- There is also a CLI (`npm run cli`) and an HTTP API with tokens.

## Capabilities and Constraints

- The UI and API never accept raw nmap arguments. Only fixed scan profiles are allowed (e.g. standard, full).
- Scanner modes are `mock`, `nmap` and `auto`. Mock results must always be labelled as such (*SIMULATED DATA* banner). The UI never presents simulated results as real.
- Device states have exact meanings and must stay distinguishable: *Not detected*, *Superseded*, *Scanner host*, auth required (NLA / password VNC), and "Not scanned yet".
- Domain exposure terms are fixed vocabulary: External / Internal / Both, Internal (authorized), Internal name exposed, Private IP in public DNS, Internal network IP, Wildcard, Zone transfer open.
- Inventory, captures and audit data stay on the host. The only outbound flows are SMTP, LDAP, scan traffic, and inbound-only public vulnerability feeds (see `docs/data-and-privacy/data-and-privacy.md`).
- Example and demo content in code, docs and design work must use anonymized or mock data (e.g. the *Mock Lab* `10.99.0.0/24` seed). Never use real hostnames, page titles or IPs from the author's network.

## Brand Commitments

- Name: **PortReveal**, with the descriptor "Network discovery".
- Existing brand assets: `docs/brand/portreveal-mark.png`, `portreveal-app-icon.png`, `portreveal-lockup-light.png`, `portreveal-lockup-dark.png`. App icons and favicons are in `frontend/public/`.
- Voice in the README and UI: plain, precise and operational. It states what the product does and does not do, without hype.

## Evidence on Hand

- Mock Lab seed and a scripted mock scenario (baseline, then port/service/IP/absence changes) for demos and screenshots.
- Internal audits: `docs/audit-ui-2026-10-18.md`, `docs/audit-ux-flow-2026-10-18.md` and earlier ones in `docs/ui/` and `docs/ux-flow/`.
- No testimonials, user counts, customer names, benchmarks or press exist. Do not fabricate any.

## Product Principles

1. **Lead with change.** What is new, gone or newly exposed matters more than the full inventory. Every surface should make the delta easy to find.
2. **Glance, then drill.** The same data has to read from across a room (wall display, morning check) and support a precise lookup (investigation). Neither use should cost the other.
3. **Honest about certainty.** Simulated, not detected, superseded, unscanned and auth-blocked are different facts. Never blur them, and never overstate a finding.
4. **Written for a generalist.** The operator is responsible for security but is not a specialist. Severity, exposure and CVE data must be explained in terms they can act on.
5. **The inventory is a map of weak spots.** Treat it as sensitive: role-gated actions, audit logging, redaction, and nothing leaving the host unless configured.

## Accessibility & Inclusion

No product-specific mandate has been stated. Past UI audits used WCAG 2.1 AA as the working bar, and the UI honors `prefers-reduced-motion`. Wall-display use means text has to stay readable from a distance.
