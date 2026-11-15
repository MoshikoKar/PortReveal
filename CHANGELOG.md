# Changelog

All notable changes to PortReveal are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-15

### Added

- First stable release of PortReveal: continuous network discovery, service inventory, and change detection for internal networks.
- Nmap-backed scanning (mock scanner in development) with fixed scan profiles, change detection, and a SOC-style dashboard.
- Inventory search (`field:value` queries, facets, export), tags, exposure scores, watches, policies, and monitors.
- CVE watchlist with in-app alerts; optional email digests and outbound webhooks.
- Optional web capture for HTTP, RTSP, RDP, and VNC stills, plus live RTSP watch.
- Domain scans: subdomain inventory (passive, wordlist, authorized AXFR), split-DNS exposure, and change alerts.
- Scheduled night scans and daytime presence / correlated absence.
- Admin / viewer roles, sessions, CSRF, optional LDAP, audit log, and CLI.
- SQLite for development; PostgreSQL for production (Windows host nmap or Linux Docker Compose).

### License

- Free for non-commercial internal use (and personal non-commercial use). Not open source; commercial use requires a separate written agreement. See LICENSE.
