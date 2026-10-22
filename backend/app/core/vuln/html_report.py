"""Self-contained HTML vulnerability report (offline: inline CSS/JS, no CDN).

Built from the same FindingFilters as CSV/print: network, search, CVSS floor
(via display rules), include/only hidden. All untrusted strings are HTML-escaped
or JSON-encoded so hostnames/titles/descriptions cannot inject script.
"""

from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .buckets import severity_bucket
from .filters import NETWORK_UNASSIGNED, FindingFilters, search_term

CVE_NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"

SEV_ORDER = ("critical", "high", "medium", "low", "unknown")
SEV_COLORS = {
    "critical": "#f87171",
    "high": "#fb923c",
    "medium": "#fbbf24",
    "low": "#34d399",
    "unknown": "#94a3b8",
}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


def _esc(value: object | None) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _iso(ts: datetime | None) -> str | None:
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.isoformat()


def _fmt_local(ts: datetime | None) -> str:
    if ts is None:
        return ""
    local = ts.astimezone() if ts.tzinfo is not None else ts.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return local.strftime("%Y-%m-%d %H:%M")


def finding_dict(
    *,
    cve_id: str,
    device_uuid: str,
    device_ip: str | None,
    device_hostname: str | None,
    network: str | None,
    network_id: int | None,
    port: int,
    protocol: str,
    service: str | None,
    product: str | None,
    version: str | None,
    state: str,
    cvss_base: float | None,
    cvss_vector: str | None,
    kev: bool,
    epss: float | None,
    summary: str | None,
    first_seen_at: datetime | None,
    matched_at: datetime | None,
    hidden_reasons: list[str] | None = None,
) -> dict[str, Any]:
    """One finding row for the report payload (JSON + charts)."""
    sev = severity_bucket(cvss_base)
    return {
        "cve_id": cve_id,
        "device_uuid": device_uuid,
        "device_ip": device_ip or "",
        "device_hostname": device_hostname or "",
        "network": network or "Unassigned",
        "network_id": network_id,
        "port": port,
        "protocol": protocol,
        "service": service or "",
        "product": product or "",
        "version": version or "",
        "state": state,
        "cvss_base": cvss_base,
        "cvss_vector": cvss_vector or "",
        "severity": sev,
        "kev": bool(kev),
        "epss": epss,
        "summary": (summary or "").replace("\r\n", " ").replace("\n", " ").strip(),
        "first_seen_at": _iso(first_seen_at),
        "last_seen_at": _iso(matched_at),
        "first_seen": _fmt_local(first_seen_at),
        "last_seen": _fmt_local(matched_at),
        "hidden_reasons": list(hidden_reasons or []),
        "references": [CVE_NVD_URL.format(cve_id=cve_id)],
    }


def format_filter_line(
    filters: FindingFilters,
    *,
    network_name: str | None = None,
    device_label: str | None = None,
) -> str:
    """Match frontend ``formatVulnPrintFilterLine`` wording for the report header."""
    parts: list[str] = []
    if filters.network_id == NETWORK_UNASSIGNED:
        parts.append("network: Unassigned")
    elif filters.network_id is not None:
        parts.append(f"network: {network_name or filters.network_id}")
    if filters.severity:
        parts.append(f"severity: {filters.severity.capitalize()}")
    if filters.kev is True:
        parts.append("KEV: yes")
    elif filters.kev is False:
        parts.append("KEV: no")
    if filters.epss_min is not None:
        parts.append(f"EPSS ≥: {int(round(filters.epss_min * 100))}%")
    if filters.service:
        parts.append(f"service: {filters.service}")
    if filters.port is not None:
        parts.append(f"port: {filters.port}")
    if filters.os_name:
        parts.append(f"OS: {filters.os_name}")
    if filters.device_type:
        parts.append(f"device type: {filters.device_type}")
    if filters.state:
        parts.append(f"state: {filters.state.capitalize()}")
    if filters.cve_age:
        parts.append(f"CVE age: {filters.cve_age}")
    if filters.exposure_duration:
        parts.append(f"exposure duration: {filters.exposure_duration}")
    if filters.risk_band:
        parts.append(f"risk band: {filters.risk_band.capitalize()}")
    if filters.vendor:
        parts.append(f"vendor: {filters.vendor}")
    if filters.product:
        parts.append(f"product: {filters.product}")
    if filters.cve_id:
        parts.append(f"CVE: {filters.cve_id}")
    if filters.device_uuid:
        parts.append(f"device: {device_label or filters.device_uuid}")
    if filters.new_since == "scan":
        parts.append("new since: last scan")
    elif filters.new_since == "db":
        parts.append("new since: last DB update")

    base = " · ".join(parts) if parts else "All networks (no filters)"
    term = search_term(filters)
    if not term:
        return base
    bits = [f'Search: "{term}"', "Only hidden" if filters.only_hidden else "Includes hidden"]
    if base == "All networks (no filters)":
        return " · ".join(bits)
    return f"{base} · {' · '.join(bits)}"


def risk_score(f: dict[str, Any]) -> float:
    """KEV-boosted CVSS used for device ranking charts."""
    return (1000.0 if f.get("kev") else 0.0) + float(f.get("cvss_base") or 0.0)


@dataclass
class ReportStats:
    findings_total: int
    kev_count: int
    device_count: int
    severity_counts: dict[str, int]
    by_network: list[tuple[str, int]]
    top_devices: list[tuple[str, int]]
    top_cves: list[tuple[str, int]]


def compute_stats(findings: list[dict[str, Any]]) -> ReportStats:
    sev = {k: 0 for k in SEV_ORDER}
    kev = 0
    devices: set[str] = set()
    nets: Counter[str] = Counter()
    device_risk: dict[str, float] = defaultdict(float)
    device_label: dict[str, str] = {}
    cve_devices: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        s = f.get("severity") or "unknown"
        if s not in sev:
            s = "unknown"
        sev[s] += 1
        if f.get("kev"):
            kev += 1
        uuid = str(f.get("device_uuid") or "")
        if uuid:
            devices.add(uuid)
            device_risk[uuid] += risk_score(f)
            ip = f.get("device_ip") or uuid
            host = f.get("device_hostname") or ""
            device_label[uuid] = f"{ip} · {host}" if host else str(ip)
        nets[str(f.get("network") or "Unassigned")] += 1
        cve_id = str(f.get("cve_id") or "")
        if cve_id and uuid:
            cve_devices[cve_id].add(uuid)
    by_net = sorted(nets.items(), key=lambda x: (-x[1], x[0]))[:12]
    top_dev = sorted(
        ((device_label[u], int(round(score))) for u, score in device_risk.items()),
        key=lambda x: (-x[1], x[0]),
    )[:8]
    top_cve = sorted(
        ((cve, len(devs)) for cve, devs in cve_devices.items()),
        key=lambda x: (-x[1], x[0]),
    )[:8]
    return ReportStats(
        findings_total=len(findings),
        kev_count=kev,
        device_count=len(devices),
        severity_counts=sev,
        by_network=by_net,
        top_devices=top_dev,
        top_cves=top_cve,
    )


def _chart_tick_label(label: str, max_len: int = 10) -> str:
    """Short axis tick: keep CVE year-id tail; trim long host/IP labels."""
    if label.upper().startswith("CVE-") and len(label) > max_len:
        # CVE-2024-1000 → 2024-1000
        return label[4:] if len(label) - 4 <= max_len else label[-max_len:]
    if len(label) <= max_len:
        return label
    return label[: max_len - 1] + "…"


def _svg_bar_chart(
    title: str,
    items: list[tuple[str, int]],
    *,
    colors: dict[str, str] | None = None,
    width: int = 320,
    height: int = 188,
) -> str:
    """Simple vertical bars as inline SVG (no libraries). Extra top pad for value labels."""
    if not items:
        return (
            f'<figure class="chart"><figcaption>{_esc(title)}</figcaption>'
            f'<p class="empty">No data</p></figure>'
        )
    max_v = max(v for _, v in items) or 1
    pad_l, pad_r, pad_t, pad_b = 8, 8, 34, 30  # pad_t leaves room for tallest-bar labels
    chart_w = width - pad_l - pad_r
    chart_h = height - pad_t - pad_b
    n = len(items)
    gap = 4
    bar_w = max(8, (chart_w - gap * (n - 1)) // n)
    bars = []
    labels = []
    for i, (label, val) in enumerate(items):
        x = pad_l + i * (bar_w + gap)
        h = int(round((val / max_v) * chart_h)) if val else 0
        y = pad_t + chart_h - h
        color = (colors or {}).get(label, "#0ed0d9")
        bars.append(
            f'<rect x="{x}" y="{y}" width="{bar_w}" height="{h}" fill="{_esc(color)}" rx="2">'
            f"<title>{_esc(label)}: {val}</title></rect>"
        )
        lx = x + bar_w / 2
        short = _chart_tick_label(label)
        labels.append(
            f'<text x="{lx:.1f}" y="{height - 6}" text-anchor="middle" class="tick">{_esc(short)}</text>'
        )
        bars.append(
            f'<text x="{lx:.1f}" y="{max(12, y - 4)}" text-anchor="middle" class="val">{val}</text>'
        )
    return (
        f'<figure class="chart"><figcaption>{_esc(title)}</figcaption>'
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" '
        f'aria-label="{_esc(title)}">{"".join(bars)}{"".join(labels)}</svg></figure>'
    )


def _charts_html(stats: ReportStats) -> str:
    sev_items = [(k, stats.severity_counts.get(k, 0)) for k in SEV_ORDER if stats.severity_counts.get(k, 0)]
    sev_chart = _svg_bar_chart("Severity distribution", sev_items, colors=SEV_COLORS)
    net_chart = _svg_bar_chart(
        "Findings by network",
        stats.by_network[:8],
        colors=defaultdict(lambda: "#1965d9"),
    )
    top_dev = _svg_bar_chart(
        "Top devices by risk",
        stats.top_devices,
        colors=defaultdict(lambda: "#0ed0d9"),
    )
    top_cve = _svg_bar_chart(
        "Top CVEs by affected devices",
        stats.top_cves,
        colors=defaultdict(lambda: "#f87171"),
    )
    return (
        f'<section class="charts" aria-label="Charts">'
        f"{sev_chart}{net_chart}{top_dev}{top_cve}</section>"
    )


def _payload_json(findings: list[dict[str, Any]]) -> str:
    """JSON for the inline script; escape ``</`` so ``</script>`` cannot break out."""
    raw = json.dumps(findings, ensure_ascii=False, separators=(",", ":"))
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _css() -> str:
    return """
:root, html[data-theme="dark"] {
  --bg:#050c18; --panel:#0a1424; --panel-2:#0e1b30; --panel-3:#13233c;
  --border:#1a2b47; --border-2:#25395c;
  --text:#d6deee; --text-2:#aab6cc; --muted:#74819b;
  --accent:#0ed0d9; --accent-bg:rgba(14,208,217,.12);
  --high:#f87171; --high-bg:rgba(248,113,113,.12);
  --medium:#fbbf24; --medium-bg:rgba(251,191,36,.12);
  --ok:#34d399; --ok-bg:rgba(52,211,153,.12);
  --info:#94a3b8; --info-bg:rgba(148,163,184,.12);
  --mono:ui-monospace,'JetBrains Mono','Cascadia Mono',Consolas,monospace;
  color-scheme:dark;
}
@media (prefers-color-scheme: light) {
  html:not([data-theme="dark"]) {
    --bg:#f4f7fb; --panel:#ffffff; --panel-2:#eef3f9; --panel-3:#e4ecf6;
    --border:#c9d5e5; --border-2:#a8b8cf;
    --text:#0f1a2a; --text-2:#3a4a62; --muted:#5c6b84;
    --accent:#0a8f96; --accent-bg:rgba(10,143,150,.1);
    --high:#c43030; --high-bg:rgba(196,48,48,.1);
    --medium:#a77800; --medium-bg:rgba(167,120,0,.1);
    --ok:#0d7a52; --ok-bg:rgba(13,122,82,.1);
    --info:#4a5a72; --info-bg:rgba(74,90,114,.1);
    color-scheme:light;
  }
}
html[data-theme="light"] {
  --bg:#f4f7fb; --panel:#ffffff; --panel-2:#eef3f9; --panel-3:#e4ecf6;
  --border:#c9d5e5; --border-2:#a8b8cf;
  --text:#0f1a2a; --text-2:#3a4a62; --muted:#5c6b84;
  --accent:#0a8f96; --accent-bg:rgba(10,143,150,.1);
  --high:#c43030; --high-bg:rgba(196,48,48,.1);
  --medium:#a77800; --medium-bg:rgba(167,120,0,.1);
  --ok:#0d7a52; --ok-bg:rgba(13,122,82,.1);
  --info:#4a5a72; --info-bg:rgba(74,90,114,.1);
  color-scheme:light;
}
* { box-sizing:border-box; }
html, body { margin:0; padding:0; background:var(--bg); color:var(--text);
  font:14px/1.45 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; }
body { min-height:100vh; }
.wrap { max-width:1400px; margin:0 auto; padding:20px 24px 48px; }
header.report-header { margin-bottom:18px; padding-bottom:12px; border-bottom:1px solid var(--border); }
.header-row { display:flex; flex-wrap:wrap; gap:12px; align-items:flex-start; justify-content:space-between; }
header.report-header h1 { margin:0 0 6px; font-size:22px; letter-spacing:.01em; }
.meta, .filters { margin:4px 0; color:var(--text-2); font-size:13px; }
.filters strong { color:var(--text); }
.theme-toggle { display:inline-flex; gap:2px; border:1px solid var(--border-2); border-radius:6px; padding:2px; }
.theme-toggle button {
  padding:4px 8px; border:0; border-radius:4px; background:transparent; color:var(--text-2);
  cursor:pointer; font:inherit; font-size:11px;
}
.theme-toggle button.on { background:var(--accent-bg); color:var(--accent); }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:10px; margin:16px 0; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:12px 14px; }
.card .label { font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
.card .value { font-size:22px; font-weight:700; margin-top:4px; }
.card.crit .value, .card.kev .value { color:var(--high); }
.charts { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:14px; margin:8px 0 20px; }
.chart {
  margin:0; background:var(--panel); border:1px solid var(--border);
  border-radius:8px; padding:10px 12px; overflow:visible;
}
.chart figcaption { font-size:12px; font-weight:600; color:var(--text-2); margin-bottom:6px; }
.chart .empty { color:var(--muted); font-style:italic; margin:12px 0; }
.chart svg .tick { fill:var(--muted); font-size:9px; }
.chart svg .val { fill:var(--text-2); font-size:10px; }
.toolbar { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin:12px 0;
  padding:10px 12px; background:var(--panel-2); border:1px solid var(--border); border-radius:8px; }
.toolbar input[type=search] { flex:1; min-width:160px; padding:6px 10px; border-radius:6px;
  border:1px solid var(--border-2); background:var(--panel); color:var(--text); }
.toolbar button, .chip, .menu-btn {
  padding:5px 10px; border-radius:6px; border:1px solid var(--border-2);
  background:var(--panel); color:var(--text); cursor:pointer; font:inherit; font-size:12px;
}
.toolbar button:hover, .chip:hover, .menu-btn:hover { border-color:var(--accent); }
.chip.on { background:var(--accent-bg); border-color:var(--accent); color:var(--accent); }
.chip-row { display:flex; flex-wrap:wrap; gap:4px; }
.group-mode { display:inline-flex; gap:4px; }
.group-mode button.on { background:var(--accent-bg); border-color:var(--accent); }
.col-menu { position:relative; }
.col-menu-panel {
  display:none; position:absolute; right:0; top:110%; z-index:20; min-width:180px;
  background:var(--panel); border:1px solid var(--border-2); border-radius:8px; padding:8px;
  box-shadow:0 8px 24px rgba(0,0,0,.35);
}
.col-menu.open .col-menu-panel { display:block; }
.col-menu-panel label { display:flex; gap:8px; align-items:center; padding:4px; font-size:12px; cursor:pointer; }
.groups { margin-top:8px; }
.group {
  border:1px solid var(--border); border-radius:8px; margin-bottom:8px; background:var(--panel); overflow:hidden;
}
.group-head {
  display:flex; align-items:center; gap:10px; width:100%; padding:10px 12px; border:0;
  background:var(--panel-2); color:var(--text); cursor:pointer; font:inherit; text-align:left;
}
.group-head:hover { background:var(--panel-3); }
.group-head .chev { width:1.2em; color:var(--muted); flex:0 0 auto; }
.group-head .title { flex:1; font-weight:600; min-width:0; }
.group-head .meta-bits { color:var(--muted); font-size:12px; white-space:nowrap; display:flex; gap:8px; align-items:center; }
.group-body { display:none; }
.group.open .group-body { display:block; }
.group.open .chev { transform:rotate(90deg); }
table.findings { width:100%; border-collapse:collapse; font-size:12.5px; table-layout:fixed; }
table.findings th, table.findings td {
  border-top:1px solid var(--border); padding:6px 8px; text-align:left; vertical-align:middle;
}
table.findings th { color:var(--muted); font-weight:600; background:var(--panel);
  position:sticky; top:0; cursor:pointer; user-select:none; }
table.findings th:hover { color:var(--text); }
table.findings tr.row { cursor:pointer; }
table.findings tr.row:hover { background:var(--panel-2); }
table.findings tr.detail-row td { background:var(--panel-3); padding:10px 12px; font-size:12px; }
.mono { font-family:var(--mono); font-size:12px; }
.nowrap { white-space:nowrap; }
.badge {
  display:inline-flex; align-items:center; justify-content:center; text-align:center;
  height:auto; min-height:20px; padding:2px 8px; border-radius:999px; box-sizing:border-box;
  font-size:11px; font-weight:600; line-height:1.2; white-space:nowrap;
  border:1px solid transparent; vertical-align:middle;
  background:var(--info-bg); color:var(--info);
}
.badge.high, .badge.critical { background:var(--high-bg); color:var(--high); }
.badge.medium { background:var(--medium-bg); color:var(--medium); }
.badge.low, .badge.ok { background:var(--ok-bg); color:var(--ok); }
.badge.outline { background:transparent; border-color:var(--border-2); color:var(--text-2); }
.badge.hidden-reason {
  display:inline-flex; align-items:center; justify-content:center; text-align:center;
  height:auto; white-space:normal; max-width:100%;
}
.clip { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.detail-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:8px 16px; }
.detail-grid dt { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.03em; }
.detail-grid dd { margin:0 0 6px; }
.empty-msg { color:var(--muted); font-style:italic; padding:16px; }
footer.report-foot { margin-top:24px; color:var(--muted); font-size:12px; border-top:1px solid var(--border); padding-top:10px; }
/* Column show/hide (screen) */
.hide-kev th.col-kev, .hide-kev td.col-kev,
.hide-sev th.col-sev, .hide-sev td.col-sev,
.hide-cvss th.col-cvss, .hide-cvss td.col-cvss,
.hide-epss th.col-epss, .hide-epss td.col-epss,
.hide-cve th.col-cve, .hide-cve td.col-cve,
.hide-title th.col-title, .hide-title td.col-title,
.hide-device th.col-device, .hide-device td.col-device,
.hide-network th.col-network, .hide-network td.col-network,
.hide-port th.col-port, .hide-port td.col-port,
.hide-state th.col-state, .hide-state td.col-state,
.hide-first th.col-first, .hide-first td.col-first { display:none; }
/* Drop columns redundant with group header */
.group-by-device th.col-device, .group-by-device td.col-device,
.group-by-device th.col-network, .group-by-device td.col-network,
.group-by-cve th.col-cve, .group-by-cve td.col-cve,
.group-by-cve th.col-title, .group-by-cve td.col-title { display:none; }

@media print {
  @page { size: A4 landscape; margin: 6mm 6mm 8mm; background: #fff; }
  /* Force light palette regardless of prefers-color-scheme / data-theme. */
  :root, html, body, .wrap, .card, .chart, .group, .group-head, .group-body,
  table.findings, table.findings th, table.findings td, tr.detail-row td {
    background: #fff !important;
    color: #111 !important;
    color-scheme: light !important;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }
  html, body {
    background: #fff !important;
    color: #111 !important;
  }
  .wrap { max-width: none; padding: 0; margin: 0; }
  .toolbar, .col-menu, .theme-toggle { display: none !important; }
  .cards {
    display: grid !important;
    grid-template-columns: repeat(7, 1fr) !important;
    gap: 4px !important;
    margin: 4px 0 6px !important;
  }
  .card {
    border: 1px solid #bbb !important;
    border-radius: 0;
    padding: 4px 6px !important;
  }
  .card .label { color: #555 !important; font-size: 7pt; }
  .card .value { color: #111 !important; font-size: 11pt; }
  .card.crit .value, .card.kev .value { color: #a00 !important; }
  .charts {
    display: grid !important;
    grid-template-columns: 1fr 1fr 1fr 1fr !important;
    gap: 4px !important;
    margin: 2px 0 4px !important;
  }
  .chart {
    border: 1px solid #bbb !important; border-radius: 0; padding: 2px 4px !important;
    min-width: 0;
  }
  .chart figcaption { color: #333 !important; font-size: 7pt; margin-bottom: 2px; }
  .chart svg { height: 72px !important; max-width: 100%; }
  .chart svg .tick, .chart svg .val { fill: #333 !important; font-size: 7px; }
  header.report-header { border-bottom: 1px solid #ccc; margin-bottom: 4px; padding-bottom: 2px; }
  header.report-header h1 { font-size: 11pt; color: #111 !important; }
  .meta, .filters { color: #333 !important; font-size: 7pt; }
  /* Expand all groups for print (JS also fills bodies beforeprint). */
  .group {
    break-inside: auto;
    page-break-inside: auto;
    border: 1px solid #bbb !important;
    border-radius: 0;
    margin-bottom: 2px;
    overflow: visible;
  }
  .group-head {
    background: #eee !important;
    color: #111 !important;
    padding: 1px 4px;
    font-size: 7pt;
    gap: 6px;
  }
  .group-body { display: block !important; }
  .group .empty-msg[data-lazy] { display: none !important; }
  table.findings {
    font-size: 7pt !important;
    line-height: 1.12;
    table-layout: fixed;
    width: 100%;
  }
  table.findings th, table.findings td {
    border: 1px solid #bbb !important;
    padding: 0 2px !important;
    color: #111 !important;
    vertical-align: middle;
  }
  table.findings th {
    background: #eee !important;
    color: #111 !important;
    position: static;
  }
  /* Repeat header on each page, but skip duplicate theads inside later groups. */
  .group:first-of-type table.findings thead { display: table-header-group; }
  .group:not(:first-of-type) table.findings thead { display: none; }
  table.findings tr.row { break-inside: avoid; page-break-inside: avoid; }
  /* Detail panels only when explicitly expanded before print. */
  table.findings tr.detail-row { display: none !important; }
  table.findings tr.detail-row.print-show { display: table-row !important; }
  .badge {
    border: 1px solid #666 !important;
    color: #111 !important;
    background: #f3f3f3 !important;
    font-size: 6.5pt;
    height: auto;
    min-height: 0;
    padding: 0 2px;
  }
  .badge.high, .badge.critical { background: #fdd !important; }
  .badge.medium { background: #ffd !important; }
  .badge.ok, .badge.low { background: #dfd !important; }
  a { color: inherit; text-decoration: none; }
  footer.report-foot { color: #555 !important; border-top-color: #ccc; font-size: 7pt; }
  /* Explicit column widths — CVE/IP/dates/scores nowrap; title flexes. */
  table.findings th.col-kev, table.findings td.col-kev { width: 4%; }
  table.findings th.col-sev, table.findings td.col-sev { width: 7%; }
  table.findings th.col-cvss, table.findings td.col-cvss,
  table.findings th.col-epss, table.findings td.col-epss { width: 5%; white-space: nowrap; }
  table.findings th.col-cve, table.findings td.col-cve { width: 13%; white-space: nowrap; }
  table.findings th.col-title, table.findings td.col-title {
    width: auto; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  table.findings th.col-device, table.findings td.col-device { width: 12%; white-space: nowrap; }
  table.findings th.col-network, table.findings td.col-network { width: 8%; }
  table.findings th.col-port, table.findings td.col-port { width: 7%; white-space: nowrap; }
  table.findings th.col-state, table.findings td.col-state { width: 9%; }
  table.findings th.col-first, table.findings td.col-first { width: 10%; white-space: nowrap; }
}
"""


def _js() -> str:
    return r"""
(function(){
  const DATA = window.__REPORT_DATA__ || [];
  const root = document.getElementById('groups');
  const searchEl = document.getElementById('q');
  const countEl = document.getElementById('visible-count');
  let groupBy = 'device';
  let sortKey = 'risk';
  let sortDir = -1;
  let sevFilter = new Set();
  let textQ = '';
  let openGroups = new Set();
  let expandedRows = new Set();
  let searchTimer = null;
  let printing = false;
  let prePrintOpen = null;
  const COLS = ['kev','sev','cvss','epss','cve','title','device','network','port','state','first'];
  const hiddenCols = new Set();
  const SEV_DESC = {critical:4,high:3,medium:2,low:1,unknown:0};
  const SEV_ASC_RANK = {critical:0,high:1,medium:2,low:3,unknown:4};

  function esc(s){
    return String(s==null?'':s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }
  function sevClass(s){
    if(s==='critical'||s==='high') return 'high';
    if(s==='medium') return 'medium';
    if(s==='low') return 'ok';
    return 'outline';
  }
  function riskScore(f){
    return (f.kev?1000:0) + (f.cvss_base==null?0:Number(f.cvss_base));
  }
  function cveParts(id){
    const m = /^CVE-(\d+)-(\d+)$/i.exec(String(id||''));
    return m ? [parseInt(m[1],10), parseInt(m[2],10)] : [0, 0];
  }
  function compareCveIds(a, b){
    const [ay, an] = cveParts(a), [by, bn] = cveParts(b);
    return (ay - by) || (an - bn) || String(a||'').localeCompare(String(b||''));
  }
  function matches(f){
    if(sevFilter.size && !sevFilter.has(f.severity||'unknown')) return false;
    if(!textQ) return true;
    const bits = [f.cve_id,f.summary,f.device_ip,f.device_hostname,f.network,
      f.product,f.service,f.state,(f.hidden_reasons||[]).join(' ')];
    return bits.join(' ').toLowerCase().includes(textQ);
  }
  function compareFindings(a, b, key, dir){
    let cmp = 0;
    switch(key){
      case 'cve': cmp = compareCveIds(a.cve_id, b.cve_id); break;
      case 'title': cmp = String(a.summary||'').localeCompare(String(b.summary||'')); break;
      case 'device': cmp = (a.device_ip||'').localeCompare(b.device_ip||'')
        || (a.device_hostname||'').localeCompare(b.device_hostname||''); break;
      case 'network': cmp = (a.network||'').localeCompare(b.network||''); break;
      case 'cvss': cmp = (Number(a.cvss_base)||0) - (Number(b.cvss_base)||0); break;
      case 'epss': cmp = (Number(a.epss)||0) - (Number(b.epss)||0); break;
      case 'port': cmp = (Number(a.port)||0) - (Number(b.port)||0)
        || String(a.protocol||'').localeCompare(String(b.protocol||'')); break;
      case 'state': cmp = String(a.state||'').localeCompare(String(b.state||'')); break;
      case 'first': cmp = String(a.first_seen_at||'').localeCompare(String(b.first_seen_at||'')); break;
      case 'severity':
        cmp = (SEV_DESC[a.severity]??-1) - (SEV_DESC[b.severity]??-1);
        break;
      case 'risk':
      default: cmp = riskScore(a) - riskScore(b); break;
    }
    return cmp * dir;
  }
  function sortFns(a,b){ return compareFindings(a,b,sortKey,sortDir); }
  function groupKey(f){
    return groupBy==='cve' ? f.cve_id : f.device_uuid;
  }
  function rowId(f){
    return f.device_uuid+'|'+f.protocol+'|'+f.port+'|'+f.cve_id;
  }
  function groupStats(items){
    let maxSev = 'unknown', maxCvss = null, anyKev = false;
    for(const {f} of items){
      if(f.kev) anyKev = true;
      const r = SEV_ASC_RANK[f.severity]??4;
      if(r < (SEV_ASC_RANK[maxSev]??4)) maxSev = f.severity||'unknown';
      if(f.cvss_base!=null && (maxCvss==null || f.cvss_base>maxCvss)) maxCvss = f.cvss_base;
    }
    return {maxSev, maxCvss, anyKev, count: items.length};
  }
  function groupTitleHtml(f, stats){
    if(groupBy==='cve'){
      const tip = f.cve_id+(f.summary? ' — '+f.summary:'');
      return '<span class="clip" title="'+esc(tip)+'">'
        +'<span class="mono">'+esc(f.cve_id)+'</span>'
        +(f.summary? ' — '+esc(f.summary.slice(0,72)):'')
        +'</span>';
    }
    const ip = f.device_ip||f.device_uuid;
    const host = f.device_hostname||'';
    const net = f.network||'';
    const tip = [ip, host, net].filter(Boolean).join(' · ');
    return '<span class="clip" title="'+esc(tip)+'">'
      +'<span class="mono">'+esc(ip)+'</span>'
      +(host? ' · '+esc(host):'')
      +(net? ' · '+esc(net):'')
      +'</span>';
  }
  function groupMetaHtml(stats){
    let bits = '';
    if(groupBy==='cve'){
      bits += '<span class="badge '+sevClass(stats.maxSev)+'">'+esc(stats.maxSev)+'</span>';
      if(stats.maxCvss!=null) bits += '<span class="mono">'+Number(stats.maxCvss).toFixed(1)+'</span>';
      if(stats.anyKev) bits += '<span class="badge high">KEV</span>';
    }
    bits += '<span>'+stats.count+' finding'+(stats.count===1?'':'s')+'</span>';
    return bits;
  }
  function detailHtml(f){
    const refs = (f.references||[]).map(u=>
      '<a href="'+esc(u)+'" rel="noopener noreferrer">'+esc(u)+'</a>').join('<br>');
    const hidden = (f.hidden_reasons||[]).map(r=>
      '<span class="badge outline hidden-reason">'+esc(r)+'</span>').join(' ');
    return '<div class="detail-grid">'
      +'<div><dt>Description</dt><dd>'+esc(f.summary||'—')+'</dd></div>'
      +'<div><dt>CVSS</dt><dd class="mono">'+(f.cvss_base==null?'—':Number(f.cvss_base).toFixed(1))
      +(f.cvss_vector? ' · '+esc(f.cvss_vector):'')+'</dd></div>'
      +'<div><dt>KEV</dt><dd>'+(f.kev?'Yes':'No')+'</dd></div>'
      +'<div><dt>Ports / services</dt><dd class="mono">'+esc((f.protocol||'').toUpperCase()+'/'+f.port)
      +' '+esc([f.product,f.version].filter(Boolean).join(' ')||f.service||'')+'</dd></div>'
      +'<div><dt>First / last seen</dt><dd>'+esc(f.first_seen||'—')+' / '+esc(f.last_seen||'—')+'</dd></div>'
      +'<div><dt>Hidden</dt><dd>'+(hidden||'—')+'</dd></div>'
      +'<div><dt>References</dt><dd>'+(refs||'—')+'</dd></div>'
      +'</div>';
  }
  function rowHtml(f){
    const id = rowId(f);
    const open = expandedRows.has(id);
    const reasons = (f.hidden_reasons||[]).map(r=>
      '<div class="badge outline hidden-reason">'+esc(r)+'</div>').join('');
    const hostTip = [f.device_ip, f.device_hostname].filter(Boolean).join(' · ');
    const host = '<span class="mono" title="'+esc(hostTip)+'">'+esc(f.device_ip)
      +(f.device_hostname?' · '+esc(f.device_hostname):'')+'</span>';
    let tr = '<tr class="row" data-row="'+esc(id)+'">'
      +'<td class="col-kev">'+(f.kev?'<span class="badge high">KEV</span>':'')+'</td>'
      +'<td class="col-sev"><span class="badge '+sevClass(f.severity)+'">'
      +esc(f.severity||'unknown')+'</span></td>'
      +'<td class="col-cvss mono nowrap">'+(f.cvss_base==null?'—':Number(f.cvss_base).toFixed(1))+'</td>'
      +'<td class="col-epss mono nowrap">'+(f.epss==null?'—':Math.round(f.epss*100)+'%')+'</td>'
      +'<td class="col-cve mono nowrap">'+esc(f.cve_id)+'</td>'
      +'<td class="col-title clip">'+esc(f.summary||'—')+'</td>'
      +'<td class="col-device clip">'+host+'</td>'
      +'<td class="col-network clip">'+esc(f.network)+'</td>'
      +'<td class="col-port clip mono nowrap">'+esc((f.protocol||'').toUpperCase()+'/'+f.port)+'</td>'
      +'<td class="col-state">'+esc(f.state)+reasons+'</td>'
      +'<td class="col-first nowrap">'+esc(f.first_seen||'—')+'</td>'
      +'</tr>';
    if(open){
      tr += '<tr class="detail-row'+(printing?' print-show':'')+'" data-detail="'+esc(id)
        +'"><td colspan="11">'+detailHtml(f)+'</td></tr>';
    }
    return tr;
  }
  function tableClass(){
    const hide = COLS.filter(c=>hiddenCols.has(c)).map(c=>'hide-'+c);
    hide.push(groupBy==='cve' ? 'group-by-cve' : 'group-by-device');
    return 'findings '+hide.join(' ');
  }
  function tableShell(rowsHtml){
    const th = (key, cls, label)=>'<th class="'+cls+'" data-sort="'+key+'">'+label
      +(sortKey===key?(sortDir<0?' ▼':' ▲'):'')+'</th>';
    return '<table class="'+tableClass()+'"><thead><tr>'
      +th('risk','col-kev','KEV')+th('severity','col-sev','Severity')
      +th('cvss','col-cvss','CVSS')+th('epss','col-epss','EPSS')
      +th('cve','col-cve','CVE')+th('title','col-title','Title')
      +th('device','col-device','Device')+th('network','col-network','Network')
      +th('port','col-port','Port')+th('state','col-state','State')
      +th('first','col-first','First seen')
      +'</tr></thead><tbody>'+rowsHtml+'</tbody></table>';
  }
  function buildGroups(filtered){
    const map = new Map();
    filtered.forEach(f=>{
      const k = groupKey(f);
      if(!map.has(k)) map.set(k, {sample:f, items:[]});
      map.get(k).items.push({f});
    });
    const keys = [...map.keys()].sort((ka, kb)=>{
      const sa = groupStats(map.get(ka).items);
      const sb = groupStats(map.get(kb).items);
      const ra = SEV_ASC_RANK[sa.maxSev]??4, rb = SEV_ASC_RANK[sb.maxSev]??4;
      return (ra - rb) || (sb.count - sa.count) || String(ka).localeCompare(String(kb));
    });
    return {map, keys};
  }
  function fillGroupBody(gEl, items){
    const body = gEl.querySelector('.group-body');
    body.innerHTML = tableShell(items.map(({f})=>rowHtml(f)).join(''));
  }
  function renderGroupElement(k, g, isOpen){
    const stats = groupStats(g.items);
    const body = isOpen
      ? tableShell(g.items.map(({f})=>rowHtml(f)).join(''))
      : '<div class="empty-msg" data-lazy="1">Expand to load '
        +g.items.length+' finding'+(g.items.length===1?'':'s')+'…</div>';
    return '<div class="group'+(isOpen?' open':'')+'" data-group="'+esc(k)+'">'
      +'<button type="button" class="group-head" aria-expanded="'+(isOpen?'true':'false')+'">'
      +'<span class="chev">▸</span>'
      +'<span class="title">'+groupTitleHtml(g.sample, stats)+'</span>'
      +'<span class="meta-bits">'+groupMetaHtml(stats)+'</span></button>'
      +'<div class="group-body">'+body+'</div></div>';
  }
  function render(opts){
    const forceFull = !!(opts && opts.forceFull);
    const filtered = DATA.filter(matches).sort(sortFns);
    countEl.textContent = String(filtered.length);
    const {map, keys} = buildGroups(filtered);
    if(!keys.length){
      root.innerHTML = '<p class="empty-msg">No findings match the current filters.</p>';
      return;
    }
    if(!forceFull && root.children.length){
      const existing = new Map();
      [...root.children].forEach(el=>{
        if(el.dataset && el.dataset.group!=null) existing.set(el.dataset.group, el);
      });
      const keep = new Set(keys);
      existing.forEach((el, k)=>{ if(!keep.has(k)) el.remove(); });
      let prev = null;
      keys.forEach(k=>{
        const g = map.get(k);
        const isOpen = printing || openGroups.has(k);
        let el = existing.get(k);
        if(!el){
          const holder = document.createElement('div');
          holder.innerHTML = renderGroupElement(k, g, isOpen);
          el = holder.firstChild;
          if(prev && prev.nextSibling) root.insertBefore(el, prev.nextSibling);
          else if(prev) root.appendChild(el);
          else root.insertBefore(el, root.firstChild);
        } else {
          // Update header meta without rebuilding collapsed bodies.
          const stats = groupStats(g.items);
          const title = el.querySelector('.title');
          const meta = el.querySelector('.meta-bits');
          const head = el.querySelector('.group-head');
          if(title) title.innerHTML = groupTitleHtml(g.sample, stats);
          if(meta) meta.innerHTML = groupMetaHtml(stats);
          if(isOpen){
            el.classList.add('open');
            if(head) head.setAttribute('aria-expanded','true');
            fillGroupBody(el, g.items);
          } else {
            el.classList.remove('open');
            if(head) head.setAttribute('aria-expanded','false');
            const body = el.querySelector('.group-body');
            if(body && !body.querySelector('[data-lazy]')){
              body.innerHTML = '<div class="empty-msg" data-lazy="1">Expand to load findings…</div>';
            }
          }
          // Reorder if needed
          if(prev){
            if(prev.nextSibling !== el) root.insertBefore(el, prev.nextSibling);
          } else if(root.firstChild !== el){
            root.insertBefore(el, root.firstChild);
          }
        }
        prev = el;
      });
      return;
    }
    const holder = document.createElement('div');
    holder.innerHTML = keys.map(k=>{
      const g = map.get(k);
      return renderGroupElement(k, g, printing || openGroups.has(k));
    }).join('');
    root.innerHTML = '';
    while(holder.firstChild) root.appendChild(holder.firstChild);
  }

  root.addEventListener('click', e=>{
    const head = e.target.closest('.group-head');
    if(head){
      const g = head.closest('.group');
      const key = g.getAttribute('data-group');
      if(openGroups.has(key)) openGroups.delete(key); else openGroups.add(key);
      if(openGroups.has(key)){
        const filtered = DATA.filter(matches).sort(sortFns);
        const items = filtered.filter(f=>groupKey(f)===key).map(f=>({f}));
        fillGroupBody(g, items);
        g.classList.add('open');
        head.setAttribute('aria-expanded','true');
      } else {
        g.classList.remove('open');
        head.setAttribute('aria-expanded','false');
        g.querySelector('.group-body').innerHTML =
          '<div class="empty-msg" data-lazy="1">Expand to load findings…</div>';
      }
      return;
    }
    const row = e.target.closest('tr.row');
    if(row){
      const id = row.getAttribute('data-row');
      if(expandedRows.has(id)) expandedRows.delete(id); else expandedRows.add(id);
      const g = row.closest('.group');
      const key = g.getAttribute('data-group');
      const filtered = DATA.filter(matches).sort(sortFns);
      const items = filtered.filter(f=>groupKey(f)===key).map(f=>({f}));
      fillGroupBody(g, items);
      return;
    }
    const th = e.target.closest('th[data-sort]');
    if(th){
      const k = th.getAttribute('data-sort');
      if(sortKey===k) sortDir = -sortDir; else { sortKey=k; sortDir=-1; }
      render();
    }
  });

  document.getElementById('group-device').addEventListener('click', ()=>{
    groupBy='device'; openGroups.clear();
    document.getElementById('group-device').classList.add('on');
    document.getElementById('group-cve').classList.remove('on');
    render({forceFull:true});
  });
  document.getElementById('group-cve').addEventListener('click', ()=>{
    groupBy='cve'; openGroups.clear();
    document.getElementById('group-cve').classList.add('on');
    document.getElementById('group-device').classList.remove('on');
    render({forceFull:true});
  });
  document.getElementById('expand-all').addEventListener('click', ()=>{
    DATA.filter(matches).forEach(f=> openGroups.add(groupKey(f)));
    render({forceFull:true});
  });
  document.getElementById('collapse-all').addEventListener('click', ()=>{
    openGroups.clear(); expandedRows.clear(); render({forceFull:true});
  });
  searchEl.addEventListener('input', ()=>{
    clearTimeout(searchTimer);
    searchTimer = setTimeout(()=>{
      textQ = searchEl.value.trim().toLowerCase();
      render();
    }, 200);
  });
  document.querySelectorAll('.sev-chip').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const s = btn.getAttribute('data-sev');
      if(sevFilter.has(s)){ sevFilter.delete(s); btn.classList.remove('on'); }
      else { sevFilter.add(s); btn.classList.add('on'); }
      render();
    });
  });
  const menu = document.getElementById('col-menu');
  document.getElementById('col-menu-btn').addEventListener('click', ()=> menu.classList.toggle('open'));
  document.addEventListener('click', e=>{ if(!menu.contains(e.target)) menu.classList.remove('open'); });
  menu.querySelectorAll('input[type=checkbox]').forEach(cb=>{
    cb.addEventListener('change', ()=>{
      if(cb.checked) hiddenCols.delete(cb.value); else hiddenCols.add(cb.value);
      root.querySelectorAll('table.findings').forEach(t=>{
        COLS.forEach(c=> t.classList.toggle('hide-'+c, hiddenCols.has(c)));
      });
    });
  });

  // Theme toggle: auto / light / dark
  const themeBtns = document.querySelectorAll('[data-theme-set]');
  function applyTheme(mode){
    if(mode==='auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', mode);
    try { localStorage.setItem('pr-vuln-report-theme', mode); } catch(e){}
    themeBtns.forEach(b=> b.classList.toggle('on', b.getAttribute('data-theme-set')===mode));
  }
  let saved = 'auto';
  try { saved = localStorage.getItem('pr-vuln-report-theme') || 'auto'; } catch(e){}
  applyTheme(saved);
  themeBtns.forEach(b=> b.addEventListener('click', ()=> applyTheme(b.getAttribute('data-theme-set'))));

  // Print: expand all groups (and keep previously expanded row details), then restore.
  window.addEventListener('beforeprint', ()=>{
    prePrintOpen = new Set(openGroups);
    printing = true;
    DATA.filter(matches).forEach(f=> openGroups.add(groupKey(f)));
    render({forceFull:true});
    // Mark currently expanded detail rows for print visibility.
    root.querySelectorAll('tr.detail-row').forEach(tr=>{
      const id = tr.getAttribute('data-detail');
      if(expandedRows.has(id)) tr.classList.add('print-show');
    });
  });
  window.addEventListener('afterprint', ()=>{
    printing = false;
    if(prePrintOpen){ openGroups = prePrintOpen; prePrintOpen = null; }
    render({forceFull:true});
  });

  // Expose sort helpers for unit/e2e tests.
  window.__REPORT_API__ = {
    compareCveIds, compareFindings, riskScore, rowId, groupKey,
    getSort: ()=>({key:sortKey, dir:sortDir}),
    setSort: (key, dir)=>{ sortKey=key; sortDir=dir; render({forceFull:true}); },
    getGroupBy: ()=>groupBy,
    getOpenGroups: ()=>[...openGroups],
    getExpandedRows: ()=>[...expandedRows],
    render,
  };

  render({forceFull:true});
})();
"""


def build_html_report(
    *,
    findings: list[dict[str, Any]],
    filter_line: str,
    generated_at: datetime | None = None,
    product_name: str = "PortReveal",
) -> str:
    """Return a full HTML document string (UTF-8), XSS-safe for untrusted finding fields."""
    now = generated_at or datetime.now().astimezone()
    stats = compute_stats(findings)
    tz = now.tzname() or "local"
    gen_label = now.strftime("%Y-%m-%d %H:%M:%S") + f" ({tz})"

    sev = stats.severity_counts
    cards = f"""
<section class="cards" aria-label="Summary">
  <div class="card"><div class="label">Findings</div><div class="value">{stats.findings_total}</div></div>
  <div class="card crit"><div class="label">Critical</div><div class="value">{sev.get('critical', 0)}</div></div>
  <div class="card"><div class="label">High</div>
    <div class="value" style="color:var(--high)">{sev.get('high', 0)}</div></div>
  <div class="card"><div class="label">Medium</div>
    <div class="value" style="color:var(--medium)">{sev.get('medium', 0)}</div></div>
  <div class="card"><div class="label">Low</div>
    <div class="value" style="color:var(--ok)">{sev.get('low', 0)}</div></div>
  <div class="card kev"><div class="label">KEV</div><div class="value">{stats.kev_count}</div></div>
  <div class="card"><div class="label">Affected devices</div><div class="value">{stats.device_count}</div></div>
</section>"""

    chips = "".join(
        f'<button type="button" class="chip sev-chip" data-sev="{s}">{s.capitalize()}</button>'
        for s in SEV_ORDER
    )
    _upper = frozenset(("kev", "cve", "cvss", "epss"))
    col_checks = "".join(
        f'<label><input type="checkbox" value="{c}" checked> '
        f"{c.upper() if c in _upper else c.capitalize()}</label>"
        for c in ("kev", "sev", "cvss", "epss", "cve", "title", "device", "network", "port", "state", "first")
    )

    payload = _payload_json(findings)
    css = _css()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>{_esc(product_name)} vulnerability report</title>
<style>{css}</style>
</head>
<body>
<div class="wrap">
<header class="report-header">
  <div class="header-row">
    <div>
      <h1>{_esc(product_name)} vulnerability report</h1>
      <p class="meta">Generated {_esc(gen_label)}</p>
      <p class="filters"><strong>Filters:</strong> {_esc(filter_line)}</p>
    </div>
    <div class="theme-toggle" role="group" aria-label="Color theme">
      <button type="button" data-theme-set="auto" class="on">Auto</button>
      <button type="button" data-theme-set="light">Light</button>
      <button type="button" data-theme-set="dark">Dark</button>
    </div>
  </div>
</header>
{cards}
{_charts_html(stats)}
<div class="toolbar" role="toolbar" aria-label="Findings controls">
  <div class="group-mode">
    <button type="button" id="group-device" class="on">Group by Device</button>
    <button type="button" id="group-cve">Group by CVE</button>
  </div>
  <button type="button" id="expand-all">Expand all</button>
  <button type="button" id="collapse-all">Collapse all</button>
  <input type="search" id="q" placeholder="Search findings…" aria-label="Search findings">
  <div class="chip-row" aria-label="Severity filter">{chips}</div>
  <div class="col-menu" id="col-menu">
    <button type="button" class="menu-btn" id="col-menu-btn">Columns</button>
    <div class="col-menu-panel">{col_checks}</div>
  </div>
  <span class="meta"><span id="visible-count">0</span> shown</span>
</div>
<div id="groups" class="groups"></div>
<footer class="report-foot">{_esc(product_name)} · offline HTML report · {stats.findings_total} findings</footer>
</div>
<script>window.__REPORT_DATA__={payload};</script>
<script>{_js()}</script>
</body>
</html>
"""
