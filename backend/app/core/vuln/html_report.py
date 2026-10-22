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
from datetime import datetime, timedelta, timezone
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


@dataclass
class ReportStats:
    findings_total: int
    kev_count: int
    device_count: int
    severity_counts: dict[str, int]
    by_network: list[tuple[str, int]]
    weekly_first_seen: list[tuple[str, int]]


def compute_stats(findings: list[dict[str, Any]]) -> ReportStats:
    sev = {k: 0 for k in SEV_ORDER}
    kev = 0
    devices: set[str] = set()
    nets: Counter[str] = Counter()
    weeks: Counter[str] = Counter()
    for f in findings:
        s = f.get("severity") or "unknown"
        if s not in sev:
            s = "unknown"
        sev[s] += 1
        if f.get("kev"):
            kev += 1
        devices.add(str(f.get("device_uuid") or ""))
        nets[str(f.get("network") or "Unassigned")] += 1
        fs = f.get("first_seen_at")
        if fs:
            try:
                dt = datetime.fromisoformat(fs.replace("Z", "+00:00"))
                # Monday-start ISO week label
                monday = (dt.date() - timedelta(days=dt.weekday())).isoformat()
                weeks[monday] += 1
            except ValueError:
                pass
    devices.discard("")
    by_net = sorted(nets.items(), key=lambda x: (-x[1], x[0]))[:12]
    weekly = sorted(weeks.items(), key=lambda x: x[0])[-16:]
    return ReportStats(
        findings_total=len(findings),
        kev_count=kev,
        device_count=len(devices),
        severity_counts=sev,
        by_network=by_net,
        weekly_first_seen=weekly,
    )


def _svg_bar_chart(
    title: str,
    items: list[tuple[str, int]],
    *,
    colors: dict[str, str] | None = None,
    width: int = 320,
    height: int = 160,
) -> str:
    """Simple horizontal or vertical bars as inline SVG (no libraries)."""
    if not items:
        return (
            f'<figure class="chart"><figcaption>{_esc(title)}</figcaption>'
            f'<p class="empty">No data</p></figure>'
        )
    max_v = max(v for _, v in items) or 1
    pad_l, pad_r, pad_t, pad_b = 8, 8, 8, 28
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
        short = label if len(label) <= 10 else label[:9] + "…"
        labels.append(
            f'<text x="{lx:.1f}" y="{height - 6}" text-anchor="middle" class="tick">{_esc(short)}</text>'
        )
        if h > 14:
            bars.append(
                f'<text x="{lx:.1f}" y="{y - 2}" text-anchor="middle" class="val">{val}</text>'
            )
        else:
            bars.append(
                f'<text x="{lx:.1f}" y="{y - 2}" text-anchor="middle" class="val">{val}</text>'
            )
    return (
        f'<figure class="chart"><figcaption>{_esc(title)}</figcaption>'
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" '
        f'aria-label="{_esc(title)}">{"".join(bars)}{"".join(labels)}</svg></figure>'
    )


def _svg_donut(
    title: str,
    parts: list[tuple[str, int, str]],
    *,
    size: int = 160,
) -> str:
    total = sum(v for _, v, _ in parts) or 1
    cx = cy = size / 2
    r = size * 0.36
    stroke = size * 0.14
    circ = 2 * 3.141592653589793 * r
    offset = 0.0
    arcs = []
    legend = []
    for label, val, color in parts:
        if val <= 0:
            continue
        length = (val / total) * circ
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{_esc(color)}" '
            f'stroke-width="{stroke:.1f}" stroke-dasharray="{length:.2f} {circ - length:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})">'
            f"<title>{_esc(label)}: {val}</title></circle>"
        )
        offset += length
        legend.append(
            f'<li><span class="swatch" style="background:{_esc(color)}"></span>'
            f"{_esc(label)} <strong>{val}</strong></li>"
        )
    if not arcs:
        return (
            f'<figure class="chart"><figcaption>{_esc(title)}</figcaption>'
            f'<p class="empty">No data</p></figure>'
        )
    return (
        f'<figure class="chart"><figcaption>{_esc(title)}</figcaption>'
        f'<div class="donut-wrap">'
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" '
        f'aria-label="{_esc(title)}">{"".join(arcs)}'
        f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="central" class="donut-total">'
        f"{total}</text></svg>"
        f'<ul class="legend">{"".join(legend)}</ul></div></figure>'
    )


def _charts_html(stats: ReportStats) -> str:
    sev_items = [(k, stats.severity_counts.get(k, 0)) for k in SEV_ORDER if stats.severity_counts.get(k, 0)]
    sev_chart = _svg_bar_chart("Severity distribution", sev_items, colors=SEV_COLORS)
    net_chart = _svg_bar_chart(
        "Findings by network",
        stats.by_network[:8],
        colors=defaultdict(lambda: "#1965d9"),
    )
    week_items = [(w[5:] if len(w) >= 10 else w, n) for w, n in stats.weekly_first_seen]  # MM-DD
    trend_chart = _svg_bar_chart("First seen (weekly)", week_items, colors=defaultdict(lambda: "#0ed0d9"))
    kev_n = stats.kev_count
    other = max(0, stats.findings_total - kev_n)
    kev_chart = _svg_donut(
        "KEV share",
        [("KEV", kev_n, "#f87171"), ("Other", other, "#25395c")],
    )
    return f'<section class="charts" aria-label="Charts">{sev_chart}{net_chart}{trend_chart}{kev_chart}</section>'


def _payload_json(findings: list[dict[str, Any]]) -> str:
    """JSON for the inline script; escape ``</`` so ``</script>`` cannot break out."""
    raw = json.dumps(findings, ensure_ascii=False, separators=(",", ":"))
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _css() -> str:
    return """
:root {
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
  :root {
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
* { box-sizing:border-box; }
html, body { margin:0; padding:0; background:var(--bg); color:var(--text);
  font:14px/1.45 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; }
body { min-height:100vh; }
.wrap { max-width:1400px; margin:0 auto; padding:20px 24px 48px; }
header.report-header { margin-bottom:18px; padding-bottom:12px; border-bottom:1px solid var(--border); }
header.report-header h1 { margin:0 0 6px; font-size:22px; letter-spacing:.01em; }
.meta, .filters { margin:4px 0; color:var(--text-2); font-size:13px; }
.filters strong { color:var(--text); }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin:16px 0; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:12px 14px; }
.card .label { font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
.card .value { font-size:22px; font-weight:700; margin-top:4px; }
.card.crit .value { color:var(--high); }
.card.kev .value { color:var(--high); }
.charts { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:14px; margin:8px 0 20px; }
.chart { margin:0; background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:10px 12px; }
.chart figcaption { font-size:12px; font-weight:600; color:var(--text-2); margin-bottom:6px; }
.chart .empty { color:var(--muted); font-style:italic; margin:12px 0; }
.chart svg .tick { fill:var(--muted); font-size:9px; }
.chart svg .val { fill:var(--text-2); font-size:10px; }
.chart svg .donut-total { fill:var(--text); font-size:18px; font-weight:700; }
.donut-wrap { display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
.legend { list-style:none; margin:0; padding:0; font-size:12px; }
.legend li { display:flex; align-items:center; gap:6px; margin:4px 0; }
.swatch { width:10px; height:10px; border-radius:2px; display:inline-block; }
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
.group-head .chev { width:1.2em; color:var(--muted); }
.group-head .title { flex:1; font-weight:600; min-width:0; }
.group-head .meta-bits { color:var(--muted); font-size:12px; white-space:nowrap; }
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
.hide-kev th:nth-child(1), .hide-kev td:nth-child(1),
.hide-sev th:nth-child(2), .hide-sev td:nth-child(2),
.hide-cvss th:nth-child(3), .hide-cvss td:nth-child(3),
.hide-epss th:nth-child(4), .hide-epss td:nth-child(4),
.hide-cve th:nth-child(5), .hide-cve td:nth-child(5),
.hide-title th:nth-child(6), .hide-title td:nth-child(6),
.hide-device th:nth-child(7), .hide-device td:nth-child(7),
.hide-network th:nth-child(8), .hide-network td:nth-child(8),
.hide-port th:nth-child(9), .hide-port td:nth-child(9),
.hide-state th:nth-child(10), .hide-state td:nth-child(10),
.hide-first th:nth-child(11), .hide-first td:nth-child(11) { display:none; }
@media print {
  @page { size: landscape; margin: 8mm; }
  body { background:#fff !important; color:#111 !important; color-scheme:light !important;
    -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .wrap { max-width:none; padding:0; }
  .toolbar, .col-menu { display:none !important; }
  .group { break-inside:avoid; border-color:#bbb; }
  .group-body { display:block !important; }
  .group:not(.open) .group-body { display:none !important; }
  table.findings th { background:#eee !important; color:#111; }
  .badge { border:1px solid #666; }
  a { color:inherit; text-decoration:none; }
}
"""


def _js() -> str:
    # Compact interactive layer: group/sort/filter/lazy row paint.
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
  const COLS = ['kev','sev','cvss','epss','cve','title','device','network','port','state','first'];
  const hiddenCols = new Set();

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
    return (f.kev?1000:0) + (f.cvss_base==null?0:f.cvss_base);
  }
  function matches(f){
    if(sevFilter.size && !sevFilter.has(f.severity||'unknown')) return false;
    if(!textQ) return true;
    const bits = [f.cve_id,f.summary,f.device_ip,f.device_hostname,f.network,
      f.product,f.service,f.state,(f.hidden_reasons||[]).join(' ')];
    return bits.join(' ').toLowerCase().includes(textQ);
  }
  function sortFns(a,b){
    let cmp = 0;
    switch(sortKey){
      case 'cve': cmp = a.cve_id.localeCompare(b.cve_id); break;
      case 'device': cmp = (a.device_ip||'').localeCompare(b.device_ip||'')
        || (a.device_hostname||'').localeCompare(b.device_hostname||''); break;
      case 'network': cmp = (a.network||'').localeCompare(b.network||''); break;
      case 'cvss': cmp = (a.cvss_base||0) - (b.cvss_base||0); break;
      case 'first': cmp = (a.first_seen_at||'').localeCompare(b.first_seen_at||''); break;
      case 'severity': {
        const o={critical:0,high:1,medium:2,low:3,unknown:4};
        cmp = (o[a.severity]??5) - (o[b.severity]??5); break;
      }
      default: cmp = riskScore(a) - riskScore(b);
    }
    return cmp * sortDir;
  }
  function groupKey(f){
    if(groupBy==='cve') return f.cve_id;
    return f.device_uuid;
  }
  function groupTitle(f){
    if(groupBy==='cve') return f.cve_id + (f.summary? ' — '+f.summary.slice(0,80):'');
    const host = f.device_hostname? ' · '+f.device_hostname:'';
    return (f.device_ip||f.device_uuid)+host+(f.network? ' · '+f.network:'');
  }
  function rowId(f,i){ return f.device_uuid+'|'+f.protocol+'|'+f.port+'|'+f.cve_id+'|'+i; }

  function detailHtml(f){
    const refs = (f.references||[]).map(u=>'<a href="'+esc(u)+'" rel="noopener noreferrer">'+esc(u)+'</a>').join('<br>');
    const hidden = (f.hidden_reasons||[]).map(r=>'<span class="badge outline hidden-reason">'+esc(r)+'</span>').join(' ');
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

  function rowHtml(f,i){
    const id = rowId(f,i);
    const open = expandedRows.has(id);
    const reasons = (f.hidden_reasons||[]).map(r=>
      '<div class="badge outline hidden-reason">'+esc(r)+'</div>').join('');
    const host = esc(f.device_ip)+(f.device_hostname?' <span class="clip">· '+esc(f.device_hostname)+'</span>':'');
    let tr = '<tr class="row" data-row="'+esc(id)+'">'
      +'<td>'+(f.kev?'<span class="badge high">KEV</span>':'')+'</td>'
      +'<td><span class="badge '+sevClass(f.severity)+'">'+esc(f.severity||'unknown')+'</span></td>'
      +'<td class="mono">'+(f.cvss_base==null?'—':Number(f.cvss_base).toFixed(1))+'</td>'
      +'<td class="mono">'+(f.epss==null?'—':Math.round(f.epss*100)+'%')+'</td>'
      +'<td class="mono">'+esc(f.cve_id)+'</td>'
      +'<td class="clip">'+esc(f.summary||'—')+'</td>'
      +'<td class="mono clip">'+host+'</td>'
      +'<td class="clip">'+esc(f.network)+'</td>'
      +'<td class="clip mono">'+esc((f.protocol||'').toUpperCase()+'/'+f.port)+'</td>'
      +'<td>'+esc(f.state)+reasons+'</td>'
      +'<td class="nowrap">'+esc(f.first_seen||'—')+'</td>'
      +'</tr>';
    if(open){
      tr += '<tr class="detail-row" data-detail="'+esc(id)+'"><td colspan="11">'+detailHtml(f)+'</td></tr>';
    }
    return tr;
  }

  function tableShell(rowsHtml){
    const th = (key,label)=>'<th data-sort="'+key+'">'+label+(sortKey===key?(sortDir<0?' ▼':' ▲'):'')+'</th>';
    return '<table class="findings '+COLS.filter(c=>hiddenCols.has(c)).map(c=>'hide-'+c).join(' ')+'">'
      +'<thead><tr>'
      +th('risk','KEV')+th('severity','Severity')+th('cvss','CVSS')+th('epss','EPSS')
      +th('cve','CVE')+th('title','Title')+th('device','Device')+th('network','Network')
      +th('port','Port')+th('state','State')+th('first','First seen')
      +'</tr></thead><tbody>'+rowsHtml+'</tbody></table>';
  }

  function render(){
    const filtered = DATA.filter(matches).sort(sortFns);
    countEl.textContent = String(filtered.length);
    const map = new Map();
    filtered.forEach((f,i)=>{
      const k = groupKey(f);
      if(!map.has(k)) map.set(k, {title: groupTitle(f), items:[]});
      map.get(k).items.push({f,i});
    });
    const keys = [...map.keys()];
    if(!keys.length){
      root.innerHTML = '<p class="empty-msg">No findings match the current filters.</p>';
      return;
    }
    const frag = document.createDocumentFragment();
    const holder = document.createElement('div');
    holder.innerHTML = keys.map(k=>{
      const g = map.get(k);
      const isOpen = openGroups.has(k);
      const body = isOpen
        ? tableShell(g.items.map(({f,i})=>rowHtml(f,i)).join(''))
        : '<div class="empty-msg" data-lazy="1">Expand to load '
          +g.items.length+' finding'+(g.items.length===1?'':'s')+'…</div>';
      return '<div class="group'+(isOpen?' open':'')+'" data-group="'+esc(k)+'">'
        +'<button type="button" class="group-head" aria-expanded="'+(isOpen?'true':'false')+'">'
        +'<span class="chev">▸</span><span class="title clip">'+esc(g.title)+'</span>'
        +'<span class="meta-bits">'+g.items.length+' finding'+(g.items.length===1?'':'s')+'</span></button>'
        +'<div class="group-body">'+body+'</div></div>';
    }).join('');
    while(holder.firstChild) frag.appendChild(holder.firstChild);
    root.innerHTML = '';
    root.appendChild(frag);
  }

  root.addEventListener('click', e=>{
    const head = e.target.closest('.group-head');
    if(head){
      const g = head.closest('.group');
      const key = g.getAttribute('data-group');
      if(openGroups.has(key)) openGroups.delete(key); else openGroups.add(key);
      // Lazy: only re-render this group's body when opening
      if(openGroups.has(key)){
        const filtered = DATA.filter(matches).sort(sortFns);
        const items = [];
        filtered.forEach((f,i)=>{ if(groupKey(f)===key) items.push({f,i}); });
        const body = g.querySelector('.group-body');
        body.innerHTML = tableShell(items.map(({f,i})=>rowHtml(f,i)).join(''));
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
      const items = [];
      filtered.forEach((f,i)=>{ if(groupKey(f)===key) items.push({f,i}); });
      g.querySelector('.group-body').innerHTML = tableShell(items.map(({f,i})=>rowHtml(f,i)).join(''));
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
    render();
  });
  document.getElementById('group-cve').addEventListener('click', ()=>{
    groupBy='cve'; openGroups.clear();
    document.getElementById('group-cve').classList.add('on');
    document.getElementById('group-device').classList.remove('on');
    render();
  });
  document.getElementById('expand-all').addEventListener('click', ()=>{
    const filtered = DATA.filter(matches);
    filtered.forEach(f=> openGroups.add(groupKey(f)));
    render();
  });
  document.getElementById('collapse-all').addEventListener('click', ()=>{
    openGroups.clear(); expandedRows.clear(); render();
  });
  searchEl.addEventListener('input', ()=>{
    textQ = searchEl.value.trim().toLowerCase();
    render();
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

  render();
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
        f'{c.upper() if c in _upper else c.capitalize()}</label>'
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
  <h1>{_esc(product_name)} vulnerability report</h1>
  <p class="meta">Generated {_esc(gen_label)}</p>
  <p class="filters"><strong>Filters:</strong> {_esc(filter_line)}</p>
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
