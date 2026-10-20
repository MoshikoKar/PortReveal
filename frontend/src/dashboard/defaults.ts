import type { Breakpoint, DashboardPrefs, KpiId, LayoutItem, Layouts, WidgetId, WidgetMeta } from './types';

export const DASHBOARD_SCHEMA_VERSION = 2;

export const BREAKPOINTS: Record<Breakpoint, number> = { lg: 1200, md: 768, sm: 0 };
// Fine grid (v2): 24/20 columns and 4px rows, so a resize step is 20px tall (row + margin).
export const COLS: Record<Breakpoint, number> = { lg: 24, md: 20, sm: 1 };
export const ROW_HEIGHT = 4;
export const GRID_MARGIN: [number, number] = [16, 16];

export const KPI_IDS: KpiId[] = [
  'known_hosts', 'active', 'new_hosts_24h', 'new_ports_24h',
  'service_changes_24h', 'open_ports', 'high_exposure', 'alerts_7d',
];

export const KPI_LABELS: Record<KpiId, string> = {
  known_hosts: 'Known hosts',
  active: 'Currently detected',
  new_hosts_24h: 'New hosts (24h)',
  new_ports_24h: 'New ports (24h)',
  service_changes_24h: 'Service changes (24h)',
  open_ports: 'Open ports',
  high_exposure: 'High exposure',
  alerts_7d: 'Alerts (7d)',
};

export const WIDGET_CATALOG: WidgetMeta[] = [
  // maxH is generous so users can fill the viewport; sparse content still truncates / Fit shrinks.
  // The KPI strip sizes its own height to its tiles (autoHeight); users only change its width.
  { id: 'kpis', title: 'KPI strip', description: 'Headline counts: hosts, ports, exposure, and alerts.',
    limits: { minW: 8, minH: 4, maxW: 24, maxH: 32 }, defaultSize: { w: 24, h: 8 }, autoHeight: true },
  { id: 'recent_changes', title: 'Recent changes', description: 'Latest events across every network.',
    limits: { minW: 6, minH: 10, maxW: 24, maxH: 125 }, defaultSize: { w: 14, h: 26 } },
  { id: 'scan_status', title: 'Scan status', description: 'Running scan progress, last result, and next schedule.',
    limits: { minW: 6, minH: 8, maxW: 24, maxH: 62 }, defaultSize: { w: 10, h: 13 } },
  { id: 'changes_by_type', title: 'Changes by type', description: 'Seven-day event counts by change type.',
    limits: { minW: 6, minH: 8, maxW: 24, maxH: 94 }, defaultSize: { w: 10, h: 13 } },
  { id: 'exposure_scores', title: 'Exposure scores', description: 'Hosts per exposure level and the riskiest hosts.',
    limits: { minW: 6, minH: 10, maxW: 24, maxH: 94 }, defaultSize: { w: 8, h: 21 } },
  { id: 'device_types', title: 'Device types', description: 'Host counts by classified device type.',
    limits: { minW: 6, minH: 8, maxW: 24, maxH: 94 }, defaultSize: { w: 8, h: 21 } },
  { id: 'watch_alerts', title: 'Watch alerts', description: 'Watch matches and policy violations from the last 7 days.',
    limits: { minW: 6, minH: 10, maxW: 24, maxH: 125 }, defaultSize: { w: 8, h: 21 } },
  { id: 'exposure_trend', title: 'Exposure trend', description: 'Thirty-day chart of hosts and open ports.',
    limits: { minW: 6, minH: 8, maxW: 24, maxH: 62 }, defaultSize: { w: 8, h: 13 }, fit: false },
  { id: 'networks', title: 'Networks', description: 'Configured networks with active hosts and baseline state.',
    limits: { minW: 6, minH: 8, maxW: 24, maxH: 94 }, defaultSize: { w: 8, h: 13 } },
  { id: 'top_ports', title: 'Most exposed ports', description: 'Ports open on the most hosts.',
    limits: { minW: 6, minH: 8, maxW: 24, maxH: 94 }, defaultSize: { w: 8, h: 21 } },
  { id: 'top_services', title: 'Exposed services', description: 'Services detected on the most hosts.',
    limits: { minW: 6, minH: 8, maxW: 24, maxH: 94 }, defaultSize: { w: 8, h: 21 } },
];

export const WIDGET_BY_ID: Record<WidgetId, WidgetMeta> = Object.fromEntries(
  WIDGET_CATALOG.map((w) => [w.id, w]),
) as Record<WidgetId, WidgetMeta>;

/** Default lg layout mirroring the previous fixed dashboard structure. */
function defaultLg(): LayoutItem[] {
  return [
    item('kpis', 0, 0, 24, 8),
    item('recent_changes', 0, 8, 14, 26),
    item('scan_status', 14, 8, 10, 13),
    item('changes_by_type', 14, 21, 10, 13),
    item('exposure_scores', 0, 34, 8, 21),
    item('device_types', 8, 34, 8, 21),
    item('watch_alerts', 16, 34, 8, 21),
    item('exposure_trend', 0, 55, 8, 13),
    item('networks', 0, 68, 8, 13),
    item('top_ports', 8, 55, 8, 26),
    item('top_services', 16, 55, 8, 26),
  ];
}

function item(id: WidgetId, x: number, y: number, w: number, h: number): LayoutItem {
  const lim = WIDGET_BY_ID[id].limits;
  return {
    i: id, x, y, w, h,
    minW: lim.minW, minH: lim.minH, maxW: lim.maxW, maxH: lim.maxH,
  };
}

/** Stack every widget full-width for single-column breakpoints. */
function stackFrom(source: LayoutItem[], cols: number): LayoutItem[] {
  let y = 0;
  return source.map((it) => {
    const meta = WIDGET_BY_ID[it.i as WidgetId];
    const lim = meta?.limits;
    const w = cols;
    const h = it.h;
    const next = {
      i: it.i, x: 0, y, w, h,
      minW: lim ? Math.min(lim.minW, cols) : 1,
      minH: lim?.minH,
      maxW: lim?.maxW != null ? Math.min(lim.maxW, cols) : cols,
      maxH: lim?.maxH,
    };
    y += h;
    return next;
  });
}

/** Scale lg layout into md columns (approximate x/w). */
function scaleToMd(source: LayoutItem[]): LayoutItem[] {
  const from = COLS.lg;
  const to = COLS.md;
  return source.map((it) => {
    const meta = WIDGET_BY_ID[it.i as WidgetId];
    const lim = meta?.limits;
    // Round the edges, not x and w separately, so neighbours that touched still touch (no overlap).
    const left = Math.round((it.x / from) * to);
    const right = Math.round(((it.x + it.w) / from) * to);
    const w = Math.max(lim ? Math.min(lim.minW, to) : 1, right - left);
    const x = Math.min(left, Math.max(0, to - w));
    return {
      i: it.i, x, y: it.y, w, h: it.h,
      minW: lim ? Math.min(lim.minW, to) : 1,
      minH: lim?.minH,
      maxW: lim?.maxW != null ? Math.min(lim.maxW, to) : to,
      maxH: lim?.maxH,
    };
  });
}

export function defaultLayouts(): Layouts {
  const lg = defaultLg();
  return { lg, md: scaleToMd(lg), sm: stackFrom(lg, COLS.sm) };
}

export function defaultDashboardPrefs(): DashboardPrefs {
  return {
    v: DASHBOARD_SCHEMA_VERSION,
    layouts: defaultLayouts(),
    hidden: [],
    kpiVisible: [...KPI_IDS],
  };
}

export function withLimits(items: LayoutItem[], cols: number): LayoutItem[] {
  return items.map((it) => {
    const meta = WIDGET_BY_ID[it.i as WidgetId];
    if (!meta) return it;
    const { minW, minH, maxW, maxH } = meta.limits;
    const floorW = Math.min(minW, cols);
    const capW = Math.min(cols, maxW ?? cols);
    const w = Math.min(capW, Math.max(floorW, it.w));
    const h = Math.min(maxH, Math.max(minH, it.h));
    const x = Math.min(Math.max(0, it.x), Math.max(0, cols - w));
    return {
      ...it, x, w, h,
      minW: floorW, minH, maxW: capW, maxH,
    };
  });
}
