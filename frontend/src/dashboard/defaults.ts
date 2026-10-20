import type { Breakpoint, DashboardPrefs, KpiId, LayoutItem, Layouts, WidgetId, WidgetMeta } from './types';

export const DASHBOARD_SCHEMA_VERSION = 1;

export const BREAKPOINTS: Record<Breakpoint, number> = { lg: 1200, md: 768, sm: 0 };
export const COLS: Record<Breakpoint, number> = { lg: 12, md: 10, sm: 1 };
export const ROW_HEIGHT = 36;
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
  { id: 'kpis', title: 'Overview KPIs', limits: { minW: 4, minH: 2, maxW: 12, maxH: 8 }, defaultSize: { w: 12, h: 2 } },
  { id: 'recent_changes', title: 'Recent changes', limits: { minW: 3, minH: 4, maxW: 12, maxH: 48 }, defaultSize: { w: 7, h: 10 } },
  { id: 'scan_status', title: 'Scan status', limits: { minW: 3, minH: 3, maxW: 12, maxH: 24 }, defaultSize: { w: 5, h: 5 } },
  { id: 'changes_by_type', title: 'Changes by type', limits: { minW: 3, minH: 3, maxW: 12, maxH: 36 }, defaultSize: { w: 5, h: 5 } },
  { id: 'exposure_scores', title: 'Exposure scores', limits: { minW: 3, minH: 4, maxW: 12, maxH: 36 }, defaultSize: { w: 4, h: 8 } },
  { id: 'device_types', title: 'Device types', limits: { minW: 3, minH: 3, maxW: 12, maxH: 36 }, defaultSize: { w: 4, h: 8 } },
  { id: 'watch_alerts', title: 'Watch alerts', limits: { minW: 3, minH: 4, maxW: 12, maxH: 48 }, defaultSize: { w: 4, h: 8 } },
  { id: 'exposure_trend', title: 'Exposure trend', limits: { minW: 3, minH: 3, maxW: 12, maxH: 24 }, defaultSize: { w: 4, h: 5 } },
  { id: 'networks', title: 'Networks', limits: { minW: 3, minH: 3, maxW: 12, maxH: 36 }, defaultSize: { w: 4, h: 5 } },
  { id: 'top_ports', title: 'Most exposed ports', limits: { minW: 3, minH: 3, maxW: 12, maxH: 36 }, defaultSize: { w: 4, h: 8 } },
  { id: 'top_services', title: 'Exposed services', limits: { minW: 3, minH: 3, maxW: 12, maxH: 36 }, defaultSize: { w: 4, h: 8 } },
];

export const WIDGET_BY_ID: Record<WidgetId, WidgetMeta> = Object.fromEntries(
  WIDGET_CATALOG.map((w) => [w.id, w]),
) as Record<WidgetId, WidgetMeta>;

/** Default lg layout mirroring the previous fixed dashboard structure. */
function defaultLg(): LayoutItem[] {
  return [
    item('kpis', 0, 0, 12, 2),
    item('recent_changes', 0, 2, 7, 10),
    item('scan_status', 7, 2, 5, 5),
    item('changes_by_type', 7, 7, 5, 5),
    item('exposure_scores', 0, 12, 4, 8),
    item('device_types', 4, 12, 4, 8),
    item('watch_alerts', 8, 12, 4, 8),
    item('exposure_trend', 0, 20, 4, 5),
    item('networks', 0, 25, 4, 5),
    item('top_ports', 4, 20, 4, 10),
    item('top_services', 8, 20, 4, 10),
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
    const w = Math.max(lim ? Math.min(lim.minW, to) : 1, Math.round((it.w / from) * to));
    const x = Math.min(Math.round((it.x / from) * to), Math.max(0, to - w));
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
