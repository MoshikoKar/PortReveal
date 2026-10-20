import { COLS, DASHBOARD_SCHEMA_VERSION, WIDGET_BY_ID, WIDGET_CATALOG, defaultDashboardPrefs, withLimits } from './defaults';
import type { Breakpoint, DashboardPrefs, KpiId, LayoutItem, Layouts, WidgetId } from './types';
import { KPI_IDS } from './defaults';
import { placeWidget, resolveOverlaps } from './layoutOps';

function isWidgetId(v: unknown): v is WidgetId {
  return typeof v === 'string' && v in WIDGET_BY_ID;
}

function isKpiId(v: unknown): v is KpiId {
  return typeof v === 'string' && (KPI_IDS as string[]).includes(v);
}

function bottom(layout: LayoutItem[]): number {
  return layout.reduce((max, it) => Math.max(max, it.y + it.h), 0);
}

/** Merge one breakpoint: drop unknown/hidden, clamp, auto-insert missing catalog widgets. */
export function mergeBreakpointLayout(
  raw: LayoutItem[] | undefined,
  hidden: Set<string>,
  cols: number,
): LayoutItem[] {
  const seen = new Set<string>();
  const out: LayoutItem[] = [];
  for (const it of raw ?? []) {
    if (!isWidgetId(it.i) || hidden.has(it.i) || seen.has(it.i)) continue;
    seen.add(it.i);
    out.push({ i: it.i, x: it.x, y: it.y, w: it.w, h: it.h });
  }
  let y = bottom(out);
  for (const meta of WIDGET_CATALOG) {
    if (seen.has(meta.id) || hidden.has(meta.id)) continue;
    const w = Math.min(cols, meta.defaultSize.w);
    out.push({ i: meta.id, x: 0, y, w, h: meta.defaultSize.h });
    seen.add(meta.id);
    y += meta.defaultSize.h;
  }
  return withLimits(out, cols);
}

// v1 used 12/10 columns and 36px rows (52px per row step); v2 uses 24/20 columns and 4px rows (20px).
const V1_COLS: Record<Breakpoint, number> = { lg: 12, md: 10, sm: 1 };
const V1_ROW_STEP = 52;
const V2_ROW_STEP = 20;

/** Convert a v1 layout to v2 units: same columns share, same pixel positions and heights. */
export function migrateV1Layouts(layouts: Partial<Layouts>): Partial<Layouts> {
  const out: Partial<Layouts> = {};
  for (const bp of Object.keys(COLS) as Breakpoint[]) {
    const items = layouts[bp];
    if (!Array.isArray(items)) continue;
    const xScale = COLS[bp] / V1_COLS[bp];
    out[bp] = resolveOverlaps(items.map((it) => ({
      i: it.i,
      x: Math.round(it.x * xScale),
      w: Math.round(it.w * xScale),
      y: Math.round((it.y * V1_ROW_STEP) / V2_ROW_STEP),
      h: Math.round((it.h * V1_ROW_STEP) / V2_ROW_STEP),
    })));
  }
  return out;
}

export function mergeLayouts(layouts: Partial<Layouts> | undefined, hidden: WidgetId[]): Layouts {
  const hide = new Set(hidden);
  const result = {} as Layouts;
  for (const bp of Object.keys(COLS) as Breakpoint[]) {
    result[bp] = mergeBreakpointLayout(layouts?.[bp], hide, COLS[bp]);
  }
  return result;
}

function sanitizeHidden(raw: unknown): WidgetId[] {
  if (!Array.isArray(raw)) return [];
  const out: WidgetId[] = [];
  for (const id of raw) {
    if (isWidgetId(id) && !out.includes(id)) out.push(id);
  }
  return out;
}

function sanitizeKpis(raw: unknown): KpiId[] {
  if (!Array.isArray(raw)) return [...KPI_IDS];
  const out: KpiId[] = [];
  for (const id of raw) {
    if (isKpiId(id) && !out.includes(id)) out.push(id);
  }
  return out.length ? out : [...KPI_IDS];
}

/**
 * Load stored preferences into a usable DashboardPrefs.
 * Unknown / future schema versions fall back to defaults without throwing.
 */
export function loadDashboardPrefs(raw: unknown): DashboardPrefs {
  const defaults = defaultDashboardPrefs();
  if (raw == null || typeof raw !== 'object') return defaults;
  const root = raw as Record<string, unknown>;
  const dash = root.dashboard;
  if (dash == null || typeof dash !== 'object') return defaults;
  const d = dash as Record<string, unknown>;
  const v = d.v;
  if (typeof v === 'number' && v !== DASHBOARD_SCHEMA_VERSION && v !== 1) {
    if (import.meta.env?.DEV) {
      console.warn(`[dashboard] unsupported prefs version ${v}; using defaults`);
    }
    return defaults;
  }
  const hidden = sanitizeHidden(d.hidden);
  const stored = (d.layouts && typeof d.layouts === 'object' ? d.layouts : {}) as Partial<Layouts>;
  const layoutsIn = v === 1 ? migrateV1Layouts(stored) : stored;
  return {
    v: DASHBOARD_SCHEMA_VERSION,
    layouts: mergeLayouts(layoutsIn, hidden),
    hidden,
    kpiVisible: sanitizeKpis(d.kpiVisible),
  };
}

/** Payload shape for PUT /auth/me/preferences (strip RGL-only fields). */
export function prefsForSave(prefs: DashboardPrefs): { dashboard: DashboardPrefs } {
  const layouts = {} as Layouts;
  for (const bp of Object.keys(COLS) as Breakpoint[]) {
    layouts[bp] = prefs.layouts[bp].map(({ i, x, y, w, h }) => ({ i, x, y, w, h }));
  }
  return {
    dashboard: {
      v: DASHBOARD_SCHEMA_VERSION,
      layouts,
      hidden: [...prefs.hidden],
      kpiVisible: [...prefs.kpiVisible],
    },
  };
}

export function hideWidget(prefs: DashboardPrefs, id: WidgetId): DashboardPrefs {
  if (prefs.hidden.includes(id)) return prefs;
  const layouts = {} as Layouts;
  for (const bp of Object.keys(COLS) as Breakpoint[]) {
    layouts[bp] = prefs.layouts[bp].filter((it) => it.i !== id);
  }
  return { ...prefs, hidden: [...prefs.hidden, id], layouts };
}

/** Bring a hidden widget back at its default size, in the first free spot of each breakpoint. */
export function showWidget(prefs: DashboardPrefs, id: WidgetId): DashboardPrefs {
  if (!prefs.hidden.includes(id)) return prefs;
  return { ...prefs, hidden: prefs.hidden.filter((h) => h !== id), layouts: placeWidget(prefs.layouts, id) };
}
