import { describe, expect, it } from 'vitest';
import { COLS, WIDGET_BY_ID, WIDGET_CATALOG, defaultDashboardPrefs } from './defaults';
import { loadDashboardPrefs, mergeBreakpointLayout, mergeLayouts } from './mergeLayout';
import type { LayoutItem, WidgetId } from './types';

describe('mergeBreakpointLayout', () => {
  it('auto-inserts catalog widgets missing from layout and not hidden', () => {
    const raw: LayoutItem[] = [{ i: 'kpis', x: 0, y: 0, w: 24, h: 8 }];
    const merged = mergeBreakpointLayout(raw, new Set(), COLS.lg);
    expect(merged.map((it) => it.i).sort()).toEqual(WIDGET_CATALOG.map((w) => w.id).sort());
    expect(merged.find((it) => it.i === 'kpis')).toMatchObject({ w: 24, h: 8 });
  });

  it('does not insert widgets listed in hidden', () => {
    const hidden = new Set<string>(['networks', 'top_ports']);
    const merged = mergeBreakpointLayout([], hidden, COLS.lg);
    const ids = merged.map((it) => it.i);
    expect(ids).not.toContain('networks');
    expect(ids).not.toContain('top_ports');
    expect(ids).toContain('kpis');
  });

  it('clamps sizes to min/max and columns', () => {
    const raw: LayoutItem[] = [{ i: 'kpis', x: 0, y: 0, w: 100, h: 100 }];
    const merged = mergeBreakpointLayout(raw, new Set(), COLS.lg);
    const kpis = merged.find((it) => it.i === 'kpis')!;
    expect(kpis.w).toBeLessThanOrEqual(COLS.lg);
    expect(kpis.h).toBeLessThanOrEqual(WIDGET_BY_ID.kpis.limits.maxH);
  });
});

describe('loadDashboardPrefs', () => {
  it('returns defaults for null or unsupported version', () => {
    expect(loadDashboardPrefs(null).layouts.lg.length).toBe(WIDGET_CATALOG.length);
    expect(loadDashboardPrefs({ dashboard: { v: 99, layouts: {}, hidden: [], kpiVisible: ['known_hosts'] } }).v).toBe(2);
    expect(loadDashboardPrefs({ dashboard: { v: 99 } }).layouts.lg.length).toBe(WIDGET_CATALOG.length);
  });

  it('migrates v1 layouts to the fine grid', () => {
    const prefs = loadDashboardPrefs({
      dashboard: {
        v: 1,
        layouts: {
          lg: [{ i: 'recent_changes', x: 0, y: 3, w: 7, h: 10 }, { i: 'scan_status', x: 7, y: 3, w: 5, h: 5 }],
          md: [],
          sm: [],
        },
        hidden: [],
        kpiVisible: ['known_hosts'],
      },
    });
    expect(prefs.v).toBe(2);
    expect(prefs.layouts.lg.find((it) => it.i === 'recent_changes')).toMatchObject({ x: 0, y: 8, w: 14, h: 26 });
    expect(prefs.layouts.lg.find((it) => it.i === 'scan_status')).toMatchObject({ x: 14, y: 8, w: 10, h: 13 });
  });

  it('loads v2 and respects hidden', () => {
    const prefs = loadDashboardPrefs({
      dashboard: {
        v: 2,
        layouts: {
          lg: [{ i: 'kpis', x: 0, y: 0, w: 24, h: 8 }],
          md: [],
          sm: [],
        },
        hidden: ['networks' as WidgetId],
        kpiVisible: ['known_hosts', 'active'],
      },
    });
    expect(prefs.hidden).toEqual(['networks']);
    expect(prefs.kpiVisible).toEqual(['known_hosts', 'active']);
    expect(prefs.layouts.lg.find((it) => it.i === 'networks')).toBeUndefined();
    expect(prefs.layouts.lg.find((it) => it.i === 'recent_changes')).toBeTruthy();
  });
});

describe('mergeLayouts', () => {
  it('produces all breakpoints', () => {
    const layouts = mergeLayouts(defaultDashboardPrefs().layouts, []);
    expect(Object.keys(layouts).sort()).toEqual(['lg', 'md', 'sm']);
    expect(layouts.sm.every((it) => it.w === 1)).toBe(true);
  });
});
