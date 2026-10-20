import { describe, expect, it } from 'vitest';
import { COLS, WIDGET_BY_ID, defaultDashboardPrefs } from './defaults';
import {
  compactLayout, findFreeSpot, kpiColumns, moveKpi, placeWidget, resolveOverlaps, setWidgetHeights, setWidgetWidth, settleDropped,
} from './layoutOps';
import { hideWidget, showWidget } from './mergeLayout';
import type { LayoutItem } from './types';

const overlaps = (items: LayoutItem[]) => items.some((a, i) => items.some((b, j) =>
  i !== j && a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h));

describe('findFreeSpot', () => {
  it('fills the first hole that fits before falling back to the bottom', () => {
    const layout: LayoutItem[] = [
      { i: 'a', x: 0, y: 0, w: 8, h: 4 },
      { i: 'b', x: 0, y: 4, w: 12, h: 4 },
    ];
    expect(findFreeSpot(layout, 4, 4, 12)).toEqual({ x: 8, y: 0 });
    expect(findFreeSpot(layout, 6, 4, 12)).toEqual({ x: 0, y: 8 });
  });
});

describe('resolveOverlaps', () => {
  it('pushes overlaps down but never pulls items up into free space', () => {
    const input: LayoutItem[] = [
      { i: 'a', x: 0, y: 0, w: 6, h: 2 },
      { i: 'b', x: 0, y: 1, w: 6, h: 2 },
      { i: 'c', x: 6, y: 9, w: 6, h: 2 },
    ];
    const out = resolveOverlaps(input);
    expect(out.find((it) => it.i === 'b')!.y).toBe(2);
    expect(out.find((it) => it.i === 'c')!.y).toBe(9);
  });

  it('keeps the priority item in place and moves the others', () => {
    const input: LayoutItem[] = [
      { i: 'a', x: 0, y: 0, w: 6, h: 2 },
      { i: 'b', x: 0, y: 1, w: 6, h: 2 },
    ];
    const out = resolveOverlaps(input, 'b');
    expect(out.find((it) => it.i === 'b')!.y).toBe(1);
    expect(out.find((it) => it.i === 'a')!.y).toBe(3);
  });
});

describe('compactLayout', () => {
  it('pulls items up and resolves overlaps without mutating input', () => {
    const input: LayoutItem[] = [
      { i: 'a', x: 0, y: 0, w: 12, h: 2 },
      { i: 'b', x: 0, y: 1, w: 6, h: 2 },
      { i: 'c', x: 6, y: 9, w: 6, h: 2 },
    ];
    const snapshot = JSON.stringify(input);
    const out = compactLayout(input, 12);
    expect(JSON.stringify(input)).toBe(snapshot);
    expect(overlaps(out)).toBe(false);
    expect(out.find((it) => it.i === 'c')!.y).toBe(2);
  });
});

describe('placeWidget / showWidget', () => {
  it('re-adds a hidden widget on every breakpoint without overlaps', () => {
    const hidden = hideWidget(defaultDashboardPrefs(), 'scan_status');
    const shown = showWidget(hidden, 'scan_status');
    expect(shown.hidden).not.toContain('scan_status');
    for (const bp of ['lg', 'md', 'sm'] as const) {
      expect(shown.layouts[bp].some((it) => it.i === 'scan_status')).toBe(true);
      expect(overlaps(shown.layouts[bp])).toBe(false);
    }
  });

  it('lands in the gap the widget left behind', () => {
    const prefs = defaultDashboardPrefs();
    const before = prefs.layouts.lg.find((it) => it.i === 'scan_status')!;
    const layouts = placeWidget(hideWidget(prefs, 'scan_status').layouts, 'scan_status');
    expect(layouts.lg.find((it) => it.i === 'scan_status')).toMatchObject({ x: before.x, y: before.y });
  });
});

describe('setWidgetWidth / setWidgetHeights', () => {
  it('sets width as a fraction of the row and keeps the layout valid', () => {
    const { layouts } = defaultDashboardPrefs();
    const next = setWidgetWidth(layouts, 'lg', 'scan_status', 1);
    const item = next.lg.find((it) => it.i === 'scan_status')!;
    expect(item).toMatchObject({ x: 0, w: COLS.lg });
    expect(overlaps(next.lg)).toBe(false);
  });

  it('clamps heights to widget limits', () => {
    const { layouts } = defaultDashboardPrefs();
    const next = setWidgetHeights(layouts, 'lg', { scan_status: 1, recent_changes: 999 });
    expect(next.lg.find((it) => it.i === 'scan_status')!.h).toBe(WIDGET_BY_ID.scan_status.limits.minH);
    expect(next.lg.find((it) => it.i === 'recent_changes')!.h).toBe(WIDGET_BY_ID.recent_changes.limits.maxH);
  });
});

describe('kpiColumns', () => {
  it('evens out rows instead of leaving a short last row', () => {
    expect(kpiColumns(8, 2000)).toBe(8);
    expect(kpiColumns(8, 900)).toBe(4);
    expect(kpiColumns(3, 2000)).toBe(3);
    expect(kpiColumns(8, 100)).toBe(1);
  });
});

describe('moveKpi', () => {
  it('moves right after the target and left before it', () => {
    expect(moveKpi(['known_hosts', 'active', 'open_ports'], 'known_hosts', 'open_ports'))
      .toEqual(['active', 'open_ports', 'known_hosts']);
    expect(moveKpi(['known_hosts', 'active', 'open_ports'], 'open_ports', 'known_hosts'))
      .toEqual(['open_ports', 'known_hosts', 'active']);
  });
});

describe('settleDropped', () => {
  const base: LayoutItem[] = [
    { i: 'a', x: 0, y: 0, w: 12, h: 10 },
    { i: 'b', x: 12, y: 0, w: 12, h: 10 },
  ];

  it('shrinks the dropped item into the free space so nothing else moves', () => {
    // a reaches down to row 20 on the left; c is dropped half over it.
    const layout: LayoutItem[] = [
      { ...base[0], h: 20 }, base[1],
      { i: 'c', x: 8, y: 10, w: 10, h: 8, minW: 6, minH: 4 },
    ];
    const out = settleDropped(layout, 'c');
    expect(out.find((it) => it.i === 'a')).toEqual(layout[0]);
    expect(out.find((it) => it.i === 'b')).toEqual(layout[1]);
    expect(out.find((it) => it.i === 'c')).toMatchObject({ x: 12, y: 10, w: 6, h: 8 });
  });

  it('pushes others down when even the minimum size does not fit', () => {
    const layout = [...base, { i: 'c', x: 4, y: 2, w: 8, h: 8, minW: 6, minH: 4 }];
    const out = settleDropped(layout, 'c');
    expect(out.find((it) => it.i === 'c')).toMatchObject({ x: 4, y: 2, w: 8, h: 8 });
    expect(out.find((it) => it.i === 'a')!.y).toBe(10);
    expect(overlaps(out)).toBe(false);
  });

  it('fits a card dropped half over a neighbour by narrowing it', () => {
    const layout = [base[0], { i: 'c', x: 8, y: 0, w: 10, h: 10, minW: 4, minH: 4 }];
    const out = settleDropped(layout, 'c');
    expect(out.find((it) => it.i === 'a')).toEqual(base[0]);
    expect(overlaps(out)).toBe(false);
  });
});
