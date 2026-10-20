import { verticalCompactor } from 'react-grid-layout';
import { COLS, WIDGET_BY_ID, withLimits } from './defaults';
import type { Breakpoint, KpiId, LayoutItem, Layouts, WidgetId } from './types';

function collides(a: LayoutItem, b: LayoutItem): boolean {
  return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
}

export function layoutBottom(layout: LayoutItem[]): number {
  return layout.reduce((max, it) => Math.max(max, it.y + it.h), 0);
}

/** Top-most, then left-most spot where a w×h block fits without overlap; the bottom when no hole fits. */
export function findFreeSpot(layout: LayoutItem[], w: number, h: number, cols: number): { x: number; y: number } {
  const width = Math.min(w, cols);
  const end = layoutBottom(layout);
  for (let y = 0; y < end; y++) {
    for (let x = 0; x + width <= cols; x++) {
      const probe = { i: '', x, y, w: width, h };
      if (!layout.some((it) => collides(probe, it))) return { x, y };
    }
  }
  return { x: 0, y: end };
}

/**
 * Free placement: push overlapping items down until nothing overlaps, never pulling anything up.
 * `first` (e.g. the widget just resized) keeps its spot and the others make room for it.
 */
export function resolveOverlaps(layout: LayoutItem[], first?: string): LayoutItem[] {
  const order = [...layout].sort((a, b) =>
    Number(b.i === first) - Number(a.i === first) || a.y - b.y || a.x - b.x);
  const placed: LayoutItem[] = [];
  for (const it of order) {
    const cur = { ...it };
    let hit: LayoutItem | undefined;
    while ((hit = placed.find((p) => collides(p, cur)))) cur.y = hit.y + hit.h;
    placed.push(cur);
  }
  const byId = new Map(placed.map((it) => [it.i, it]));
  return layout.map((it) => byId.get(it.i)!);
}

/**
 * After a drop: if the dropped item overlaps others, shrink it (never below its minimum size) to
 * the largest free block inside the area it was dropped on, so nothing else moves. Only when even
 * its minimum does not fit there are the others pushed down.
 */
export function settleDropped(layout: LayoutItem[], id: string): LayoutItem[] {
  const dropped = layout.find((it) => it.i === id);
  if (!dropped) return resolveOverlaps(layout);
  const others = layout.filter((it) => it.i !== id);
  const free = (x: number, y: number, w: number, h: number) =>
    !others.some((o) => collides({ i: '', x, y, w, h }, o));
  if (free(dropped.x, dropped.y, dropped.w, dropped.h)) return layout;
  const minW = dropped.minW ?? 1;
  const minH = dropped.minH ?? 1;
  let best: { x: number; y: number; w: number; h: number; dist: number } | null = null;
  // Every column span inside the footprint; for each, the longest run of free rows.
  for (let w = dropped.w; w >= minW; w--) {
    for (let x = dropped.x; x + w <= dropped.x + dropped.w; x++) {
      let runStart = dropped.y;
      for (let y = dropped.y; y <= dropped.y + dropped.h; y++) {
        const rowFree = y < dropped.y + dropped.h && free(x, y, w, 1);
        if (rowFree) continue;
        const h = y - runStart;
        if (h >= minH) {
          const dist = Math.abs(x - dropped.x) + Math.abs(runStart - dropped.y);
          if (!best || w * h > best.w * best.h || (w * h === best.w * best.h && dist < best.dist)) {
            best = { x, y: runStart, w, h, dist };
          }
        }
        runStart = y + 1;
      }
    }
  }
  if (!best) return resolveOverlaps(layout, id);
  const { x, y, w, h } = best;
  return layout.map((it) => (it.i === id ? { ...it, x, y, w, h } : it));
}

/** "Close gaps": pull every item up as far as it goes (vertical compaction). */
export function compactLayout(layout: LayoutItem[], cols: number): LayoutItem[] {
  // The compactor moves colliding items in place: hand it copies.
  const copies = layout.map((it) => ({ ...it }));
  return verticalCompactor.compact(copies, cols).map(({ i, x, y, w, h, minW, minH, maxW, maxH }) => ({
    i, x, y, w, h, minW, minH, maxW, maxH,
  }));
}

/** Add a widget at its default size into the first free spot of every breakpoint. */
export function placeWidget(layouts: Layouts, id: WidgetId): Layouts {
  const meta = WIDGET_BY_ID[id];
  const next = {} as Layouts;
  for (const bp of Object.keys(COLS) as Breakpoint[]) {
    const cols = COLS[bp];
    const rest = layouts[bp].filter((it) => it.i !== id);
    const w = bp === 'sm' ? cols : Math.min(cols, Math.round((meta.defaultSize.w / COLS.lg) * cols));
    const { x, y } = findFreeSpot(rest, w, meta.defaultSize.h, cols);
    next[bp] = withLimits([...rest, { i: id, x, y, w, h: meta.defaultSize.h }], cols);
  }
  return next;
}

/** Resize one widget on one breakpoint (width as a fraction of the row); neighbours it now overlaps move down. */
export function setWidgetWidth(layouts: Layouts, bp: Breakpoint, id: WidgetId, fraction: number): Layouts {
  const cols = COLS[bp];
  const items = layouts[bp].map((it) => {
    if (it.i !== id) return it;
    const w = Math.max(1, Math.round(cols * fraction));
    return { ...it, w, x: Math.min(it.x, cols - w) };
  });
  return { ...layouts, [bp]: resolveOverlaps(withLimits(items, cols), id) };
}

/** Set heights (grid rows) for several widgets on one breakpoint; growth pushes items below, shrinking leaves the gap. */
export function setWidgetHeights(layouts: Layouts, bp: Breakpoint, heights: Partial<Record<WidgetId, number>>): Layouts {
  const cols = COLS[bp];
  const items = layouts[bp].map((it) => {
    const h = heights[it.i as WidgetId];
    return h == null ? it : { ...it, h };
  });
  return { ...layouts, [bp]: resolveOverlaps(withLimits(items, cols)) };
}

const KPI_MIN_TILE = 165;

/** Tiles per row: as many as fit at KPI_MIN_TILE, then evened out so rows hold similar counts (8 → 4+4, not 5+3). */
export function kpiColumns(n: number, width: number, gap = 12): number {
  if (n <= 0) return 1;
  if (width <= 0) return n;
  const fit = Math.max(1, Math.floor((width + gap) / (KPI_MIN_TILE + gap)));
  const rows = Math.ceil(n / Math.min(n, fit));
  return Math.ceil(n / rows);
}

/** Move `from` into the slot `to` occupies (lands after it when moving right, before it when moving left). */
export function moveKpi(order: KpiId[], from: KpiId, to: KpiId): KpiId[] {
  if (from === to || !order.includes(from) || !order.includes(to)) return order;
  const idx = order.indexOf(to);
  const rest = order.filter((k) => k !== from);
  rest.splice(idx, 0, from);
  return rest;
}
