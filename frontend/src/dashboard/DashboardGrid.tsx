import { useCallback, useEffect, useLayoutEffect, useMemo, useState, type ReactNode } from 'react';
import {
  ResponsiveGridLayout,
  getCompactor,
  useContainerWidth,
  type Layout,
  type LayoutItem as RglItem,
} from 'react-grid-layout';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';
import type { Dashboard as DashboardData } from '../types';
import { BREAKPOINTS, COLS, GRID_MARGIN, ROW_HEIGHT, WIDGET_BY_ID, WIDGET_CATALOG, withLimits } from './defaults';
import { compactLayout, resolveOverlaps, setWidgetHeights, setWidgetWidth, settleDropped } from './layoutOps';
import { hideWidget, showWidget } from './mergeLayout';
import { Popover } from './Popover';
import type { Breakpoint, DashboardPrefs, KpiId, LayoutItem, WidgetId } from './types';
import { rowsForContentHeight } from './useFittingContent';
import { renderWidget, type WidgetEditControls } from './widgets';

interface Props {
  data: DashboardData;
  prefs: DashboardPrefs;
  editing: boolean;
  onPrefsCommit: (next: DashboardPrefs) => void;
  reload: () => void;
  /** Page-level edit actions (undo, save, …) shown at the end of the sticky edit bar. */
  editActions?: ReactNode;
}

const BREAKPOINT_LABELS: Record<Breakpoint, string> = {
  lg: 'Wide screens',
  md: 'Medium screens',
  sm: 'Narrow screens',
};

// No compaction (free space stays free) and overlap allowed during a gesture: other cards stay put
// until drop, then settleDropped / resolveOverlaps decide.
const FREE_PLACEMENT = getCompactor(null, true);

const DRAG_CANCEL ='button, a, input, select, label, summary, .dash-popover-panel';

// Ours, not RGL's: RGL only reports breakpoint *changes*, so a page that mounts at md would
// otherwise save its drags into the lg layout.
function breakpointFor(width: number): Breakpoint {
  if (width >= BREAKPOINTS.lg) return 'lg';
  if (width >= BREAKPOINTS.md) return 'md';
  return 'sm';
}

function clampRows(id: WidgetId, rows: number): number {
  const { minH, maxH } = WIDGET_BY_ID[id].limits;
  return Math.min(maxH, Math.max(minH, rows));
}

function fromRgl(items: Layout): LayoutItem[] {
  return items.map((it) => ({
    i: it.i, x: it.x, y: it.y, w: it.w, h: it.h,
    minW: it.minW, minH: it.minH, maxW: it.maxW, maxH: it.maxH,
  }));
}

function samePositions(a: LayoutItem[], b: LayoutItem[]): boolean {
  if (a.length !== b.length) return false;
  const byId = new Map(b.map((it) => [it.i, it]));
  return a.every((it) => {
    const o = byId.get(it.i);
    return !!o && o.x === it.x && o.y === it.y && o.w === it.w && o.h === it.h;
  });
}

export function DashboardGrid({ data, prefs, editing, onPrefsCommit, reload, editActions }: Props) {
  const { width, containerRef, mounted } = useContainerWidth({ measureBeforeMount: true });
  const breakpoint = breakpointFor(width);
  const cols = COLS[breakpoint];
  // Pixel heights reported by autoHeight widgets (the KPI strip).
  const [autoPx, setAutoPx] = useState<Partial<Record<WidgetId, number>>>({});
  const [measuring, setMeasuring] = useState<WidgetId[] | null>(null);
  const [flashId, setFlashId] = useState<WidgetId | null>(null);

  const autoHeightHandlers = useMemo(() => {
    const out: Partial<Record<WidgetId, (px: number) => void>> = {};
    for (const w of WIDGET_CATALOG) {
      if (!w.autoHeight) continue;
      out[w.id] = (px: number) => setAutoPx((prev) => (prev[w.id] === px ? prev : { ...prev, [w.id]: px }));
    }
    return out;
  }, []);

  const autoRows = useCallback((id: WidgetId): number | null => {
    const px = autoPx[id];
    return px == null ? null : clampRows(id, rowsForContentHeight(px, ROW_HEIGHT, GRID_MARGIN[1]));
  }, [autoPx]);

  // What RGL renders: stored layouts, with autoHeight widgets pinned to their measured height
  // (resizable sideways only; whatever sits below shifts by the difference) and per-breakpoint
  // resize handles. There is no compaction, so overlaps are resolved here, pushing down only.
  const layouts = useMemo(() => {
    const out = {} as Record<Breakpoint, RglItem[]>;
    for (const bp of Object.keys(COLS) as Breakpoint[]) {
      let items = prefs.layouts[bp];
      for (const it of prefs.layouts[bp]) {
        const pinned = WIDGET_BY_ID[it.i as WidgetId]?.autoHeight ? autoRows(it.i as WidgetId) : null;
        if (pinned == null || pinned === it.h) continue;
        const delta = pinned - it.h;
        const below = it.y + it.h;
        items = items.map((o) => {
          if (o.i === it.i) return { ...o, h: pinned };
          return o.y >= below ? { ...o, y: Math.max(0, o.y + delta) } : o;
        });
      }
      out[bp] = resolveOverlaps(items).map((it) => {
        const autoHeight = !!WIDGET_BY_ID[it.i as WidgetId]?.autoHeight && autoRows(it.i as WidgetId) != null;
        const base: RglItem = {
          i: it.i, x: it.x, y: it.y, w: it.w, h: it.h,
          minW: it.minW, minH: it.minH, maxW: it.maxW, maxH: it.maxH,
          resizeHandles: bp === 'sm' ? ['s'] : ['s', 'e', 'se'],
        };
        if (!autoHeight) return base;
        return {
          ...base, minH: it.h, maxH: it.h,
          resizeHandles: bp === 'sm' ? [] : ['e'],
          isResizable: bp !== 'sm',
        };
      });
    }
    return out;
  }, [prefs.layouts, autoRows]);

  // Overlap is allowed while the pointer is down, so nothing else moves mid-gesture; it is settled here.
  const commitLayout = useCallback((layout: LayoutItem[]) => {
    if (samePositions(layout, prefs.layouts[breakpoint])) return;
    onPrefsCommit({ ...prefs, layouts: { ...prefs.layouts, [breakpoint]: layout } });
  }, [breakpoint, onPrefsCommit, prefs]);

  const onDragStop = useCallback((layout: Layout, _old: RglItem | null, moved: RglItem | null) => {
    const items = withLimits(fromRgl(layout), cols);
    commitLayout(moved ? settleDropped(items, moved.i) : resolveOverlaps(items));
  }, [cols, commitLayout]);

  const onResizeStop = useCallback((layout: Layout, _old: RglItem | null, resized: RglItem | null) => {
    commitLayout(resolveOverlaps(withLimits(fromRgl(layout), cols), resized?.i));
  }, [cols, commitLayout]);

  const onHide = (id: WidgetId) => onPrefsCommit(hideWidget(prefs, id));

  const onShow = (id: WidgetId) => {
    onPrefsCommit(showWidget(prefs, id));
    setFlashId(id);
  };

  const onWidth = (id: WidgetId, fraction: number) =>
    onPrefsCommit({ ...prefs, layouts: setWidgetWidth(prefs.layouts, breakpoint, id, fraction) });

  const onCloseGaps = () => {
    const next = compactLayout(prefs.layouts[breakpoint], cols);
    if (!samePositions(next, prefs.layouts[breakpoint])) onPrefsCommit({ ...prefs, layouts: { ...prefs.layouts, [breakpoint]: next } });
  };

  const onKpisChange = (next: KpiId[]) => {
    if (next.length) onPrefsCommit({ ...prefs, kpiVisible: next });
  };

  const fitIds = prefs.layouts[breakpoint]
    .map((it) => it.i as WidgetId)
    .filter((id) => WIDGET_BY_ID[id] && WIDGET_BY_ID[id].fit !== false && !WIDGET_BY_ID[id].autoHeight);

  // Fit: render the requested widgets untruncated at natural height (.is-measuring), read it,
  // and commit the row counts — all before the browser paints, so nothing flickers.
  useLayoutEffect(() => {
    if (!measuring) return;
    const heights: Partial<Record<WidgetId, number>> = {};
    for (const id of measuring) {
      const card = document.querySelector(`.dashboard-grid-item[data-grid-id="${id}"] .dashboard-widget`) as HTMLElement | null;
      if (card) heights[id] = clampRows(id, rowsForContentHeight(card.offsetHeight, ROW_HEIGHT, GRID_MARGIN[1]));
    }
    setMeasuring(null);
    const layoutsNext = setWidgetHeights(prefs.layouts, breakpoint, heights);
    if (!samePositions(layoutsNext[breakpoint], prefs.layouts[breakpoint])) onPrefsCommit({ ...prefs, layouts: layoutsNext });
  }, [measuring, breakpoint, onPrefsCommit, prefs]);

  // Scroll a just-added widget into view and pulse it briefly.
  useEffect(() => {
    if (!flashId) return;
    const el = document.querySelector(`.dashboard-grid-item[data-grid-id="${flashId}"]`);
    el?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    const t = window.setTimeout(() => setFlashId(null), 1600);
    return () => window.clearTimeout(t);
  }, [flashId]);

  // Render the union of widget ids across breakpoints so Responsive can switch layouts.
  const visibleIds = useMemo(() => {
    const ids = new Set<string>();
    for (const bp of Object.keys(COLS) as Breakpoint[]) {
      for (const it of prefs.layouts[bp]) ids.add(it.i);
    }
    return WIDGET_CATALOG.map((w) => w.id).filter((id) => ids.has(id));
  }, [prefs.layouts]);

  const hiddenCount = prefs.hidden.length;

  const editControls = (id: WidgetId): WidgetEditControls | undefined => {
    if (!editing) return undefined;
    const meta = WIDGET_BY_ID[id];
    return {
      onHide: () => onHide(id),
      onFit: meta.fit !== false && !meta.autoHeight ? () => setMeasuring([id]) : undefined,
      onWidth: breakpoint === 'sm' ? undefined : (f) => onWidth(id, f),
    };
  };

  return (
    <div className={`dashboard-grid-wrap${editing ? ' is-editing' : ''}`} ref={containerRef}>
      {editing && (
        <div className="dashboard-editbar">
          <div className="dashboard-editbar-info">
            <strong>Editing layout</strong>
            <span className="muted small" title="Each screen size keeps its own arrangement; edits apply to the size you are viewing now.">
              {BREAKPOINT_LABELS[breakpoint]} · drag headers to move, pull edges to resize
            </span>
          </div>
          <div className="row wrap dashboard-editbar-tools">
            <Popover label={<>+ Add widget{hiddenCount ? <span className="dash-count">{hiddenCount}</span> : null}</>}
              className="widget-library" panelClassName="widget-library-panel">
              {() => (
                <ul className="widget-library-list">
                  {WIDGET_CATALOG.map((w) => {
                    const hidden = prefs.hidden.includes(w.id);
                    return (
                      <li key={w.id}>
                        <div className="widget-library-text">
                          <div className="widget-library-title">{w.title}</div>
                          <div className="muted small">{w.description}</div>
                        </div>
                        {hidden ? (
                          <button type="button" className="btn sm primary" onClick={() => onShow(w.id)}>Add</button>
                        ) : (
                          <button type="button" className="btn sm ghost" onClick={() => onHide(w.id)}
                            title="Remove from dashboard">On board ✕</button>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </Popover>
            <button type="button" className="btn sm" disabled={!fitIds.length} onClick={() => setMeasuring(fitIds)}
              title="Shrink or grow every widget to its content">Fit all heights</button>
            <button type="button" className="btn sm" onClick={onCloseGaps}
              title="Pull every widget up into the empty space above it">Close gaps</button>
            {editActions && <span className="dashboard-editbar-sep" aria-hidden="true" />}
            {editActions}
          </div>
        </div>
      )}
      {mounted && width > 0 && (
        <ResponsiveGridLayout
          className="dashboard-rgl"
          width={width}
          breakpoint={breakpoint}
          layouts={layouts}
          breakpoints={BREAKPOINTS}
          cols={COLS}
          rowHeight={ROW_HEIGHT}
          margin={GRID_MARGIN}
          containerPadding={[0, 0]}
          compactor={FREE_PLACEMENT}
          dragConfig={{
            enabled: editing,
            handle: '.dashboard-widget > .card-head',
            cancel: DRAG_CANCEL,
          }}
          resizeConfig={{
            enabled: editing,
            handles: breakpoint === 'sm' ? ['s'] : ['s', 'e', 'se'],
          }}
          onDragStop={onDragStop}
          onResizeStop={onResizeStop}
          // Deliberately omit onLayoutChange — do not persist/commit on mount or width changes.
        >
          {visibleIds.map((id) => (
            <div key={id}
              className={`dashboard-grid-item${measuring?.includes(id) ? ' is-measuring' : ''}${flashId === id ? ' is-new' : ''}`}
              data-grid-id={id}>
              {renderWidget(id, {
                data,
                edit: editControls(id),
                measuring: !!measuring?.includes(id),
                kpiVisible: prefs.kpiVisible,
                onKpisChange: editing ? onKpisChange : undefined,
                onAutoHeight: autoHeightHandlers[id],
                reload,
              })}
            </div>
          ))}
        </ResponsiveGridLayout>
      )}
    </div>
  );
}
