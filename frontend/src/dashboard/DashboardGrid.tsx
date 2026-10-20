import { useCallback, useMemo, useState } from 'react';
import {
  ResponsiveGridLayout,
  useContainerWidth,
  verticalCompactor,
  type Layout,
} from 'react-grid-layout';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';
import type { Dashboard as DashboardData } from '../types';
import { BREAKPOINTS, COLS, GRID_MARGIN, ROW_HEIGHT, WIDGET_BY_ID, WIDGET_CATALOG, withLimits } from './defaults';
import { hideWidget, showWidget } from './mergeLayout';
import type { Breakpoint, DashboardPrefs, KpiId, LayoutItem, WidgetId } from './types';
import { rowsForContentHeight } from './useFittingContent';
import { renderWidget } from './widgets';

interface Props {
  data: DashboardData;
  prefs: DashboardPrefs;
  editing: boolean;
  onPrefsCommit: (next: DashboardPrefs) => void;
  reload: () => void;
}

function toRgl(items: LayoutItem[]): Layout {
  return items.map((it) => ({
    i: it.i, x: it.x, y: it.y, w: it.w, h: it.h,
    minW: it.minW, minH: it.minH, maxW: it.maxW, maxH: it.maxH,
  }));
}

function fromRgl(items: Layout): LayoutItem[] {
  return items.map((it) => ({
    i: it.i, x: it.x, y: it.y, w: it.w, h: it.h,
    minW: it.minW, minH: it.minH, maxW: it.maxW, maxH: it.maxH,
  }));
}

export function DashboardGrid({ data, prefs, editing, onPrefsCommit, reload }: Props) {
  const { width, containerRef, mounted } = useContainerWidth({ measureBeforeMount: true });
  const [breakpoint, setBreakpoint] = useState<Breakpoint>('lg');

  const layouts = useMemo(() => ({
    lg: toRgl(prefs.layouts.lg),
    md: toRgl(prefs.layouts.md),
    sm: toRgl(prefs.layouts.sm),
  }), [prefs.layouts]);

  const dragEnabled = editing && breakpoint !== 'sm';
  const resizeEnabled = editing && breakpoint !== 'sm';

  const applyLayout = useCallback((bp: Breakpoint, layout: Layout) => {
    const next = {
      ...prefs,
      layouts: {
        ...prefs.layouts,
        [bp]: withLimits(fromRgl(layout), COLS[bp]),
      },
    };
    return next;
  }, [prefs]);

  const onDragStop = useCallback((layout: Layout) => {
    onPrefsCommit(applyLayout(breakpoint, layout));
  }, [applyLayout, breakpoint, onPrefsCommit]);

  const onResizeStop = useCallback((layout: Layout) => {
    onPrefsCommit(applyLayout(breakpoint, layout));
  }, [applyLayout, breakpoint, onPrefsCommit]);

  const onBreakpointChange = useCallback((bp: string) => {
    if (bp === 'lg' || bp === 'md' || bp === 'sm') setBreakpoint(bp);
  }, []);

  const onHide = (id: WidgetId) => onPrefsCommit(hideWidget(prefs, id));

  const onFit = (id: WidgetId) => {
    const node = document.querySelector(`.dashboard-grid-item[data-grid-id="${id}"] .card-body`) as HTMLElement | null;
    if (!node) return;
    // Measure scrollHeight of content; add card-head roughly via parent.
    const card = node.closest('.card') as HTMLElement | null;
    const head = card?.querySelector('.card-head') as HTMLElement | null;
    const contentPx = node.scrollHeight + (head?.offsetHeight ?? 40) + GRID_MARGIN[1];
    const h = rowsForContentHeight(contentPx, ROW_HEIGHT, GRID_MARGIN[1]);
    const lim = WIDGET_BY_ID[id].limits;
    const clamped = Math.min(lim.maxH, Math.max(lim.minH, h));
    const layoutsNext = { ...prefs.layouts };
    for (const bp of Object.keys(COLS) as Breakpoint[]) {
      layoutsNext[bp] = prefs.layouts[bp].map((it) => (it.i === id ? { ...it, h: clamped } : it));
      layoutsNext[bp] = withLimits(layoutsNext[bp], COLS[bp]);
    }
    onPrefsCommit({ ...prefs, layouts: layoutsNext });
  };

  const onToggleKpi = (id: KpiId) => {
    const on = prefs.kpiVisible.includes(id);
    let next: KpiId[];
    if (on) {
      if (prefs.kpiVisible.length <= 1) return;
      next = prefs.kpiVisible.filter((k) => k !== id);
    } else {
      next = [...prefs.kpiVisible, id];
    }
    onPrefsCommit({ ...prefs, kpiVisible: next });
  };

  // Render the union of widget ids across breakpoints so Responsive can switch layouts.
  const visibleIds = useMemo(() => {
    const ids = new Set<string>();
    for (const bp of Object.keys(COLS) as Breakpoint[]) {
      for (const it of prefs.layouts[bp]) ids.add(it.i);
    }
    return WIDGET_CATALOG.map((w) => w.id).filter((id) => ids.has(id));
  }, [prefs.layouts]);

  const hiddenCatalog = WIDGET_CATALOG.filter((w) => prefs.hidden.includes(w.id));

  return (
    <div className={`dashboard-grid-wrap${editing ? ' is-editing' : ''}`} ref={containerRef}>
      {editing && (
        <div className="dashboard-add-row row wrap" style={{ gap: 8, marginBottom: 8 }}>
          <span className="muted small">Add widget:</span>
          {hiddenCatalog.length === 0 ? (
            <span className="muted small">All widgets are on the board.</span>
          ) : hiddenCatalog.map((w) => (
            <button key={w.id} type="button" className="btn sm"
              onClick={() => onPrefsCommit(showWidget(prefs, w.id, breakpoint))}>
              {w.title}
            </button>
          ))}
        </div>
      )}
      {mounted && width > 0 && (
        <ResponsiveGridLayout
          className="dashboard-rgl"
          width={width}
          layouts={layouts}
          breakpoints={BREAKPOINTS}
          cols={COLS}
          rowHeight={ROW_HEIGHT}
          margin={GRID_MARGIN}
          compactor={verticalCompactor}
          dragConfig={{
            enabled: dragEnabled,
            handle: '.dashboard-drag-handle',
          }}
          resizeConfig={{
            enabled: resizeEnabled,
            handles: ['se'],
          }}
          onDragStop={onDragStop}
          onResizeStop={onResizeStop}
          onBreakpointChange={onBreakpointChange}
          // Deliberately omit onLayoutChange — do not persist/commit on mount or width changes.
        >
          {visibleIds.map((id) => (
            <div key={id} className="dashboard-grid-item" data-grid-id={id}>
              {renderWidget(id, {
                data,
                editing,
                kpiVisible: prefs.kpiVisible,
                onToggleKpi: editing ? onToggleKpi : undefined,
                onHide: editing ? () => onHide(id) : undefined,
                onFit: editing ? () => onFit(id) : undefined,
                reload,
              })}
            </div>
          ))}
        </ResponsiveGridLayout>
      )}
    </div>
  );
}
