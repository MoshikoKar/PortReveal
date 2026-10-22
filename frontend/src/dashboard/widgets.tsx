import { useLayoutEffect, useRef, useState, type MouseEvent, type ReactNode } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { post } from '../api';
import { useApp } from '../context';
import { EventFeed } from '../components/EventFeed';
import { Trend } from '../components/Trend';
import { Empty, Kpi, MockBadge, Progress, ScanStatusBadge, ScoreBadge } from '../components/ui';
import type { Dashboard as DashboardData, EventType, Network } from '../types';
import {
  EVENT_LABELS, SCAN_TYPE_LABELS, SCORE_HIGH, SCORE_MEDIUM,
  duration, fmtTime, quoteValue, relTime, scanStageFraction,
} from '../util';
import { KPI_IDS, KPI_LABELS } from './defaults';
import type { KpiId, WidgetId } from './types';
import { useContainerSize, useFittingRows } from './useFittingContent';
import { kpiColumns, moveKpi } from './layoutOps';
import { Popover } from './Popover';

const TYPE_COLORS: Record<EventType, string> = {
  device_discovered: 'var(--high)', port_opened: 'var(--high)', service_changed: 'var(--medium)',
  device_disappeared: 'var(--medium)', port_closed: 'var(--medium)', ip_changed: 'var(--low)',
  version_changed: 'var(--low)', device_reappeared: 'var(--low)', service_detected: 'var(--info)',
  tag_added: 'var(--info)', tag_removed: 'var(--info)', watch_match: 'var(--medium)', policy_violation: 'var(--high)',
  banner_changed: 'var(--info)', os_changed: 'var(--medium)', monitor_change: 'var(--medium)',
  geo_mismatch: 'var(--high)', cve_watch_match: 'var(--high)',
};

const LEVEL_COLORS = { high: 'var(--high)', medium: 'var(--medium)', low: 'var(--ok)' } as const;
const LEVEL_LABELS = { high: 'High', medium: 'Medium', low: 'Low' } as const;
const LEVEL_QUERIES = {
  high: `score:>=${SCORE_HIGH}`,
  medium: `score:${SCORE_MEDIUM}-${SCORE_HIGH - 1}`,
  low: `score:<${SCORE_MEDIUM}`,
} as const;
export const searchLink = (q: string) => `/search?q=${encodeURIComponent(q)}`;

/** Edit-mode controls the grid hands each widget; absent outside edit mode. */
export interface WidgetEditControls {
  onHide: () => void;
  /** Fit height to content; absent for widgets whose content fills any height. */
  onFit?: () => void;
  /** Set width as a fraction of the row; absent on single-column screens. */
  onWidth?: (fraction: number) => void;
}

const WIDTH_PRESETS: [string, number][] = [['¼', 1 / 4], ['⅓', 1 / 3], ['½', 1 / 2], ['⅔', 2 / 3], ['Full', 1]];

export function WidgetChrome({
  title, actions, edit, children, flush, bare, className,
}: {
  title: ReactNode;
  actions?: ReactNode;
  edit?: WidgetEditControls;
  children: ReactNode;
  flush?: boolean;
  /** No card frame or header outside edit mode (the KPI strip reads as page content). */
  bare?: boolean;
  className?: string;
}) {
  return (
    <section className={`card dashboard-widget${bare && !edit ? ' bare' : ''} ${className ?? ''}`}>
      {(!bare || edit) && (
        <div className="card-head">
          {edit && (
            <span className="dashboard-grip" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="currentColor"><circle cx="9" cy="6" r="1.6" /><circle cx="15" cy="6" r="1.6" /><circle cx="9" cy="12" r="1.6" /><circle cx="15" cy="12" r="1.6" /><circle cx="9" cy="18" r="1.6" /><circle cx="15" cy="18" r="1.6" /></svg>
            </span>
          )}
          {typeof title === 'string' ? <h2>{title}</h2> : title}
          <div className="row dashboard-widget-actions">
            {edit ? (
              <>
                {edit.onWidth && (
                  <Popover label="Width ▾" title="Set width" className="dashboard-width-menu"
                    buttonClassName="btn ghost sm" panelClassName="dashboard-width-panel">
                    {(close) => WIDTH_PRESETS.map(([label, f]) => (
                      <button key={label} type="button" className="btn ghost sm dash-popover-item"
                        onClick={() => { edit.onWidth!(f); close(); }}>
                        {label === 'Full' ? 'Full row' : `${label} of the row`}
                      </button>
                    ))}
                  </Popover>
                )}
                {edit.onFit && (
                  <button type="button" className="btn ghost sm" onClick={edit.onFit} title="Fit height to content">Fit</button>
                )}
                <button type="button" className="btn ghost sm dashboard-remove" onClick={edit.onHide}
                  title="Remove from dashboard" aria-label="Remove from dashboard">✕</button>
              </>
            ) : actions}
          </div>
        </div>
      )}
      <div className={`card-body ${flush ? 'flush' : ''}`}>{children}</div>
    </section>
  );
}

function BaselineCell({ n, onStarted }: { n: Network; onStarted: () => void }) {
  const { isAdmin } = useApp();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (n.baseline_at) return <>{fmtTime(n.baseline_at)}</>;
  const start = async (e: MouseEvent) => {
    e.stopPropagation();
    setBusy(true);
    setErr(null);
    try {
      await post('/scans', { scan_type: 'standard', network_ids: [n.id] });
      onStarted();
    } catch (ex: any) {
      setErr(ex.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="row wrap" style={{ gap: 8 }}>
      <span className="badge medium">pending first complete scan</span>
      {n.scan_active ? (
        <span className="muted small">scan queued / running</span>
      ) : isAdmin && (
        <button className="btn sm" disabled={busy} onClick={start}
          title="Run a standard scan of this network; when it completes, its result becomes the baseline">
          {busy ? 'Starting…' : 'Run baseline scan'}
        </button>
      )}
      {err && <span className="small" style={{ color: 'var(--high)' }}>{err}</span>}
    </div>
  );
}

export interface WidgetRenderProps {
  data: DashboardData;
  edit?: WidgetEditControls;
  /** Render untruncated content so the grid can measure the natural height (Fit). */
  measuring: boolean;
  kpiVisible: KpiId[];
  onKpisChange?: (next: KpiId[]) => void;
  /** Report the pixel height the content needs (autoHeight widgets). */
  onAutoHeight?: (px: number) => void;
  reload: () => void;
}

function KpisWidget({ data, edit, kpiVisible, onKpisChange, onAutoHeight }: WidgetRenderProps) {
  const nav = useNavigate();
  const editing = !!edit;
  const contentRef = useRef<HTMLDivElement>(null);
  const { width } = useContainerSize(contentRef);
  const [dragId, setDragId] = useState<KpiId | null>(null);
  const [overId, setOverId] = useState<KpiId | null>(null);
  const { devices, last_24h: d1, last_7d: d7 } = data;
  const go = (to: string) => (editing ? undefined : () => nav(to));
  const tiles: Record<KpiId, ReactNode> = {
    known_hosts: (
      <Kpi label="Known hosts" value={devices.total} sub={`${devices.exposed} with open ports`} color="var(--accent)"
        onClick={go('/devices')} />
    ),
    active: (
      <Kpi label="Currently detected" value={devices.active}
        sub={devices.not_detected ? `${devices.not_detected} not detected` : devices.unknown ? `${devices.unknown} unconfirmed` : 'seen in latest scans'}
        color="var(--ok)" onClick={go('/devices?status=active')} />
    ),
    new_hosts_24h: (
      <Kpi label="New hosts (24h)" value={d1.new_hosts} sub={`${data.new_hosts_7d} in last 7d`}
        color={d1.new_hosts ? 'var(--high)' : undefined}
        onClick={go(searchLink('new:24h'))} />
    ),
    new_ports_24h: (
      <Kpi label="New ports (24h)" value={d1.new_ports} sub={`${d7.new_ports} opened in 7d`}
        color={d1.new_ports ? 'var(--high)' : undefined}
        onClick={go('/changes?type=port_opened&range=24h')} />
    ),
    service_changes_24h: (
      <Kpi label="Service changes (24h)" value={d1.service_changes} sub={`${d7.service_changes} in last 7d`}
        color={d1.service_changes ? 'var(--medium)' : undefined}
        onClick={go('/changes?type=service_changed,version_changed&range=24h')} />
    ),
    open_ports: (
      <Kpi label="Open ports" value={data.open_ports_total} sub={`${d1.closed_ports} closed in 24h`} color="var(--low)"
        onClick={go('/ports')} />
    ),
    high_exposure: (
      <Kpi label="High exposure" value={data.exposure.high}
        sub={`score ≥ ${SCORE_HIGH} · ${data.exposure.medium} medium`}
        color={data.exposure.high ? 'var(--high)' : undefined}
        onClick={go(searchLink(LEVEL_QUERIES.high))} />
    ),
    alerts_7d: (
      <Kpi label="Alerts (7d)" value={data.watch_alerts.last_7d}
        sub="watches, policies, monitors"
        color={data.watch_alerts.last_7d ? 'var(--medium)' : undefined}
        onClick={go('/changes?type=watch_match,policy_violation,monitor_change&range=7d')} />
    ),
  };
  const shown = kpiVisible.filter((id) => KPI_IDS.includes(id));
  const available = KPI_IDS.filter((id) => !shown.includes(id));
  const canEdit = editing && !!onKpisChange;
  const columns = kpiColumns(shown.length + (canEdit && available.length ? 1 : 0), width);

  // Report the height the strip needs (head + padding + tiles) so the grid sizes its cell to it.
  useLayoutEffect(() => {
    const el = contentRef.current;
    const body = el?.parentElement;
    const section = el?.closest('.dashboard-widget') as HTMLElement | null;
    if (!el || !body || !section || !onAutoHeight) return;
    const measure = () => {
      const head = section.querySelector(':scope > .card-head') as HTMLElement | null;
      const pad = getComputedStyle(body);
      const frame = section.offsetHeight - section.clientHeight;
      onAutoHeight((head?.offsetHeight ?? 0) + parseFloat(pad.paddingTop) + parseFloat(pad.paddingBottom) + el.offsetHeight + frame);
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [onAutoHeight, editing]);

  const move = (from: KpiId, to: KpiId) => onKpisChange?.(moveKpi(shown, from, to));
  const step = (id: KpiId, delta: number) => {
    const target = shown[shown.indexOf(id) + delta];
    if (target) move(id, target);
  };
  const endDrag = () => { setDragId(null); setOverId(null); };

  return (
    <WidgetChrome title="KPI strip" edit={edit} bare className="kpis-widget">
      <div ref={contentRef} className="grid kpis dashboard-kpis" style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}>
        {shown.map((id, idx) => (
          <div key={id}
            className={`kpi-slot${canEdit ? ' editable' : ''}${dragId === id ? ' dragging' : ''}${overId === id && dragId && dragId !== id ? ' drop-target' : ''}`}
            draggable={canEdit}
            onDragStart={canEdit ? (e) => { setDragId(id); e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', id); } : undefined}
            onDragOver={canEdit ? (e) => { if (!dragId) return; e.preventDefault(); e.dataTransfer.dropEffect = 'move'; setOverId(id); } : undefined}
            onDragLeave={canEdit ? () => setOverId((cur) => (cur === id ? null : cur)) : undefined}
            onDrop={canEdit ? (e) => { e.preventDefault(); if (dragId) move(dragId, id); endDrag(); } : undefined}
            onDragEnd={canEdit ? endDrag : undefined}>
            {tiles[id]}
            {canEdit && (
              <div className="kpi-slot-tools">
                <button type="button" className="btn ghost sm" disabled={idx === 0} onClick={() => step(id, -1)}
                  title="Move left" aria-label={`Move ${KPI_LABELS[id]} left`}>‹</button>
                <button type="button" className="btn ghost sm" disabled={idx === shown.length - 1} onClick={() => step(id, 1)}
                  title="Move right" aria-label={`Move ${KPI_LABELS[id]} right`}>›</button>
                <button type="button" className="btn ghost sm" disabled={shown.length <= 1}
                  onClick={() => onKpisChange!(shown.filter((k) => k !== id))}
                  title={shown.length <= 1 ? 'Keep at least one KPI' : 'Remove KPI'} aria-label={`Remove ${KPI_LABELS[id]}`}>✕</button>
              </div>
            )}
          </div>
        ))}
        {canEdit && available.length > 0 && (
          <Popover label={<>+ Add KPI <span className="muted">({available.length})</span></>} className="kpi-add">
            {(close) => (
              <div className="stack" style={{ gap: 2 }}>
                {available.map((id) => (
                  <button key={id} type="button" className="btn ghost sm dash-popover-item"
                    onClick={() => { onKpisChange!([...shown, id]); if (available.length === 1) close(); }}>
                    + {KPI_LABELS[id]}
                  </button>
                ))}
                {available.length > 1 && (
                  <button type="button" className="btn sm" style={{ marginTop: 6 }}
                    onClick={() => { onKpisChange!([...shown, ...available]); close(); }}>Add all</button>
                )}
              </div>
            )}
          </Popover>
        )}
      </div>
    </WidgetChrome>
  );
}

function RecentChangesWidget({ data, edit, measuring }: WidgetRenderProps) {
  const listRef = useRef<HTMLDivElement>(null);
  const fit = useFittingRows(listRef, data.recent_events.length, '.feed > li', measuring);
  const events = fit == null ? data.recent_events.slice(0, 10) : data.recent_events.slice(0, fit);
  const hidden = Math.max(0, Math.min(10, data.recent_events.length) - events.length);
  return (
    <WidgetChrome title="Recent changes" edit={edit} flush
      actions={<Link to="/changes" className="small">All changes →</Link>}>
      <div ref={listRef} className="dashboard-fit-body">
        <EventFeed events={events}
          empty="No changes recorded. The first complete scan of each network is a silent baseline." />
        {hidden > 0 && <div className="muted small" style={{ padding: '4px 12px' }}>+{hidden} more in feed</div>}
      </div>
    </WidgetChrome>
  );
}

function ScanStatusWidget({ data, edit }: WidgetRenderProps) {
  const { scans } = data;
  const current = scans.current;
  const last = scans.last_completed;
  return (
    <WidgetChrome title="Scan status" edit={edit}
      actions={<Link to="/scans" className="small">Scans →</Link>}>
      <div className="stack" style={{ gap: 10 }}>
        {current ? (
          <div className="stack" style={{ gap: 6 }}>
            <div className="spread">
              <span><ScanStatusBadge status="running" /> {SCAN_TYPE_LABELS[current.scan_type]} · {current.network_name ?? 'custom targets'}</span>
              <MockBadge mode={current.scanner_mode} />
            </div>
            <Progress value={current.progress} />
            <div className="muted small">
              {current.stage} · {Math.round(scanStageFraction(current) * 100)}% of stage · {current.hosts_discovered} hosts found · {current.hosts_scanned} scanned · {duration(current.started_at, null)}
            </div>
          </div>
        ) : (
          <div className="muted">No scan running{scans.queued ? ` · ${scans.queued} queued` : ''}.</div>
        )}
        <dl className="dl" style={{ gridTemplateColumns: '130px 1fr' }}>
          <dt>Last completed</dt>
          <dd>
            {last ? (
              <>
                {fmtTime(last.finished_at)} <span className="muted">({relTime(last.finished_at)})</span>
                <div className="small"><ScanStatusBadge status={last.status} /> {SCAN_TYPE_LABELS[last.scan_type]} · {last.hosts_discovered} hosts · {last.events_count} changes <MockBadge mode={last.scanner_mode} /></div>
              </>
            ) : 'never'}
          </dd>
          <dt>Next scheduled</dt>
          <dd>{scans.next_scheduled ? <>{fmtTime(scans.next_scheduled)} <span className="muted">({relTime(scans.next_scheduled)})</span></> : <span className="muted">not scheduled</span>}</dd>
          {scans.last_failed && (!last || scans.last_failed.id > last.id) && (
            <><dt>Last failure</dt><dd style={{ color: 'var(--high)' }}>{fmtTime(scans.last_failed.finished_at)} · {scans.last_failed.error}</dd></>
          )}
        </dl>
      </div>
    </WidgetChrome>
  );
}

function ChangesByTypeWidget({ data, edit, measuring }: WidgetRenderProps) {
  const byType = Object.entries(data.last_7d.by_type) as [EventType, number][];
  const barsRef = useRef<HTMLDivElement>(null);
  const fit = useFittingRows(barsRef, byType.length, undefined, measuring);
  const sorted = [...byType].sort((a, b) => b[1] - a[1]);
  const shown = fit == null ? sorted : sorted.slice(0, fit);
  const hiddenN = sorted.length - shown.length;
  const maxType = Math.max(1, ...byType.map(([, n]) => n));
  return (
    <WidgetChrome title="Changes by type (7 days)" edit={edit}
      actions={hiddenN > 0 ? <Link to="/changes?range=7d" className="small">+{hiddenN} more →</Link> : undefined}>
      {byType.length === 0 ? <div className="muted">No changes in the last 7 days.</div> : (
        <div className="bars" ref={barsRef}>
          {shown.map(([t, n]) => (
            <Link to={`/changes?type=${t}&range=7d`} key={t} className="bar-row" title={`${EVENT_LABELS[t]}: ${n}`}>
              <span>{EVENT_LABELS[t]}</span>
              <span className="bar-track"><span className="bar-fill" style={{ width: `${(n / maxType) * 100}%`, ['--bar-color' as any]: TYPE_COLORS[t] }} /></span>
              <span className="right">{n}</span>
            </Link>
          ))}
        </div>
      )}
    </WidgetChrome>
  );
}

function ExposureScoresWidget({ data, edit, measuring }: WidgetRenderProps) {
  const nav = useNavigate();
  const tableRef = useRef<HTMLTableElement>(null);
  const fit = useFittingRows(tableRef, data.exposure.top.length, 'tbody tr', measuring);
  const rows = fit == null ? data.exposure.top : data.exposure.top.slice(0, Math.max(0, fit - 1));
  return (
    <WidgetChrome title="Exposure scores" edit={edit}
      actions={<Link to="/reports" className="small">Reports →</Link>}>
      <div className="stack">
        <div className="bars">
          {(['high', 'medium', 'low'] as const).map((lvl) => (
            <Link key={lvl} to={searchLink(LEVEL_QUERIES[lvl])} className="bar-row">
              <span>{LEVEL_LABELS[lvl]}</span>
              <span className="bar-track"><span className="bar-fill" style={{ width: `${(data.exposure[lvl] / Math.max(1, data.devices.total)) * 100}%`, ['--bar-color' as any]: LEVEL_COLORS[lvl] }} /></span>
              <span className="right">{data.exposure[lvl]}</span>
            </Link>
          ))}
        </div>
        {data.exposure.top.length > 0 && (
          <table ref={tableRef}>
            <thead><tr><th>IP</th><th>Hostname</th><th>Type</th><th className="right">Score</th></tr></thead>
            <tbody>
              {rows.map((h) => (
                <tr key={h.uuid} className="clickable" onClick={() => !edit && nav(`/devices/${h.uuid}`)}>
                  <td className="mono nowrap">{h.ip}</td>
                  <td className="muted small">{h.hostname || '-'}</td>
                  <td className="muted small">{h.type || '-'}</td>
                  <td className="right"><ScoreBadge score={h.score} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </WidgetChrome>
  );
}

function DeviceTypesWidget({ data, edit, measuring }: WidgetRenderProps) {
  const barsRef = useRef<HTMLDivElement>(null);
  const fit = useFittingRows(barsRef, data.device_types.length, undefined, measuring);
  const maxTypeCount = Math.max(1, ...data.device_types.map((t) => t.count));
  const shown = fit == null ? data.device_types : data.device_types.slice(0, fit);
  const hiddenN = data.device_types.length - shown.length;
  return (
    <WidgetChrome title="Device types" edit={edit}
      actions={<>
        {hiddenN > 0 && <span className="small muted">+{hiddenN}</span>}
        <Link to="/search" className="small">Search →</Link>
      </>}>
      {data.device_types.length === 0 ? <div className="muted">No devices classified yet. Types are assigned after a port scan.</div> : (
        <div className="bars" ref={barsRef}>
          {shown.map((t) => (
            <Link key={t.type} to={searchLink(`type:${quoteValue(t.type)}`)} className="bar-row" title={`${t.type}: ${t.count}`}>
              <span>{t.type}</span>
              <span className="bar-track"><span className="bar-fill" style={{ width: `${(t.count / maxTypeCount) * 100}%` }} /></span>
              <span className="right">{t.count}</span>
            </Link>
          ))}
        </div>
      )}
    </WidgetChrome>
  );
}

function WatchAlertsWidget({ data, edit, measuring }: WidgetRenderProps) {
  const listRef = useRef<HTMLDivElement>(null);
  const fit = useFittingRows(listRef, data.watch_alerts.recent.length, '.feed > li', measuring);
  const events = fit == null ? data.watch_alerts.recent : data.watch_alerts.recent.slice(0, fit);
  return (
    <WidgetChrome title="Watch alerts (7 days)" edit={edit} flush
      actions={<Link to="/watches" className="small">Watches →</Link>}>
      <div ref={listRef}>
        <EventFeed events={events}
          empty="No watch matches or policy violations. Save a search as a watch to be alerted when new hosts match." />
      </div>
    </WidgetChrome>
  );
}

function ExposureTrendWidget({ data, edit }: WidgetRenderProps) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const { width, height } = useContainerSize(wrapRef);
  return (
    <WidgetChrome title="Exposure trend (30 days)" edit={edit}>
      <div ref={wrapRef} className="dashboard-chart-fill">
        <Trend points={data.trend} width={width || undefined} height={height || undefined} />
      </div>
    </WidgetChrome>
  );
}

function NetworksWidget({ data, edit, measuring, reload }: WidgetRenderProps) {
  const nav = useNavigate();
  const tableRef = useRef<HTMLTableElement>(null);
  const fit = useFittingRows(tableRef, data.networks.length, 'tbody tr', measuring);
  const rows = fit == null ? data.networks : data.networks.slice(0, fit);
  if (data.networks.length === 0) {
    return (
      <WidgetChrome title="Networks" edit={edit}>
        <div className="muted">No networks configured.</div>
      </WidgetChrome>
    );
  }
  return (
    <WidgetChrome title="Networks" edit={edit} flush>
      <table ref={tableRef}>
        <thead><tr><th>Network</th><th>Scope</th><th>Active / known</th><th>Baseline</th></tr></thead>
        <tbody>
          {rows.map((n) => (
            <tr key={n.id} className="clickable" onClick={() => !edit && nav(`/devices?network_id=${n.id}`)}>
              <td>{n.name}</td>
              <td className="mono">{n.cidr}</td>
              <td>{n.active_count} / {n.device_count}</td>
              <td><BaselineCell n={n} onStarted={reload} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </WidgetChrome>
  );
}

function TopPortsWidget({ data, edit, measuring }: WidgetRenderProps) {
  const nav = useNavigate();
  const tableRef = useRef<HTMLTableElement>(null);
  const fit = useFittingRows(tableRef, data.top_ports.length, 'tbody tr', measuring);
  const rows = fit == null ? data.top_ports : data.top_ports.slice(0, fit);
  const hiddenN = data.top_ports.length - rows.length;
  return (
    <WidgetChrome title="Most exposed ports" edit={edit} flush
      actions={<Link to="/ports" className="small">See all{data.exposed_ports_total ? ` ${data.exposed_ports_total}` : ''}{hiddenN ? ` · +${hiddenN}` : ''} →</Link>}>
      {data.top_ports.length === 0 ? <Empty>No open ports known yet.</Empty> : (
        <table ref={tableRef}>
          <tbody>
            {rows.map((p) => (
              <tr key={`${p.protocol}${p.port}`} className="clickable" onClick={() => !edit && nav(`/devices?port=${p.port}`)}>
                <td className="mono">{p.protocol.toUpperCase()}/{p.port}</td>
                <td className="muted">{p.service ?? ''}</td>
                <td className="right">{p.count} host{p.count === 1 ? '' : 's'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </WidgetChrome>
  );
}

function TopServicesWidget({ data, edit, measuring }: WidgetRenderProps) {
  const barsRef = useRef<HTMLDivElement>(null);
  const maxSvc = Math.max(1, ...data.top_services.map((s) => s.count));
  const fit = useFittingRows(barsRef, data.top_services.length, undefined, measuring);
  const shown = fit == null ? data.top_services : data.top_services.slice(0, fit);
  const hiddenN = data.top_services.length - shown.length;
  return (
    <WidgetChrome title="Exposed services" edit={edit}
      actions={hiddenN > 0 ? <span className="small muted">+{hiddenN} more</span> : undefined}>
      {data.top_services.length === 0 ? <div className="muted">No services known yet.</div> : (
        <div className="bars" ref={barsRef}>
          {shown.map((s) => (
            <Link key={s.service} to={`/devices?service=${encodeURIComponent(s.service)}`} className="bar-row" title={`${s.service}: ${s.count}`}>
              <span className="mono">{s.service}</span>
              <span className="bar-track"><span className="bar-fill" style={{ width: `${(s.count / maxSvc) * 100}%` }} /></span>
              <span className="right">{s.count}</span>
            </Link>
          ))}
        </div>
      )}
    </WidgetChrome>
  );
}

const RENDERERS: Record<WidgetId, (p: WidgetRenderProps) => ReactNode> = {
  kpis: (p) => <KpisWidget {...p} />,
  recent_changes: (p) => <RecentChangesWidget {...p} />,
  scan_status: (p) => <ScanStatusWidget {...p} />,
  changes_by_type: (p) => <ChangesByTypeWidget {...p} />,
  exposure_scores: (p) => <ExposureScoresWidget {...p} />,
  device_types: (p) => <DeviceTypesWidget {...p} />,
  watch_alerts: (p) => <WatchAlertsWidget {...p} />,
  exposure_trend: (p) => <ExposureTrendWidget {...p} />,
  networks: (p) => <NetworksWidget {...p} />,
  top_ports: (p) => <TopPortsWidget {...p} />,
  top_services: (p) => <TopServicesWidget {...p} />,
};

export function renderWidget(id: WidgetId, props: WidgetRenderProps): ReactNode {
  const fn = RENDERERS[id];
  return fn ? fn(props) : null;
}
