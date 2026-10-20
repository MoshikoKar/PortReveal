import { useLayoutEffect, useRef, useState, type FormEvent, type MouseEvent, type RefObject } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { post } from '../api';
import { useApp } from '../context';
import { EventFeed } from '../components/EventFeed';
import { Trend } from '../components/Trend';
import { Card, Empty, ErrorBox, Kpi, Loading, MockBadge, Progress, ScanStatusBadge, ScoreBadge } from '../components/ui';
import type { Dashboard as DashboardData, EventType, Network } from '../types';
import { EVENT_LABELS, SCAN_TYPE_LABELS, SCORE_HIGH, SCORE_MEDIUM, duration, fmtTime, quoteValue, relTime, scanStageFraction, useApi } from '../util';

const TYPE_COLORS: Record<EventType, string> = {
  device_discovered: 'var(--high)', port_opened: 'var(--high)', service_changed: 'var(--medium)',
  device_disappeared: 'var(--medium)', port_closed: 'var(--medium)', ip_changed: 'var(--low)',
  version_changed: 'var(--low)', device_reappeared: 'var(--low)', service_detected: 'var(--info)',
  tag_added: 'var(--info)', tag_removed: 'var(--info)', watch_match: 'var(--medium)', policy_violation: 'var(--high)',
  banner_changed: 'var(--info)', os_changed: 'var(--medium)', monitor_change: 'var(--medium)',
  geo_mismatch: 'var(--high)',
};

const LEVEL_COLORS = { high: 'var(--high)', medium: 'var(--medium)', low: 'var(--ok)' } as const;
const LEVEL_QUERIES = { high: `score:>=${SCORE_HIGH}`, medium: `score:${SCORE_MEDIUM}-${SCORE_HIGH - 1}`, low: `score:<${SCORE_MEDIUM}` } as const;
const searchLink = (q: string) => `/search?q=${encodeURIComponent(q)}`;

function SearchBox() {
  const nav = useNavigate();
  const [q, setQ] = useState('');
  const submit = (e: FormEvent) => {
    e.preventDefault();
    nav(q.trim() ? searchLink(q.trim()) : '/search');
  };
  return (
    <form className="search-bar" onSubmit={submit}>
      <input type="search" value={q} onChange={(e) => setQ(e.target.value)} maxLength={1000} aria-label="Search the inventory"
        placeholder='Search the inventory: port:3389 · tag:camera · product:openssh · http.title:"login"' />
      <button className="btn primary" type="submit">Search</button>
    </form>
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
        <button className="btn sm" disabled={busy} onClick={start} title="Run a standard scan of this network; when it completes, its result becomes the baseline">
          {busy ? 'Starting…' : 'Run baseline scan'}
        </button>
      )}
      {err && <span className="small" style={{ color: 'var(--high)' }}>{err}</span>}
    </div>
  );
}

// .grid.two drops to one column at 1200px; side by side, Recent changes alone sets the row height.
const SIDE_BY_SIDE = '(min-width: 1201px)';

/** How many `.bar-row`s fit in the card body around `ref` (null = no limit: stacked layout). */
function useFittingRows(ref: RefObject<HTMLDivElement | null>, count: number): number | null {
  const [fit, setFit] = useState<number | null>(null);
  useLayoutEffect(() => {
    const bars = ref.current;
    const body = bars?.parentElement;
    if (!bars || !body) return;
    const mq = window.matchMedia(SIDE_BY_SIDE);
    const measure = () => {
      const row = bars.querySelector('.bar-row');
      if (!mq.matches || !row) { setFit(null); return; }
      const pad = getComputedStyle(body);
      const room = body.clientHeight - parseFloat(pad.paddingTop) - parseFloat(pad.paddingBottom);
      const gap = parseFloat(getComputedStyle(bars).rowGap) || 0;
      setFit(Math.max(1, Math.floor((room + gap) / (row.getBoundingClientRect().height + gap))));
    };
    measure();
    // The card is size-contained, so its body only resizes with the row, never with the bars.
    const ro = new ResizeObserver(measure);
    ro.observe(body);
    mq.addEventListener('change', measure);
    return () => { ro.disconnect(); mq.removeEventListener('change', measure); };
  }, [ref, count]);
  return fit;
}

/** Busiest change types first, cut to what fits beside Recent changes so neither column has a gap. */
function ChangesByType({ byType }: { byType: [EventType, number][] }) {
  const barsRef = useRef<HTMLDivElement>(null);
  const fit = useFittingRows(barsRef, byType.length);
  const sorted = [...byType].sort((a, b) => b[1] - a[1]);
  const shown = fit == null ? sorted : sorted.slice(0, fit);
  const hidden = sorted.length - shown.length;
  const maxType = Math.max(1, ...byType.map(([, n]) => n));
  return (
    <Card title="Changes by type (7 days)" className="fill-rest"
      actions={hidden > 0 && <Link to="/changes?range=7d" className="small">+{hidden} more →</Link>}>
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
    </Card>
  );
}

export default function Dashboard() {
  const { data, error, reload } = useApi<DashboardData>('/dashboard', undefined, 10000);
  const nav = useNavigate();
  if (!data) return <>{error ? <ErrorBox error={error} /> : <Loading />}</>;
  const { devices, last_24h: d1, last_7d: d7, scans } = data;
  const byType = Object.entries(d7.by_type) as [EventType, number][];
  const maxSvc = Math.max(1, ...data.top_services.map((s) => s.count));
  const current = scans.current;
  const last = scans.last_completed;

  return (
    <div className="dashboard">
      <div className="page-head">
        <div>
          <h1>Network overview</h1>
          <p>What exists on the network, what it exposes, and what changed.</p>
        </div>
      </div>
      <ErrorBox error={error} />
      <SearchBox />

      <div className="grid kpis">
        <Kpi label="Known hosts" value={devices.total} sub={`${devices.exposed} with open ports`} color="var(--accent)" onClick={() => nav('/devices')} />
        <Kpi label="Currently detected" value={devices.active} sub={devices.not_detected ? `${devices.not_detected} not detected` : devices.unknown ? `${devices.unknown} unconfirmed` : 'seen in latest scans'} color="var(--ok)" onClick={() => nav('/devices?status=active')} />
        <Kpi label="New hosts (24h)" value={d1.new_hosts} sub={`${data.new_hosts_7d} in last 7d`} color={d1.new_hosts ? 'var(--high)' : undefined} onClick={() => nav(searchLink('new:24h'))} />
        <Kpi label="New ports (24h)" value={d1.new_ports} sub={`${d7.new_ports} opened in 7d`} color={d1.new_ports ? 'var(--high)' : undefined} onClick={() => nav('/changes?type=port_opened&range=24h')} />
        <Kpi label="Service changes (24h)" value={d1.service_changes} sub={`${d7.service_changes} in last 7d`} color={d1.service_changes ? 'var(--medium)' : undefined} onClick={() => nav('/changes?type=service_changed,version_changed&range=24h')} />
        <Kpi label="Open ports" value={data.open_ports_total} sub={`${d1.closed_ports} closed in 24h`} color="var(--low)" onClick={() => nav('/ports')} />
        <Kpi label="High exposure" value={data.exposure.high} sub={`score ≥ ${SCORE_HIGH} · ${data.exposure.medium} medium`} color={data.exposure.high ? 'var(--high)' : undefined} onClick={() => nav(searchLink(LEVEL_QUERIES.high))} />
        <Kpi label="Alerts (7d)" value={data.watch_alerts.last_7d} sub="watch matches, policy violations, and monitored changes" color={data.watch_alerts.last_7d ? 'var(--medium)' : undefined} onClick={() => nav('/changes?type=watch_match,policy_violation,monitor_change&range=7d')} />
      </div>

      <div className="grid two">
        <Card title="Recent changes" flush actions={<Link to="/changes" className="small">All changes →</Link>}>
          <EventFeed events={data.recent_events.slice(0, 10)} empty="No changes recorded. The first complete scan of each network is a silent baseline." />
        </Card>

        <div className="stack" style={{ gap: 16 }}>
          <Card title="Scan status" actions={<Link to="/scans" className="small">Scans →</Link>}>
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
          </Card>

          <ChangesByType byType={byType} />
        </div>
      </div>

      <div className="grid three">
        <Card title="Exposure scores" actions={<Link to="/reports" className="small">Reports →</Link>}>
          <div className="stack">
            <div className="bars">
              {(['high', 'medium', 'low'] as const).map((lvl) => (
                <Link key={lvl} to={searchLink(LEVEL_QUERIES[lvl])} className="bar-row">
                  <span style={{ textTransform: 'capitalize' }}>{lvl}</span>
                  <span className="bar-track"><span className="bar-fill" style={{ width: `${(data.exposure[lvl] / Math.max(1, devices.total)) * 100}%`, ['--bar-color' as any]: LEVEL_COLORS[lvl] }} /></span>
                  <span className="right">{data.exposure[lvl]}</span>
                </Link>
              ))}
            </div>
            {data.exposure.top.length > 0 && (
              <table>
                <thead><tr><th>IP</th><th>Hostname</th><th>Type</th><th className="right">Score</th></tr></thead>
                <tbody>
                  {data.exposure.top.map((h) => (
                    <tr key={h.uuid} className="clickable" onClick={() => nav(`/devices/${h.uuid}`)}>
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
        </Card>
        <Card title="Device types" actions={<Link to="/search" className="small">Search →</Link>}>
          {data.device_types.length === 0 ? <div className="muted">No devices classified yet. Types are assigned after a port scan.</div> : (
            <div className="bars">
              {data.device_types.map((t) => (
                <Link key={t.type} to={searchLink(`type:${quoteValue(t.type)}`)} className="bar-row" title={`${t.type}: ${t.count}`}>
                  <span>{t.type}</span>
                  <span className="bar-track"><span className="bar-fill" style={{ width: `${(t.count / Math.max(1, ...data.device_types.map((x) => x.count))) * 100}%` }} /></span>
                  <span className="right">{t.count}</span>
                </Link>
              ))}
            </div>
          )}
        </Card>
        <Card title="Watch alerts (7 days)" flush actions={<Link to="/watches" className="small">Watches →</Link>}>
          <EventFeed events={data.watch_alerts.recent} empty="No watch matches or policy violations. Save a search as a watch to be alerted when new hosts match." />
        </Card>
      </div>

      <div className="grid three">
        <div className="stack" style={{ gap: 16 }}>
          <Card title="Exposure trend (30 days)"><Trend points={data.trend} /></Card>
          {data.networks.length > 0 && (
            <Card title="Networks" flush>
              <table>
                <thead><tr><th>Network</th><th>Scope</th><th>Active / known</th><th>Baseline</th></tr></thead>
                <tbody>
                  {data.networks.map((n) => (
                    <tr key={n.id} className="clickable" onClick={() => nav(`/devices?network_id=${n.id}`)}>
                      <td>{n.name}</td>
                      <td className="mono">{n.cidr}</td>
                      <td>{n.active_count} / {n.device_count}</td>
                      <td><BaselineCell n={n} onStarted={reload} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}
        </div>
        <Card title="Most exposed ports" flush actions={<Link to="/ports" className="small">See all{data.exposed_ports_total ? ` ${data.exposed_ports_total}` : ''} →</Link>}>
          {data.top_ports.length === 0 ? <Empty>No open ports known yet.</Empty> : (
            <table>
              <tbody>
                {data.top_ports.map((p) => (
                  <tr key={`${p.protocol}${p.port}`} className="clickable" onClick={() => nav(`/devices?port=${p.port}`)}>
                    <td className="mono">{p.protocol.toUpperCase()}/{p.port}</td>
                    <td className="muted">{p.service ?? ''}</td>
                    <td className="right">{p.count} host{p.count === 1 ? '' : 's'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card title="Exposed services">
          {data.top_services.length === 0 ? <div className="muted">No services known yet.</div> : (
            <div className="bars">
              {data.top_services.map((s) => (
                <Link key={s.service} to={`/devices?service=${encodeURIComponent(s.service)}`} className="bar-row" title={`${s.service}: ${s.count}`}>
                  <span className="mono">{s.service}</span>
                  <span className="bar-track"><span className="bar-fill" style={{ width: `${(s.count / maxSvc) * 100}%` }} /></span>
                  <span className="right">{s.count}</span>
                </Link>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
