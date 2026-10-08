import { useState, type MouseEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { post } from '../api';
import { useApp } from '../context';
import { EventFeed } from '../components/EventFeed';
import { Trend } from '../components/Trend';
import { Card, ErrorBox, Kpi, Loading, MockBadge, Progress, ScanStatusBadge } from '../components/ui';
import type { Dashboard as DashboardData, EventType, Network } from '../types';
import { EVENT_LABELS, SCAN_TYPE_LABELS, duration, fmtTime, relTime, useApi } from '../util';

const TYPE_COLORS: Record<EventType, string> = {
  device_discovered: 'var(--high)', port_opened: 'var(--high)', service_changed: 'var(--medium)',
  device_disappeared: 'var(--medium)', port_closed: 'var(--medium)', ip_changed: 'var(--low)',
  version_changed: 'var(--low)', device_reappeared: 'var(--low)', service_detected: 'var(--info)',
};

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

export default function Dashboard() {
  const { data, error, reload } = useApi<DashboardData>('/dashboard', undefined, 10000);
  const nav = useNavigate();
  if (!data) return <>{error ? <ErrorBox error={error} /> : <Loading />}</>;
  const { devices, last_24h: d1, last_7d: d7, scans } = data;
  const byType = Object.entries(d7.by_type) as [EventType, number][];
  const maxType = Math.max(1, ...byType.map(([, n]) => n));
  const maxSvc = Math.max(1, ...data.top_services.map((s) => s.count));
  const current = scans.current;
  const last = scans.last_completed;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Network overview</h1>
          <p>What exists on the network, what it exposes, and what changed.</p>
        </div>
      </div>
      <ErrorBox error={error} />

      <div className="grid kpis">
        <Kpi label="Known hosts" value={devices.total} sub={`${devices.exposed} with open ports`} color="var(--accent)" onClick={() => nav('/devices')} />
        <Kpi label="Currently detected" value={devices.active} sub={devices.unknown ? `${devices.unknown} unconfirmed` : 'seen in latest scans'} color="var(--ok)" onClick={() => nav('/devices?status=active')} />
        <Kpi label="Not detected" value={devices.not_detected} sub="missed by consecutive scans" color={devices.not_detected ? 'var(--medium)' : undefined} onClick={() => nav('/devices?status=not_detected')} />
        <Kpi label="New hosts (7d)" value={d7.new_hosts} sub={`${d1.new_hosts} in last 24h`} color={d7.new_hosts ? 'var(--high)' : undefined} onClick={() => nav('/changes?type=device_discovered&range=7d')} />
        <Kpi label="Open ports" value={data.open_ports_total} sub="total exposure" color="var(--low)" />
        <Kpi label="New ports (7d)" value={d7.new_ports} sub={`${d1.new_ports} in last 24h`} color={d7.new_ports ? 'var(--high)' : undefined} onClick={() => nav('/changes?type=port_opened&range=7d')} />
        <Kpi label="Closed ports (7d)" value={d7.closed_ports} sub={`${d1.closed_ports} in last 24h`} onClick={() => nav('/changes?type=port_closed&range=7d')} />
        <Kpi label="Service changes (7d)" value={d7.service_changes} sub={`${d1.service_changes} in last 24h`} color={d7.service_changes ? 'var(--medium)' : undefined} onClick={() => nav('/changes?type=service_changed,version_changed&range=7d')} />
        <Kpi label="Changes 24h" value={d1.changes} sub="all event types" onClick={() => nav('/changes?range=24h')} />
        <Kpi label="Changes 7d" value={d7.changes} sub="all event types" onClick={() => nav('/changes?range=7d')} />
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
                    {current.stage} · {Math.round(current.progress * 100)}% · {current.hosts_discovered} hosts found · {current.hosts_scanned} scanned{current.open_ports_found > 0 && ` · ${current.open_ports_found} open ports so far`} · {duration(current.started_at, null)}
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

          <Card title="Changes by type (7 days)">
            {byType.length === 0 ? <div className="muted">No changes in the last 7 days.</div> : (
              <div className="bars">
                {byType.sort((a, b) => b[1] - a[1]).map(([t, n]) => (
                  <Link to={`/changes?type=${t}&range=7d`} key={t} className="bar-row" style={{ color: 'var(--text-2)' }}>
                    <span>{EVENT_LABELS[t]}</span>
                    <span className="bar-track"><span className="bar-fill" style={{ display: 'block', width: `${(n / maxType) * 100}%`, ['--bar-color' as any]: TYPE_COLORS[t] }} /></span>
                    <span className="right">{n}</span>
                  </Link>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      <div className="grid three">
        <Card title="Exposure trend (30 days)"><Trend points={data.trend} /></Card>
        <Card title="Most exposed ports" flush actions={<Link to="/ports" className="small">See all{data.exposed_ports_total ? ` ${data.exposed_ports_total}` : ''} →</Link>}>
          {data.top_ports.length === 0 ? <div className="empty">No open ports known yet.</div> : (
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
                <Link key={s.service} to={`/devices?service=${encodeURIComponent(s.service)}`} className="bar-row" style={{ color: 'var(--text-2)' }}>
                  <span className="mono">{s.service}</span>
                  <span className="bar-track"><span className="bar-fill" style={{ display: 'block', width: `${(s.count / maxSvc) * 100}%` }} /></span>
                  <span className="right">{s.count}</span>
                </Link>
              ))}
            </div>
          )}
        </Card>
      </div>

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
    </>
  );
}
