import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { post } from '../api';
import { EventTable } from '../components/EventTable';
import { SubdomainDevicesCard, SubdomainPortsCard, SubdomainScoreBadges, SubdomainVulnsCard, SubdomainWebCard } from '../components/SubdomainIntel';
import { Card, Empty, ErrorBox, Loading, Pager } from '../components/ui';
import { WebCaptureDialog } from '../components/WebCaptureDialog';
import { useApp } from '../context';
import {
  EXPOSURE_BADGE, EXPOSURE_LABELS, EXPOSURE_TIPS, ROW_STATUS, SOURCE_LABELS, SOURCE_TIPS, collapseHistory, hostingLabel,
  subdomainFindings, subdomainStatus, subdomainStatusTip, webPreviewHref,
} from '../domains';
import type { ChangeEvent, DnsView, Paged, SubdomainDetail as Detail, SubdomainHistoryRow } from '../types';
import { fmtTime, relTime, useApi, useInFlight } from '../util';

// One page holds the whole retention window of a daily scan, so identical scans fold together.
const HISTORY_PAGE = 100;
const EVENTS_PAGE = 20;

function recordsText(v: DnsView | undefined): string {
  if (!v) return '-';
  const parts = [
    v.a.length ? `A ${v.a.join(', ')}` : null,
    v.aaaa.length ? `AAAA ${v.aaaa.join(', ')}` : null,
    v.cname.length ? `CNAME ${v.cname.join(', ')}` : null,
  ].filter(Boolean);
  return parts.join(' · ') || (v.status && v.status !== 'ok' ? v.status : '-');
}

/** One subdomain, laid out like DeviceDetail: scores and counts from the linked inventory devices (their
 *  existing scans), addresses next to the ports behind them, web pages, vulnerabilities, then DNS records,
 *  history and change events. History and events load only here (the inventory list never fetches them). */
export default function SubdomainDetail() {
  const { domainId, id } = useParams();
  const { isAdmin } = useApp();
  const nav = useNavigate();
  const [histPage, setHistPage] = useState(1);
  const [evPage, setEvPage] = useState(1);
  const [capture, setCapture] = useState(false);
  const [notice, setNotice] = useState<{ error?: string; scanId?: number; targets?: string[] } | null>(null);
  const { pending, track } = useInFlight();
  const base = `/domains/${domainId}/subdomains/${id}`;
  const { data: s, error } = useApi<Detail>(base);
  const history = useApi<Paged<SubdomainHistoryRow>>(`${base}/history`, { page: histPage, page_size: HISTORY_PAGE });
  const events = useApi<Paged<ChangeEvent>>(`${base}/events`, { page: evPage, page_size: EVENTS_PAGE });

  if (error && !s) return <Card title="Subdomain"><ErrorBox error={error} /></Card>;
  if (!s) return <Loading />;
  const st = ROW_STATUS[subdomainStatus(s)];
  const findings = subdomainFindings(s);
  const devByIp = new Map(s.devices.map((dv) => [dv.ip, dv]));
  const webHref = webPreviewHref(s);

  const portScan = () => track('port-scan', async () => {
    setNotice(null);
    try {
      const r = await post<{ scan_id: number; targets: string[] }>(`${base}/port-scan`);
      setNotice({ scanId: r.scan_id, targets: r.targets });
    } catch (e: any) {
      setNotice({ error: e.message });
    }
  });
  const scanButton = isAdmin && s.ips.length > 0 && (
    <button className="btn sm" disabled={pending('port-scan')} onClick={portScan} data-testid="subdomain-port-scan">
      {pending('port-scan') ? 'Queuing…' : 'Port scan now'}
    </button>
  );
  const captureButton = isAdmin && s.devices.length > 0 && <button className="btn sm" onClick={() => setCapture(true)}>Capture web interfaces</button>;

  return (
    <>
      <div className="page-head">
        <div style={{ minWidth: 0 }}>
          <div className="small muted"><Link to="/domains">Domains</Link> / <Link to={`/domains/${s.domain_id}`}>{s.domain_name}</Link></div>
          <h1 className="page-title-ellipsis"><span className="mono" title={s.name}>{s.name}</span></h1>
          <p className="row wrap" style={{ gap: 6 }}>
            <span className={`badge ${EXPOSURE_BADGE[s.exposure]}`} title={EXPOSURE_TIPS[s.exposure]}>{EXPOSURE_LABELS[s.exposure]}</span>
            <span className={`badge ${st.badge}`} title={subdomainStatusTip(s, fmtTime)}>{st.label}</span>
            {findings.map((f) => <span key={f.key} className={`badge ${f.badge}`} title={f.tip}>{f.label}</span>)}
            <SubdomainScoreBadges s={s} />
          </p>
        </div>
        <div className="row wrap gap-2">
          {s.devices.length === 1 && <Link className="btn" to={`/devices/${s.devices[0].uuid}`}>Device: {s.devices[0].label}</Link>}
          {webHref && <Link className="btn" to={webHref}>Open web preview →</Link>}
          {isAdmin && s.ips.length > 0 && (
            <button className="btn primary" disabled={pending('port-scan')} onClick={portScan}>{pending('port-scan') ? 'Queuing…' : 'Port scan now'}</button>
          )}
        </div>
      </div>
      <ErrorBox error={notice?.error} />
      {notice?.scanId && (
        <div className="alert" role="status">
          Port scan <Link to="/scans">#{notice.scanId}</Link> queued for {notice.targets?.join(', ')}. Scores and ports update when it finishes.
        </div>
      )}

      {s.devices.length > 1 && <SubdomainDevicesCard devices={s.devices} />}

      <Card title="Addresses" flush>
        {!s.ips.length ? <Empty>Resolves to no address right now.</Empty> : (
          <div className="table-wrap">
            <table className="domain-table fit-table" data-testid="subdomain-addresses">
              <thead><tr><th>IP</th><th className="domain-col-fluid">Hosting</th><th className="domain-col-fluid">Device</th><th>Open ports</th><th>Vulnerabilities</th></tr></thead>
              <tbody>
                {s.ips.map((ip) => {
                  const h = s.hosting.find((x) => x.ip === ip);
                  const dv = devByIp.get(ip);
                  return (
                    <tr key={ip}>
                      <td className="mono">{dv ? <Link to={`/devices/${dv.uuid}`}>{ip}</Link> : ip}</td>
                      <td className="domain-col-fluid small"><span className="cell-ellipsis" title={h ? hostingLabel(h) : undefined}>{h ? hostingLabel(h) : '-'}</span></td>
                      <td className="domain-col-fluid small"><span className="cell-ellipsis" title={dv?.label}>{dv ? <Link to={`/devices/${dv.uuid}`} data-testid="subdomain-device-link">{dv.label}</Link> : <span className="muted">not in inventory</span>}</span></td>
                      <td className="small">{dv ? `${dv.open_ports_count} open` : '-'}</td>
                      <td className="small">{dv && dv.vulnerabilities > 0
                        ? <Link to={`/vulnerabilities?device_uuid=${encodeURIComponent(dv.uuid)}`}>{dv.vulnerabilities}</Link>
                        : <span className="muted">{dv ? '0' : '-'}</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <SubdomainPortsCard s={s} scanAction={scanButton} />

      <div className="grid halves">
        <SubdomainWebCard pages={s.web_pages} captureAction={captureButton}
          onOpen={(p) => (p.device_uuid ? nav(`/devices/${p.device_uuid}/web`) : window.open(p.url, '_blank', 'noopener'))} />
        <SubdomainVulnsCard s={s} />
      </div>

      <div className="grid halves">
        <Card title="Overview">
          <dl className="dl">
            <dt>Exposure</dt><dd>{EXPOSURE_LABELS[s.exposure]} <span className="muted small">- {EXPOSURE_TIPS[s.exposure]}</span></dd>
            <dt>Sources</dt>
            <dd>{s.sources.length ? s.sources.map((src) => <span key={src} className="badge outline" title={SOURCE_TIPS[src]} style={{ marginRight: 4 }}>{SOURCE_LABELS[src]}</span>) : '-'}</dd>
            <dt>First seen</dt><dd title={fmtTime(s.first_seen)}>{fmtTime(s.first_seen)} <span className="muted small">({relTime(s.first_seen)})</span></dd>
            <dt>Last seen</dt><dd title={fmtTime(s.last_seen)}>{fmtTime(s.last_seen)} <span className="muted small">({relTime(s.last_seen)})</span></dd>
            <dt>Last verified</dt><dd>{s.last_verified_at ? fmtTime(s.last_verified_at) : 'never'}{s.unverified && <span className="badge medium" style={{ marginLeft: 6 }}>not verified by the last scan</span>}</dd>
            <dt>Last port scan</dt>
            <dd>{s.last_scan?.port_scan_id ? <Link to="/scans">#{s.last_scan.port_scan_id}</Link> : <span className="muted">-</span>}</dd>
          </dl>
        </Card>
        <Card title="Findings">
          {!findings.length ? <Empty>No findings.</Empty> : (
            <ul className="stack"style={{ gap: 8, margin: 0, padding: 0, listStyle: 'none' }} data-testid="subdomain-findings-list">
              {findings.map((f) => (
                <li key={f.key}><span className={`badge ${f.badge}`}>{f.label}</span> <span className="small muted">{f.tip}</span></li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title="DNS records" flush>
        <div className="table-wrap">
          <table className="domain-table fit-table">
            <thead><tr><th>View</th><th className="domain-col-fluid">Current answer</th></tr></thead>
            <tbody>
              <tr><td>Internal resolvers</td><td className="domain-col-fluid mono small"><span className="cell-ellipsis" title={recordsText(s.records.internal)}>{recordsText(s.records.internal)}</span></td></tr>
              <tr><td>Public resolvers</td><td className="domain-col-fluid mono small"><span className="cell-ellipsis" title={recordsText(s.records.public)}>{recordsText(s.records.public)}</span></td></tr>
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Records history" flush>
        <ErrorBox error={history.error} />
        {!history.data ? <Loading /> : !history.data.items.length ? <Empty>No scan snapshots kept for this name.</Empty> : (
          <>
            <div className="table-wrap">
              <table className="domain-table fit-table" data-testid="subdomain-history">
                <thead><tr><th>Scan</th><th>Since</th><th>Exposure</th><th className="domain-col-fluid">Internal</th><th className="domain-col-fluid">Public</th></tr></thead>
                <tbody>
                  {collapseHistory(history.data.items).map(({ row, unchanged }) => (
                    <tr key={row.scan_id}>
                      <td className="small" title={unchanged ? `Same answer in ${unchanged} later scan${unchanged === 1 ? '' : 's'}` : undefined}>
                        #{row.scan_id}{unchanged > 0 && <span className="muted"> · unchanged for {unchanged} more scan{unchanged === 1 ? '' : 's'}</span>}
                      </td>
                      <td className="small" title={fmtTime(row.at)}>{relTime(row.at)}</td>
                      <td><span className={`badge ${EXPOSURE_BADGE[row.exposure]}`}>{EXPOSURE_LABELS[row.exposure]}</span></td>
                      <td className="domain-col-fluid mono small"><span className="cell-ellipsis" title={recordsText(row.records.internal)}>{recordsText(row.records.internal)}</span></td>
                      <td className="domain-col-fluid mono small"><span className="cell-ellipsis" title={recordsText(row.records.public)}>{recordsText(row.records.public)}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={histPage} pageSize={HISTORY_PAGE} total={history.data.total} onPage={setHistPage} />
          </>
        )}
      </Card>

      <Card title="Change events" flush>
        <ErrorBox error={events.error} />
        {!events.data ? <Loading /> : !events.data.items.length ? <Empty>No change events for this name.</Empty> : (
          <>
            <div className="table-wrap"><EventTable events={events.data.items} /></div>
            <Pager page={evPage} pageSize={EVENTS_PAGE} total={events.data.total} onPage={setEvPage} />
          </>
        )}
      </Card>
      {capture && (
        <WebCaptureDialog
          preset={{ device_uuids: s.devices.map((dv) => dv.uuid), deviceLabel: s.devices.map((dv) => `${dv.label} (${dv.ip})`).join(', '), lockTargets: true }}
          onClose={() => setCapture(false)}
          onStarted={() => nav(`/devices/${s.devices[0].uuid}/web`)}
        />
      )}
    </>
  );
}
