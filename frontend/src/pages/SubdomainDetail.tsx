import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { EventTable } from '../components/EventTable';
import { Card, Empty, ErrorBox, Loading, Pager } from '../components/ui';
import {
  EXPOSURE_BADGE, EXPOSURE_LABELS, EXPOSURE_TIPS, ROW_STATUS, SOURCE_LABELS, SOURCE_TIPS, hostingLabel, subdomainFindings,
  subdomainStatus, subdomainStatusTip,
} from '../domains';
import type { ChangeEvent, DnsView, Paged, SubdomainDetail as Detail, SubdomainHistoryRow } from '../types';
import { fmtTime, relTime, useApi } from '../util';

const HISTORY_PAGE = 20;
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

/** One subdomain: records (current + per scan), addresses with hosting / device / open ports, findings and
 *  change events. History and events load only here (the inventory list never fetches them). */
export default function SubdomainDetail() {
  const { domainId, id } = useParams();
  const [histPage, setHistPage] = useState(1);
  const [evPage, setEvPage] = useState(1);
  const base = `/domains/${domainId}/subdomains/${id}`;
  const { data: s, error } = useApi<Detail>(base);
  const history = useApi<Paged<SubdomainHistoryRow>>(`${base}/history`, { page: histPage, page_size: HISTORY_PAGE });
  const events = useApi<Paged<ChangeEvent>>(`${base}/events`, { page: evPage, page_size: EVENTS_PAGE });

  if (error && !s) return <Card title="Subdomain"><ErrorBox error={error} /></Card>;
  if (!s) return <Loading />;
  const st = ROW_STATUS[subdomainStatus(s)];
  const findings = subdomainFindings(s);
  const devByIp = new Map(s.devices.map((dv) => [dv.ip, dv]));

  return (
    <>
      <div className="page-head">
        <div>
          <div className="small muted"><Link to="/domains">Domains</Link> / <Link to={`/domains/${s.domain_id}`}>{s.domain_name}</Link></div>
          <h1 className="mono">{s.name}</h1>
          <p className="row wrap" style={{ gap: 6 }}>
            <span className={`badge ${EXPOSURE_BADGE[s.exposure]}`} title={EXPOSURE_TIPS[s.exposure]}>{EXPOSURE_LABELS[s.exposure]}</span>
            <span className={`badge ${st.badge}`} title={subdomainStatusTip(s, fmtTime)}>{st.label}</span>
            {findings.map((f) => <span key={f.key} className={`badge ${f.badge}`} title={f.tip}>{f.label}</span>)}
          </p>
        </div>
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

      <Card title="Addresses" flush>
        {!s.ips.length ? <Empty>Resolves to no address right now.</Empty> : (
          <div className="table-wrap">
            <table className="domain-table" data-testid="subdomain-addresses">
              <thead><tr><th>IP</th><th className="domain-col-fluid">Hosting</th><th>Device</th><th className="domain-col-fluid">Open ports</th><th>Vulnerabilities</th></tr></thead>
              <tbody>
                {s.ips.map((ip) => {
                  const h = s.hosting.find((x) => x.ip === ip);
                  const dv = devByIp.get(ip);
                  const ports = dv?.open_ports.map((p) => `${p.protocol}/${p.port}${p.service ? ` ${p.service}` : ''}`).join(', ');
                  return (
                    <tr key={ip}>
                      <td className="mono">{dv ? <Link to={`/devices/${dv.uuid}`}>{ip}</Link> : ip}</td>
                      <td className="domain-col-fluid small"><span className="cell-ellipsis" title={h ? hostingLabel(h) : undefined}>{h ? hostingLabel(h) : '-'}</span></td>
                      <td className="small">{dv ? <Link to={`/devices/${dv.uuid}`} data-testid="subdomain-device-link">{dv.label}</Link> : <span className="muted">not in inventory</span>}</td>
                      <td className="domain-col-fluid small"><span className="cell-ellipsis" title={ports || undefined}>{dv ? (ports || 'none open') : '-'}</span></td>
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

      <Card title="DNS records" flush>
        <div className="table-wrap">
          <table className="domain-table">
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
              <table className="domain-table">
                <thead><tr><th>Scan</th><th>When</th><th>Exposure</th><th className="domain-col-fluid">Internal</th><th className="domain-col-fluid">Public</th></tr></thead>
                <tbody>
                  {history.data.items.map((row) => (
                    <tr key={row.scan_id}>
                      <td>#{row.scan_id}</td>
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

      {s.web_pages.length > 0 && (
        <Card title="Web capture" flush>
          <div className="table-wrap">
            <table className="domain-table">
              <thead><tr><th className="domain-col-fluid">URL</th><th className="domain-col-fluid">Title</th><th>Status</th><th>Captured</th></tr></thead>
              <tbody>
                {s.web_pages.map((p) => (
                  <tr key={`${p.url}-${p.captured_at}`}>
                    <td className="domain-col-fluid mono small">
                      <span className="cell-ellipsis" title={p.url}>{p.device_uuid ? <Link to={`/devices/${p.device_uuid}/web`}>{p.url}</Link> : p.url}</span>
                    </td>
                    <td className="domain-col-fluid small"><span className="cell-ellipsis" title={p.title ?? undefined}>{p.title ?? '-'}</span></td>
                    <td className="small">{p.http_status ?? '-'}</td>
                    <td className="small" title={fmtTime(p.captured_at)}>{relTime(p.captured_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </>
  );
}
