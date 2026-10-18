import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { del, post } from '../api';
import { Card, Empty, ErrorBox, Loading } from '../components/ui';
import { useApp } from '../context';
import type { CveDetail as CveDetailData } from '../types';
import { fmtTime, relTime, useApi } from '../util';
import { dismissBusyKey, formatCvss, formatEpssPct } from '../vulnFormat';

export default function CveDetail() {
  const { cve_id = '' } = useParams();
  const { isAdmin } = useApp();
  const { data, error, reload } = useApi<CveDetailData>(cve_id ? `/vulns/${encodeURIComponent(cve_id)}` : null);
  const [busy, setBusy] = useState<string | null>(null);
  const notFound = !!error && /unknown cve/i.test(error);

  const dismiss = async (deviceUuid: string) => {
    const key = dismissBusyKey(deviceUuid, cve_id);
    if (busy) return;
    setBusy(key);
    try {
      await post(`/devices/${deviceUuid}/vulns/${encodeURIComponent(cve_id)}/dismiss`);
      await reload();
    } finally {
      setBusy(null);
    }
  };

  const undismiss = async (deviceUuid: string) => {
    const key = dismissBusyKey(deviceUuid, cve_id);
    if (busy) return;
    setBusy(key);
    try {
      await del(`/devices/${deviceUuid}/vulns/${encodeURIComponent(cve_id)}/dismiss`);
      await reload();
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <div className="muted small"><Link to="/vulnerabilities">Vulnerabilities</Link> /</div>
          <h1 className="mono">{cve_id}</h1>
          <p>Severity bands use the cached CVSS base score (9 / 7 / 4). Missing CVSS is unscored — not a guessed medium.</p>
        </div>
        <Link className="btn" to="/vulnerabilities">&larr; Back to vulnerabilities</Link>
      </div>

      {notFound ? (
        <Card><Empty>{cve_id} is not in the local vulnerability cache.</Empty></Card>
      ) : (
        <>
          {error && (
            <div className="stack">
              <ErrorBox error={error} />
              <div><button type="button" className="btn sm" onClick={() => reload()}>Retry</button></div>
            </div>
          )}
          {!data ? (!error && <Loading />) : (
            <>
              <Card title="CVE details">
                <dl className="dl">
                  <dt>Summary</dt>
                  <dd>{data.summary || <span className="muted">No description in the local cache.</span>}</dd>
                  <dt>CVSS</dt>
                  <dd className="mono">
                    {formatCvss(data.cvss_base)}
                    {data.cvss_vector && <span className="muted small" style={{ marginLeft: 8 }}>{data.cvss_vector}</span>}
                    {data.cvss_base == null ? (
                      <span className="badge outline" style={{ marginLeft: 8 }}>Unscored</span>
                    ) : data.severity && data.severity !== 'unknown' ? (
                      <span className="badge outline" style={{ marginLeft: 8, textTransform: 'capitalize' }}>{data.severity}</span>
                    ) : null}
                  </dd>
                  <dt>EPSS</dt>
                  <dd>
                    {formatEpssPct(data.epss)}
                    {data.epss_percentile != null && (
                      <span className="muted small" style={{ marginLeft: 8 }}>
                        percentile {(data.epss_percentile * 100).toFixed(0)}%
                      </span>
                    )}
                  </dd>
                  <dt>KEV</dt>
                  <dd>
                    {data.kev
                      ? <>Actively exploited (CISA KEV){data.kev_added_at && <span className="muted"> · added {fmtTime(data.kev_added_at)}</span>}</>
                      : <span className="muted">Not on the KEV list</span>}
                  </dd>
                  <dt>Published</dt>
                  <dd>{data.published_at ? <>{fmtTime(data.published_at)} <span className="muted">({relTime(data.published_at)})</span></> : '—'}</dd>
                  <dt>First seen on this network</dt>
                  <dd>{data.first_seen_at ? <>{fmtTime(data.first_seen_at)} <span className="muted">({relTime(data.first_seen_at)})</span></> : '—'}</dd>
                </dl>
              </Card>

              <Card title="Affected devices" flush>
                {!data.affected_devices.length ? (
                  <Empty>No visible devices currently match this CVE.</Empty>
                ) : (
                  <div className="table-wrap">
                    <table className="compact">
                      <thead>
                        <tr>
                          <th>Device</th>
                          <th>Network</th>
                          <th>Port / service</th>
                          <th>State</th>
                          <th>First seen</th>
                          {isAdmin && <th />}
                        </tr>
                      </thead>
                      <tbody>
                        {data.affected_devices.map((d) => {
                          const busyKey = dismissBusyKey(d.device_uuid, cve_id);
                          return (
                            <tr key={`${d.device_uuid}-${d.protocol}-${d.port}`} className={d.state === 'dismissed' ? 'dim' : ''}>
                              <td>
                                <Link className="mono" to={`/devices/${d.device_uuid}`}>{d.device_ip}</Link>
                                {d.device_hostname && <div className="muted small">{d.device_hostname}</div>}
                              </td>
                              <td>{d.network ?? '—'}</td>
                              <td className="small">
                                {d.protocol.toUpperCase()}/{d.port} {d.product ?? d.service ?? ''} {d.version ?? ''}
                              </td>
                              <td>
                                <span className={`badge ${d.state === 'confirmed' ? 'high' : d.state === 'potential' ? 'medium' : 'outline'}`}>
                                  {d.state}
                                </span>
                              </td>
                              <td className="small muted">{fmtTime(d.first_seen_at ?? d.matched_at)}</td>
                              {isAdmin && (
                                <td className="right">
                                  {d.state === 'dismissed' ? (
                                    <button type="button" className="btn sm ghost" disabled={busy === busyKey}
                                      onClick={() => undismiss(d.device_uuid)}>Undo</button>
                                  ) : (
                                    <button type="button" className="btn sm ghost" disabled={busy === busyKey}
                                      onClick={() => dismiss(d.device_uuid)}>Dismiss</button>
                                  )}
                                </td>
                              )}
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>
            </>
          )}
        </>
      )}
    </>
  );
}
