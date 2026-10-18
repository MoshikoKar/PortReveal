import { Link } from 'react-router-dom';
import type { VulnNewFinding, VulnSummary } from '../types';
import { fmtTime } from '../util';
import { formatCvss } from '../vulnFormat';
import { Card, Empty, RiskBadge, ScoreBadge } from './ui';

function NewList({ title, items, empty }: { title: string; items: VulnNewFinding[]; empty: string }) {
  return (
    <Card title={title} flush>
      {!items.length ? <Empty>{empty}</Empty> : (
        <div className="table-wrap">
          <table className="compact">
            <thead><tr><th>CVE</th><th>Device</th><th className="right">CVSS</th><th>First seen</th></tr></thead>
            <tbody>
              {items.map((row) => (
                <tr key={`${row.cve_id}-${row.device_uuid}`}>
                  <td className="mono nowrap">
                    <Link to={`/vulnerabilities/${encodeURIComponent(row.cve_id)}`}>{row.cve_id}</Link>
                    {row.kev && <span className="badge high" style={{ marginLeft: 6 }}>KEV</span>}
                  </td>
                  <td><Link className="mono" to={`/devices/${row.device_uuid}`}>{row.device_ip}</Link></td>
                  <td className="right mono">{formatCvss(row.cvss_base)}</td>
                  <td className="small muted">{fmtTime(row.first_seen_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export function VulnTopLists({ summary }: { summary: VulnSummary }) {
  return (
    <>
      <div className="grid halves">
        <Card title="Top 10 CVEs (most devices)" flush>
          {!summary.top_cves.length ? <Empty>No vulnerability matched yet.</Empty> : (
            <div className="table-wrap">
              <table className="compact">
                <thead><tr><th>CVE</th><th className="right">CVSS</th><th>KEV</th><th className="right">Devices</th></tr></thead>
                <tbody>
                  {summary.top_cves.map((c) => (
                    <tr key={c.cve_id}>
                      <td className="mono"><Link to={`/vulnerabilities/${encodeURIComponent(c.cve_id)}`}>{c.cve_id}</Link></td>
                      <td className="right mono">{formatCvss(c.cvss_base)}</td>
                      <td>{c.kev && <span className="badge high">KEV</span>}</td>
                      <td className="right">{c.device_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Top 10 highest-risk devices" flush>
          {!summary.top_devices.length ? <Empty>No device has a non-zero risk score yet.</Empty> : (
            <div className="table-wrap">
              <table className="compact">
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>Network</th>
                    <th className="right">Risk</th>
                    <th className="right">Exposure</th>
                    <th className="right">Combined</th>
                  </tr>
                </thead>
                <tbody>
                  {summary.top_devices.map((d) => (
                    <tr key={d.uuid}>
                      <td>
                        <Link className="mono" to={`/devices/${d.uuid}`}>{d.ip}</Link>
                        {d.hostname && <div className="muted small">{d.hostname}</div>}
                      </td>
                      <td>{d.network_name ?? '—'}</td>
                      <td className="right"><RiskBadge score={d.risk_score} kind="risk" /></td>
                      <td className="right"><ScoreBadge score={d.exposure_score} /></td>
                      <td className="right"><RiskBadge score={d.combined_score} kind="combined" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
      <div className="grid halves">
        <NewList title="New since last scan" items={summary.new_since_last_scan}
          empty="No new findings since the last completed scan." />
        <NewList title="New since last DB update" items={summary.new_since_last_db_update}
          empty="No new findings since the newest enabled feed sync." />
      </div>
    </>
  );
}
