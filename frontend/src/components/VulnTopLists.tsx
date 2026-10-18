import { Link } from 'react-router-dom';
import type { VulnNewFinding, VulnSummary } from '../types';
import { fmtTime } from '../util';
import { formatCvss } from '../vulnFormat';
import type { VulnFilters } from '../vulnFilters';
import { Card, Empty, RiskBadge, ScoreBadge, useClientSort } from './ui';

function NewList({ title, items, empty, active, onFilter }: {
  title: string;
  items: VulnNewFinding[];
  empty: string;
  active: boolean;
  onFilter: () => void;
}) {
  const { rows, th } = useClientSort(items, {
    cve: (r) => r.cve_id, device: (r) => r.device_ip, cvss: (r) => r.cvss_base, first_seen: (r) => r.first_seen_at,
  }, ['cvss', 'first_seen']);
  return (
    <Card
      title={title}
      flush
      actions={
        <button type="button" className={`btn sm ${active ? '' : 'ghost'}`} onClick={onFilter}
          title={active ? 'Clear this filter' : 'Filter findings to this list'}>
          {active ? 'Filtered ✕' : 'Filter table'}
        </button>
      }
    >
      {!items.length ? <Empty>{empty}</Empty> : (
        <div className="table-wrap">
          <table className="compact">
            <thead><tr>{th('cve', 'CVE')}{th('device', 'Device')}{th('cvss', 'CVSS', 'right')}{th('first_seen', 'First seen')}</tr></thead>
            <tbody>
              {rows.map((row) => (
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

function TopCves({ items, filters, onToggleCve }: {
  items: VulnSummary['top_cves']; filters: VulnFilters; onToggleCve: (cveId: string) => void;
}) {
  const { rows, th } = useClientSort(items, {
    cve: (c) => c.cve_id, cvss: (c) => c.cvss_base, kev: (c) => c.kev, devices: (c) => c.device_count,
  }, ['cvss', 'kev', 'devices']);
  return (
    <Card title="Top 10 CVEs (most devices)" flush>
      {!items.length ? <Empty>No vulnerability matched yet.</Empty> : (
        <div className="table-wrap">
          <table className="compact">
            <thead><tr>{th('cve', 'CVE')}{th('cvss', 'CVSS', 'right')}{th('kev', 'KEV')}{th('devices', 'Devices', 'right')}</tr></thead>
            <tbody>
              {rows.map((c) => {
                const active = filters.cve_id === c.cve_id;
                return (
                  <tr key={c.cve_id} className={active ? 'row-active' : undefined}
                    style={{ cursor: 'pointer' }}
                    onClick={() => onToggleCve(c.cve_id)}
                    title={active ? 'Clear CVE filter' : 'Filter findings to this CVE'}>
                    <td className="mono">
                      <Link to={`/vulnerabilities/${encodeURIComponent(c.cve_id)}`}
                        onClick={(e) => e.stopPropagation()}>{c.cve_id}</Link>
                    </td>
                    <td className="right mono">{formatCvss(c.cvss_base)}</td>
                    <td>{c.kev && <span className="badge high">KEV</span>}</td>
                    <td className="right">{c.device_count}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function TopDevices({ items, filters, onToggleDevice }: {
  items: VulnSummary['top_devices']; filters: VulnFilters; onToggleDevice: (uuid: string) => void;
}) {
  const { rows, th } = useClientSort(items, {
    host: (d) => d.ip, network: (d) => d.network_name, risk: (d) => d.risk_score,
    exposure: (d) => d.exposure_score, combined: (d) => d.combined_score,
  }, ['risk', 'exposure', 'combined']);
  return (
    <Card title="Top 10 highest-risk devices" flush>
      {!items.length ? <Empty>No device has a non-zero risk score yet.</Empty> : (
        <div className="table-wrap">
          <table className="compact">
            <thead>
              <tr>
                {th('host', 'Host')}
                {th('network', 'Network')}
                {th('risk', 'Risk', 'right')}
                {th('exposure', 'Exposure', 'right')}
                {th('combined', 'Combined', 'right')}
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => {
                const active = filters.device_uuid === d.uuid;
                return (
                  <tr key={d.uuid} className={active ? 'row-active' : undefined}
                    style={{ cursor: 'pointer' }}
                    onClick={() => onToggleDevice(d.uuid)}
                    title={active ? 'Clear device filter' : 'Filter findings to this device'}>
                    <td>
                      <Link className="mono" to={`/devices/${d.uuid}`}
                        onClick={(e) => e.stopPropagation()}>{d.ip}</Link>
                      {d.hostname && <div className="muted small">{d.hostname}</div>}
                    </td>
                    <td>{d.network_name ?? '—'}</td>
                    <td className="right"><RiskBadge score={d.risk_score} kind="risk" /></td>
                    <td className="right"><ScoreBadge score={d.exposure_score} /></td>
                    <td className="right"><RiskBadge score={d.combined_score} kind="combined" /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

/** Top lists sort client-side (10 rows each); clicking a row still filters the findings table. */
export function VulnTopLists({ summary, filters, onToggleCve, onToggleDevice, onToggleNewSince }: {
  summary: VulnSummary;
  filters: VulnFilters;
  onToggleCve: (cveId: string) => void;
  onToggleDevice: (uuid: string) => void;
  onToggleNewSince: (value: 'scan' | 'db') => void;
}) {
  return (
    <>
      <div className="grid halves">
        <TopCves items={summary.top_cves} filters={filters} onToggleCve={onToggleCve} />
        <TopDevices items={summary.top_devices} filters={filters} onToggleDevice={onToggleDevice} />
      </div>
      <div className="grid halves">
        <NewList title="New since last scan" items={summary.new_since_last_scan}
          empty="No new findings since the last completed scan."
          active={filters.new_since === 'scan'}
          onFilter={() => onToggleNewSince('scan')} />
        <NewList title="New since last DB update" items={summary.new_since_last_db_update}
          empty="No new findings since the newest enabled feed sync."
          active={filters.new_since === 'db'}
          onFilter={() => onToggleNewSince('db')} />
      </div>
    </>
  );
}
