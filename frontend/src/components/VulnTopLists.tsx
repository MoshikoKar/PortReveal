import { Link } from 'react-router-dom';
import type { VulnNewFinding, VulnSummary } from '../types';
import { fmtTime } from '../util';
import { formatCvss, severityBand } from '../vulnFormat';
import type { VulnFilters } from '../vulnFilters';
import { Card, Empty, RiskBadge, ScoreBadge, useClientSort } from './ui';

/** CVSS number tinted by its severity band; the band name is spoken and shown on hover. */
export function CvssScore({ cvss }: { cvss: number | null }) {
  const sev = severityBand(cvss);
  return (
    <span className={`mono sev-text sev-${sev}`}
      title={sev === 'unscored' ? 'No CVSS score in the local cache' : `${sev} severity`}>
      {formatCvss(cvss)}<span className="sr-only"> ({sev})</span>
    </span>
  );
}

function FilterToggle({ active, label, onClick }: { active: boolean; label: string; onClick: () => void }) {
  return (
    <button type="button" className={`btn sm ${active ? 'toggle on' : 'ghost'}`} aria-pressed={active}
      aria-label={active ? `Clear filter for ${label}` : `Filter findings to ${label}`} onClick={onClick}>
      {active ? 'Filtered ✕' : 'Filter'}
    </button>
  );
}

function NewList({ title, items, total, empty, active, onFilter }: {
  title: string;
  items: VulnNewFinding[];
  /** Full count; `items` holds at most 10. */
  total: number;
  empty: string;
  active: boolean;
  onFilter: () => void;
}) {
  const { rows, th } = useClientSort(items, {
    cve: (r) => r.cve_id, device: (r) => r.device_ip, cvss: (r) => r.cvss_base, first_seen: (r) => r.first_seen_at,
  }, ['cvss', 'first_seen']);
  return (
    <Card
      title={<h2>{title} <span className="muted vuln-count">{total}</span></h2>}
      flush
      actions={(total > 0 || active) && (
        <button type="button" className={`btn sm ${active ? 'toggle on' : 'ghost'}`} onClick={onFilter}
          aria-pressed={active}>
          {active ? 'Showing in findings ✕' : `Show all ${total} in findings`}
        </button>
      )}
    >
      {!items.length ? <Empty>{empty}</Empty> : (
        <div className="table-wrap">
          <table className="compact" aria-label={title}>
            <thead><tr>{th('cve', 'CVE')}{th('device', 'Device')}{th('cvss', 'CVSS', 'right')}{th('first_seen', 'First seen')}</tr></thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.cve_id}-${row.device_uuid}`}>
                  <td className="mono nowrap">
                    <Link to={`/vulnerabilities/${encodeURIComponent(row.cve_id)}`}>{row.cve_id}</Link>
                    {row.kev && <span className="badge kev" style={{ marginLeft: 6 }}>KEV</span>}
                  </td>
                  <td><Link className="mono" to={`/devices/${row.device_uuid}`}>{row.device_ip}</Link></td>
                  <td className="right"><CvssScore cvss={row.cvss_base} /></td>
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
          <table className="compact" aria-label="Top 10 CVEs by affected devices">
            <thead>
              <tr>
                {th('cve', 'CVE')}{th('cvss', 'CVSS', 'right')}{th('kev', 'KEV')}{th('devices', 'Devices', 'right')}
                <th><span className="sr-only">Filter</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => {
                const active = filters.cve_id === c.cve_id;
                return (
                  <tr key={c.cve_id} className={active ? 'row-active' : undefined}>
                    <td className="mono">
                      <Link to={`/vulnerabilities/${encodeURIComponent(c.cve_id)}`}>{c.cve_id}</Link>
                    </td>
                    <td className="right"><CvssScore cvss={c.cvss_base} /></td>
                    <td>{c.kev && <span className="badge kev">KEV</span>}</td>
                    <td className="right">{c.device_count}</td>
                    <td className="right">
                      <FilterToggle active={active} label={c.cve_id} onClick={() => onToggleCve(c.cve_id)} />
                    </td>
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

function TopDevices({ items, filters, onToggleDevice, onToggleNetwork }: {
  items: VulnSummary['top_devices'];
  filters: VulnFilters;
  onToggleDevice: (uuid: string) => void;
  onToggleNetwork: (networkId: number | null) => void;
}) {
  const { rows, th } = useClientSort(items, {
    host: (d) => d.ip, network: (d) => d.network_name, risk: (d) => d.risk_score,
    exposure: (d) => d.exposure_score, combined: (d) => d.combined_score,
  }, ['risk', 'exposure', 'combined']);
  return (
    <Card title="Top 10 highest-risk devices" flush>
      {!items.length ? <Empty>No device has a non-zero risk score yet.</Empty> : (
        <div className="table-wrap">
          <table className="compact domain-table fit-table" aria-label="Top 10 highest-risk devices">
            <thead>
              <tr>
                {th('host', 'Host')}
                {th('network', 'Network')}
                {th('risk', 'Risk', 'right')}
                {th('exposure', 'Exposure', 'right')}
                {th('combined', 'Combined', 'right')}
                <th><span className="sr-only">Filter</span></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => {
                const active = filters.device_uuid === d.uuid;
                const netKey = d.network_id != null ? String(d.network_id) : 'unassigned';
                const netActive = filters.network_id === netKey;
                const netLabel = d.network_name ?? 'Unassigned';
                const hostTip = [d.ip, d.hostname].filter(Boolean).join('\n');
                return (
                  <tr key={d.uuid} className={active ? 'row-active' : undefined}>
                    <td className="domain-col-fluid vuln-host-col" title={hostTip}>
                      <span className="cell-ellipsis">
                        <Link className="mono" to={`/devices/${d.uuid}`}>{d.ip}</Link>
                        {d.hostname && <span className="muted small"> · {d.hostname}</span>}
                      </span>
                    </td>
                    <td className="domain-col-fluid">
                      <button
                        type="button"
                        className={`heatmap-network-btn cell-ellipsis ${netActive ? 'active' : ''}`}
                        aria-pressed={netActive}
                        title={netActive ? 'Clear network filter' : `Filter by network: ${netLabel}`}
                        onClick={() => onToggleNetwork(d.network_id)}
                      >
                        {netLabel}
                      </button>
                    </td>
                    <td className="right"><RiskBadge score={d.risk_score} kind="risk" /></td>
                    <td className="right"><ScoreBadge score={d.exposure_score} /></td>
                    <td className="right"><RiskBadge score={d.combined_score} kind="combined" /></td>
                    <td className="right">
                      <FilterToggle active={active} label={d.ip} onClick={() => onToggleDevice(d.uuid)} />
                    </td>
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

/** Top lists sort client-side (10 rows each); the trailing Filter button narrows the findings table. */
export function VulnTopLists({ summary, filters, onToggleCve, onToggleDevice, onToggleNetwork }: {
  summary: VulnSummary;
  filters: VulnFilters;
  onToggleCve: (cveId: string) => void;
  onToggleDevice: (uuid: string) => void;
  onToggleNetwork: (networkId: number | null) => void;
}) {
  return (
    <div className="grid halves">
      <TopCves items={summary.top_cves} filters={filters} onToggleCve={onToggleCve} />
      <TopDevices items={summary.top_devices} filters={filters} onToggleDevice={onToggleDevice}
        onToggleNetwork={onToggleNetwork} />
    </div>
  );
}

/** What changed: findings first seen since the last scan, and since the last feed update. */
export function VulnNewLists({ summary, filters, onToggleNewSince }: {
  summary: VulnSummary;
  filters: VulnFilters;
  onToggleNewSince: (value: 'scan' | 'db') => void;
}) {
  // Nothing new: the headline and the "New since last scan" tile already say so; skip two empty cards.
  if (!summary.new_since_last_scan_count && !summary.new_since_last_db_update_count && !filters.new_since) return null;
  return (
    <div className="grid halves">
      <NewList title="New since last scan" items={summary.new_since_last_scan}
        total={summary.new_since_last_scan_count}
        empty="No new findings since the last completed scan."
        active={filters.new_since === 'scan'}
        onFilter={() => onToggleNewSince('scan')} />
      <NewList title="New since last vulnerability-data update" items={summary.new_since_last_db_update}
        total={summary.new_since_last_db_update_count}
        empty="No new findings since the newest feed sync."
        active={filters.new_since === 'db'}
        onFilter={() => onToggleNewSince('db')} />
    </div>
  );
}
