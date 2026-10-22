import type { VulnFindingListItem, VulnSummary } from '../types';
import { fmtTime } from '../util';
import {
  formatVulnFilterSummary, type VulnFilterLabelContext, type VulnFilters,
} from '../vulnFilters';
import { formatCvss } from '../vulnFormat';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'unknown'] as const;

function severityClass(sev: string | null | undefined): string {
  if (sev === 'critical' || sev === 'high') return 'high';
  if (sev === 'medium') return 'medium';
  if (sev === 'low') return 'ok';
  return 'outline';
}

/** Print-only vulnerability findings report: filter summary, executive counts, full findings table. */
export function VulnPrintReport({
  filters, labelCtx, summary, findings, loading, error,
}: {
  filters: VulnFilters;
  labelCtx: VulnFilterLabelContext;
  summary: VulnSummary | null;
  findings: VulnFindingListItem[];
  loading: boolean;
  error: string | null;
}) {
  const generatedAt = new Date();
  const filterSummary = formatVulnFilterSummary(filters, labelCtx);
  const kevCount = summary?.kev_count ?? findings.filter((f) => f.kev).length;
  const deviceCount = new Set(findings.map((f) => f.device_uuid)).size;
  const sev = summary?.severity_counts;
  const topCves = summary?.top_cves?.slice(0, 5) ?? [];
  const topDevices = summary?.top_devices?.slice(0, 5) ?? [];

  return (
    <div className="vuln-print-report">
      <header className="vuln-print-header">
        <h1>PortReveal vulnerability report</h1>
        <p className="vuln-print-meta">
          Generated {fmtTime(generatedAt.toISOString(), true)}
          <span className="vuln-print-tz"> ({Intl.DateTimeFormat().resolvedOptions().timeZone})</span>
        </p>
        <p className="vuln-print-filters"><strong>Filters:</strong> {filterSummary}</p>
      </header>

      {error && <p className="vuln-print-empty">Could not load findings for this report: {error}</p>}
      {loading && !error && <p className="vuln-print-empty">Loading findings…</p>}

      {!loading && !error && (
        <>
          <section className="vuln-print-exec">
            <h2>Executive summary</h2>
            {!findings.length && !summary ? (
              <p className="vuln-print-empty">No vulnerability findings match the current filters.</p>
            ) : (
              <>
                <ul className="vuln-print-kpis">
                  <li>Findings: <strong>{findings.length || (sev
                    ? SEV_ORDER.reduce((n, k) => n + (sev[k] ?? 0), 0) : 0)}</strong></li>
                  <li>KEV (actively exploited): <strong>{kevCount}</strong></li>
                  <li>Affected devices: <strong>{deviceCount || (summary?.top_devices.length ?? 0)}</strong></li>
                  {sev && SEV_ORDER.map((k) => (sev[k] ?? 0) > 0 && (
                    <li key={k}><span className="vuln-print-sev-label">{k}</span>: <strong>{sev[k]}</strong></li>
                  ))}
                </ul>
                {(topCves.length > 0 || topDevices.length > 0) && (
                  <div className="vuln-print-tops">
                    {topCves.length > 0 && (
                      <div>
                        <h3>Top CVEs</h3>
                        <ol>
                          {topCves.map((c) => (
                            <li key={c.cve_id}>
                              <span className="mono">{c.cve_id}</span>
                              {c.kev ? ' · KEV' : ''}
                              {c.cvss_base != null ? ` · CVSS ${c.cvss_base.toFixed(1)}` : ''}
                              {` · ${c.device_count} device${c.device_count === 1 ? '' : 's'}`}
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}
                    {topDevices.length > 0 && (
                      <div>
                        <h3>Top devices</h3>
                        <ol>
                          {topDevices.map((d) => (
                            <li key={d.uuid}>
                              <span className="mono">{d.ip}</span>
                              {d.hostname ? ` (${d.hostname})` : ''}
                              {d.network_name ? ` · ${d.network_name}` : ''}
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </section>

          <section className="vuln-print-findings">
            <h2>Findings</h2>
            {!findings.length ? (
              <p className="vuln-print-empty">No vulnerability findings match the current filters.</p>
            ) : (
              <table className="vuln-print-table">
                <thead>
                  <tr>
                    <th>KEV</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>CVE</th>
                    <th>Device</th>
                    <th>Network</th>
                    <th>Port / service</th>
                    <th>State</th>
                    <th>First seen</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => (
                    <tr key={`${f.device_uuid}-${f.protocol}-${f.port}-${f.cve_id}`}>
                      <td>{f.kev ? <span className="badge high">KEV</span> : ''}</td>
                      <td>
                        <span className={`badge ${severityClass(f.severity)}`}>
                          {f.severity ?? 'unknown'}
                        </span>
                      </td>
                      <td className="mono">{formatCvss(f.cvss_base)}</td>
                      <td className="mono">{f.cve_id}</td>
                      <td>
                        <span className="mono">{f.device_ip}</span>
                        {f.device_hostname && <div className="small muted">{f.device_hostname}</div>}
                      </td>
                      <td>{f.network ?? '—'}</td>
                      <td className="small">
                        {f.protocol.toUpperCase()}/{f.port}
                        {' '}
                        {[f.product, f.version].filter(Boolean).join(' ') || f.service || ''}
                      </td>
                      <td>{f.state}</td>
                      <td className="small nowrap">{fmtTime(f.first_seen_at ?? f.matched_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      )}

      <footer className="vuln-print-footer">
        <span className="vuln-print-page" />
      </footer>
    </div>
  );
}
