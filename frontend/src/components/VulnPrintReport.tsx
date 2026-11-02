import type { VulnFindingListItem, VulnSummary } from '../types';
import { fmtTime } from '../util';
import {
  formatVulnPrintFilterLine, type VulnFilterLabelContext, type VulnFilters,
} from '../vulnFilters';
import { formatCvss, formatEpssPct } from '../vulnFormat';
import { STATE_HELP } from './VulnFindingsTable';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
const SEV_LABEL: Record<(typeof SEV_ORDER)[number], string> = {
  critical: 'critical', high: 'high', medium: 'medium', low: 'low', unknown: 'unscored',
};

function plural(n: number, one: string, many = `${one}s`) {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

/** "12 findings on 4 devices: 2 critical, 5 high, 5 medium. 1 is on the CISA KEV list." */
function summarySentence(total: number, devices: number, kev: number, sev: Record<string, number> | undefined) {
  const bands = sev
    ? SEV_ORDER.filter((k) => (sev[k] ?? 0) > 0).map((k) => `${sev[k]} ${SEV_LABEL[k]}`)
    : [];
  const head = `${plural(total, 'finding')} on ${plural(devices, 'device')}${bands.length ? `: ${bands.join(', ')}` : ''}.`;
  const kevLine = kev > 0
    ? ` ${plural(kev, 'finding')} ${kev === 1 ? 'is' : 'are'} on the CISA KEV list of actively exploited vulnerabilities.`
    : ' None is on the CISA KEV list of actively exploited vulnerabilities.';
  return head + kevLine;
}

/** Print-only vulnerability findings report: filter summary, executive counts, full findings table. */
export function VulnPrintReport({
  filters, labelCtx, summary, findings, loading, error, preview = false, searchQ, onlyHidden = false,
}: {
  filters: VulnFilters;
  labelCtx: VulnFilterLabelContext;
  summary: VulnSummary | null;
  findings: VulnFindingListItem[];
  loading: boolean;
  error: string | null;
  /** When true, show the report on-screen (before opening the system print dialog). */
  preview?: boolean;
  /** Active free-text search term (not part of VulnFilters). */
  searchQ?: string;
  /** When searching, restrict to normally-hidden findings (`only_hidden=1`). */
  onlyHidden?: boolean;
}) {
  const generatedAt = new Date();
  const filterSummary = formatVulnPrintFilterLine(filters, labelCtx, { searchQ, onlyHidden });
  const kevCount = summary?.kev_count ?? findings.filter((f) => f.kev).length;
  const deviceCount = summary?.device_count ?? new Set(findings.map((f) => f.device_uuid)).size;
  const sev = summary?.severity_counts;
  const topCves = summary?.top_cves?.slice(0, 5) ?? [];
  const topDevices = summary?.top_devices?.slice(0, 5) ?? [];
  const findingsTotal = summary?.findings_total ?? findings.length;
  const feed = summary?.feed;
  // On screen the preview sits under the page's own h1, so its headings step down one level.
  const H1 = preview ? 'h2' : 'h1';
  const H2 = preview ? 'h3' : 'h2';
  const H3 = preview ? 'h4' : 'h3';

  return (
    <div className={`vuln-print-report${preview ? ' is-preview' : ''}`}>
      <header className="vuln-print-header">
        <H1 className="vuln-print-title-head" tabIndex={-1}>PortReveal vulnerability report</H1>
        <p className="vuln-print-meta">
          Generated {fmtTime(generatedAt.toISOString(), true)}
          <span className="vuln-print-tz"> ({Intl.DateTimeFormat().resolvedOptions().timeZone})</span>
        </p>
        <p className="vuln-print-filters"><strong>Filters:</strong> {filterSummary}</p>
        <p className="vuln-print-method">
          <strong>Method:</strong> the product and version each service reports (CPE) are compared with a
          local copy of NVD, CISA KEV and EPSS. No exploit or intrusive check is run, so verify a finding
          before acting on it. Severity is the CVSS base-score band (critical 9+, high 7+, medium 4+).
          {' '}<strong>Confirmed</strong>: {STATE_HELP.confirmed}
          {' '}<strong>Potential</strong>: {STATE_HELP.potential}
        </p>
        {feed && (
          <p className="vuln-print-method">
            <strong>Vulnerability data:</strong> last synced{' '}
            {feed.newest_synced_at ? fmtTime(feed.newest_synced_at, true) : 'never'}; oldest enabled source{' '}
            {feed.oldest_synced_at ? fmtTime(feed.oldest_synced_at, true) : 'never'}.
            {feed.stale && <strong> The data is stale, so recent CVEs may be missing.</strong>}
          </p>
        )}
      </header>

      {error && <p className="vuln-print-empty">Could not load findings for this report: {error}</p>}
      {loading && !error && <p className="vuln-print-empty">Loading findings…</p>}

      {!loading && !error && (
        <>
          <section className="vuln-print-exec">
            <H2 className="vuln-print-section-head">Executive summary</H2>
            {!findings.length && !summary ? (
              <p className="vuln-print-empty">No vulnerability findings match the current filters.</p>
            ) : (
              <>
                <p className="vuln-print-sentence">
                  {summarySentence(findings.length || findingsTotal, deviceCount, kevCount, sev)}
                </p>
                {(topCves.length > 0 || topDevices.length > 0) && (
                  <div className="vuln-print-tops">
                    {topCves.length > 0 && (
                      <div>
                        <H3 className="vuln-print-sub-head">Top CVEs</H3>
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
                        <H3 className="vuln-print-sub-head">Top devices</H3>
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
            <H2 className="vuln-print-section-head">Findings</H2>
            {!findings.length ? (
              <p className="vuln-print-empty">No vulnerability findings match the current filters.</p>
            ) : (
              <table className="vuln-print-table">
                <thead>
                  <tr>
                    <th>KEV</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>EPSS</th>
                    <th>CVE</th>
                    <th>Title</th>
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
                      <td>{f.kev ? <span className="badge kev">KEV</span> : ''}</td>
                      <td>
                        <span className={`badge sev-${f.severity && f.severity !== 'unknown' ? f.severity : 'unscored'}`}>
                          {f.severity && f.severity !== 'unknown' ? f.severity : 'unscored'}
                        </span>
                      </td>
                      <td className="mono">{formatCvss(f.cvss_base)}</td>
                      <td className="mono small">{formatEpssPct(f.epss)}</td>
                      <td className="mono nowrap">{f.cve_id}</td>
                      <td className="small vuln-print-title vuln-print-clip">
                        {(f.summary || '').replace(/\s+/g, ' ').trim() || '—'}
                      </td>
                      <td>
                        <div className="vuln-print-host">
                          <span className="mono">{f.device_ip}</span>
                          {f.device_hostname && (
                            <span className="vuln-print-hostname vuln-print-clip">
                              {' '}· {f.device_hostname}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>{f.network ?? 'Unassigned'}</td>
                      <td className="small vuln-print-clip">
                        {f.protocol.toUpperCase()}/{f.port}
                        {' '}
                        {[f.product, f.version].filter(Boolean).join(' ') || f.service || ''}
                      </td>
                      <td className="vuln-print-state">
                        <div className="vuln-print-state-main">{f.state}</div>
                        {f.state === 'dismissed' && f.dismiss_reason && (
                          <div className="vuln-print-dismiss-reason">{f.dismiss_reason}</div>
                        )}
                        {(f.hidden_reasons ?? []).map((reason) => (
                          <div key={reason} className="badge outline vuln-print-hidden-reason">
                            {reason}
                          </div>
                        ))}
                      </td>
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
