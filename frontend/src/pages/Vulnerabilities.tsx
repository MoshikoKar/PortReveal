import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { downloadBlob, query } from '../api';
import { VulnFacets } from '../components/VulnFacets';
import { VulnFindingsTable } from '../components/VulnFindingsTable';
import { VulnHeatmap } from '../components/VulnHeatmap';
import { VulnTopLists } from '../components/VulnTopLists';
import { VulnRiskTrend, VulnSeverityTrend, VulnTrend } from '../components/VulnTrend';
import { Card, ErrorBox, Kpi, Loading } from '../components/ui';
import type { VulnSummary } from '../types';
import { fmtTime, relTime, useApi } from '../util';
import {
  buildVulnQuery, clearVulnFilters, parseVulnFilters, scrollToVulnFindings, setVulnFilter,
  toggleHeatmapCell, toggleVulnFilter, toggleVendorProductFilter, type VulnFilterKey,
} from '../vulnFilters';

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--high)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--ok)',
};

const FILTER_LABELS: Record<VulnFilterKey, string> = {
  severity: 'severity', kev: 'KEV', epss_min: 'EPSS ≥', network_id: 'network', service: 'service',
  port: 'port', os_name: 'OS', device_type: 'device type', state: 'state', cve_age: 'CVE age',
  exposure_duration: 'exposure duration', risk_band: 'risk band', vendor: 'vendor', product: 'product',
  cve_id: 'CVE', device_uuid: 'device', new_since: 'new since',
};

export default function Vulnerabilities() {
  const [sp, setSp] = useSearchParams();
  const filters = parseVulnFilters(sp);
  const page = Number(sp.get('page') || 1);
  const { data, error, reload } = useApi<VulnSummary>('/vulns/summary', undefined, 30000);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const applySp = (next: URLSearchParams, scroll = true) => {
    setSp(next);
    if (scroll) scrollToVulnFindings();
  };
  const toggle = (key: VulnFilterKey, value: string) => applySp(toggleVulnFilter(sp, key, value));
  const set = (key: VulnFilterKey, value: string | undefined, scroll = true) =>
    applySp(setVulnFilter(sp, key, value), scroll);
  const toggleVendorProduct = (facetKey: string) => applySp(toggleVendorProductFilter(sp, facetKey));
  const setPage = (p: number) => {
    const next = new URLSearchParams(sp);
    if (p <= 1) next.delete('page');
    else next.set('page', String(p));
    setSp(next);
  };
  const activeFilters = Object.entries(filters) as [VulnFilterKey, string][];

  const exportCsv = async () => {
    setExportError(null);
    setExporting(true);
    try {
      await downloadBlob(
        `/vulns/export${query(buildVulnQuery(filters))}`,
        `portreveal-vulns-${new Date().toISOString().slice(0, 10)}.csv`,
      );
    } catch (e: unknown) {
      setExportError(e instanceof Error ? e.message : 'Export failed.');
    } finally {
      setExporting(false);
    }
  };

  const severity = data?.severity_counts ?? { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const risk = data?.risk_device_levels ?? { high: 0, medium: 0, low: 0 };
  const epssPct = data ? Math.round(data.epss_threshold * 100) : 0;
  const epssValue = data ? String(data.epss_threshold) : '0.1';

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Vulnerabilities</h1>
          <p>
            Matched CVEs across the network. Severity bands come from the cached CVSS base score
            (9 / 7 / 4 thresholds), preferring CVSS v3.1 → v3.0 → v2 when present — not NVD&apos;s
            own severity label. CVEs with no score in the cache are shown as unscored.
          </p>
        </div>
        <div className="row wrap no-print" style={{ gap: 8 }}>
          <button type="button" className="btn" disabled={exporting} onClick={() => { void exportCsv(); }}>
            {exporting ? 'Exporting…' : 'Export CSV'}
          </button>
          <button type="button" className="btn" onClick={() => window.print()}>Print report</button>
        </div>
      </div>
      {exportError && <div className="alert error no-print">{exportError}</div>}
      <ErrorBox error={error} />
      {!data ? (!error && <Loading />) : (
        <>
          {activeFilters.length > 0 && (
            <div className="row wrap" style={{ gap: 8, marginBottom: 12 }}>
              <span className="muted small">Filters:</span>
              {activeFilters.map(([key, value]) => (
                <button key={key} type="button" className="badge outline" style={{ cursor: 'pointer', border: 0 }}
                  onClick={() => set(key, undefined, false)} title="Remove this filter">
                  {FILTER_LABELS[key]}: {value === 'true' && key === 'kev' ? 'yes' : value === 'scan' ? 'last scan' : value === 'db' ? 'last DB update' : value} ✕
                </button>
              ))}
              <button type="button" className="btn sm ghost" onClick={() => { setSp(clearVulnFilters(sp)); }}>Clear all</button>
            </div>
          )}

          <Card className={data.kev_count > 0 ? 'kev-card active' : 'kev-card'}>
            <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
              role="button" tabIndex={0} aria-pressed={filters.kev === 'true'}
              onClick={() => toggle('kev', 'true')}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle('kev', 'true'); } }}>
              <div>
                <div className="label" style={{ fontSize: 13, fontWeight: 600, color: data.kev_count > 0 ? 'var(--high)' : 'var(--muted)' }}>
                  Actively exploited (CISA KEV)
                  {filters.kev === 'true' && <span className="badge high" style={{ marginLeft: 8 }}>filtered</span>}
                </div>
                <div className="muted small">Known to be exploited in the wild — the most urgent findings on this network.</div>
              </div>
              <div style={{ fontSize: 40, fontWeight: 700, color: data.kev_count > 0 ? 'var(--high)' : undefined }}>
                {data.kev_count}
              </div>
            </div>
          </Card>

          <div className="grid kpis">
            <Kpi label="Critical" value={severity.critical} color={SEVERITY_COLOR.critical}
              active={filters.severity === 'critical'} onClick={() => toggle('severity', 'critical')} />
            <Kpi label="High" value={severity.high} color={SEVERITY_COLOR.high}
              active={filters.severity === 'high'} onClick={() => toggle('severity', 'high')} />
            <Kpi label="Medium" value={severity.medium} color={SEVERITY_COLOR.medium}
              active={filters.severity === 'medium'} onClick={() => toggle('severity', 'medium')} />
            <Kpi label="Low" value={severity.low} color={SEVERITY_COLOR.low}
              active={filters.severity === 'low'} onClick={() => toggle('severity', 'low')} />
            {(severity.unknown ?? 0) > 0 && (
              <Kpi label="Unscored" value={severity.unknown} sub="No CVSS in local cache"
                active={filters.severity === 'unknown'} onClick={() => toggle('severity', 'unknown')} />
            )}
            <Kpi label={`High exploit probability (EPSS ≥ ${epssPct}%)`} value={data.epss_high_count}
              sub="FIRST.org exploitation-probability score"
              active={filters.epss_min === epssValue}
              onClick={() => toggle('epss_min', epssValue)} />
            <Kpi label="High-risk devices" value={risk.high} sub={`${risk.medium} medium · ${risk.low} low`}
              color={risk.high ? 'var(--high)' : undefined}
              active={filters.risk_band === 'high'} onClick={() => toggle('risk_band', 'high')} />
            <Kpi label="Confirmed findings" value={data.confirmed_count}
              active={filters.state === 'confirmed'} onClick={() => toggle('state', 'confirmed')} />
            <Kpi label="Potential findings" value={data.potential_count}
              active={filters.state === 'potential'} onClick={() => toggle('state', 'potential')} />
          </div>

          <Card title="Vulnerability feed">
            {data.feed.stale && (
              <div className="badge high" style={{ marginBottom: 10 }}>
                Stale — oldest enabled source hasn&apos;t synced in over {data.feed.stale_threshold_hours}h
              </div>
            )}
            <dl className="dl">
              <dt>Oldest enabled-source sync</dt>
              <dd>
                {data.feed.oldest_synced_at
                  ? <>{fmtTime(data.feed.oldest_synced_at)} <span className="muted">({relTime(data.feed.oldest_synced_at)})</span></>
                  : <span className="muted">never synced</span>}
              </dd>
              <dt>Most recent enabled-source sync</dt>
              <dd>
                {data.feed.newest_synced_at
                  ? <>{fmtTime(data.feed.newest_synced_at)} <span className="muted">({relTime(data.feed.newest_synced_at)})</span></>
                  : <span className="muted">never synced</span>}
              </dd>
            </dl>
          </Card>

          <div className="grid three">
            <Card title="New vs. resolved vs. dismissed (weekly)">
              <VulnTrend points={data.weekly} />
            </Card>
            <Card title="Open vulnerabilities over time (by severity)">
              <VulnSeverityTrend points={data.snapshot_trend} />
            </Card>
            <Card title="Average network risk score over time">
              <VulnRiskTrend points={data.snapshot_trend} />
            </Card>
          </div>

          <Card title="Severity by network" actions={<span className="muted small">Severity is derived from CVSS, not NVD&apos;s label</span>}>
            <VulnHeatmap rows={data.severity_by_network} filters={filters}
              onCellClick={(networkId, sev) => applySp(toggleHeatmapCell(sp, networkId, sev))} />
          </Card>

          <VulnFacets summary={data} filters={filters} onToggle={toggle}
            onToggleVendorProduct={toggleVendorProduct} />
          <VulnTopLists
            summary={data}
            filters={filters}
            onToggleCve={(id) => toggle('cve_id', id)}
            onToggleDevice={(uuid) => toggle('device_uuid', uuid)}
            onToggleNewSince={(v) => toggle('new_since', v)}
          />
          <div id="vuln-findings">
            <VulnFindingsTable
              filters={filters}
              page={page}
              onPage={setPage}
              onToggleDismissed={(show) => set('state', show ? 'dismissed' : undefined, false)}
              onChanged={() => { void reload(); }}
            />
          </div>
        </>
      )}
    </>
  );
}
