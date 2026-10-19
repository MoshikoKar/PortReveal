import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { downloadBlob, query } from '../api';
import { VulnFacets } from '../components/VulnFacets';
import { FINDING_DESC_FIRST, FINDING_SORTS, VulnFindingsTable, type FindingSort } from '../components/VulnFindingsTable';
import { VulnHeatmap } from '../components/VulnHeatmap';
import { VulnTopLists } from '../components/VulnTopLists';
import { VulnRiskTrend, VulnSeverityTrend, VulnTrend } from '../components/VulnTrend';
import { Card, ErrorBox, Kpi, Loading } from '../components/ui';
import type { VulnSummary } from '../types';
import { fmtTime, relTime, useApi } from '../util';
import {
  buildVulnQuery, clearVulnFilters, formatVulnFilterChip, parseVulnFilters, scrollToVulnFindings,
  setVulnFilter, toggleHeatmapCell, toggleVulnFilter, toggleVendorProductFilter,
  VULN_FILTER_KEYS, type VulnFilterKey, type VulnFilters,
} from '../vulnFilters';

/** Merge optimistic filters into the current URL (keeps page/sort until applySp drops page). */
function spWithFilters(base: URLSearchParams, filters: VulnFilters): URLSearchParams {
  const next = new URLSearchParams(base);
  for (const key of VULN_FILTER_KEYS) {
    const value = filters[key];
    if (value) next.set(key, value);
    else next.delete(key);
  }
  return next;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--high)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--ok)',
};

function labelContextFromSummary(summary: VulnSummary | null | undefined) {
  const networkNames: Record<string, string> = {};
  const deviceLabels: Record<string, string> = {};
  if (!summary) return { networkNames, deviceLabels };
  for (const b of summary.facets.network) {
    networkNames[String(b.key)] = b.label ?? String(b.key);
  }
  for (const row of summary.severity_by_network) {
    const key = row.network_id != null ? String(row.network_id) : 'unassigned';
    networkNames[key] = row.network;
  }
  for (const d of summary.top_devices) {
    deviceLabels[d.uuid] = d.hostname ? `${d.ip} (${d.hostname})` : d.ip;
  }
  for (const row of [...summary.new_since_last_scan, ...summary.new_since_last_db_update]) {
    if (!deviceLabels[row.device_uuid]) deviceLabels[row.device_uuid] = row.device_ip;
  }
  return { networkNames, deviceLabels };
}

export default function Vulnerabilities() {
  const [sp, setSp] = useSearchParams();
  const searchKey = sp.toString();
  // Optimistic copy so chips/active states update on the same click as setSp (URL can lag a tick).
  const [filters, setFilters] = useState<VulnFilters>(() => parseVulnFilters(sp));
  useEffect(() => {
    setFilters(parseVulnFilters(new URLSearchParams(searchKey)));
  }, [searchKey]);

  const page = Number(sp.get('page') || 1);
  const { data, error, reload } = useApi<VulnSummary>('/vulns/summary', undefined, 30000);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const labelCtx = useMemo(() => labelContextFromSummary(data), [data]);

  const applySp = (next: URLSearchParams, scroll = true) => {
    setFilters(parseVulnFilters(next));
    setSp(next);
    if (scroll) scrollToVulnFindings();
  };
  // Toggle against optimistic filters so a second click before the URL catches up still clears.
  const liveSp = () => spWithFilters(sp, filters);
  const toggle = (key: VulnFilterKey, value: string) => applySp(toggleVulnFilter(liveSp(), key, value));
  const set = (key: VulnFilterKey, value: string | undefined, scroll = true) =>
    applySp(setVulnFilter(liveSp(), key, value), scroll);
  const toggleVendorProduct = (facetKey: string) => applySp(toggleVendorProductFilter(liveSp(), facetKey));
  const setPage = (p: number) => {
    const next = new URLSearchParams(sp);
    if (p <= 1) next.delete('page');
    else next.set('page', String(p));
    setSp(next);
  };
  const activeFilters = Object.entries(filters) as [VulnFilterKey, string][];
  // Findings sort lives in the URL next to the filters (filter helpers keep it, and drop only `page`).
  const sortKey: FindingSort = FINDING_SORTS.find((k) => k === sp.get('sort')) ?? 'risk';
  const findingSort = { key: sortKey, desc: sp.get('order') === 'desc' };
  const setFindingSort = (key: FindingSort) => {
    const next = new URLSearchParams(sp);
    if (key === 'risk') {
      next.delete('sort');
      next.delete('order');
    } else {
      const desc = key === sortKey ? !findingSort.desc : FINDING_DESC_FIRST.includes(key);
      next.set('sort', key);
      next.set('order', desc ? 'desc' : 'asc');
    }
    next.delete('page');
    setSp(next);
  };

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
            (9 / 7 / 4 thresholds), preferring CVSS v3.1 → v3.0 → v2 when present - not NVD&apos;s
            own severity label. CVEs with no score in the cache are shown as unscored.
          </p>
        </div>
        <div className="row wrap gap-2 no-print">
          <button type="button" className="btn" disabled={exporting} onClick={() => { void exportCsv(); }}>
            {exporting ? 'Exporting…' : 'Export CSV'}
          </button>
          <button type="button" className="btn" onClick={() => window.print()}>Print report</button>
        </div>
      </div>
      {exportError && <div className="alert error no-print">{exportError}</div>}
      <ErrorBox error={error} />
      {/* Chips stay outside the summary loading gate so filter state paints immediately on click. */}
      {activeFilters.length > 0 && (
        <div className="row wrap gap-2">
          <span className="muted small">Filters:</span>
          {activeFilters.map(([key, value]) => (
            <button key={key} type="button" className="btn sm toggle on" aria-pressed="true" title="Remove this filter"
              onClick={() => set(key, undefined, false)}>
              {formatVulnFilterChip(key, value, labelCtx)} <span aria-hidden>✕</span>
            </button>
          ))}
          <button type="button" className="btn sm ghost"
            onClick={() => applySp(clearVulnFilters(sp), false)}>Clear all</button>
        </div>
      )}
      {!data ? (!error && <Loading />) : (
        <>
          {/* Same toggle affordance as the KPI row (.kpi.active + aria-pressed); full width as the most urgent figure. */}
          <Kpi label="Actively exploited (CISA KEV)"
            value={<span style={{ color: data.kev_count > 0 ? 'var(--high)' : undefined }}>{data.kev_count}</span>}
            sub="Known to be exploited in the wild - the most urgent findings on this network."
            color={data.kev_count > 0 ? 'var(--high)' : undefined}
            active={filters.kev === 'true'} onClick={() => toggle('kev', 'true')} />

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
              <div className="badge high" style={{ marginBottom: 'var(--space-3)' }}>
                Stale - oldest enabled source hasn&apos;t synced in over {data.feed.stale_threshold_hours}h
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

          <VulnHeatmap rows={data.severity_by_network} filters={filters}
            onCellClick={(networkId, sev) => applySp(toggleHeatmapCell(liveSp(), networkId, sev))} />

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
              sort={findingSort}
              onSort={setFindingSort}
              onToggleDismissed={(show) => set('state', show ? 'dismissed' : undefined, false)}
              onChanged={() => { void reload(); }}
            />
          </div>
        </>
      )}
    </>
  );
}
