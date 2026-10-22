import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
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
  applyVulnSearchQ, buildVulnQuery, clearVulnFilters, formatVulnFilterChip, liveSearchParams,
  clearVulnFindingsHash, parseVulnFilters, scrollToVulnFindings, setVulnFilter,
  shouldResyncVulnQInput, shouldScrollVulnFindingsHash, toggleHeatmapCell, toggleVulnFilter,
  toggleVendorProductFilter, withPendingVulnSearchQ, VULN_FILTER_KEYS,
  type VulnFilterKey, type VulnFilters,
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
  const q = sp.get('q') ?? '';
  const onlyHidden = sp.get('only_hidden') === '1';
  // Local input + debounce into URL. Do NOT sync q→qInput on every URL write (that drops keystrokes);
  // only resync when URL q changed externally (back/forward/link).
  const [qInput, setQInput] = useState(q);
  const lastWrittenQ = useRef(q);
  const searchDebounceRef = useRef<number | null>(null);
  const cancelSearchDebounce = () => {
    if (searchDebounceRef.current != null) {
      window.clearTimeout(searchDebounceRef.current);
      searchDebounceRef.current = null;
    }
  };
  /** Write trimmed q onto the live address-bar params (RR's setSp(prev=>) snapshot is stale). */
  const commitSearchQ = (raw: string) => {
    const trimmed = raw.trim();
    const next = applyVulnSearchQ(liveSearchParams(), trimmed);
    lastWrittenQ.current = trimmed;
    if (!next) return;
    setSp(next, { replace: true });
  };
  useEffect(() => {
    if (shouldResyncVulnQInput(q, lastWrittenQ.current)) {
      lastWrittenQ.current = q;
      setQInput(q);
    }
  }, [q]);
  useEffect(() => {
    cancelSearchDebounce();
    searchDebounceRef.current = window.setTimeout(() => {
      searchDebounceRef.current = null;
      commitSearchQ(qInput);
    }, 300);
    return () => cancelSearchDebounce();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qInput]);

  // First keystroke of a new search scrolls the findings table into view.
  const wasSearching = useRef(Boolean(q));
  useEffect(() => {
    const nowSearching = Boolean(qInput.trim());
    if (nowSearching && !wasSearching.current) scrollToVulnFindings();
    wasSearching.current = nowSearching;
  }, [qInput]);

  const { data, error, reload } = useApi<VulnSummary>('/vulns/summary', undefined, 30000);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const labelCtx = useMemo(() => labelContextFromSummary(data), [data]);

  // Deep links from the watchlist (`?cve_id=…#vuln-findings`): scroll once per arrival, then drop
  // the hash so the 30s /vulns/summary poll does not jump the page back to findings.
  const scrolledFindingsHashKey = useRef<string | null>(null);
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const arrivalKey = `${searchKey}${window.location.hash}`;
    if (!shouldScrollVulnFindingsHash(window.location.hash, arrivalKey, scrolledFindingsHashKey.current)) {
      return;
    }
    if (!document.getElementById('vuln-findings')) return;
    scrolledFindingsHashKey.current = arrivalKey;
    const t = window.setTimeout(() => {
      scrollToVulnFindings();
      window.history.replaceState(null, '', clearVulnFindingsHash(window.location.href));
    }, 50);
    return () => window.clearTimeout(t);
  }, [searchKey, data]);

  const applySp = (next: URLSearchParams, scroll = true) => {
    // Cancel pending debounce so a late timer cannot rewrite this navigation with a stale snapshot.
    cancelSearchDebounce();
    // Keep in-progress (not-yet-debounced) search text so facet clicks don't drop typed q.
    const withQ = withPendingVulnSearchQ(next, qInput);
    lastWrittenQ.current = qInput.trim();
    setFilters(parseVulnFilters(withQ));
    setSp(withQ);
    if (scroll) scrollToVulnFindings();
  };
  // Build facet updates from the live address bar + optimistic filters (not a stale RR snapshot).
  const liveSp = () => spWithFilters(liveSearchParams(), filters);
  const toggle = (key: VulnFilterKey, value: string) => applySp(toggleVulnFilter(liveSp(), key, value));
  const set = (key: VulnFilterKey, value: string | undefined, scroll = true) =>
    applySp(setVulnFilter(liveSp(), key, value), scroll);
  const toggleVendorProduct = (facetKey: string) => applySp(toggleVendorProductFilter(liveSp(), facetKey));
  const setPage = (p: number) => {
    const next = liveSearchParams();
    if (p <= 1) next.delete('page');
    else next.set('page', String(p));
    setSp(next);
  };
  const clearSearch = () => {
    cancelSearchDebounce();
    lastWrittenQ.current = '';
    setQInput('');
    const next = liveSearchParams();
    next.delete('q');
    next.delete('only_hidden');
    next.delete('page');
    setSp(next, { replace: true });
  };
  const clearAll = () => {
    // Do not route through applySp: setQInput is async and withPendingVulnSearchQ would
    // re-commit the pre-clear search text from this render's closure.
    cancelSearchDebounce();
    lastWrittenQ.current = '';
    setQInput('');
    const next = clearVulnFilters(liveSearchParams());
    setFilters(parseVulnFilters(next));
    setSp(next);
  };
  const toggleOnlyHidden = () => {
    cancelSearchDebounce();
    const next = withPendingVulnSearchQ(liveSearchParams(), qInput);
    if (next.get('only_hidden') === '1') next.delete('only_hidden');
    else next.set('only_hidden', '1');
    next.delete('page');
    lastWrittenQ.current = qInput.trim();
    setSp(next);
    scrollToVulnFindings();
  };
  const activeFilters = Object.entries(filters) as [VulnFilterKey, string][];
  const hasSearch = Boolean(q);
  const showFilterBar = activeFilters.length > 0 || hasSearch || onlyHidden;
  // Findings sort lives in the URL next to the filters (filter helpers keep it, and drop only `page`).
  const sortKey: FindingSort = FINDING_SORTS.find((k) => k === sp.get('sort')) ?? 'risk';
  const findingSort = { key: sortKey, desc: sp.get('order') === 'desc' };
  const setFindingSort = (key: FindingSort) => {
    cancelSearchDebounce();
    const next = withPendingVulnSearchQ(liveSearchParams(), qInput);
    if (key === 'risk') {
      next.delete('sort');
      next.delete('order');
    } else {
      const desc = key === sortKey ? !findingSort.desc : FINDING_DESC_FIRST.includes(key);
      next.set('sort', key);
      next.set('order', desc ? 'desc' : 'asc');
    }
    next.delete('page');
    lastWrittenQ.current = qInput.trim();
    setSp(next);
  };

  const exportCsv = async () => {
    setExportError(null);
    setExporting(true);
    try {
      await downloadBlob(
        `/vulns/export${query(buildVulnQuery(filters, {
          q: q || undefined,
          only_hidden: onlyHidden ? 'true' : undefined,
        }))}`,
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
          <Link className="btn" to="/vulnerabilities/watchlist">CVE Watchlist</Link>
          <button type="button" className="btn" disabled={exporting} onClick={() => { void exportCsv(); }}>
            {exporting ? 'Exporting…' : 'Export CSV'}
          </button>
          <button type="button" className="btn" onClick={() => window.print()}>Print report</button>
        </div>
      </div>

      <div className="vuln-search-bar no-print">
        <div className="row wrap gap-2" style={{ alignItems: 'center' }}>
          <div className="row gap-1" style={{ flex: 1, minWidth: 260, alignItems: 'center' }}>
            <input
              type="text"
              inputMode="search"
              enterKeyHint="search"
              className="vuln-search-input"
              placeholder="Search CVE, device, product… or port:22"
              aria-label="Search findings"
              title="Also shows findings normally hidden by the CVSS floor, dismissal, or potential filter. Use port:22 for an exact port."
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              style={{ flex: 1, minWidth: 200 }}
            />
            {qInput.length > 0 && (
              <button type="button" className="btn sm ghost" aria-label="Clear search"
                onClick={clearSearch} title="Clear search">✕</button>
            )}
          </div>
          {hasSearch && (
            <span className="badge accent" title="Search lifts the display floor for matching rows">
              Includes hidden findings
            </span>
          )}
        </div>
        {hasSearch && (
          <p className="muted small" style={{ margin: '8px 0 0' }}>
            Cards and charts above are not filtered by this search - only the findings table is.
          </p>
        )}
      </div>

      {exportError && <div className="alert error no-print">{exportError}</div>}
      <ErrorBox error={error} />
      {/* Chips stay outside the summary loading gate so filter state paints immediately on click. */}
      {showFilterBar && (
        <div className="row wrap gap-2">
          <span className="muted small">Filters:</span>
          {hasSearch && (
            <button type="button" className="btn sm toggle on" aria-pressed="true" title="Clear search"
              onClick={clearSearch}>
              Search: &quot;{q}&quot; <span aria-hidden>✕</span>
            </button>
          )}
          {onlyHidden && (
            <button type="button" className="btn sm toggle on" aria-pressed="true" title="Show all matches"
              onClick={toggleOnlyHidden}>
              Only hidden <span aria-hidden>✕</span>
            </button>
          )}
          {activeFilters.map(([key, value]) => (
            <button key={key} type="button" className="btn sm toggle on" aria-pressed="true" title="Remove this filter"
              onClick={() => set(key, undefined, false)}>
              {formatVulnFilterChip(key, value, labelCtx)} <span aria-hidden>✕</span>
            </button>
          ))}
          <button type="button" className="btn sm ghost" onClick={clearAll}>Clear all</button>
        </div>
      )}
      {!data ? (!error && <Loading />) : (
        <>
          {/* Five columns: KEV + severities on the first row, the remaining figures on the second. */}
          <div className="grid kpis five">
            {/* First tile as the most urgent figure; value tinted red when any KEV findings exist. */}
            <Kpi label="Actively exploited (CISA KEV)"
              value={<span style={{ color: data.kev_count > 0 ? 'var(--high)' : undefined }}>{data.kev_count}</span>}
              sub="Known to be exploited in the wild - the most urgent findings."
              color={data.kev_count > 0 ? 'var(--high)' : undefined}
              active={filters.kev === 'true'} onClick={() => toggle('kev', 'true')} />
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

          {/* One status line rather than a card: the API only exposes the oldest/newest enabled-source sync. */}
          <div className="row wrap gap-2 small muted">
            <span>
              Vulnerability feed - oldest enabled-source sync{' '}
              {data.feed.oldest_synced_at
                ? <>{fmtTime(data.feed.oldest_synced_at)} ({relTime(data.feed.oldest_synced_at)})</>
                : 'never'}
              {' · '}most recent{' '}
              {data.feed.newest_synced_at
                ? <>{fmtTime(data.feed.newest_synced_at)} ({relTime(data.feed.newest_synced_at)})</>
                : 'never'}
            </span>
            {data.feed.stale && (
              <span className="badge high">
                Stale - oldest enabled source hasn&apos;t synced in over {data.feed.stale_threshold_hours}h
              </span>
            )}
          </div>

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
              q={q}
              onlyHidden={onlyHidden}
              onToggleOnlyHidden={toggleOnlyHidden}
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
