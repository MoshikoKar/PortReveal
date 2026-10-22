import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { downloadBlob, get, query } from '../api';
import { VulnFacets } from '../components/VulnFacets';
import { FINDING_DESC_FIRST, FINDING_SORTS, VulnFindingsTable, type FindingSort } from '../components/VulnFindingsTable';
import { VulnHeatmap } from '../components/VulnHeatmap';
import { VulnPrintReport } from '../components/VulnPrintReport';
import { VulnTopLists } from '../components/VulnTopLists';
import { VulnRiskTrend, VulnSeverityTrend, VulnTrend } from '../components/VulnTrend';
import { Card, ErrorBox, Kpi, Loading } from '../components/ui';
import type { Network, Paged, VulnFindingListItem, VulnSummary } from '../types';
import { fmtTime, relTime, useApi } from '../util';
import {
  applyVulnSearchQ, buildVulnQuery, clearVulnFilters, formatVulnFilterChip, liveSearchParams,
  clearVulnFindingsHash, parseVulnFilters, scrollToVulnFindings, setVulnFilter,
  shouldResyncVulnQInput, shouldScrollVulnFindingsHash, toggleHeatmapCell,
  toggleNetworkFilter, toggleVulnFilter, toggleVendorProductFilter, withPendingVulnSearchQ,
  vulnExportFilename, VULN_FILTER_KEYS, type VulnFilterKey, type VulnFilters,
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

const REPORT_PAGE_SIZE = 500;

/** Stable key for the summary query so print can wait for the matching response. */
function summaryFilterKey(filters: VulnFilters, q: string, onlyHidden: boolean): string {
  return query(buildVulnQuery(filters, {
    q: q || undefined,
    only_hidden: q && onlyHidden ? 'true' : undefined,
  }));
}

function labelContextFromSummary(summary: VulnSummary | null | undefined, networks: Network[] | null | undefined) {
  const networkNames: Record<string, string> = {};
  const deviceLabels: Record<string, string> = {};
  for (const n of networks ?? []) {
    networkNames[String(n.id)] = n.name;
  }
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

/** Fetch every finding matching the active filters (for print/PDF), paging at the API max. */
async function fetchAllFindings(
  filters: VulnFilters, q: string, onlyHidden: boolean,
): Promise<VulnFindingListItem[]> {
  const items: VulnFindingListItem[] = [];
  let page = 1;
  let total = Infinity;
  while (items.length < total) {
    const body = await get<Paged<VulnFindingListItem>>(
      '/vulns',
      buildVulnQuery(filters, {
        page, page_size: REPORT_PAGE_SIZE, sort: 'risk',
        q: q || undefined,
        only_hidden: q && onlyHidden ? 'true' : undefined,
      }),
    );
    total = body.total;
    items.push(...body.items);
    if (!body.items.length) break;
    page += 1;
    if (page > 100) break; // hard stop: 50k rows
  }
  return items;
}

const waitForPrintPaint = () => new Promise<void>((resolve) => {
  requestAnimationFrame(() => {
    requestAnimationFrame(() => resolve());
  });
});

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
  const [qInput, setQInput] = useState(q);
  const lastWrittenQ = useRef(q);
  const searchDebounceRef = useRef<number | null>(null);
  const cancelSearchDebounce = () => {
    if (searchDebounceRef.current != null) {
      window.clearTimeout(searchDebounceRef.current);
      searchDebounceRef.current = null;
    }
  };
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

  const wasSearching = useRef(Boolean(q));
  useEffect(() => {
    const nowSearching = Boolean(qInput.trim());
    if (nowSearching && !wasSearching.current) scrollToVulnFindings();
    wasSearching.current = nowSearching;
  }, [qInput]);

  const summaryParams = useMemo(
    () => buildVulnQuery(filters, {
      q: q || undefined,
      only_hidden: q && onlyHidden ? 'true' : undefined,
    }),
    [filters, q, onlyHidden],
  );
  const wantedSummaryKey = useMemo(
    () => summaryFilterKey(filters, q, onlyHidden),
    [filters, q, onlyHidden],
  );
  const { data, error, reload, loading: summaryLoading } = useApi<VulnSummary>(
    '/vulns/summary', summaryParams, 30000,
  );
  // useApi keeps the previous payload while a new filter fetch is in flight — track which
  // filter key the current `data` actually belongs to so print cannot pair network-B findings
  // with an all-networks (or network-A) summary.
  const [loadedSummaryKey, setLoadedSummaryKey] = useState<string | null>(null);
  useEffect(() => {
    if (summaryLoading) {
      setLoadedSummaryKey(null);
      return;
    }
    if (data) setLoadedSummaryKey(wantedSummaryKey);
  }, [summaryLoading, data, wantedSummaryKey]);
  const summaryReady = !!data && !summaryLoading && loadedSummaryKey === wantedSummaryKey;

  const networks = useApi<Network[]>('/networks');
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [printFindings, setPrintFindings] = useState<VulnFindingListItem[]>([]);
  const [printLoading, setPrintLoading] = useState(false);
  const [printError, setPrintError] = useState<string | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [pendingPrint, setPendingPrint] = useState(() => sp.get('print') === '1');
  const printInFlight = useRef(false);
  const labelCtx = useMemo(() => labelContextFromSummary(data, networks.data), [data, networks.data]);

  useEffect(() => {
    if (sp.get('print') === '1') setPendingPrint(true);
  }, [searchKey, sp]);

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
    cancelSearchDebounce();
    const withQ = withPendingVulnSearchQ(next, qInput);
    lastWrittenQ.current = qInput.trim();
    setFilters(parseVulnFilters(withQ));
    setSp(withQ);
    if (scroll) scrollToVulnFindings();
  };
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
          only_hidden: q && onlyHidden ? 'true' : undefined,
        }))}`,
        vulnExportFilename(filters, labelCtx),
      );
    } catch (e: unknown) {
      setExportError(e instanceof Error ? e.message : 'Export failed.');
    } finally {
      setExporting(false);
    }
  };

  const prepareReport = useCallback(async () => {
    setPrintError(null);
    setPrintLoading(true);
    try {
      const rows = await fetchAllFindings(filters, q, onlyHidden);
      setPrintFindings(rows);
      return true;
    } catch (e: unknown) {
      setPrintError(e instanceof Error ? e.message : 'Could not prepare the print report.');
      return false;
    } finally {
      setPrintLoading(false);
    }
  }, [filters, q, onlyHidden]);

  const printReport = useCallback(async () => {
    // Wait for the summary that matches the current filters (not a stale all-networks payload).
    if (!summaryReady) {
      setPendingPrint(true);
      return;
    }
    if (printInFlight.current) return;
    printInFlight.current = true;
    try {
      const ok = await prepareReport();
      if (!ok) return;
      await waitForPrintPaint();
      window.print();
    } finally {
      printInFlight.current = false;
    }
  }, [summaryReady, prepareReport]);

  const openPreview = useCallback(async () => {
    if (!summaryReady) {
      setPrintError('Wait for the summary to finish loading for the current filters.');
      return;
    }
    const ok = await prepareReport();
    if (ok) setPreviewOpen(true);
  }, [summaryReady, prepareReport]);

  useEffect(() => {
    if (!pendingPrint || !summaryReady) return;
    let alive = true;
    setPrintError(null);
    setPrintLoading(true);
    (async () => {
      try {
        const rows = await fetchAllFindings(filters, q, onlyHidden);
        if (!alive) return;
        setPrintFindings(rows);
        setPrintLoading(false);
        await waitForPrintPaint();
        if (!alive) return;
        window.print();
        if (sp.get('print') === '1') {
          const next = new URLSearchParams(sp);
          next.delete('print');
          setSp(next, { replace: true });
        }
      } catch (e: unknown) {
        if (alive) {
          setPrintError(e instanceof Error ? e.message : 'Could not prepare the print report.');
          setPrintLoading(false);
        }
      } finally {
        if (alive) setPendingPrint(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [pendingPrint, summaryReady, filters, q, onlyHidden, sp, setSp]);

  const severity = data?.severity_counts ?? { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const risk = data?.risk_device_levels ?? { high: 0, medium: 0, low: 0 };
  const epssPct = data ? Math.round(data.epss_threshold * 100) : 0;
  const epssValue = data ? String(data.epss_threshold) : '0.1';
  const networkSelectValue = filters.network_id ?? '';
  const hasUnassigned = (data?.facets.network ?? []).some((b) => String(b.key) === 'unassigned');
  const networkActive = !!networkSelectValue;
  const networkLabel = networkSelectValue
    ? (labelCtx.networkNames[networkSelectValue]
      ?? (networkSelectValue === 'unassigned' ? 'Unassigned' : `Network ${networkSelectValue}`))
    : 'All networks';
  const filtered = activeFilters.length > 0 || hasSearch;
  const snapshotNote = data?.snapshot_trend_note ?? null;
  const printDisabled = printLoading || pendingPrint || !summaryReady;

  return (
    <>
      <div className="page-head no-print">
        <div>
          <h1>Vulnerabilities</h1>
          <p>
            Matched CVEs across the network. Severity bands come from the cached CVSS base score
            (9 / 7 / 4 thresholds), preferring CVSS v3.1 → v3.0 → v2 when present - not NVD&apos;s
            own severity label. CVEs with no score in the cache are shown as unscored.
          </p>
        </div>
        <div className="row wrap gap-2" style={{ alignItems: 'center' }}>
          <label
            className={`vuln-network-select ${networkActive ? 'active' : ''}`}
            title="Scope the dashboard and reports to one network"
          >
            <span className="vuln-network-select-label">Network</span>
            <select
              aria-label={`Network filter: ${networkLabel}`}
              value={networkSelectValue}
              onChange={(e) => set('network_id', e.target.value || undefined, false)}
            >
              <option value="">All networks</option>
              {hasUnassigned && <option value="unassigned">Unassigned</option>}
              {(networks.data ?? []).map((n) => (
                <option key={n.id} value={String(n.id)}>{n.name}</option>
              ))}
            </select>
          </label>
          <Link className="btn" to="/vulnerabilities/watchlist">CVE Watchlist</Link>
          <button type="button" className="btn" disabled={exporting} onClick={() => { void exportCsv(); }}>
            {exporting ? 'Exporting…' : 'Export CSV'}
          </button>
          <button type="button" className="btn" disabled={printDisabled || !summaryReady}
            onClick={() => { void openPreview(); }}>
            {printLoading && !previewOpen ? 'Preparing…' : 'Preview'}
          </button>
          <button type="button" className="btn" disabled={printDisabled}
            title={!summaryReady ? 'Waiting for summary to match the current filters…' : undefined}
            onClick={() => { void printReport(); }}>
            {printLoading || pendingPrint || !summaryReady ? 'Preparing…' : 'Print / PDF report'}
          </button>
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
      </div>

      {exportError && <div className="alert error no-print">{exportError}</div>}
      {printError && <div className="alert error no-print">{printError}</div>}
      <ErrorBox error={error} />
      {showFilterBar && (
        <div className="row wrap gap-2 no-print">
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

      {previewOpen && (
        <div className="vuln-print-preview no-print" role="region" aria-label="Report preview">
          <div className="row wrap gap-2" style={{ justifyContent: 'space-between', marginBottom: 12 }}>
            <strong>Report preview</strong>
            <div className="row gap-2">
              <button type="button" className="btn" disabled={printLoading}
                onClick={() => { window.print(); }}>
                Print / PDF
              </button>
              <button type="button" className="btn ghost" onClick={() => setPreviewOpen(false)}>
                Close preview
              </button>
            </div>
          </div>
        </div>
      )}

      <VulnPrintReport
        filters={filters}
        labelCtx={labelCtx}
        summary={summaryReady ? data : null}
        findings={printFindings}
        loading={printLoading}
        error={printError}
        preview={previewOpen}
        searchQ={q || undefined}
      />

      <div className="vuln-screen no-print">
      {!data ? (!error && <Loading />) : (
        <>
          <div className="grid kpis five">
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
            <Kpi label="High-risk devices" value={risk.high}
              sub={filtered
                ? `Among matching findings · ${risk.medium} medium · ${risk.low} low`
                : `${risk.medium} medium · ${risk.low} low`}
              color={risk.high ? 'var(--high)' : undefined}
              active={filters.risk_band === 'high'} onClick={() => toggle('risk_band', 'high')} />
            <Kpi label="Confirmed findings" value={data.confirmed_count}
              active={filters.state === 'confirmed'} onClick={() => toggle('state', 'confirmed')} />
            <Kpi label="Potential findings" value={data.potential_count}
              active={filters.state === 'potential'} onClick={() => toggle('state', 'potential')} />
          </div>

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
              {snapshotNote && <p className="muted small vuln-snapshot-note">{snapshotNote}</p>}
              <VulnSeverityTrend points={data.snapshot_trend} />
            </Card>
            <Card title="Average network risk score over time">
              {snapshotNote && <p className="muted small vuln-snapshot-note">{snapshotNote}</p>}
              <VulnRiskTrend points={data.snapshot_trend} />
            </Card>
          </div>

          <VulnHeatmap
            rows={data.severity_by_network}
            filters={filters}
            onCellClick={(networkId, sev) => applySp(toggleHeatmapCell(liveSp(), networkId, sev))}
            onNetworkClick={(networkId) => applySp(toggleNetworkFilter(liveSp(), networkId))}
          />

          <VulnFacets summary={data} filters={filters} onToggle={toggle}
            onToggleVendorProduct={toggleVendorProduct} />
          <VulnTopLists
            summary={data}
            filters={filters}
            onToggleCve={(id) => toggle('cve_id', id)}
            onToggleDevice={(uuid) => toggle('device_uuid', uuid)}
            onToggleNetwork={(networkId) => applySp(toggleNetworkFilter(liveSp(), networkId))}
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
              onToggleNetwork={(networkId) => applySp(toggleNetworkFilter(liveSp(), networkId))}
              onChanged={() => { void reload(); }}
            />
          </div>
        </>
      )}
      </div>
    </>
  );
}
