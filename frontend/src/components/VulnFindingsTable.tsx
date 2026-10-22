import { useState } from 'react';
import { Link } from 'react-router-dom';
import { del, post } from '../api';
import { useApp } from '../context';
import type { Paged, VulnFindingListItem } from '../types';
import { fmtTime, useApi } from '../util';
import { buildVulnQuery, type VulnFilters } from '../vulnFilters';
import { dismissBusyKey, findingRowKey, formatCvss, formatEpss } from '../vulnFormat';
import { Card, Empty, ErrorBox, Pager, SkeletonRows, SortTh } from './ui';

const PAGE_SIZE = 50;

/** Server-side sort keys (GET /api/vulns `sort`). `risk` is the default triage order: KEV, then CVSS. */
export const FINDING_SORTS = ['risk', 'cve', 'device', 'network', 'port', 'cvss', 'state', 'first_seen'] as const;
export type FindingSort = (typeof FINDING_SORTS)[number];
/** Scores and dates read best largest/newest first; names and numbers ascending. */
export const FINDING_DESC_FIRST: readonly FindingSort[] = ['cvss', 'first_seen'];

/** Paginated CVE-centric findings table. Dismiss/undismiss reuse the existing per-device endpoints;
 * after a mutation the parent reloads the summary so cards stay in sync. */
export function VulnFindingsTable({
  filters, q, qInput, onQInput, page, onPage, sort, onSort, onToggleDismissed, onChanged,
}: {
  filters: VulnFilters;
  /** Debounced search term from the URL (`q`); lifts the display floor when non-empty. */
  q: string;
  qInput: string;
  onQInput: (value: string) => void;
  page: number;
  onPage: (page: number) => void;
  sort: { key: FindingSort; desc: boolean };
  onSort: (key: FindingSort) => void;
  onToggleDismissed: (show: boolean) => void;
  onChanged: () => void;
}) {
  const { isAdmin } = useApp();
  const params = buildVulnQuery(filters, {
    page, page_size: PAGE_SIZE,
    sort: sort.key === 'risk' ? undefined : sort.key,
    order: sort.key === 'risk' ? undefined : sort.desc ? 'desc' : 'asc',
    q: q || undefined,
  });
  const sortTh = (key: FindingSort, label: string) => (
    <SortTh active={sort.key === key} desc={sort.desc} onSort={() => onSort(key)}>{label}</SortTh>
  );
  const { data, error, reload } = useApi<Paged<VulnFindingListItem>>('/vulns', params, 30000);
  const [busy, setBusy] = useState<string | null>(null);
  const showingDismissed = filters.state === 'dismissed';
  const searching = Boolean(q);

  const dismiss = async (deviceUuid: string, cveId: string) => {
    const key = dismissBusyKey(deviceUuid, cveId);
    if (busy) return;
    setBusy(key);
    try {
      await post(`/devices/${deviceUuid}/vulns/${encodeURIComponent(cveId)}/dismiss`);
      await reload();
      onChanged();
    } finally {
      setBusy(null);
    }
  };

  const undismiss = async (deviceUuid: string, cveId: string) => {
    const key = dismissBusyKey(deviceUuid, cveId);
    if (busy) return;
    setBusy(key);
    try {
      await del(`/devices/${deviceUuid}/vulns/${encodeURIComponent(cveId)}/dismiss`);
      await reload();
      onChanged();
    } finally {
      setBusy(null);
    }
  };

  const items = data?.items ?? [];

  return (
    <Card title="Findings" flush actions={
      <>
        {sort.key !== 'risk' && (
          <button type="button" className="btn sm ghost" onClick={() => onSort('risk')}
            title="Back to the default order: actively exploited (KEV) first, then highest CVSS">
            Triage order
          </button>
        )}
        <label className="check small">
          <input type="checkbox" checked={showingDismissed}
            onChange={(e) => onToggleDismissed(e.target.checked)} />
          show dismissed only
        </label>
      </>
    }>
      <div className="row wrap gap-2" style={{ padding: '10px 14px 0' }}>
        <input
          type="search"
          placeholder="Search CVE, device, product, port…"
          aria-label="Search findings"
          title="Also shows findings normally hidden by the CVSS floor, dismissal, or potential filter"
          value={qInput}
          onChange={(e) => onQInput(e.target.value)}
          style={{ minWidth: 260, flex: 1 }}
        />
        {searching && (
          <span className="muted small">
            Search includes findings hidden by display rules
          </span>
        )}
      </div>
      <ErrorBox error={error} />
      {!data ? (!error && <SkeletonRows cols={isAdmin ? 8 : 7} rows={5} />) : !items.length ? (
        <Empty>
          {showingDismissed
            ? 'No dismissed findings.'
            : searching
              ? 'No findings match this search.'
              : (
              <>
                No findings match the current filters.
                <div className="muted small" style={{ marginTop: 8 }}>
                  Matching needs product/version (CPE) from a <strong>standard</strong> or{' '}
                  <strong>full</strong> port scan. Discovery-only scans find hosts but collect no
                  service data, so they never produce vulnerability findings.
                </div>
              </>
            )}
        </Empty>
      ) : (
        <>
          <div className="table-wrap">
            <table className="compact">
              <thead>
                <tr>
                  {sortTh('cve', 'CVE')}
                  {sortTh('device', 'Device')}
                  {sortTh('network', 'Network')}
                  {sortTh('port', 'Port / service')}
                  {sortTh('cvss', 'CVSS')}
                  {sortTh('state', 'State')}
                  {sortTh('first_seen', 'First seen')}
                  {isAdmin && <th />}
                </tr>
              </thead>
              <tbody>
                {items.map((v) => {
                  const key = findingRowKey(v);
                  const busyKey = dismissBusyKey(v.device_uuid, v.cve_id);
                  const reasons = v.hidden_reasons ?? [];
                  return (
                    <tr key={key} className={v.state === 'dismissed' ? 'dim' : ''}>
                      <td className="mono nowrap">
                        <Link to={`/vulnerabilities/${encodeURIComponent(v.cve_id)}`}>{v.cve_id}</Link>
                        {v.kev && <span className="badge high" style={{ marginLeft: 6 }} title="Known to be exploited in the wild (CISA KEV)">KEV</span>}
                        {v.epss != null && <span className="muted small" style={{ marginLeft: 6 }}>{formatEpss(v.epss)}</span>}
                        {reasons.map((reason) => (
                          <span key={reason} className="badge outline" style={{ marginLeft: 6 }}
                            title="Normally hidden from the default findings list">
                            {reason}
                          </span>
                        ))}
                      </td>
                      <td>
                        <Link className="mono" to={`/devices/${v.device_uuid}`}>{v.device_ip}</Link>
                        {v.device_hostname && <div className="muted small">{v.device_hostname}</div>}
                      </td>
                      <td>{v.network ?? '-'}</td>
                      <td className="small">
                        {v.protocol.toUpperCase()}/{v.port} {v.product ?? v.service ?? ''} {v.version ?? ''}
                      </td>
                      <td className="mono small">{formatCvss(v.cvss_base)}</td>
                      <td>
                        <span className={`badge ${v.state === 'confirmed' ? 'high' : v.state === 'potential' ? 'medium' : 'outline'}`}>
                          {v.state}
                        </span>
                      </td>
                      <td className="small muted">{fmtTime(v.first_seen_at)}</td>
                      {isAdmin && (
                        <td className="right">
                          {v.state === 'dismissed' ? (
                            <button type="button" className="btn sm ghost" disabled={busy === busyKey}
                              onClick={() => undismiss(v.device_uuid, v.cve_id)}>Undo</button>
                          ) : (
                            <button type="button" className="btn sm ghost" disabled={busy === busyKey}
                              onClick={() => dismiss(v.device_uuid, v.cve_id)}>Dismiss</button>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pager page={data.page} pageSize={data.page_size} total={data.total} onPage={onPage} />
        </>
      )}
    </Card>
  );
}
