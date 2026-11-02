import { useState } from 'react';
import { Link } from 'react-router-dom';
import { del, post } from '../api';
import { useApp } from '../context';
import type { VulnFindingListItem, VulnFindingsPage } from '../types';
import { fmtTime, relTime, useApi } from '../util';
import { buildVulnQuery, displayHiddenReasons, type VulnFilterKey, type VulnFilters } from '../vulnFilters';
import { dismissBusyKey, findingRowKey, formatEpss } from '../vulnFormat';
import { CvssScore } from './VulnTopLists';
import { Card, Empty, ErrorBox, Pager, SkeletonRows, SortTh } from './ui';

const PAGE_SIZE = 50;

/** Server-side sort keys (GET /api/vulns `sort`). `risk` is the default triage order: KEV, then CVSS. */
export const FINDING_SORTS = ['risk', 'cve', 'device', 'network', 'port', 'cvss', 'state', 'first_seen'] as const;
export type FindingSort = (typeof FINDING_SORTS)[number];
/** Scores and dates read best largest/newest first; names and numbers ascending. */
export const FINDING_DESC_FIRST: readonly FindingSort[] = ['cvss', 'first_seen'];
const SORT_LABELS: Record<FindingSort, string> = {
  risk: 'KEV first, then highest CVSS', cve: 'CVE', device: 'Device', network: 'Network',
  port: 'Port / service', cvss: 'CVSS', state: 'State', first_seen: 'First seen',
};

/** Plain-language meaning of each match state; shown in the legend and on each badge. */
export const STATE_HELP: Record<string, string> = {
  confirmed: 'The exact product version reported by the service is listed as affected.',
  potential: 'The version is imprecise or falls in an affected range. Verify it on the device.',
  dismissed: 'An admin marked this finding as not applicable.',
};

/** Paginated CVE-centric findings table. Dismiss/undismiss reuse the existing per-device endpoints;
 * after a mutation the parent reloads the summary so cards stay in sync. */
export function VulnFindingsTable({
  filters, q, onlyHidden, onToggleOnlyHidden, page, onPage, sort, onSort,
  onToggleFilter, epssValue, epssPct, onToggleNetwork, onChanged,
}: {
  filters: VulnFilters;
  /** Debounced search term from the URL (`q`); lifts the display floor when non-empty. */
  q: string;
  onlyHidden: boolean;
  onToggleOnlyHidden: () => void;
  page: number;
  onPage: (page: number) => void;
  sort: { key: FindingSort; desc: boolean };
  onSort: (key: FindingSort) => void;
  /** Toggle a state / EPSS filter without scrolling (the toolbar is already beside the table). */
  onToggleFilter: (key: VulnFilterKey, value: string) => void;
  epssValue: string;
  epssPct: number;
  onToggleNetwork: (networkId: number | null) => void;
  onChanged: () => void;
}) {
  const { isAdmin } = useApp();
  const searching = Boolean(q);
  const params = buildVulnQuery(filters, {
    page, page_size: PAGE_SIZE,
    sort: sort.key === 'risk' ? undefined : sort.key,
    order: sort.key === 'risk' ? undefined : sort.desc ? 'desc' : 'asc',
    q: q || undefined,
    only_hidden: searching && onlyHidden ? 'true' : undefined,
  });
  const sortTh = (key: FindingSort) => (
    <SortTh title={SORT_LABELS[key]} active={sort.key === key} desc={sort.desc} onSort={() => onSort(key)}>{SORT_LABELS[key]}</SortTh>
  );
  const { data, error, reload } = useApi<VulnFindingsPage>('/vulns', params, 30000);
  const [busy, setBusy] = useState<string | null>(null);
  // Row whose inline "why dismiss?" form is open, and the reason being typed.
  const [dismissing, setDismissing] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);
  const [announce, setAnnounce] = useState('');

  // Closing the inline form unmounts the focused field; hand focus back to the row's Dismiss button.
  const cancelDismiss = (key: string) => {
    setDismissing(null);
    requestAnimationFrame(() => {
      document.querySelector<HTMLButtonElement>(`button[data-dismiss-key="${key}"]`)?.focus();
    });
  };

  const mutate = async (v: VulnFindingListItem, undo: boolean, note?: string) => {
    const key = dismissBusyKey(v.device_uuid, v.cve_id);
    if (busy) return;
    setBusy(key);
    setActionError(null);
    const path = `/devices/${v.device_uuid}/vulns/${encodeURIComponent(v.cve_id)}/dismiss`;
    try {
      if (undo) await del(path);
      else await post(path, { reason: note?.trim() || null });
      setDismissing(null);
      setReason('');
      setAnnounce(`${v.cve_id} on ${v.device_ip} ${undo ? 'restored' : 'dismissed'}.`);
      await reload();
      onChanged();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Request failed.';
      setActionError(`Could not ${undo ? 'restore' : 'dismiss'} ${v.cve_id} on ${v.device_ip}: ${msg} Try again.`);
    } finally {
      setBusy(null);
    }
  };

  const items = data?.items ?? [];
  const matchTotal = data?.total_matches ?? data?.total ?? 0;
  const hiddenTotal = data?.hidden_total ?? 0;
  const showingDismissed = filters.state === 'dismissed';
  const colCount = isAdmin ? 8 : 7;
  const stateToggle = (value: 'confirmed' | 'potential', label: string) => {
    const on = filters.state === value;
    return (
      <button type="button" className={`btn sm toggle ${on ? 'on' : ''}`} aria-pressed={on}
        title={STATE_HELP[value]} onClick={() => onToggleFilter('state', value)}>
        {label}
      </button>
    );
  };
  const epssOn = filters.epss_min === epssValue;

  return (
    <Card title="Findings" flush>
      <div className="card-toolbar vuln-findings-toolbar">
        <div className="row wrap gap-2" role="group" aria-label="Narrow findings">
          {stateToggle('confirmed', 'Confirmed')}
          {stateToggle('potential', 'Potential')}
          <button type="button" className={`btn sm toggle ${epssOn ? 'on' : ''}`} aria-pressed={epssOn}
            title="FIRST.org EPSS: estimated probability of exploitation in the next 30 days"
            onClick={() => onToggleFilter('epss_min', epssValue)}>
            Likely exploited (EPSS ≥ {epssPct}%)
          </button>
          <label className="check small">
            <input type="checkbox" checked={showingDismissed}
              onChange={() => onToggleFilter('state', 'dismissed')} />
            Dismissed only
          </label>
          {searching && (
            <label className="check small" title="Show only findings the default list would hide">
              <input type="checkbox" checked={onlyHidden} onChange={onToggleOnlyHidden} />
              Only normally hidden
            </label>
          )}
        </div>
        <div className="row wrap gap-2 small" style={{ alignItems: 'center' }}>
          <span className="muted">
            Sorted by {SORT_LABELS[sort.key]}{sort.key !== 'risk' && (sort.desc ? ' ↓' : ' ↑')}
            {sort.key === 'risk' && ' (default)'}
          </span>
          {sort.key !== 'risk' && (
            <button type="button" className="btn sm" onClick={() => onSort('risk')}
              title="Back to the default order: actively exploited (KEV) first, then highest CVSS">
              Reset to KEV first
            </button>
          )}
        </div>
        <p className="vuln-state-legend small muted">
          <span className="badge state-confirmed">confirmed</span> exact version match
          <span className="vuln-legend-sep" aria-hidden>·</span>
          <span className="badge state-potential">potential</span> version range or imprecise version, verify on the device
        </p>
      </div>
      {searching && data && (
        <p className="vuln-findings-count small">
          <strong>{matchTotal.toLocaleString()}</strong> matches
          {hiddenTotal > 0 && <> · <strong>{hiddenTotal.toLocaleString()}</strong> normally hidden</>}
        </p>
      )}
      <p className="sr-only" aria-live="polite">
        {announce || (data ? `${data.total.toLocaleString()} findings` : '')}
      </p>
      <ErrorBox error={error} />
      {actionError && <div className="alert error" role="alert">{actionError}</div>}
      {!data ? (!error && <SkeletonRows cols={colCount} rows={5} />) : !items.length ? (
        <Empty>
          {showingDismissed
            ? 'No dismissed findings.'
            : searching
              ? (onlyHidden ? 'No normally hidden findings match this search.' : 'No findings match this search.')
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
            <table className="compact domain-table fit-table vuln-findings-table" aria-label="Vulnerability findings">
              <thead>
                <tr>
                  {sortTh('cve')}
                  {sortTh('device')}
                  {sortTh('network')}
                  {sortTh('port')}
                  {sortTh('cvss')}
                  {sortTh('state')}
                  {sortTh('first_seen')}
                  {isAdmin && <th><span className="sr-only">Actions</span></th>}
                </tr>
              </thead>
              <tbody>
                {items.map((v) => {
                  const key = findingRowKey(v);
                  const busyKey = dismissBusyKey(v.device_uuid, v.cve_id);
                  const reasons = displayHiddenReasons(v.state, v.hidden_reasons);
                  const netKey = v.network_id != null ? String(v.network_id) : 'unassigned';
                  const netActive = filters.network_id === netKey;
                  const netLabel = v.network ?? 'Unassigned';
                  const portText = [v.protocol.toUpperCase() + '/' + v.port, v.product ?? v.service, v.version].filter(Boolean).join(' ');
                  const cveTip = [
                    v.cve_id,
                    v.kev ? 'CISA KEV: known to be exploited' : null,
                    formatEpss(v.epss) || null,
                    ...reasons,
                  ].filter(Boolean).join('\n');
                  const deviceTip = [v.device_ip, v.device_hostname].filter(Boolean).join('\n');
                  const formOpen = dismissing === key;
                  const rowName = `${v.cve_id} on ${v.device_ip}`;
                  return [
                    <tr key={key} className={v.state === 'dismissed' ? 'dim' : ''}>
                      <td className="mono" data-label="CVE">
                        <span className="cell-ellipsis" title={cveTip}>
                          <Link to={`/vulnerabilities/${encodeURIComponent(v.cve_id)}`}>{v.cve_id}</Link>
                          {v.kev && <span className="badge kev" style={{ marginLeft: 6 }}>KEV</span>}
                          {reasons.length > 0 && (
                            <span className="badge outline" style={{ marginLeft: 6 }} title={reasons.join('\n')}>
                              {reasons.length === 1 ? reasons[0] : `+${reasons.length}`}
                            </span>
                          )}
                        </span>
                      </td>
                      <td className="domain-col-fluid" title={deviceTip} data-label="Device">
                        <span className="cell-ellipsis">
                          <Link className="mono" to={`/devices/${v.device_uuid}`}>{v.device_ip}</Link>
                          {v.device_hostname && <span className="muted small"> · {v.device_hostname}</span>}
                        </span>
                      </td>
                      <td className="domain-col-fluid" data-label="Network">
                        <button
                          type="button"
                          className={`heatmap-network-btn cell-ellipsis ${netActive ? 'active' : ''}`}
                          aria-pressed={netActive}
                          title={netActive ? 'Clear network filter' : `Filter by network: ${netLabel}`}
                          onClick={() => onToggleNetwork(v.network_id)}
                        >
                          {netLabel}
                        </button>
                      </td>
                      <td className="small domain-col-fluid" data-label="Service">
                        <span className="cell-ellipsis" title={portText}>{portText}</span>
                      </td>
                      <td data-label="CVSS"><CvssScore cvss={v.cvss_base} /></td>
                      <td data-label="State">
                        <span className={`badge state-${v.state}`} title={STATE_HELP[v.state]}>{v.state}</span>
                        {v.state === 'dismissed' && v.dismiss_reason && (
                          <span className="muted small vuln-dismiss-reason" title={v.dismiss_reason}> {v.dismiss_reason}</span>
                        )}
                      </td>
                      <td className="small muted" title={fmtTime(v.first_seen_at)} data-label="First seen">{relTime(v.first_seen_at)}</td>
                      {isAdmin && (
                        <td className="right vuln-row-action">
                          {v.state === 'dismissed' ? (
                            <button type="button" className="btn sm ghost" disabled={busy === busyKey}
                              aria-label={`Restore ${rowName}`}
                              onClick={() => { void mutate(v, true); }}>Restore</button>
                          ) : (
                            <button type="button" className="btn sm ghost" disabled={busy === busyKey}
                              aria-expanded={formOpen} aria-label={`Dismiss ${rowName}`} data-dismiss-key={key}
                              onClick={() => { setDismissing(formOpen ? null : key); setReason(''); }}>
                              Dismiss
                            </button>
                          )}
                        </td>
                      )}
                    </tr>,
                    formOpen && (
                      <tr key={`${key}-dismiss`} className="vuln-dismiss-row">
                        <td colSpan={colCount}>
                          <form className="row wrap gap-2" style={{ alignItems: 'center' }}
                            onSubmit={(e) => { e.preventDefault(); void mutate(v, false, reason); }}>
                            <label className="small" htmlFor={`dismiss-${key}`}>
                              Dismiss <span className="mono">{v.cve_id}</span> on <span className="mono">{v.device_ip}</span>. Why?
                            </label>
                            <input id={`dismiss-${key}`} type="text" maxLength={200} autoFocus
                              placeholder="Optional: e.g. not reachable, patched by vendor backport"
                              value={reason} onChange={(e) => setReason(e.target.value)}
                              onKeyDown={(e) => { if (e.key === 'Escape') cancelDismiss(key); }}
                              style={{ flex: '1 1 16rem', minWidth: 0 }} />
                            <button type="submit" className="btn sm" disabled={busy === busyKey}>
                              {busy === busyKey ? 'Dismissing…' : 'Dismiss finding'}
                            </button>
                            <button type="button" className="btn sm ghost" onClick={() => cancelDismiss(key)}>Cancel</button>
                          </form>
                          <p className="muted small" style={{ margin: '6px 0 0' }}>
                            It stays dismissed across rescans until restored. The reason appears in reports.
                          </p>
                        </td>
                      </tr>
                    ),
                  ];
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
