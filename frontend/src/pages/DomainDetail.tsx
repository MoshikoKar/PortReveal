import { useEffect, useRef, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { post } from '../api';
import { DomainDialog } from '../components/DomainDialog';
import { DomainLookup } from '../components/DomainLookup';
import { DomainScanProgress } from '../components/DomainScanProgress';
import { Card, Empty, ErrorBox, Kpi, Loading, Pager, ScanStatusBadge, SkeletonRows, SortTh } from '../components/ui';
import { useApp } from '../context';
import {
  EXPOSURE_BADGE, EXPOSURE_LABELS, EXPOSURE_TIPS, FLAG_BADGE, FLAG_LABELS, FLAG_SHORT, FLAG_TIPS, ROW_STATUS, SOURCE_LABELS,
  SOURCE_TIPS, sourcesText, subdomainStatus, subdomainStatusTip,
  type DomainDraft, type SubdomainFilterKey, activeFilterCount, draftFromDomain, hostingLabel, patchParams,
  phaseSummaryTip, problemPhases, scanPollMs, subdomainQuery, wildcardTip, wordlistTruncationNote,
} from '../domains';
import type { Domain, DomainScanJob, Exposure, Paged, Subdomain, SubdomainFlag, SubdomainSource } from '../types';
import { duration, fmtTime, relTime, useApi, useInFlight } from '../util';

const PAGE = 100;

function scanSummary(j: DomainScanJob): string {
  const s = j.stats;
  if (!s) return j.error ?? '-';
  const parts = [`${s.total ?? 0} names`];
  if (s.baseline) parts.push('baseline');
  else parts.push(`${s.new ?? 0} new`, `${s.gone ?? 0} gone`, `${s.changed ?? 0} changed`);
  if (s.zone_transfer_open) parts.push(`AXFR open on ${s.zone_transfer_open}`);
  if (s.port_scan_targets) parts.push(`${s.port_scan_targets} new address(es) port-scanned`);
  if (s.unverified) parts.push(`${s.unverified} unverified`);
  if (s.partial_reasons?.length) parts.push(`partial: ${s.partial_reasons.join('; ')}`);
  return parts.join(' · ');
}

function HostingCell({ s }: { s: Subdomain }) {
  if (!s.hosting.length) return <span className="muted">-</span>;
  const first = s.hosting.find((h) => h.kind === 'network') ?? s.hosting[0];
  const title = s.hosting.map((h) => `${h.ip}: ${hostingLabel(h)}`).join('\n');
  return (
    <span className="cell-ellipsis" title={title}>
      {first.device_uuid ? <Link to={`/devices/${first.device_uuid}`} onClick={(e) => e.stopPropagation()}>{hostingLabel(first)}</Link> : hostingLabel(first)}
      {s.hosting.length > 1 && <span className="muted"> +{s.hosting.length - 1}</span>}
    </span>
  );
}

function SubdomainRow({ s, domain, showWildcard, hostingFlex }: {
  s: Subdomain; domain: Domain; showWildcard: boolean; hostingFlex: boolean;
}) {
  const st = ROW_STATUS[subdomainStatus(s)];
  const authorized = s.flags.includes('internal_authorized');
  return (
    <tr className={s.status === 'gone' ? 'dim' : undefined}>
      <td className="sd-name"><span className="cell-ellipsis mono" title={s.name}>{s.name}</span></td>
      <td className="sd-fit">
        <span className={`badge ${EXPOSURE_BADGE[s.exposure]}`} title={EXPOSURE_TIPS[s.exposure]}>
          {authorized && s.exposure === 'internal' ? 'Internal (authorized)' : EXPOSURE_LABELS[s.exposure]}
        </span>
        {s.flags.filter((f) => f !== 'internal_authorized' || s.exposure !== 'internal').map((f) => (
          <span key={f} className={`badge ${FLAG_BADGE[f]}`} title={`${FLAG_LABELS[f]}: ${FLAG_TIPS[f]}`} style={{ marginLeft: 4 }}>{FLAG_SHORT[f]}</span>
        ))}
      </td>
      <td className="small sd-flex"><span className="cell-ellipsis" title={[
        s.records.internal && `internal: ${[...s.records.internal.a, ...s.records.internal.aaaa, ...s.records.internal.cname].join(', ') || '-'}`,
        s.records.public && `public: ${[...s.records.public.a, ...s.records.public.aaaa, ...s.records.public.cname].join(', ') || '-'}`,
      ].filter(Boolean).join('\n')}>{s.records_summary}</span></td>
      <td className="sd-flex sd-ips"><span className="cell-ellipsis mono small" title={s.ips.join('\n')}>{s.ips.join(', ') || '-'}</span></td>
      <td className={`small ${hostingFlex ? 'sd-flex sd-hosting' : 'sd-fit'}`}><HostingCell s={s} /></td>
      <td className="small sd-fit" title={s.sources.map((src) => `${SOURCE_LABELS[src]}: ${SOURCE_TIPS[src]}`).join('\n')}>
        {sourcesText(s.sources)}
      </td>
      {showWildcard && <td className="sd-fit">{s.wildcard ? <span className="badge medium" title={wildcardTip(domain.name, domain.wildcard)}>Wildcard</span> : null}</td>}
      <td className="small sd-fit" title={fmtTime(s.first_seen)}>{relTime(s.first_seen)}</td>
      <td className="small sd-fit" title={fmtTime(s.last_seen)}>{relTime(s.last_seen)}</td>
      <td className="sd-fit"><span className={`badge ${st.badge}`} title={subdomainStatusTip(s, fmtTime)} data-testid="subdomain-status">{st.label}</span></td>
    </tr>
  );
}

export default function DomainDetail() {
  const { id } = useParams();
  const { isAdmin } = useApp();
  const [sp, setSp] = useSearchParams();
  const [qInput, setQInput] = useState(sp.get('q') ?? '');
  const [draft, setDraft] = useState<DomainDraft | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const { pending, track } = useInFlight();
  // Poll only while a scan is queued / running (useApi also skips ticks while the tab is hidden).
  const [pollMs, setPollMs] = useState<number | undefined>(undefined);
  const domain = useApi<Domain>(`/domains/${id}`, undefined, pollMs);
  const subs = useApi<Paged<Subdomain>>(`/domains/${id}/subdomains`, subdomainQuery(sp, PAGE), pollMs);
  const scans = useApi<Paged<DomainScanJob>>(`/domains/${id}/scans`, { page_size: 20 }, pollMs);
  const wasActive = useRef(false);
  const lastStatus = domain.data?.last_scan?.status;
  useEffect(() => {
    const next = scanPollMs(domain.data?.last_scan);
    setPollMs(next);
    if (wasActive.current && next === undefined) {
      // The scan just ended: one last refresh of the final inventory and history.
      subs.reload();
      scans.reload();
    }
    wasActive.current = next !== undefined;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastStatus, domain.data?.last_scan?.id]);

  const set = (patch: Partial<Record<SubdomainFilterKey, string | undefined>>, replace = false) => setSp(patchParams(sp, patch), { replace });
  useEffect(() => {
    const t = window.setTimeout(() => {
      if ((sp.get('q') ?? '') !== qInput) set({ q: qInput || undefined }, true);
    }, 300);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qInput]);

  const d = domain.data;
  if (domain.error && !d) return <Card title="Domain"><ErrorBox error={domain.error} /></Card>;
  if (!d) return <Loading />;
  const last = d.last_scan;
  const active = !!last && (last.status === 'queued' || last.status === 'running');
  const sort = sp.get('sort') ?? 'name';
  // The Wildcard column only when a listed row is wildcard (the "Wildcard only" filter stays); Hosting
  // shrinks to a compact "-" column when no listed row has hosting data.
  const showWildcard = !!subs.data?.items.some((s) => s.wildcard);
  const hostingFlex = !!subs.data?.items.some((s) => s.hosting.length);
  const sortTh = (key: string, label: string, className?: string) => (
    <SortTh className={className} active={sort.replace('-', '') === key} desc={sort.startsWith('-')}
      onSort={() => set({ sort: sort === key ? `-${key}` : key })}>{label}</SortTh>
  );

  const scanNow = () => track('scan', async () => {
    setActionError(null);
    try {
      await post(`/domains/${d.id}/scan`);
      domain.reload();
      scans.reload();
    } catch (e: any) {
      setActionError(e.message);
    }
  });
  const cancel = () => last && track('cancel', async () => {
    setActionError(null);
    try {
      await post(`/domain-scans/${last.id}/cancel`);
      domain.reload();
      scans.reload();
    } catch (e: any) {
      setActionError(e.message);
    }
  });
  const reloadAll = () => { domain.reload(); subs.reload(); scans.reload(); };

  return (
    <>
      <div className="page-head">
        <div>
          <div className="small muted"><Link to="/domains">Domains</Link></div>
          <h1 className="mono">{d.name}</h1>
          <p>
            {d.passive_enabled ? 'Passive' : 'No passive'} · {d.wordlist_mode === 'none' ? 'no wordlist' : d.wordlist_mode === 'library' ? `wordlist ${d.wordlist_name ?? '(missing)'}` : `${d.custom_words.length} typed subdomains`}
            {d.wordlist_mode !== 'none' && wordlistTruncationNote(d.wordlist_entries, d.wordlist_limit) && (
              <span className="badge medium" style={{ marginLeft: 6 }} data-testid="wordlist-truncated">
                {wordlistTruncationNote(d.wordlist_entries, d.wordlist_limit)}
              </span>
            )}
            {' · '}{d.axfr_enabled ? `AXFR from ${d.axfr_servers.join(', ') || 'internal resolvers'}` : 'no AXFR'}
            {' · '}internal {d.internal_resolvers.join(', ') || 'system resolver'} · public {d.public_resolvers.join(', ')}
          </p>
        </div>
        {isAdmin && (
          <div className="row">
            {active
              ? <button className="btn warn" disabled={pending('cancel')} onClick={cancel}>Cancel scan</button>
              : <button className="btn primary" disabled={pending('scan')} onClick={scanNow} data-testid="domain-scan-now">Scan now</button>}
            <button className="btn" onClick={() => setDraft(draftFromDomain(d))}>Edit</button>
          </div>
        )}
      </div>
      <ErrorBox error={actionError} />
      {d.zone_transfer_open.length > 0 && (
        <div className="alert error" role="alert">
          Zone transfer open: {d.zone_transfer_open.join(', ')} answered AXFR from the scan host. Anyone on the internet can list the whole zone.
        </div>
      )}
      {active && last && <DomainScanProgress scan={last} />}
      <div className="grid kpis five">
        <Kpi label="Subdomains" value={d.counts.active} onClick={() => set({ exposure: undefined, status: undefined })} />
        {(['external', 'internal', 'both'] as Exposure[]).map((e) => (
          <Kpi key={e} label={EXPOSURE_LABELS[e]} value={d.counts[e]} active={sp.get('exposure') === e}
            onClick={() => set({ exposure: sp.get('exposure') === e ? undefined : e })} />
        ))}
        <Kpi label="Wildcard" value={d.counts.wildcard} active={sp.get('wildcard') === '1'}
          sub={d.wildcard.public.length || d.wildcard.internal.length ? 'wildcard DNS detected' : undefined}
          onClick={() => set({ wildcard: sp.get('wildcard') === '1' ? undefined : '1' })} />
      </div>
      {isAdmin && <DomainLookup domains={[d.name]} onChanged={reloadAll} />}
      <Card flush title={
        <div className="row wrap" style={{ gap: 8, flex: 1 }}>
          <input type="search" placeholder="Search name or IP…" value={qInput} onChange={(e) => setQInput(e.target.value)} style={{ minWidth: 220, flex: 1 }} aria-label="Search subdomains" />
          <select value={sp.get('exposure') ?? ''} onChange={(e) => set({ exposure: e.target.value || undefined })} aria-label="Exposure">
            <option value="">All exposures</option>
            {(Object.keys(EXPOSURE_LABELS) as Exposure[]).map((e) => <option key={e} value={e}>{EXPOSURE_LABELS[e]}</option>)}
          </select>
          <select value={sp.get('source') ?? ''} onChange={(e) => set({ source: e.target.value || undefined })} aria-label="Source">
            <option value="">All sources</option>
            {(Object.keys(SOURCE_LABELS) as SubdomainSource[]).map((s) => <option key={s} value={s}>{SOURCE_LABELS[s]}</option>)}
          </select>
          <select value={sp.get('flag') ?? ''} onChange={(e) => set({ flag: e.target.value || undefined })} aria-label="Finding">
            <option value="">All findings</option>
            {(Object.keys(FLAG_LABELS) as SubdomainFlag[]).map((f) => <option key={f} value={f}>{FLAG_LABELS[f]}</option>)}
          </select>
          <select value={sp.get('status') ?? 'active'} onChange={(e) => set({ status: e.target.value === 'active' ? undefined : e.target.value })} aria-label="Status">
            <option value="active">Active</option><option value="gone">Gone</option><option value="all">All</option>
          </select>
          <label className="check small"><input type="checkbox" checked={sp.get('wildcard') === '1'} onChange={(e) => set({ wildcard: e.target.checked ? '1' : undefined })} />Wildcard only</label>
          {activeFilterCount(sp) > 0 && <button className="btn sm ghost" onClick={() => { setQInput(''); setSp(new URLSearchParams()); }}>Clear</button>}
        </div>
      }>
        <ErrorBox error={subs.error} />
        {subs.loading && !subs.data ? <SkeletonRows cols={10} /> : !subs.data?.items.length ? (
          <Empty>{d.last_scan ? 'No subdomains match these filters.' : 'No scan yet. Run a scan to build the inventory.'}</Empty>
        ) : (
          <div className="table-wrap">
            <table className="domain-table subdomain-table" data-testid="subdomain-table">
              <thead>
                <tr>
                  {sortTh('name', 'Name', 'sd-name')}
                  {sortTh('exposure', 'Exposure', 'sd-fit')}
                  <th className="sd-flex">Records</th>
                  <th className="sd-flex sd-ips">IPs</th>
                  <th className={hostingFlex ? 'sd-flex sd-hosting' : 'sd-fit'}>Hosting</th>
                  <th className="sd-fit">Sources</th>
                  {showWildcard && <th className="sd-fit">Wildcard</th>}
                  {sortTh('first_seen', 'First seen', 'sd-fit')}
                  {sortTh('last_seen', 'Last seen', 'sd-fit')}
                  {sortTh('status', 'Status', 'sd-fit')}
                </tr>
              </thead>
              <tbody>{subs.data.items.map((s) => <SubdomainRow key={s.id} s={s} domain={d} showWildcard={showWildcard} hostingFlex={hostingFlex} />)}</tbody>
            </table>
          </div>
        )}
        {subs.data && <Pager page={Number(sp.get('page') || 1)} pageSize={PAGE} total={subs.data.total} onPage={(p) => set({ page: String(p) })} />}
      </Card>
      <Card title="Scan history" flush>
        <ErrorBox error={scans.error} />
        {!scans.data?.items.length ? <Empty>No scans yet.</Empty> : (
          <div className="table-wrap">
            <table className="domain-table">
              <thead><tr><th>#</th><th>Status</th><th>Trigger</th><th>Started</th><th>Duration</th><th className="domain-col-fluid">Summary</th><th>Port scan</th></tr></thead>
              <tbody>
                {scans.data.items.map((j) => (
                  <tr key={j.id}>
                    <td>{j.id}</td>
                    <td className="nowrap">
                      <ScanStatusBadge status={j.status} />
                      {problemPhases(j.phases).length > 0 && (
                        <span className="badge high" style={{ marginLeft: 4 }} title={problemPhases(j.phases).map((p) => `${p.label}: ${p.reason ?? p.status}`).join('\n')}>
                          {problemPhases(j.phases).length} phase(s)
                        </span>
                      )}
                    </td>
                    <td className="small">{j.trigger}{j.requested_by ? ` · ${j.requested_by}` : ''}</td>
                    <td className="nowrap small" title={fmtTime(j.started_at ?? j.created_at)}>{relTime(j.started_at ?? j.created_at)}</td>
                    <td className="nowrap small" title={phaseSummaryTip(j.phases) || undefined}>{j.started_at ? duration(j.started_at, j.finished_at) : '-'}</td>
                    <td className="domain-col-fluid small">
                      <span className="cell-clamp-2" title={[scanSummary(j), j.notes].filter(Boolean).join('\n')}>{scanSummary(j)}</span>
                    </td>
                    <td className="small">{j.port_scan_id ? <Link to="/scans">#{j.port_scan_id}</Link> : <span className="muted">-</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {draft && <DomainDialog initial={draft} onClose={() => setDraft(null)} onSaved={() => { setDraft(null); reloadAll(); }} />}
    </>
  );
}
