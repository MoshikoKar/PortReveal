import { Fragment, useEffect, useRef, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { post } from '../api';
import { DomainDialog } from '../components/DomainDialog';
import { DomainLookup } from '../components/DomainLookup';
import { DomainScanProgress } from '../components/DomainScanProgress';
import { PortsCell, ScoreCell } from '../components/SubdomainIntel';
import { Card, Empty, ErrorBox, Kpi, Loading, Pager, ScanStatusBadge, SkeletonRows, SortTh } from '../components/ui';
import { useApp } from '../context';
import {
  EXPOSURE_BADGE, EXPOSURE_LABELS, EXPOSURE_TIPS, FLAG_LABELS, PAGE_SIZES, ROW_STATUS, SCORE_FILTER_LABELS, SOURCE_LABELS,
  SOURCE_TIPS, SUBDOMAIN_COLUMNS, sourcesText, subdomainStatus, subdomainStatusTip,
  type DomainDraft, type SubdomainFilterKey, activeFilterCount, draftFromDomain, hostingLabel, hostingShort, ipsCell,
  pageSizeParam, patchParams, phaseSummaryTip, problemPhases, scanPollMs, subdomainFindings, subdomainQuery, wildcardTip,
  wordlistTruncationNote,
} from '../domains';
import type { Domain, DomainScanJob, Exposure, Paged, Subdomain, SubdomainCounts, SubdomainFlag, SubdomainSource } from '../types';
import { duration, fmtTime, relTime, useApi, useInFlight } from '../util';

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
  const first = s.hosting.find((h) => h.device_uuid) ?? s.hosting.find((h) => h.kind === 'network') ?? s.hosting[0];
  const title = s.hosting.map((h) => `${h.ip}: ${hostingLabel(h)}`).join('\n');
  return (
    <span className="cell-ellipsis" title={title}>
      {first.device_uuid ? <Link to={`/devices/${first.device_uuid}`}>{hostingShort(first)}</Link> : hostingShort(first)}
      {s.hosting.length > 1 && <span className="muted"> +{s.hosting.length - 1}</span>}
    </span>
  );
}

function IpsCell({ s }: { s: Subdomain }) {
  const c = ipsCell(s.ips);
  if (!c.first) return <span className="muted">-</span>;
  const dev = s.hosting.find((h) => h.ip === c.first)?.device_uuid;
  return (
    <span className="sd-ips-cell" title={c.title}>
      <span className="mono small">{dev ? <Link to={`/devices/${dev}`}>{c.first}</Link> : c.first}</span>
      {c.more > 0 && <span className="muted small">+{c.more}</span>}
    </span>
  );
}

function SubdomainRow({ s, domain }: { s: Subdomain; domain: Domain }) {
  const st = ROW_STATUS[subdomainStatus(s)];
  const findings = subdomainFindings(s, wildcardTip(domain.name, domain.wildcard));
  return (
    <tr className={s.status === 'gone' ? 'dim' : undefined}>
      <td className="sd-name">
        {/* Records and Sources drop out of narrow tables (styles.css): the name's title carries them too. */}
        <Link className="cell-ellipsis mono" title={`${s.name}\nRecords: ${s.records_summary}\nSources: ${sourcesText(s.sources)}`}
          to={`/domains/${domain.id}/subdomains/${s.id}`}>{s.name}</Link>
      </td>
      <td className="sd-fit sd-exposure">
        <span className={`badge ${EXPOSURE_BADGE[s.exposure]}`} title={EXPOSURE_TIPS[s.exposure]}>{EXPOSURE_LABELS[s.exposure]}</span>
      </td>
      <td className="sd-fit sd-findings-col" data-testid="subdomain-findings">
        {findings.length ? (
          <span className="sd-findings" title={findings.map((f) => `${f.label}: ${f.tip}`).join('\n')}>
            <span className={`badge ${findings[0].badge}`}>{findings[0].short}</span>
            {findings.length > 1 && <span className="muted small">+{findings.length - 1}</span>}
          </span>
        ) : <span className="muted">-</span>}
      </td>
      <td className="sd-fit sd-score" data-testid="subdomain-exposure-score"><ScoreCell score={s.exposure_score} kind="exposure" /></td>
      <td className="sd-fit sd-score"><ScoreCell score={s.risk_score} kind="risk" /></td>
      <td className="sd-fit sd-score" data-testid="subdomain-combined-score"><ScoreCell score={s.combined_score} kind="combined" /></td>
      <td className="sd-fit small" data-testid="subdomain-ports"><PortsCell s={s} /></td>
      <td className="sd-fit sd-ips"><IpsCell s={s} /></td>
      <td className="small sd-flex sd-records"><span className="cell-ellipsis" title={[
        s.records.internal && `internal: ${[...s.records.internal.a, ...s.records.internal.aaaa, ...s.records.internal.cname].join(', ') || '-'}`,
        s.records.public && `public: ${[...s.records.public.a, ...s.records.public.aaaa, ...s.records.public.cname].join(', ') || '-'}`,
      ].filter(Boolean).join('\n')}>{s.records_summary}</span></td>
      <td className="small sd-flex sd-hosting"><HostingCell s={s} /></td>
      <td className="small sd-flex sd-sources">
        <span className="cell-ellipsis" title={s.sources.map((src) => `${SOURCE_LABELS[src]}: ${SOURCE_TIPS[src]}`).join('\n')}>{sourcesText(s.sources)}</span>
      </td>
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
  // Poll only while a scan is queued / running (useApi also skips ticks while the tab is hidden); only
  // the current inventory page and the counters refresh, the scan history once the scan ends.
  const [pollMs, setPollMs] = useState<number | undefined>(undefined);
  const pageSize = pageSizeParam(sp);
  const domain = useApi<Domain>(`/domains/${id}`, undefined, pollMs);
  const counts = useApi<SubdomainCounts>(`/domains/${id}/subdomains/counts`, undefined, pollMs);
  const subs = useApi<Paged<Subdomain>>(`/domains/${id}/subdomains`, subdomainQuery(sp, pageSize), pollMs);
  const scans = useApi<Paged<DomainScanJob>>(`/domains/${id}/scans`, { page_size: 20 });
  const wasActive = useRef(false);
  const lastStatus = domain.data?.last_scan?.status;
  useEffect(() => {
    const next = scanPollMs(domain.data?.last_scan);
    setPollMs(next);
    if (wasActive.current && next === undefined) {
      // The scan just ended: one last refresh of the final inventory, counters and history.
      subs.reload();
      counts.reload();
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
  const c = counts.data ?? d.counts;
  // Scores and counts start largest-first, like the Devices list.
  const descFirst = ['combined_score', 'exposure_score', 'open_ports_count'];
  const sortTh = (key: string, label: string, className?: string, title?: string) => (
    <SortTh className={className} active={sort.replace('-', '') === key} desc={sort.startsWith('-')}
      onSort={() => set({ sort: sort === key ? `-${key}` : sort === `-${key}` || !descFirst.includes(key) ? key : `-${key}` })}>
      <span title={title}>{label}</span>
    </SortTh>
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
  const reloadAll = () => { domain.reload(); counts.reload(); subs.reload(); scans.reload(); };

  return (
    <>
      <div className="page-head">
        <div>
          <div className="small muted"><Link to="/domains">Domains</Link></div>
          <h1 className="page-title-ellipsis"><span className="mono" title={d.name}>{d.name}</span></h1>
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
        <Kpi label="Subdomains" value={c.active} onClick={() => set({ exposure: undefined, status: undefined })} />
        {(['external', 'internal', 'both'] as Exposure[]).map((e) => (
          <Kpi key={e} label={EXPOSURE_LABELS[e]} value={c[e]} active={sp.get('exposure') === e}
            onClick={() => set({ exposure: sp.get('exposure') === e ? undefined : e })} />
        ))}
        <Kpi label="Wildcard" value={c.wildcard} active={sp.get('wildcard') === '1'}
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
          <select value={sp.get('score') ?? ''} onChange={(e) => set({ score: e.target.value || undefined })} aria-label="Combined score">
            <option value="">All scores</option>
            {(Object.keys(SCORE_FILTER_LABELS) as (keyof typeof SCORE_FILTER_LABELS)[]).map((k) => <option key={k} value={k}>{SCORE_FILTER_LABELS[k]}</option>)}
          </select>
          <label className="check small"><input type="checkbox" checked={sp.get('has_ports') === '1'} onChange={(e) => set({ has_ports: e.target.checked ? '1' : undefined })} />Has open ports</label>
          <label className="check small"><input type="checkbox" checked={sp.get('has_web') === '1'} onChange={(e) => set({ has_web: e.target.checked ? '1' : undefined })} />Has web preview</label>
          <label className="check small"><input type="checkbox" checked={sp.get('wildcard') === '1'} onChange={(e) => set({ wildcard: e.target.checked ? '1' : undefined })} />Wildcard only</label>
          {activeFilterCount(sp) > 0 && <button className="btn sm ghost" onClick={() => { setQInput(''); setSp(patchParams(new URLSearchParams(), { page_size: sp.get('page_size') ?? undefined })); }}>Clear</button>}
        </div>
      }>
        <ErrorBox error={subs.error} />
        {subs.loading && !subs.data ? <SkeletonRows cols={SUBDOMAIN_COLUMNS.length} /> : !subs.data?.items.length ? (
          <Empty>{d.last_scan ? 'No subdomains match these filters.' : 'No scan yet. Run a scan to build the inventory.'}</Empty>
        ) : (
          <div className="table-wrap subdomain-table-wrap">
            <table className="domain-table subdomain-table" data-testid="subdomain-table">
              <thead>
                <tr>
                  {SUBDOMAIN_COLUMNS.map((col) => (col.sort
                    ? <Fragment key={col.key}>{sortTh(col.sort, col.label, col.className, col.title)}</Fragment>
                    : <th key={col.key} className={col.className} title={col.title}>{col.label}</th>))}
                </tr>
              </thead>
              <tbody>{subs.data.items.map((s) => <SubdomainRow key={s.id} s={s} domain={d} />)}</tbody>
            </table>
          </div>
        )}
        {subs.data && (
          <Pager page={Number(sp.get('page') || 1)} pageSize={pageSize} total={subs.data.total} onPage={(p) => set({ page: String(p) })}
            pageSizes={PAGE_SIZES} onPageSize={(n) => set({ page_size: String(n) })} />
        )}
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
