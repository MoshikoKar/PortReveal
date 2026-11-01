import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { del, post } from '../api';
import { DomainDialog } from '../components/DomainDialog';
import { DomainLookup } from '../components/DomainLookup';
import { ScoreCell } from '../components/SubdomainIntel';
import { Card, Empty, ErrorBox, ScanStatusBadge, SkeletonRows } from '../components/ui';
import { useApp } from '../context';
import { type DomainDraft, draftFromDomain, emptyDraft } from '../domains';
import type { Domain } from '../types';
import { DAYS, fmtTime, relTime, useApi, useInFlight } from '../util';

function scheduleText(d: Domain): string {
  const s = d.schedule;
  if (!s?.enabled) return 'manual';
  const days = s.days.length === 7 ? 'daily' : s.days.map((i) => DAYS[i]).join(' ');
  return `${days} ${s.time}`;
}

function IconScan({ spinning }: { spinning?: boolean }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
      style={spinning ? { animation: 'nf-spin 0.8s linear infinite' } : undefined} aria-hidden>
      <path d="M21 12a9 9 0 1 1-2.6-6.4" />
      <polyline points="21 3 21 9 15 9" />
    </svg>
  );
}

function IconEdit() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M12 20h9" />
      <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z" />
    </svg>
  );
}

function IconDelete() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M3 6h18" />
      <path d="M8 6V4h8v2" />
      <path d="M19 6l-1 14H6L5 6" />
    </svg>
  );
}

/** Tools status line: Domain scans still run without them (resolution, AXFR), just with fewer sources. */
function ToolsNotice() {
  const { system } = useApp();
  const tools = system?.domain_scans?.tools;
  if (!tools) return null;
  const missing = Object.values(tools).filter((t) => !t.found).map((t) => t.name);
  if (!missing.length) return null;
  return (
    <div className="alert warn" role="status">
      {missing.join(' and ')} not installed: {missing.includes('subfinder') && 'passive enumeration'}
      {missing.length === 2 && ' and '}{missing.includes('dnsx') && 'wordlist brute force'} will be skipped.
      Install with <code>npm run setup:capture-tools</code> (Windows) or <code>npm run setup</code> (Linux); see <Link to="/settings/health">System health</Link>.
    </div>
  );
}

export default function Domains() {
  const { isAdmin } = useApp();
  const nav = useNavigate();
  const { data, error, loading, reload } = useApi<Domain[]>('/domains', undefined, 15000);
  const [draft, setDraft] = useState<DomainDraft | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const { pending, track } = useInFlight();

  const scan = (d: Domain) => track(`scan-${d.id}`, async () => {
    setActionError(null);
    try {
      await post(`/domains/${d.id}/scan`);
      reload();
    } catch (e: any) {
      setActionError(`Could not start the scan of ${d.name}: ${e.message}`);
    }
  });

  const remove = (d: Domain) => {
    if (!confirm(`Delete ${d.name}, its subdomain inventory and scan history?`)) return;
    track(`del-${d.id}`, async () => {
      setActionError(null);
      try {
        await del(`/domains/${d.id}`);
        reload();
      } catch (e: any) {
        setActionError(`Could not delete ${d.name}: ${e.message}`);
      }
    });
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Domains</h1>
          <p>Subdomain inventory per domain: what an outside attacker can find (passive sources, wordlist), checked against your own zone transfer.</p>
        </div>
        {isAdmin && <button className="btn primary" onClick={() => setDraft(emptyDraft())}>Add domain</button>}
      </div>
      <ToolsNotice />
      {isAdmin && data && data.length > 0 && <DomainLookup domains={data.map((d) => d.name)} onChanged={reload} />}
      <Card title="Domains" flush>
        <ErrorBox error={error || actionError} />
        {loading && !data ? <SkeletonRows cols={11} /> : !data?.length ? (
          <Empty>No domains yet.{isAdmin ? ' Add one to start the subdomain inventory.' : ''}</Empty>
        ) : (
          <div className="table-wrap">
            <table className="domain-table domains-list-table">
              <thead>
                <tr>
                  <th className="domain-col-name">Domain</th>
                  <th className="right dl-fit">Subdomains</th>
                  <th className="right dl-fit" title="Resolves publicly only">External</th>
                  <th className="right dl-fit" title="Resolves internally only">Internal</th>
                  <th className="right dl-fit" title="Split DNS: resolves on both">Both</th>
                  <th className="right dl-fit">Wildcard</th>
                  <th className="dl-fit" title="Highest combined score among the active subdomains (from their linked devices)">Top risk</th>
                  <th className="right dl-fit" title="Active subdomains with a high combined score">High risk</th>
                  <th className="right dl-fit" title="Active subdomains whose linked devices have open ports">With ports</th>
                  <th className="dl-fluid" title="Last scan">Last scan</th>
                  <th className="dl-fluid" title="Schedule">Schedule</th>
                  {isAdmin && <th className="dl-fit" />}
                </tr>
              </thead>
              <tbody>
                {data.map((d) => {
                  const last = d.last_scan;
                  const active = last && (last.status === 'queued' || last.status === 'running');
                  const lastAt = last ? (last.finished_at ?? last.created_at) : null;
                  const lastTitle = last ? `${last.status}${lastAt ? ` · ${fmtTime(lastAt)}` : ''}` : 'never';
                  const sched = scheduleText(d);
                  const scanBusy = !!active || pending(`scan-${d.id}`);
                  return (
                    <tr key={d.id} className={`clickable${d.enabled ? '' : ' dim'}`} onClick={() => nav(`/domains/${d.id}`)}>
                      <td className="domain-col-name">
                        <span className="cell-ellipsis" title={d.name}>
                          <Link to={`/domains/${d.id}`} onClick={(e) => e.stopPropagation()}>{d.name}</Link>
                          {!d.enabled && <span className="badge outline" style={{ marginLeft: 6 }}>disabled</span>}
                          {d.zone_transfer_open.length > 0 && (
                            <span className="badge high" style={{ marginLeft: 6 }} title={`Zone transfer open: ${d.zone_transfer_open.join(', ')}`}>AXFR open</span>
                          )}
                        </span>
                      </td>
                      <td className="right dl-fit">{d.counts.active.toLocaleString()}</td>
                      <td className="right dl-fit">{d.counts.external.toLocaleString()}</td>
                      <td className="right dl-fit">{d.counts.internal.toLocaleString()}</td>
                      <td className="right dl-fit">{d.counts.both.toLocaleString()}</td>
                      <td className="right dl-fit">{d.counts.wildcard ? d.counts.wildcard.toLocaleString() : <span className="muted">-</span>}</td>
                      <td className="dl-fit" data-testid="domain-top-risk"><ScoreCell score={d.risk.max_combined_score} kind="combined" /></td>
                      <td className="right dl-fit">
                        {d.risk.high_risk ? <Link className="badge high" to={`/domains/${d.id}?score=high`} onClick={(e) => e.stopPropagation()}>{d.risk.high_risk.toLocaleString()}</Link> : <span className="muted">0</span>}
                      </td>
                      <td className="right dl-fit">
                        {d.risk.with_open_ports ? <Link to={`/domains/${d.id}?has_ports=1&sort=-open_ports_count`} onClick={(e) => e.stopPropagation()}>{d.risk.with_open_ports.toLocaleString()}</Link> : <span className="muted">0</span>}
                      </td>
                      <td className="dl-fluid" title={lastTitle}>
                        <span className="cell-ellipsis">
                          {last ? <><ScanStatusBadge status={last.status} /> <span className="muted small">{relTime(lastAt)}</span></>
                            : <span className="muted">never</span>}
                        </span>
                      </td>
                      <td className="dl-fluid small" title={sched}><span className="cell-ellipsis">{sched}</span></td>
                      {isAdmin && (
                        <td className="right nowrap dl-fit" onClick={(e) => e.stopPropagation()}>
                          <button className="btn icon sm" title={active ? 'Scanning…' : 'Scan now'} aria-label={active ? 'Scanning…' : 'Scan now'} disabled={scanBusy} onClick={() => scan(d)}>
                            <IconScan spinning={scanBusy} />
                          </button>
                          <button className="btn ghost icon sm" title="Edit" aria-label="Edit" onClick={() => setDraft(draftFromDomain(d))}>
                            <IconEdit />
                          </button>
                          <button className="btn danger icon sm" title="Delete" aria-label="Delete" disabled={pending(`del-${d.id}`)} onClick={() => remove(d)}>
                            <IconDelete />
                          </button>
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {draft && (
        <DomainDialog initial={draft} onClose={() => setDraft(null)} onSaved={(d) => { setDraft(null); reload(); if (!draft.id) nav(`/domains/${d.id}`); }} />
      )}
    </>
  );
}
