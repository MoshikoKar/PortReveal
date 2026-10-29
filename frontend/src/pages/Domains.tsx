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
                  <th className="right">Subdomains</th>
                  <th className="right" title="Resolves publicly only">External</th>
                  <th className="right" title="Resolves internally only">Internal</th>
                  <th className="right" title="Split DNS: resolves on both">Both</th>
                  <th className="right">Wildcard</th>
                  <th title="Highest combined score among the active subdomains (from their linked devices)">Top risk</th>
                  <th className="right" title="Active subdomains with a high combined score">High risk</th>
                  <th className="right" title="Active subdomains whose linked devices have open ports">With ports</th>
                  <th>Last scan</th>
                  <th>Schedule</th>
                  {isAdmin && <th />}
                </tr>
              </thead>
              <tbody>
                {data.map((d) => {
                  const last = d.last_scan;
                  const active = last && (last.status === 'queued' || last.status === 'running');
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
                      <td className="right">{d.counts.active.toLocaleString()}</td>
                      <td className="right">{d.counts.external.toLocaleString()}</td>
                      <td className="right">{d.counts.internal.toLocaleString()}</td>
                      <td className="right">{d.counts.both.toLocaleString()}</td>
                      <td className="right">{d.counts.wildcard ? d.counts.wildcard.toLocaleString() : <span className="muted">-</span>}</td>
                      <td data-testid="domain-top-risk"><ScoreCell score={d.risk.max_combined_score} kind="combined" /></td>
                      <td className="right">
                        {d.risk.high_risk ? <Link className="badge high" to={`/domains/${d.id}?score=high`} onClick={(e) => e.stopPropagation()}>{d.risk.high_risk.toLocaleString()}</Link> : <span className="muted">0</span>}
                      </td>
                      <td className="right">
                        {d.risk.with_open_ports ? <Link to={`/domains/${d.id}?has_ports=1&sort=-open_ports_count`} onClick={(e) => e.stopPropagation()}>{d.risk.with_open_ports.toLocaleString()}</Link> : <span className="muted">0</span>}
                      </td>
                      <td className="nowrap">
                        {last ? <><ScanStatusBadge status={last.status} /> <span className="muted small" title={fmtTime(last.finished_at ?? last.created_at)}>{relTime(last.finished_at ?? last.created_at)}</span></>
                          : <span className="muted">never</span>}
                      </td>
                      <td className="nowrap small">{scheduleText(d)}</td>
                      {isAdmin && (
                        <td className="right nowrap" onClick={(e) => e.stopPropagation()}>
                          <button className="btn sm" disabled={!!active || pending(`scan-${d.id}`)} onClick={() => scan(d)}>{active ? 'Scanning…' : 'Scan now'}</button>
                          <button className="btn ghost sm" onClick={() => setDraft(draftFromDomain(d))}>Edit</button>
                          <button className="btn danger sm" disabled={pending(`del-${d.id}`)} onClick={() => remove(d)}>Delete</button>
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
