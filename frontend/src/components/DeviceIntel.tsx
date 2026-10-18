import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { del, post, put } from '../api';
import type { DeviceDetail, DeviceProfile, DeviceVuln, TimelineItem } from '../types';
import { CRITICALITY_LEVELS, EVENT_LABELS, SCAN_TYPE_LABELS, fmtTime, useApi } from '../util';
import { Card, Empty, ErrorBox, Loading, Modal, RiskBadge, ScanStatusBadge, ScoreBadge, confirmDiscard } from './ui';

const TIMELINE_LIMIT = 100;
const TIMELINE_PREVIEW = 10;

function tagTitle(t: { source: string; reason: string | null }) {
  const kind = t.source === 'manual' ? 'Manual' : t.source === 'suppressed' ? 'Dismissed' : 'Rule';
  return `${kind} tag${t.reason ? `: ${t.reason}` : ''}`;
}

function tagChipClass(source: string) {
  if (source === 'manual') return 'chip on';
  if (source === 'suppressed') return 'chip suppressed';
  return 'chip';
}

function tagActionTitle(source: string) {
  if (source === 'manual') return 'Remove tag';
  if (source === 'suppressed') return 'Clear dismiss (auto may return)';
  return 'Dismiss tag (stays off after rescans)';
}

/** Rule tags (recomputed each scan), manual pins, and admin-dismissed suppressions. */
export function TagEditor({ d, isAdmin, onChange }: { d: DeviceDetail; isAdmin: boolean; onChange: () => void }) {
  const [tag, setTag] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const add = async (e: FormEvent) => {
    e.preventDefault();
    if (!tag.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await post(`/devices/${d.uuid}/tags`, { tag: tag.trim() });
      setTag('');
      onChange();
    } catch (ex: any) {
      setError(ex.message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (t: string) => {
    setError(null);
    try {
      await del(`/devices/${d.uuid}/tags/${encodeURIComponent(t)}`);
      onChange();
    } catch (ex: any) {
      setError(ex.message);
    }
  };

  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="row wrap" style={{ gap: 6 }}>
        {d.tags.length === 0 && <span className="muted small">No tags.</span>}
        {d.tags.map((t) => (
          <span key={t.tag} className={tagChipClass(t.source)} title={tagTitle(t)}>
            {t.source === 'suppressed' ? (
              <span>{t.tag}</span>
            ) : (
              <Link to={`/search?q=${encodeURIComponent(`tag:${t.tag}`)}`}>{t.tag}</Link>
            )}
            {isAdmin && (
              <button className="chip-x" onClick={() => remove(t.tag)} aria-label={`${tagActionTitle(t.source)} ${t.tag}`} title={tagActionTitle(t.source)}>×</button>
            )}
          </span>
        ))}
      </div>
      {isAdmin && (
        <form className="row" onSubmit={add}>
          <input type="text" value={tag} onChange={(e) => setTag(e.target.value)} maxLength={60} placeholder="add tag (a-z, 0-9, -)" aria-label="New tag" />
          <button className="btn sm" type="submit" disabled={busy || !tag.trim()}>Add</button>
        </form>
      )}
      {isAdmin && (
        <div className="muted small">
          Rule tags recompute each scan. × dismisses a rule tag so it stays off; × on a dismissed tag clears the dismiss.
          Adding a rule or dismissed tag pins it as manual.
        </div>
      )}
      <ErrorBox error={error} />
    </div>
  );
}

type ProfileDraft = { owner: string; location: string; criticality: string; notes: string };

function toDraft(p: DeviceProfile): ProfileDraft {
  return { owner: p.owner ?? '', location: p.location ?? '', criticality: p.criticality ?? '', notes: p.notes ?? '' };
}

export function ProfileCard({ d, isAdmin, onChange }: { d: DeviceDetail; isAdmin: boolean; onChange: () => void }) {
  const [draft, setDraft] = useState<ProfileDraft | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const initial = toDraft(d.profile);
  const dirty = draft !== null && JSON.stringify(draft) !== JSON.stringify(initial);
  const p = d.profile;

  const save = async () => {
    if (!draft || saving) return;
    setSaving(true);
    setError(null);
    try {
      await put(`/devices/${d.uuid}/profile`, {
        owner: draft.owner || null, location: draft.location || null, criticality: draft.criticality || null, notes: draft.notes || null,
      });
      setDraft(null);
      onChange();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card title="Profile" actions={isAdmin && <button className="btn ghost sm" onClick={() => { setDraft(initial); setError(null); }}>Edit</button>}>
      <dl className="dl compact">
        <dt>Owner</dt><dd>{p.owner ?? '—'}</dd>
        <dt>Location</dt><dd>{p.location ?? '—'}</dd>
        <dt>Criticality</dt><dd>{p.criticality ? <span className={`badge ${p.criticality === 'critical' || p.criticality === 'high' ? 'high' : p.criticality === 'medium' ? 'medium' : 'outline'}`}>{p.criticality}</span> : '—'}</dd>
        <dt>Notes</dt><dd style={{ whiteSpace: 'pre-wrap' }}>{p.notes ?? '—'}</dd>
      </dl>
      {draft && (
        <Modal title="Edit profile" onClose={() => setDraft(null)} dirty={dirty} footer={<>
          <button className="btn ghost" onClick={() => confirmDiscard(dirty) && setDraft(null)}>Cancel</button>
          <button className="btn primary" onClick={save} disabled={saving}>{saving ? 'Saving…' : 'Save'}</button>
        </>}>
          <label className="field">Owner<input type="text" value={draft.owner} maxLength={150} onChange={(e) => setDraft({ ...draft, owner: e.target.value })} /></label>
          <label className="field">Location<input type="text" value={draft.location} maxLength={200} onChange={(e) => setDraft({ ...draft, location: e.target.value })} /></label>
          <label className="field">Criticality
            <select value={draft.criticality} onChange={(e) => setDraft({ ...draft, criticality: e.target.value })}>
              <option value="">Not set</option>
              {CRITICALITY_LEVELS.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </label>
          <label className="field">Notes<textarea rows={4} value={draft.notes} maxLength={5000} onChange={(e) => setDraft({ ...draft, notes: e.target.value })} /></label>
          <ErrorBox error={error} />
        </Modal>
      )}
    </Card>
  );
}

export function ExposureCard({ d }: { d: DeviceDetail }) {
  const factors = d.profile.exposure_factors;
  return (
    <Card title={<h2 className="row" style={{ gap: 8 }}>Exposure score <ScoreBadge score={d.score} /></h2>} flush>
      {!d.classified_at ? (
        <div className="card-body muted small">Not scored yet. The score is computed after the next scan or web capture of this device.</div>
      ) : !factors.length ? (
        <div className="card-body muted small">No exposure factors: no risky services, logins or recent first sighting.</div>
      ) : (
        <table>
          <tbody>
            {factors.map((f, i) => (
              <tr key={`${f.factor}-${i}`}>
                <td>{f.detail}</td>
                <td className="right mono nowrap">+{f.points}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

export function RiskCard({ d }: { d: DeviceDetail }) {
  const factors = d.profile.risk_factors;
  return (
    <Card title={<h2 className="row" style={{ gap: 8 }}>Risk score <RiskBadge score={d.risk_score} kind="risk" /></h2>} flush>
      {!d.risk_scored_at ? (
        <div className="card-body muted small">Not scored yet: no vulnerability feed sync has run, or no CVE matched this device's services.</div>
      ) : !factors.length ? (
        <div className="card-body muted small">No known vulnerabilities matched to this device's identified services.</div>
      ) : (
        <table>
          <tbody>
            {factors.map((f, i) => (
              <tr key={`${f.factor}-${i}`}>
                <td>{f.detail}</td>
                <td className="right mono nowrap">+{f.points}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="card-body muted small" style={{ borderTop: '1px solid var(--border)' }}>
        Combined score (risk boosted by exposure): <RiskBadge score={d.combined_score} kind="combined" />
      </div>
    </Card>
  );
}

/** Matched CVEs for this device's open services (spec section 5): confirmed/potential, KEV, EPSS. */
export function VulnPanel({ d, isAdmin, onReload }: { d: DeviceDetail; isAdmin: boolean; onReload: () => void }) {
  const { data, error, reload } = useApi<{ items: DeviceVuln[] }>(`/devices/${d.uuid}/vulns`, undefined, 30000);
  const [busy, setBusy] = useState<string | null>(null);
  const items = data?.items ?? [];
  const active = items.filter((v) => v.state !== 'dismissed');
  const dismissed = items.filter((v) => v.state === 'dismissed');
  const [showDismissed, setShowDismissed] = useState(false);

  const dismiss = async (cve_id: string) => {
    if (busy) return;
    setBusy(cve_id);
    try {
      await post(`/devices/${d.uuid}/vulns/${encodeURIComponent(cve_id)}/dismiss`);
      await reload();
      onReload();
    } finally {
      setBusy(null);
    }
  };
  const undismiss = async (cve_id: string) => {
    if (busy) return;
    setBusy(cve_id);
    try {
      await del(`/devices/${d.uuid}/vulns/${encodeURIComponent(cve_id)}/dismiss`);
      await reload();
      onReload();
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card title="Vulnerabilities" flush
      actions={dismissed.length > 0 && (
        <label className="check small">
          <input type="checkbox" checked={showDismissed} onChange={(e) => setShowDismissed(e.target.checked)} />
          show {dismissed.length} dismissed
        </label>
      )}>
      <ErrorBox error={error} />
      {!data ? (!error && <Loading />) : !active.length && !showDismissed ? (
        <Empty>No matched CVEs for this device's identified services.</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>CVE</th><th>Port / service</th><th>CVSS</th><th>State</th><th></th></tr></thead>
            <tbody>
              {[...active, ...(showDismissed ? dismissed : [])].map((v) => (
                <tr key={v.cve_id} className={v.state === 'dismissed' ? 'dim' : ''}>
                  <td className="mono nowrap">
                    {v.cve_id}
                    {v.kev && <span className="badge high" style={{ marginLeft: 6 }} title="Known to be exploited in the wild (CISA KEV)">KEV</span>}
                    {v.epss != null && <span className="muted small" style={{ marginLeft: 6 }}>EPSS {(v.epss * 100).toFixed(0)}%</span>}
                  </td>
                  <td className="small">
                    {v.protocol.toUpperCase()}/{v.port} {v.product ?? v.service ?? ''} {v.version ?? ''}
                  </td>
                  <td className="mono small">{v.cvss_base != null ? v.cvss_base.toFixed(1) : '—'}</td>
                  <td>
                    <span className={`badge ${v.state === 'confirmed' ? 'high' : v.state === 'potential' ? 'medium' : 'outline'}`}>
                      {v.state}
                    </span>
                    {v.source === 'nmap_script' && <span className="badge outline" style={{ marginLeft: 6 }}>script</span>}
                  </td>
                  <td className="right">
                    {isAdmin && (
                      v.state === 'dismissed' ? (
                        <button className="btn sm ghost" disabled={busy === v.cve_id} onClick={() => undismiss(v.cve_id)}>Undo</button>
                      ) : (
                        <button className="btn sm ghost" disabled={busy === v.cve_id} onClick={() => dismiss(v.cve_id)}>Dismiss</button>
                      )
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

const RTT_CHART_W = 280;
const RTT_CHART_H = 48;

/** Minimal dependency-free RTT-over-time sparkline (no chart library needed for one line). */
function RttSparkline({ samples }: { samples: { rtt_ms: number; sampled_at: string }[] }) {
  if (samples.length < 2) return null;
  const values = samples.map((s) => s.rtt_ms);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const step = RTT_CHART_W / (samples.length - 1);
  const points = values.map((v, i) => `${(i * step).toFixed(1)},${(RTT_CHART_H - ((v - min) / span) * RTT_CHART_H).toFixed(1)}`).join(' ');
  return (
    <svg width={RTT_CHART_W} height={RTT_CHART_H} role="img" aria-label="RTT over time">
      <polyline points={points} fill="none" stroke="var(--accent, #4a90d9)" strokeWidth={1.5} />
    </svg>
  );
}

export function RttCard({ d }: { d: DeviceDetail }) {
  return (
    <Card title="Latency &amp; uptime">
      <dl className="dl">
        <dt>Last RTT</dt>
        <dd>{d.last_rtt_ms != null ? `${d.last_rtt_ms.toFixed(1)} ms` : <span className="muted">—</span>}</dd>
        <dt>Availability ({d.availability_window_days}d)</dt>
        <dd>{d.availability_pct != null ? `${d.availability_pct}%` : <span className="muted">not enough history</span>}</dd>
        <dt>Continuous since</dt>
        <dd>{d.continuous_since ? fmtTime(d.continuous_since) : <span className="muted">—</span>}</dd>
      </dl>
      {d.rtt_samples.length >= 2 && (
        <div className="card-body" style={{ paddingTop: 0 }}>
          <RttSparkline samples={d.rtt_samples} />
        </div>
      )}
    </Card>
  );
}

function timelineLabel(it: TimelineItem) {
  if (it.kind === 'event') {
    return <><span className={`badge ${it.severity}`}>{EVENT_LABELS[it.event_type] ?? it.event_type}</span> <span>{it.message}</span></>;
  }
  if (it.kind === 'scan') {
    return (
      <>
        <span className="badge outline">{SCAN_TYPE_LABELS[it.scan_type]} scan</span>{' '}
        <span>#{it.scan_id} · {it.ip} · {it.status === 'up' ? (it.open_ports != null ? `${it.open_ports} open ports` : 'up') : it.status}</span>{' '}
        <ScanStatusBadge status={it.scan_status} />
      </>
    );
  }
  return (
    <>
      <span className="badge accent">Web capture</span>{' '}
      <span>#{it.capture_id} · {it.pages} page{it.pages === 1 ? '' : 's'} · {it.screenshots} screenshot{it.screenshots === 1 ? '' : 's'} · {it.status}</span>
    </>
  );
}

/** Events, scans and web captures of one device, grouped by local day. */
export function Timeline({ uuid }: { uuid: string }) {
  const [open, setOpen] = useState(false);
  const { data, error } = useApi<{ items: TimelineItem[] }>(`/devices/${uuid}/timeline`, { limit: TIMELINE_LIMIT }, 30000);
  if (!data) return <Card title="Timeline">{error ? <ErrorBox error={error} /> : <Loading />}</Card>;
  const all = data.items;
  const shown = open ? all : all.slice(0, TIMELINE_PREVIEW);
  const days: [string, TimelineItem[]][] = [];
  for (const it of shown) {
    const day = new Date(it.at).toLocaleDateString(undefined, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' });
    const last = days[days.length - 1];
    if (last && last[0] === day) last[1].push(it);
    else days.push([day, [it]]);
  }
  return (
    <Card title="Timeline" flush>
      {!all.length ? <Empty>Nothing recorded for this device yet.</Empty> : (
        <>
          {days.map(([day, items]) => (
            <div key={day}>
              <div className="timeline-day">{day}</div>
              <ul className="feed">
                {items.map((it) => (
                  <li key={`${it.kind}-${it.kind === 'event' ? it.id : it.kind === 'scan' ? it.scan_id : it.capture_id}`}>
                    <span className="time" title={fmtTime(it.at)}>{new Date(it.at).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}</span>
                    <span className="msg" style={{ gridColumn: 'span 2' }}>{timelineLabel(it)}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
          {all.length > TIMELINE_PREVIEW && (
            <button type="button" className="btn see-all" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
              {open ? 'Show less' : `See all ${all.length} →`}
            </button>
          )}
        </>
      )}
    </Card>
  );
}
