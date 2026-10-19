import { useState } from 'react';
import { Link } from 'react-router-dom';
import { post } from '../api';
import type { FacetValue, Facets, SavedSearch, SearchHost, SearchService } from '../types';
import { httpTitleDisplay, relTime } from '../util';
import { DeviceStatusBadge, ErrorBox, Modal, ScoreBadge, confirmDiscard } from './ui';
import { ShotImg } from './WebShots';

export const FACET_LABELS: Record<string, string> = {
  port: 'Top ports', product: 'Products', tag: 'Tags', type: 'Device types', os: 'Operating systems',
  network: 'Networks', version: 'Versions', 'http.title': 'HTTP titles', 'http.server': 'HTTP servers',
  service: 'Services', vendor: 'Vendors', net: 'Subnets',
};

export function serviceLabel(s: SearchService): string {
  return [s.product, s.version].filter(Boolean).join(' ') || s.service || '';
}

/** A query syntax error with a caret under the offending character. */
export function QueryError({ query, error, pos }: { query: string; error: string; pos?: number }) {
  return (
    <div className="alert error">
      <div>{error}</div>
      {pos !== undefined && pos <= query.length && (
        <pre className="query-caret">{query}{'\n'}{' '.repeat(pos)}^</pre>
      )}
    </div>
  );
}

export function FacetList({ facets, onPick }: { facets: Facets; onPick: (f: FacetValue) => void }) {
  const groups = Object.entries(facets).filter(([, v]) => v.length > 0);
  if (!groups.length) return <div className="muted small">No facets for these results.</div>;
  return (
    <div className="stack" style={{ gap: 16 }}>
      {groups.map(([name, values]) => (
        <div key={name} className="facet">
          <h3>{FACET_LABELS[name] ?? name}</h3>
          {values.map((v) => (
            <button key={`${v.value}`} className="facet-row" onClick={() => onPick(v)} title={`Add ${v.term}`}>
              <span className="facet-value">{String(v.value)}</span>
              <span className="muted">{v.count}</span>
            </button>
          ))}
        </div>
      ))}
    </div>
  );
}

export function HostResult({ h }: { h: SearchHost }) {
  return (
    <div className="result">
      <div className="result-main">
        <div className="row wrap" style={{ gap: 8 }}>
          <Link to={`/devices/${h.uuid}`} className="mono"><strong>{h.ip}</strong></Link>
          {h.hostname && <span>{h.hostname}</span>}
          <ScoreBadge score={h.score} />
          {h.type && <span className="badge accent">{h.type}</span>}
          <DeviceStatusBadge status={h.status} />
        </div>
        <div className="muted small">
          {[h.network, h.os, h.vendor].filter(Boolean).join(' · ') || '-'} · seen {relTime(h.last_seen)}
        </div>
        {h.tags.length > 0 && <div>{h.tags.map((t) => <span key={t} className="chip">{t}</span>)}</div>}
        {h.services.length > 0 && (
          <ul className="result-services">
            {h.services.map((s) => (
              <li key={`${s.protocol}${s.port}`}>
                <span className="mono nowrap">{s.port}/{s.protocol}</span>
                <span>{serviceLabel(s) || <span className="muted">unknown</span>}</span>
                {s.http && httpTitleDisplay(s.http.status, s.http.title) && (
                  <span className="muted small" title="HTTP page title">“{httpTitleDisplay(s.http.status, s.http.title)}”</span>
                )}
                {s.http?.status != null && <span className="badge outline">{s.http.status}</span>}
                {s.http?.login && <span className="badge medium">login</span>}
              </li>
            ))}
            {h.matched_services > h.services.length && (
              <li className="muted small">+{h.matched_services - h.services.length} more matching services</li>
            )}
          </ul>
        )}
      </div>
      {h.screenshot && (
        <Link to={`/devices/${h.uuid}/web`} className="result-shot" title={h.screenshot.title ?? `Port ${h.screenshot.port}`}>
          <ShotImg src={`/api/web-pages/${h.screenshot.page_id}/screenshot`} alt={h.screenshot.title ?? 'Web screenshot'} loading="lazy" />
        </Link>
      )}
    </div>
  );
}

type Draft = { name: string; description: string; kind: 'watch' | 'policy' | 'monitor'; alert: boolean };

export function SaveWatchDialog({ query, onClose, onSaved }: {
  query: string; onClose: () => void; onSaved: (s: SavedSearch) => void;
}) {
  const initial: Draft = { name: '', description: '', kind: 'watch', alert: true };
  const [draft, setDraft] = useState<Draft>(initial);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);

  const save = async () => {
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      const s = await post<SavedSearch>('/saved-searches', {
        name: draft.name, query, description: draft.description || null, kind: draft.kind, alert: draft.alert,
      });
      onSaved(s);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="Save as watch" onClose={onClose} dirty={dirty} footer={<>
      <button className="btn ghost" onClick={() => confirmDiscard(dirty) && onClose()}>Cancel</button>
      <button className="btn primary" onClick={save} disabled={saving || !draft.name.trim()}>{saving ? 'Saving…' : 'Save'}</button>
    </>}>
      <div className="field small">Query<code className="query-preview">{query}</code></div>
      <label className="field">Name<input type="text" value={draft.name} maxLength={120} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="New Telnet hosts" /></label>
      <label className="field">Description<input type="text" value={draft.description} maxLength={1000} onChange={(e) => setDraft({ ...draft, description: e.target.value })} /></label>
      <label className="field">Kind
        <select value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value as Draft['kind'] })}>
          <option value="watch">Watch: alert when a new host starts matching</option>
          <option value="policy">Policy: every new match is a violation</option>
          <option value="monitor">Monitor: alert when a matching host changes</option>
        </select>
      </label>
      <label className="check"><input type="checkbox" checked={draft.alert} onChange={(e) => setDraft({ ...draft, alert: e.target.checked })} />Send notifications for watch matches, policy violations, and monitored changes</label>
      <div className="muted small">Hosts matching now are recorded as the baseline and do not alert.</div>
      <ErrorBox error={error} />
    </Modal>
  );
}
