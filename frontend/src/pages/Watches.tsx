import { useState } from 'react';
import { Link } from 'react-router-dom';
import { del, post, put } from '../api';
import { Card, Empty, ErrorBox, Modal, SkeletonRows, confirmDiscard } from '../components/ui';
import type { SavedSearch } from '../types';
import { fmtTime, relTime, useApi, useInFlight } from '../util';

type Draft = { id?: number; name: string; query: string; description: string; kind: 'watch' | 'policy' | 'monitor'; alert: boolean };

const EMPTY: Draft = { name: '', query: '', description: '', kind: 'watch', alert: true };

export default function Watches() {
  const { data, error, loading, reload } = useApi<SavedSearch[]>('/saved-searches', undefined, 30000);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [initial, setInitial] = useState<Draft | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const { pending, track } = useInFlight();
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);

  const open = (d: Draft) => { setDraft(d); setInitial(d); setSaveError(null); };

  const save = async () => {
    if (!draft || saving) return;
    setSaving(true);
    setSaveError(null);
    try {
      const body = { name: draft.name, query: draft.query, description: draft.description || null, kind: draft.kind, alert: draft.alert };
      if (draft.id) await put(`/saved-searches/${draft.id}`, body);
      else await post('/saved-searches', body);
      setDraft(null);
      reload();
    } catch (e: any) {
      setSaveError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const remove = async (s: SavedSearch) => {
    if (pending(`watch-${s.id}`)) return;
    if (!confirm(`Delete the saved search "${s.name}"?`)) return;
    setActionError(null);
    await track(`watch-${s.id}`, async () => {
      try {
        await del(`/saved-searches/${s.id}`);
      } catch (e: any) {
        setActionError(`Could not delete "${s.name}": ${e.message}`);
        return;
      }
      reload();
    });
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Watches</h1>
          <p>Saved searches re-run after every scan and web capture. Watches and policies alert when a host newly matches; monitors alert when a matching host itself changes.</p>
        </div>
        <button className="btn primary" onClick={() => open(EMPTY)}>New watch</button>
      </div>
      <ErrorBox error={error || actionError} />
      <Card flush>
        {loading && !data ? <SkeletonRows cols={6} /> : !data?.length ? (
          <Empty>No watches yet. Run a search and use <strong>Save as watch</strong>, or create one here.</Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Name</th><th>Query</th><th>Kind</th><th className="right">Matching hosts</th><th>Last run</th><th>Owner</th><th /></tr></thead>
              <tbody>
                {data.map((s) => (
                  <tr key={s.id}>
                    <td><strong>{s.name}</strong>{s.description && <div className="muted small">{s.description}</div>}</td>
                    <td className="mono small"><Link to={`/search?q=${encodeURIComponent(s.query)}`}>{s.query}</Link></td>
                    <td>
                      <span className={`badge ${s.kind === 'policy' ? 'high' : s.kind === 'monitor' ? 'medium' : 'accent'}`}>{s.kind}</span>
                      {!s.alert && <span className="badge outline" style={{ marginLeft: 6 }} title="Matches are recorded without notifications">silent</span>}
                    </td>
                    <td className="right">{s.initialized ? s.last_count : <span className="muted">—</span>}</td>
                    <td className="small nowrap">
                      {s.last_run_at ? <span title={fmtTime(s.last_run_at)}>{relTime(s.last_run_at)}</span> : 'never'}
                      {s.last_error && <div style={{ color: 'var(--high)' }} title={s.last_error}>error: {s.last_error}</div>}
                    </td>
                    <td className="small">{s.created_by ?? '—'}</td>
                    <td className="right nowrap">
                      {s.can_edit && (
                        <>
                          <button className="btn ghost sm" onClick={() => open({ id: s.id, name: s.name, query: s.query, description: s.description ?? '', kind: s.kind, alert: s.alert })}>Edit</button>
                          <button className="btn danger sm" disabled={pending(`watch-${s.id}`)} onClick={() => remove(s)}>
                            {pending(`watch-${s.id}`) ? 'Deleting…' : 'Delete'}
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {draft && (
        <Modal title={draft.id ? 'Edit watch' : 'New watch'} onClose={() => setDraft(null)} dirty={dirty} footer={<>
          <button className="btn ghost" onClick={() => confirmDiscard(dirty) && setDraft(null)}>Cancel</button>
          <button className="btn primary" onClick={save} disabled={saving || !draft.name.trim() || !draft.query.trim()}>{saving ? 'Saving…' : 'Save'}</button>
        </>}>
          <label className="field">Name<input type="text" value={draft.name} maxLength={120} onChange={(e) => setDraft({ ...draft, name: e.target.value })} /></label>
          <label className="field">Query<input type="text" className="mono" value={draft.query} maxLength={1000} onChange={(e) => setDraft({ ...draft, query: e.target.value })} placeholder="port:23 OR port:2323" />
            <span className="hint">Changing the query re-records the baseline; hosts matching then do not alert.</span></label>
          <label className="field">Description<input type="text" value={draft.description} maxLength={1000} onChange={(e) => setDraft({ ...draft, description: e.target.value })} /></label>
          <label className="field">Kind
            <select value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value as Draft['kind'] })}>
              <option value="watch">Watch: alert when a new host starts matching</option>
              <option value="policy">Policy: every new match is a violation</option>
              <option value="monitor">Monitor: alert when a matching host changes</option>
            </select>
          </label>
          <label className="check"><input type="checkbox" checked={draft.alert} onChange={(e) => setDraft({ ...draft, alert: e.target.checked })} />Send notifications for watch matches, policy violations, and monitored changes</label>
          <ErrorBox error={saveError} />
        </Modal>
      )}
    </>
  );
}
