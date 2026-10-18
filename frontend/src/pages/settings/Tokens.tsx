import { useState } from 'react';
import { del, post } from '../../api';
import { Card, Empty, ErrorBox, Modal, SkeletonRows, confirmDiscard, useReportDirty } from '../../components/ui';
import type { ApiToken } from '../../types';
import { fmtTime, relTime, useApi, useInFlight } from '../../util';

const EXPIRY_OPTIONS = [
  { days: 30, label: '30 days' }, { days: 90, label: '90 days' }, { days: 365, label: '1 year' }, { days: 0, label: 'Never' },
];

/** Personal read-only API tokens (GET/HEAD only), managed from a signed-in session. */
export function TokensSettings({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const { data, error, loading, reload } = useApi<ApiToken[]>('/tokens');
  const [draft, setDraft] = useState<{ name: string; days: number } | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [created, setCreated] = useState<ApiToken | null>(null);
  const [copied, setCopied] = useState(false);
  const { pending, track } = useInFlight();
  const dirty = !!draft?.name;
  useReportDirty(dirty, onDirtyChange); // feeds the Settings leave guard

  const create = async () => {
    if (!draft || saving) return;
    setSaving(true);
    setSaveError(null);
    try {
      const t = await post<ApiToken>('/tokens', { name: draft.name, expires_days: draft.days || null });
      setDraft(null);
      setCreated(t);
      setCopied(false);
      reload();
    } catch (e: any) {
      setSaveError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const revoke = async (t: ApiToken) => {
    if (pending(`token-${t.id}`)) return;
    if (!confirm(`Revoke the token "${t.name}"? Scripts using it stop working immediately.`)) return;
    setActionError(null);
    await track(`token-${t.id}`, async () => {
      try {
        await del(`/tokens/${t.id}`);
      } catch (e: any) {
        setActionError(`Could not revoke "${t.name}": ${e.message}`);
        return;
      }
      reload();
    });
  };

  const copy = async () => {
    if (!created?.token) return;
    try {
      await navigator.clipboard.writeText(created.token);
      setCopied(true);
    } catch {
      setActionError('Copy failed; select the token and copy it manually.');
    }
  };

  const expired = (t: ApiToken) => !!t.expires_at && new Date(t.expires_at).getTime() < Date.now();

  return (
    <Card title="API tokens" flush actions={<button className="btn primary sm" onClick={() => { setDraft({ name: '', days: 90 }); setSaveError(null); }}>Create token</button>}>
      <div className="card-body muted small" style={{ borderBottom: '1px solid var(--border)' }}>
        Personal, read-only tokens for scripts and integrations. Send <code>Authorization: Bearer &lt;token&gt;</code>; only
        GET requests are allowed (for example <code>/api/search?q=port:22</code> or <code>/api/search/export?q=tag:camera&amp;format=csv</code>).
        A token acts with your role and stops working when revoked or expired.
      </div>
      <ErrorBox error={error || actionError} />
      {created?.token && (
        <div className="card-body">
          <div className="alert ok stack" style={{ gap: 8 }}>
            <div>Token “{created.name}” created. Copy it now — it is not shown again.</div>
            <div className="row wrap">
              <code className="query-preview grow" style={{ userSelect: 'all' }}>{created.token}</code>
              <button className="btn sm" onClick={copy}>{copied ? 'Copied' : 'Copy'}</button>
              <button className="btn ghost sm" onClick={() => setCreated(null)}>Done</button>
            </div>
          </div>
        </div>
      )}
      {loading && !data ? <SkeletonRows cols={6} /> : !data?.length ? <Empty>No API tokens yet.</Empty> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Token</th><th>Created</th><th>Last used</th><th>Expires</th><th /></tr></thead>
            <tbody>
              {data.map((t) => (
                <tr key={t.id} className={t.revoked || expired(t) ? 'dim' : ''}>
                  <td><strong>{t.name}</strong></td>
                  <td className="mono">{t.prefix}…</td>
                  <td className="small nowrap">{fmtTime(t.created_at)}</td>
                  <td className="small nowrap">{t.last_used_at ? relTime(t.last_used_at) : 'never'}</td>
                  <td className="small nowrap">
                    {t.revoked ? <span className="badge outline">revoked</span> : expired(t) ? <span className="badge high">expired</span> : t.expires_at ? fmtTime(t.expires_at) : 'never'}
                  </td>
                  <td className="right">{!t.revoked && (
                    <button className="btn danger sm" disabled={pending(`token-${t.id}`)} onClick={() => revoke(t)}>
                      {pending(`token-${t.id}`) ? 'Revoking…' : 'Revoke'}
                    </button>
                  )}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {draft && (
        <Modal title="Create API token" onClose={() => setDraft(null)} dirty={dirty} footer={<>
          <button className="btn ghost" onClick={() => confirmDiscard(dirty) && setDraft(null)}>Cancel</button>
          <button className="btn primary" onClick={create} disabled={saving || !draft.name.trim()}>{saving ? 'Creating…' : 'Create'}</button>
        </>}>
          <label className="field">Name<input type="text" value={draft.name} maxLength={100} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="SIEM export" /></label>
          <label className="field">Expires
            <select value={draft.days} onChange={(e) => setDraft({ ...draft, days: Number(e.target.value) })}>
              {EXPIRY_OPTIONS.map((o) => <option key={o.days} value={o.days}>{o.label}</option>)}
            </select>
          </label>
          <ErrorBox error={saveError} />
        </Modal>
      )}
    </Card>
  );
}
