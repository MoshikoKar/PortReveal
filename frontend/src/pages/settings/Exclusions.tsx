import { useState } from 'react';
import { del, post, put } from '../../api';
import { Card, Empty, ErrorBox, Modal, SkeletonRows, confirmDiscard } from '../../components/ui';
import { useApp } from '../../context';
import type { Exclusion } from '../../types';
import { useApi, useInFlight } from '../../util';

type Draft = { id?: number; value: string; description: string; enabled: boolean };

export function ExclusionsSettings() {
  const { isAdmin } = useApp();
  const { data, error, loading, reload } = useApi<Exclusion[]>('/exclusions');
  const [draft, setDraft] = useState<Draft | null>(null);
  const [initial, setInitial] = useState<Draft | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const { pending, track } = useInFlight();
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  const canSave = !!draft?.value.trim();

  const openDraft = (d: Draft) => { setDraft(d); setInitial(d); setSaveError(null); };
  const closeDraft = () => confirmDiscard(dirty) && setDraft(null);

  const save = async (d: Draft, { list = false }: { list?: boolean } = {}) => {
    if (saving) return;
    if (list) setActionError(null);
    else setSaveError(null);
    setSaving(true);
    try {
      const body = { value: d.value, description: d.description || null, enabled: d.enabled };
      if (d.id) await put(`/exclusions/${d.id}`, body);
      else await post('/exclusions', body);
      if (!list) setDraft(null);
      reload();
    } catch (e: any) {
      if (list) setActionError(`Could not update the exclusion: ${e.message}`);
      else setSaveError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const remove = async (x: Exclusion) => {
    if (pending(`excl-${x.id}`)) return;
    if (!confirm('Delete this exclusion?')) return;
    setActionError(null);
    await track(`excl-${x.id}`, async () => {
      try {
        await del(`/exclusions/${x.id}`);
      } catch (e: any) {
        setActionError(`Could not delete the exclusion: ${e.message}`);
        return;
      }
      reload();
    });
  };

  return (
    <Card
      title="Exclusions"
      flush
      actions={isAdmin && <button className="btn primary sm" onClick={() => openDraft({ value: '', description: '', enabled: true })}>Add exclusion</button>}
    >
      <div className="card-body muted small" style={{ borderBottom: '1px solid var(--border)' }}>
        Excluded addresses are removed from every scan before nmap runs and are never probed.
      </div>
      <ErrorBox error={error || actionError} />
      {loading && !data ? <SkeletonRows cols={isAdmin ? 5 : 4} /> : !data?.length ? <Empty>No exclusions.</Empty> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Addresses</th><th>Count</th><th>Description</th><th>Status</th>{isAdmin && <th />}</tr></thead>
            <tbody>
              {data.map((x) => (
                <tr key={x.id} className={x.enabled ? '' : 'dim'}>
                  <td className="mono" style={{ maxWidth: 360, overflowWrap: 'anywhere' }}>{x.value}</td>
                  <td>{x.address_count.toLocaleString()}</td>
                  <td>{x.description}</td>
                  <td>
                    {isAdmin ? (
                      <label className="check small"><input type="checkbox" checked={x.enabled} disabled={saving} onChange={(e) => save({ id: x.id, value: x.value, description: x.description ?? '', enabled: e.target.checked }, { list: true })} />{x.enabled ? 'enabled' : 'disabled'}</label>
                    ) : x.enabled ? 'enabled' : 'disabled'}
                  </td>
                  {isAdmin && (
                    <td className="right nowrap">
                      <button className="btn ghost sm" onClick={() => openDraft({ id: x.id, value: x.value, description: x.description ?? '', enabled: x.enabled })}>Edit</button>
                      <button className="btn danger sm" disabled={pending(`excl-${x.id}`)} onClick={() => remove(x)}>Delete</button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {draft && (
        <Modal
          title={draft.id ? 'Edit exclusion' : 'Add exclusion'}
          onClose={() => setDraft(null)}
          dirty={dirty}
          footer={<>
            <button className="btn ghost" onClick={closeDraft}>Cancel</button>
            <button className="btn primary" onClick={() => save(draft)} disabled={saving || !canSave} title={canSave ? undefined : 'Enter at least one address'}>{saving ? 'Saving…' : 'Save'}</button>
          </>}
        >
          <label className="field">Addresses
            <textarea rows={4} value={draft.value} onChange={(e) => setDraft({ ...draft, value: e.target.value })} placeholder={'10.20.1.5\n10.20.1.10, 10.20.1.11\n10.20.2.10-10.20.2.50\n10.20.9.0/24'} />
            <span className="hint">Single IPs, lists, ranges (a.b.c.d-e.f.g.h or a.b.c.d-N) and CIDRs.</span>
          </label>
          <label className="field">Description<input type="text" value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} placeholder="Fragile OT devices" /></label>
          <label className="check"><input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />Enabled</label>
          <ErrorBox error={saveError} />
        </Modal>
      )}
    </Card>
  );
}
