import { useState } from 'react';
import { del, post, put } from '../../api';
import { Card, Empty, ErrorBox, Loading, Modal } from '../../components/ui';
import { useApp } from '../../context';
import type { Exclusion } from '../../types';
import { useApi } from '../../util';

type Draft = { id?: number; value: string; description: string; enabled: boolean };

export function ExclusionsSettings() {
  const { isAdmin } = useApp();
  const { data, error, loading, reload } = useApi<Exclusion[]>('/exclusions');
  const [draft, setDraft] = useState<Draft | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const save = async (d: Draft) => {
    setSaveError(null);
    try {
      const body = { value: d.value, description: d.description || null, enabled: d.enabled };
      if (d.id) await put(`/exclusions/${d.id}`, body);
      else await post('/exclusions', body);
      setDraft(null);
      reload();
    } catch (e: any) {
      setSaveError(e.message);
    }
  };

  return (
    <Card
      title="Exclusions"
      flush
      actions={isAdmin && <button className="btn primary sm" onClick={() => setDraft({ value: '', description: '', enabled: true })}>Add exclusion</button>}
    >
      <div className="card-body muted small" style={{ borderBottom: '1px solid var(--border)' }}>
        Excluded addresses are removed from every scan before nmap runs and are never probed.
      </div>
      <ErrorBox error={error} />
      {loading && !data ? <Loading /> : !data?.length ? <Empty>No exclusions.</Empty> : (
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
                      <label className="check small"><input type="checkbox" checked={x.enabled} onChange={(e) => save({ id: x.id, value: x.value, description: x.description ?? '', enabled: e.target.checked })} />{x.enabled ? 'enabled' : 'disabled'}</label>
                    ) : x.enabled ? 'enabled' : 'disabled'}
                  </td>
                  {isAdmin && (
                    <td className="right nowrap">
                      <button className="btn ghost sm" onClick={() => setDraft({ id: x.id, value: x.value, description: x.description ?? '', enabled: x.enabled })}>Edit</button>
                      <button className="btn ghost sm" onClick={async () => { if (confirm('Delete this exclusion?')) { await del(`/exclusions/${x.id}`); reload(); } }}>Delete</button>
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
          footer={<><button className="btn ghost" onClick={() => setDraft(null)}>Cancel</button><button className="btn primary" onClick={() => save(draft)}>Save</button></>}
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
