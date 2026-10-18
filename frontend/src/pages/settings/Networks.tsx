import { useEffect, useState } from 'react';
import { del, post, put } from '../../api';
import { Card, Empty, ErrorBox, Modal, SkeletonRows, confirmDiscard } from '../../components/ui';
import { useApp } from '../../context';
import type { Network } from '../../types';
import { NETWORK_ZONES, fmtTime, useApi, useInFlight } from '../../util';

type Draft = { id?: number; name: string; cidr: string; description: string; enabled: boolean; zone: string; vpn_s2s: boolean };

const VPN_S2S_TIP = 'Mark networks reached over a site-to-site VPN. Scans use the same remote discovery speed as '
  + 'before (so a /16 still finishes in about an hour), force the routed profile even if a NIC looks local, '
  + 'and block "fast" timing so the tunnel never sees a 2000 probes/s burst. Scanning is not slowed or disabled.';

/** `onCount`: told how many networks exist whenever the list loads (the setup wizard gates on it). */
export function NetworksSettings({ compact, onCount }: { compact?: boolean; onCount?: (n: number) => void }) {
  const { isAdmin } = useApp();
  const [showArchived, setShowArchived] = useState(false);
  const { data, error, loading, reload } = useApi<Network[]>('/networks', { include_archived: showArchived ? 'true' : undefined });
  useEffect(() => {
    if (data) onCount?.(data.filter((n) => !n.archived_at).length);
  }, [data, onCount]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [initial, setInitial] = useState<Draft | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const { pending, track } = useInFlight();
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  const canSave = !!draft && !!draft.name.trim() && !!draft.cidr.trim();

  const openDraft = (d: Draft) => { setDraft(d); setInitial(d); setSaveError(null); };
  const closeDraft = () => confirmDiscard(dirty) && setDraft(null);

  const save = async () => {
    if (!draft || saving || !canSave) return;
    setSaveError(null);
    setSaving(true);
    try {
      const body = { name: draft.name, cidr: draft.cidr, description: draft.description || null, enabled: draft.enabled, zone: draft.zone || null, vpn_s2s: draft.vpn_s2s };
      if (draft.id) await put(`/networks/${draft.id}`, body);
      else await post('/networks', body);
      setDraft(null);
      reload();
    } catch (e: any) {
      setSaveError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const remove = async (n: Network) => {
    if (pending(`net-${n.id}`)) return;
    if (!confirm(`Archive network "${n.name}"? It stops being scanned. Its devices, events and history are kept `
      + 'but hidden from default views (Devices > "Show archived networks" reveals them). You can restore it later.')) return;
    setActionError(null);
    await track(`net-${n.id}`, async () => {
      try {
        await del(`/networks/${n.id}`);
      } catch (e: any) {
        setActionError(`Could not archive "${n.name}": ${e.message}`);
        return;
      }
      reload();
    });
  };

  const restore = async (n: Network) => {
    if (pending(`net-${n.id}`)) return;
    setActionError(null);
    await track(`net-${n.id}`, async () => {
      try {
        await post(`/networks/${n.id}/restore`);
      } catch (e: any) {
        setActionError(`Could not restore "${n.name}": ${e.message}`);
        return;
      }
      reload();
    });
  };

  const resetBaseline = async (n: Network) => {
    if (pending(`net-${n.id}`)) return;
    if (!confirm(`Reset the baseline of "${n.name}"? The next complete standard scan becomes the new baseline (no alerts).`)) return;
    setActionError(null);
    await track(`net-${n.id}`, async () => {
      try {
        await post(`/networks/${n.id}/reset-baseline`);
      } catch (e: any) {
        setActionError(`Could not reset the baseline of "${n.name}": ${e.message}`);
        return;
      }
      reload();
    });
  };

  return (
    <Card
      title="Network scopes"
      flush
      actions={isAdmin && <button className="btn primary sm" onClick={() => openDraft({ name: '', cidr: '', description: '', enabled: true, zone: '', vpn_s2s: false })}>Add network</button>}
    >
      {!compact && (
        <div className="card-body muted small" style={{ borderBottom: '1px solid var(--border)' }}>
          Reusable scan scopes (up to /16 each). Enabled networks are scanned by the daily schedule. The first complete standard
          scan of a network is its baseline and never alerts. Archiving a network keeps its findings but hides them.
          <label className="check small" style={{ marginTop: 6 }}>
            <input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} />Show archived networks
          </label>
        </div>
      )}
      <ErrorBox error={error || actionError} />
      {loading && !data ? <SkeletonRows cols={isAdmin ? 7 : 6} /> : !data?.length ? <Empty>No networks yet.</Empty> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>CIDR</th><th>Zone</th><th>Devices</th><th>Baseline</th><th>Schedule</th>{isAdmin && <th />}</tr></thead>
            <tbody>
              {data.map((n) => (
                <tr key={n.id} className={n.archived_at ? 'dim' : undefined}>
                  <td><strong>{n.name}</strong>{n.vpn_s2s && <> <span className="badge outline" title={VPN_S2S_TIP}>VPN</span></>}{n.description && <div className="muted small">{n.description}</div>}</td>
                  <td className="mono">{n.cidr}</td>
                  <td>{n.zone ?? <span className="muted">—</span>}</td>
                  <td>{n.active_count ?? 0} active / {n.device_count ?? 0}</td>
                  <td>{n.archived_at ? <span className="muted">—</span> : n.baseline_at ? fmtTime(n.baseline_at) : <span className="badge medium">pending</span>}</td>
                  <td>{n.archived_at
                    ? <span className="badge outline" title={`Archived ${fmtTime(n.archived_at)}`}>archived</span>
                    : n.enabled ? <span className="badge ok">enabled</span> : <span className="badge outline">disabled</span>}</td>
                  {isAdmin && (
                    <td className="right nowrap">
                      {n.archived_at ? (
                        <button className="btn sm" disabled={pending(`net-${n.id}`)} onClick={() => restore(n)}>Restore</button>
                      ) : (
                        <>
                          <button className="btn ghost sm" onClick={() => openDraft({ id: n.id, name: n.name, cidr: n.cidr, description: n.description ?? '', enabled: n.enabled, zone: n.zone ?? '', vpn_s2s: n.vpn_s2s })}>Edit</button>
                          {n.baseline_at && <button className="btn danger sm" disabled={pending(`net-${n.id}`)} onClick={() => resetBaseline(n)}>Reset baseline</button>}
                          <button className="btn danger sm" disabled={pending(`net-${n.id}`)} onClick={() => remove(n)}>Archive</button>
                        </>
                      )}
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
          title={draft.id ? 'Edit network' : 'Add network'}
          onClose={() => setDraft(null)}
          dirty={dirty}
          footer={<>
            <button className="btn ghost" onClick={closeDraft}>Cancel</button>
            <button className="btn primary" onClick={save} disabled={saving || !canSave} title={canSave ? undefined : 'Enter a name and a CIDR'}>{saving ? 'Saving…' : 'Save'}</button>
          </>}
        >
          <label className="field">Name<input type="text" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="Office LAN" /></label>
          <label className="field">CIDR<input type="text" value={draft.cidr} onChange={(e) => setDraft({ ...draft, cidr: e.target.value })} placeholder="10.0.0.0/24" />
            <span className="hint">IPv4, maximum size /16 (65,536 addresses). Changing it resets the baseline.</span></label>
          <label className="field">Description<input type="text" value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} /></label>
          <label className="field">Zone
            <select value={draft.zone} onChange={(e) => setDraft({ ...draft, zone: e.target.value })}>
              <option value="">None</option>
              {NETWORK_ZONES.map((z) => <option key={z} value={z}>{z}</option>)}
            </select>
            <span className="hint">Admin services and databases score higher in users, iot and guest zones. Changing it re-scores this network's devices.</span></label>
          <label className="check"><input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />Include in the scheduled daily scan</label>
          <label className="check" title={VPN_S2S_TIP}><input type="checkbox" checked={draft.vpn_s2s} onChange={(e) => setDraft({ ...draft, vpn_s2s: e.target.checked })} />Reached over VPN (site-to-site)</label>
          <span className="hint">{VPN_S2S_TIP}</span>
          <ErrorBox error={saveError} />
        </Modal>
      )}
    </Card>
  );
}
