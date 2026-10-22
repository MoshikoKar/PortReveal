import { useState } from 'react';
import { Link } from 'react-router-dom';
import { del, patch, post } from '../api';
import { Card, Empty, ErrorBox, SkeletonRows } from '../components/ui';
import { useApp } from '../context';
import type { CveWatchlistAddResult, CveWatchlistEntry } from '../types';
import { fmtTime, relTime, useApi, useInFlight } from '../util';

const STATUS_BADGE: Record<CveWatchlistEntry['status'], string> = {
  pending: 'medium',
  not_found: 'outline',
  found: 'high',
  only_dismissed: 'outline',
};

const STATUS_LABEL: Record<CveWatchlistEntry['status'], string> = {
  pending: 'Pending sync',
  not_found: 'Not found',
  found: 'Found',
  only_dismissed: 'Only dismissed findings',
};

const BULK_EXAMPLE = 'CVE-2024-1234, CVE-2024-5678 and CVE-2025-1111';

function findingsHref(cveId: string) {
  return `/vulnerabilities?cve_id=${encodeURIComponent(cveId)}#vuln-findings`;
}

function pendingTitle(entry: CveWatchlistEntry) {
  if (entry.status !== 'pending') return undefined;
  if (entry.next_sync_at) {
    return `Not in the local CVE cache yet. Next scheduled sync: ${fmtTime(entry.next_sync_at)}`;
  }
  return 'Not in the local CVE cache yet. Waiting for the next CVE feed sync.';
}

function deviceCell(entry: CveWatchlistEntry) {
  if (entry.status !== 'found' || !entry.affected_devices) {
    return <span className="muted">-</span>;
  }
  const stateBits: string[] = [];
  if (entry.confirmed_count) stateBits.push(`${entry.confirmed_count} confirmed`);
  if (entry.potential_count) stateBits.push(`${entry.potential_count} potential`);
  const stateSuffix = stateBits.length ? ` (${stateBits.join(', ')})` : '';
  const label = `${entry.affected_devices} device${entry.affected_devices === 1 ? '' : 's'} · ${entry.finding_count} finding${entry.finding_count === 1 ? '' : 's'}${stateSuffix}`;
  return (
    <Link to={findingsHref(entry.cve_id)} title={label}>
      {label}
    </Link>
  );
}

export default function CveWatchlist() {
  const { isAdmin } = useApp();
  const { data, error, loading, reload } = useApi<CveWatchlistEntry[]>('/cve-watchlist', undefined, 30000);
  const [bulk, setBulk] = useState('');
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [addMsg, setAddMsg] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const { pending, track } = useInFlight();

  const add = async () => {
    if (!bulk.trim() || saving) return;
    setSaving(true);
    setSaveError(null);
    setAddMsg(null);
    try {
      const result = await post<CveWatchlistAddResult>('/cve-watchlist', {
        cve_ids: bulk,
        note: note.trim() || null,
      });
      setBulk('');
      setNote('');
      const added = result.added?.length ?? 0;
      const already = result.already_watched?.length ?? 0;
      setAddMsg(`Added ${added}, already watched ${already}.`);
      reload();
    } catch (e: any) {
      setSaveError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const toggleEnabled = async (entry: CveWatchlistEntry) => {
    if (pending(`watch-${entry.id}`)) return;
    setActionError(null);
    await track(`watch-${entry.id}`, async () => {
      try {
        await patch(`/cve-watchlist/${entry.id}`, { enabled: !entry.enabled });
      } catch (e: any) {
        setActionError(`Could not update ${entry.cve_id}: ${e.message}`);
        return;
      }
      reload();
    });
  };

  const remove = async (entry: CveWatchlistEntry) => {
    if (pending(`del-${entry.id}`)) return;
    if (!confirm(`Remove ${entry.cve_id} from the CVE watchlist?`)) return;
    setActionError(null);
    await track(`del-${entry.id}`, async () => {
      try {
        await del(`/cve-watchlist/${entry.id}`);
      } catch (e: any) {
        setActionError(`Could not delete ${entry.cve_id}: ${e.message}`);
        return;
      }
      reload();
    });
  };

  return (
    <>
      <div className="page-head">
        <div>
          <div className="muted small"><Link to="/vulnerabilities">Vulnerabilities</Link> /</div>
          <h1>CVE Watchlist</h1>
          <p>
            Subscribe to CVE IDs. When a watched CVE appears on a device or port (confirmed or potential),
            PortReveal raises an alert immediately. CVEs not yet in the local feed show as pending until the
            next sync.
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          {isAdmin && <Link className="btn" to="/settings/notifications">Delivery settings</Link>}
          <Link className="btn" to="/vulnerabilities">&larr; Back to vulnerabilities</Link>
        </div>
      </div>
      <ErrorBox error={error || actionError} />

      {isAdmin && (
        <Card title="Add CVEs">
          <div className="stack">
            <label className="field">
              CVE IDs
              <textarea
                rows={3}
                className="mono"
                value={bulk}
                onChange={(e) => setBulk(e.target.value)}
                placeholder={BULK_EXAMPLE}
              />
              <span className="hint">Separate with spaces, commas, newlines, or &quot;and&quot;. Example: {BULK_EXAMPLE}</span>
            </label>
            <label className="field">
              Note (optional)
              <input type="text" value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} />
            </label>
            <ErrorBox error={saveError} />
            {addMsg && <div className="alert ok">{addMsg}</div>}
            <div>
              <button type="button" className="btn primary" disabled={saving || !bulk.trim()} onClick={() => { void add(); }}>
                {saving ? 'Adding…' : 'Add to watchlist'}
              </button>
            </div>
          </div>
        </Card>
      )}

      <Card flush title="Watched CVEs">
        {loading && !data ? <SkeletonRows cols={6} /> : !data?.length ? (
          <Empty>
            No CVEs on the watchlist yet.
            {isAdmin ? (
              <>
                {' '}Paste IDs above to subscribe — for example{' '}
                <span className="mono">{BULK_EXAMPLE}</span>.
              </>
            ) : null}
          </Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Status</th>
                  <th className="right">Devices</th>
                  <th>Note</th>
                  <th>Enabled</th>
                  <th>Last alert</th>
                  {isAdmin && <th />}
                </tr>
              </thead>
              <tbody>
                {data.map((e) => (
                  <tr key={e.id} className={!e.enabled ? 'dim' : ''}>
                    <td className="mono nowrap">
                      {e.cve_known ? (
                        <Link to={`/vulnerabilities/${encodeURIComponent(e.cve_id)}`}>{e.cve_id}</Link>
                      ) : (
                        <span title="Not in the local CVE cache yet">{e.cve_id}</span>
                      )}
                    </td>
                    <td>
                      <span className={`badge ${STATUS_BADGE[e.status]}`} title={pendingTitle(e)}>
                        {STATUS_LABEL[e.status]}
                      </span>
                    </td>
                    <td className="right">{deviceCell(e)}</td>
                    <td className="small">{e.note || <span className="muted">-</span>}</td>
                    <td>
                      {isAdmin ? (
                        <label className="check">
                          <input
                            type="checkbox"
                            checked={e.enabled}
                            disabled={pending(`watch-${e.id}`)}
                            onChange={() => { void toggleEnabled(e); }}
                          />
                        </label>
                      ) : (
                        e.enabled ? 'yes' : 'no'
                      )}
                    </td>
                    <td className="small nowrap">
                      {e.last_alert_at
                        ? <span title={fmtTime(e.last_alert_at)}>{relTime(e.last_alert_at)}</span>
                        : <span className="muted">never</span>}
                    </td>
                    {isAdmin && (
                      <td className="right">
                        <button
                          type="button"
                          className="btn danger sm"
                          disabled={pending(`del-${e.id}`)}
                          onClick={() => { void remove(e); }}
                        >
                          {pending(`del-${e.id}`) ? 'Deleting…' : 'Delete'}
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
