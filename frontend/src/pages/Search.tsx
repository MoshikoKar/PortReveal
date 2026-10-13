import { useEffect, useState, type FormEvent } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ApiError, downloadBlob, get, query } from '../api';
import { ScanDialog } from '../components/ScanDialog';
import { FacetList, HostResult, QueryError, SaveWatchDialog, serviceLabel } from '../components/SearchParts';
import { WebCaptureDialog } from '../components/WebCaptureDialog';
import { Card, Empty, ErrorBox, Loading, Pager, ScoreBadge } from '../components/ui';
import { useApp } from '../context';
import type { FacetValue, Facets, FieldDoc, SearchHost, SearchServiceRow } from '../types';
import { addTerm, useApi } from '../util';

const PAGE_SIZE = 25;
const SEARCH_FACETS = 'port,product,tag,type,os,network';
const SORTS = [
  { id: 'score', label: 'Exposure score' }, { id: 'ip', label: 'IP address' }, { id: 'hostname', label: 'Hostname' },
  { id: 'last_seen', label: 'Last seen' }, { id: 'first_seen', label: 'First seen' },
];
const EXAMPLES = [
  'port:22 product:openssh', 'tag:camera', 'score:>=60', 'http.title:"login"', 'port:3389 net:10.0.0.0/8',
  'first_seen:<7d', 'product:nginx -version:1.25*',
];

interface HistoryHost {
  uuid: string; ip: string; hostname: string | null; status: string; network: string | null;
  ports: { port: number; proto: string; service: string | null; product: string | null; version: string | null }[];
  tags: string[]; type: string | null; score: number | null;
}

interface Results {
  items: (SearchHost | SearchServiceRow | HistoryHost)[];
  total: number;
  facets?: Facets;
  snapshots?: { network: string | null; snapshot_date: string; scan_id: number | null }[];
}

type Bulk = { kind: 'scan' | 'web'; uuids: string[] };

function FieldReference() {
  const { data, error } = useApi<FieldDoc[]>('/search/fields');
  if (!data) return error ? <ErrorBox error={error} /> : <Loading />;
  const groups = [...new Set(data.map((f) => f.group))];
  return (
    <div className="stack">
      <div className="muted small">
        Terms are <code>field:value</code>; terms separated by spaces must all match, <code>OR</code> and parentheses group,
        a leading <code>-</code> negates. Numbers take <code>&gt;</code> <code>&gt;=</code> <code>&lt;</code> <code>&lt;=</code> and
        ranges <code>1-1024</code>; text takes <code>*</code> wildcards, <code>=</code> for exact match and quotes for spaces.
        A bare word searches IP (current and past), hostname, DNS name, MAC, vendor, OS, tags, service, product, version and HTTP title.
      </div>
      {groups.map((g) => (
        <div key={g}>
          <h3 style={{ marginBottom: 6 }}>{g}</h3>
          <table>
            <tbody>
              {data.filter((f) => f.group === g).map((f) => (
                <tr key={f.name}>
                  <td className="mono nowrap">{f.name}{f.aliases.length > 0 && <div className="muted small">{f.aliases.join(', ')}</div>}</td>
                  <td className="small">{f.help}{f.historical && <span className="badge outline" style={{ marginLeft: 6 }} title="Usable with the “as of” date">history</span>}</td>
                  <td className="mono small nowrap">{f.example}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}

export default function Search() {
  const { isAdmin } = useApp();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const q = params.get('q') ?? '';
  const view = params.get('view') === 'services' ? 'services' : 'hosts';
  const sort = params.get('sort') ?? 'score';
  const at = params.get('at') ?? '';
  const page = Math.max(1, Number(params.get('page')) || 1);
  // Hosts vs services (and live vs as-of) return different row shapes; keep the mode the
  // current `results` were loaded for so we never render the wrong table mid-switch.
  const resultsMode = at ? `at:${at}` : view;
  const [text, setText] = useState(q);
  const [results, setResults] = useState<Results | null>(null);
  const [loadedMode, setLoadedMode] = useState<string | null>(null);
  const [error, setError] = useState<{ message: string; pos?: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [showFields, setShowFields] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<string | null>(null);
  const [bulk, setBulk] = useState<Bulk | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [exporting, setExporting] = useState<'csv' | 'ndjson' | null>(null);
  const [busy, setBusy] = useState<Bulk['kind'] | null>(null);
  const live = useApi<Facets>(at ? null : '/search/facets', { q, facets: SEARCH_FACETS });

  useEffect(() => setText(q), [q]);

  useEffect(() => {
    let stale = false;
    setLoading(true);
    get<Results>('/search', { q, view, sort, at: at || undefined, page, page_size: PAGE_SIZE })
      .then((r) => { if (!stale) { setResults(r); setLoadedMode(resultsMode); setError(null); } })
      .catch((e: any) => {
        if (!stale) {
          setResults(null);
          setLoadedMode(null);
          setError({ message: e.message, pos: e instanceof ApiError ? e.pos : undefined });
        }
      })
      .finally(() => { if (!stale) setLoading(false); });
    return () => { stale = true; };
  }, [q, view, sort, at, page, resultsMode]);

  const update = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!('page' in changes)) next.delete('page');
    setParams(next);
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSaved(null);
    update({ q: text.trim() || null });
  };

  const pick = (f: FacetValue) => update({ q: addTerm(q, f.term) });

  const exportAs = async (format: 'csv' | 'ndjson') => {
    setActionError(null);
    setExporting(format);
    try {
      await downloadBlob(`/search/export${query({ q, format })}`, `portreveal-search.${format}`);
    } catch (e: any) {
      setActionError(`Export failed: ${e.message}`);
    } finally {
      setExporting(null);
    }
  };

  const openBulk = async (kind: Bulk['kind']) => {
    setActionError(null);
    setBusy(kind);
    try {
      const r = await get<{ uuids: string[] }>('/search/uuids', { q });
      if (!r.uuids.length) setActionError('No hosts match this query.');
      else setBulk({ kind, uuids: r.uuids });
    } catch (e: any) {
      setActionError(e.message);
    } finally {
      setBusy(null);
    }
  };

  const shown = loadedMode === resultsMode ? results : null;
  const facets = at ? shown?.facets : live.data;
  const bulkLabel = bulk && `${bulk.uuids.length} host${bulk.uuids.length === 1 ? '' : 's'} matching “${q || 'everything'}”`;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Search</h1>
          <p>Query the inventory built from scans and web captures. Searching never sends traffic to the network.</p>
        </div>
      </div>

      <form className="search-bar" onSubmit={submit}>
        <input type="search" value={text} onChange={(e) => setText(e.target.value)} maxLength={1000} autoFocus
          placeholder='e.g. port:22 product:openssh  ·  tag:camera  ·  http.title:"login"' aria-label="Search query" />
        <label className="row small muted" title="Search the daily snapshots as of this date instead of current data">
          As of<input type="date" value={at} onChange={(e) => update({ at: e.target.value || null })} />
        </label>
        <button className="btn primary" type="submit">Search</button>
      </form>
      <div className="row wrap small muted" style={{ gap: 6 }}>
        Try:
        {EXAMPLES.map((ex) => <button key={ex} type="button" className="chip" onClick={() => update({ q: ex })}>{ex}</button>)}
        <button type="button" className="btn ghost sm" onClick={() => setShowFields(!showFields)}>{showFields ? 'Hide' : 'Show'} field reference</button>
      </div>
      {showFields && <Card title="Field reference"><FieldReference /></Card>}
      {error && <QueryError query={q} error={error.message} pos={error.pos} />}
      <ErrorBox error={actionError} />
      {saved && <div className="alert ok">Saved watch “{saved}”. <Link to="/watches">Open watches →</Link></div>}

      <div className="search-layout">
        <aside className="card card-body">
          {error ? <div className="muted small">Fix the query to see facets.</div>
            : facets ? <FacetList facets={facets} onPick={pick} />
            : live.error && !at ? <ErrorBox error={live.error} /> : <Loading />}
        </aside>
        <div className="stack" style={{ minWidth: 0 }}>
          <div className="spread" style={{ flexWrap: 'wrap' }}>
            <div className="row wrap">
              <strong>{shown ? `${shown.total.toLocaleString()} ${at ? 'hosts' : view}` : '…'}</strong>
              {at && shown?.snapshots && (
                <span className="muted small">
                  from {shown.snapshots.length ? shown.snapshots.map((s) => `${s.network ?? 'network'} @ ${s.snapshot_date}`).join(', ') : 'no snapshots on or before this date'}
                </span>
              )}
            </div>
            <div className="row wrap">
              {!at && (
                <div className="tabs" role="tablist" style={{ borderBottom: 0 }}>
                  <button role="tab" aria-selected={view === 'hosts'} className={view === 'hosts' ? 'active' : ''} onClick={() => update({ view: null })}>Hosts</button>
                  <button role="tab" aria-selected={view === 'services'} className={view === 'services' ? 'active' : ''} onClick={() => update({ view: 'services' })}>Services</button>
                </div>
              )}
              {!at && view === 'hosts' && (
                <select value={sort} onChange={(e) => update({ sort: e.target.value === 'score' ? null : e.target.value })} aria-label="Sort by">
                  {SORTS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
                </select>
              )}
              <button className="btn sm" onClick={() => exportAs('csv')} disabled={loading || !!error || exporting !== null}>
                {exporting === 'csv' ? 'Exporting…' : 'Export CSV'}
              </button>
              <button className="btn sm" onClick={() => exportAs('ndjson')} disabled={loading || !!error || exporting !== null}>
                {exporting === 'ndjson' ? 'Exporting…' : 'Export NDJSON'}
              </button>
              <button className="btn sm" onClick={() => setSaving(true)} disabled={!q || !!error}>Save as watch</button>
              {isAdmin && !at && (
                <>
                  <button className="btn sm" onClick={() => openBulk('scan')} disabled={loading || busy !== null || !!error || !shown?.total}>
                    {busy === 'scan' ? 'Loading hosts…' : 'Scan results'}
                  </button>
                  <button className="btn sm" onClick={() => openBulk('web')} disabled={loading || busy !== null || !!error || !shown?.total}>
                    {busy === 'web' ? 'Loading hosts…' : 'Capture web'}
                  </button>
                </>
              )}
            </div>
          </div>

          {loading && !shown ? <Loading /> : !shown ? null : (
            <div
              aria-busy={loading || undefined}
              style={loading ? { opacity: 0.55, pointerEvents: 'none' } : undefined}
            >
              {!shown.items.length ? (
                <Card><Empty>No hosts match this query.</Empty></Card>
              ) : at ? (
                <Card flush>
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>IP</th><th>Hostname</th><th>Network</th><th>Type</th><th>Score</th><th>Ports</th><th>Tags</th></tr></thead>
                      <tbody>
                        {(shown.items as HistoryHost[]).map((h) => (
                          <tr key={`${h.network}-${h.uuid}`} className="clickable" onClick={() => nav(`/devices/${h.uuid}`)}>
                            <td className="mono">{h.ip}</td>
                            <td>{h.hostname ?? '—'}</td>
                            <td>{h.network ?? '—'}</td>
                            <td>{h.type ?? '—'}</td>
                            <td>{h.score != null ? <ScoreBadge score={h.score} /> : '—'}</td>
                            <td>{h.ports.slice(0, 8).map((p) => <span key={`${p.proto}${p.port}`} className="chip" title={p.product ?? p.service ?? undefined}>{p.port}</span>)}</td>
                            <td>{h.tags.map((t) => <span key={t} className="chip">{t}</span>)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>
              ) : view === 'services' ? (
                <Card flush>
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>HTTP</th><th>Score</th></tr></thead>
                      <tbody>
                        {(shown.items as SearchServiceRow[]).map((s) => (
                          <tr key={`${s.host.uuid}-${s.protocol}${s.port}`} className="clickable" onClick={() => nav(`/devices/${s.host.uuid}`)}>
                            <td><span className="mono">{s.host.ip}</span>{s.host.hostname && <div className="muted small">{s.host.hostname}</div>}</td>
                            <td className="mono nowrap">{s.port}/{s.protocol}</td>
                            <td>{serviceLabel(s) || <span className="muted">—</span>}{s.extra_info && <div className="muted small">{s.extra_info}</div>}</td>
                            <td className="small">{s.http ? <>{s.http.status ?? ''} {s.http.title ?? ''}</> : <span className="muted">—</span>}</td>
                            <td><ScoreBadge score={s.host.score} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>
              ) : (
                <Card flush>
                  {(shown.items as SearchHost[]).map((h) => <HostResult key={h.uuid} h={h} />)}
                </Card>
              )}
              {shown.total > 0 && (
                <Pager page={page} pageSize={PAGE_SIZE} total={shown.total} onPage={(p) => update({ page: p > 1 ? String(p) : null })} />
              )}
            </div>
          )}
        </div>
      </div>

      {saving && (
        <SaveWatchDialog query={q} onClose={() => setSaving(false)} onSaved={(s) => { setSaving(false); setSaved(s.name); }} />
      )}
      {bulk?.kind === 'scan' && (
        <ScanDialog
          preset={{ scan_type: 'standard', device_uuids: bulk.uuids, deviceLabel: bulkLabel ?? undefined, criteria: q }}
          onClose={() => setBulk(null)}
          onStarted={() => nav('/scans')}
        />
      )}
      {bulk?.kind === 'web' && (
        <WebCaptureDialog
          preset={{ device_uuids: bulk.uuids, deviceLabel: bulkLabel ?? undefined }}
          onClose={() => setBulk(null)}
          onStarted={() => nav('/web')}
        />
      )}
    </>
  );
}
