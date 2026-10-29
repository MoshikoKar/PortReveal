import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { get, post } from '../api';
import { useApp } from '../context';
import { HttpBadge, LazyShot, Lightbox, endpointUrl, isRtspPage, shotNote, thumbUrl } from '../components/WebShots';
import { Card, ErrorBox } from '../components/ui';
import type { Network, WebCapture, WebPreviewCard, WebPreviewPage } from '../types';
import { fmtTime, relTime, useApi } from '../util';
import { type PreviewStatus, type WebFilters, filtersFromParams, previewQuery, withFilters } from '../webGallery';

const STATUS_CHIPS: { id: PreviewStatus | null; label: string }[] = [
  { id: null, label: 'All' },
  { id: 'ok', label: 'With preview' },
  { id: 'no_preview', label: 'No preview' },
  { id: 'error', label: 'Errors' },
];
const ACTIVE_CAPTURE = new Set(['queued', 'running']);

/** Why a card has no image, in words (the full reason is in the tooltip). */
function noPreviewLabel(c: WebPreviewCard): string {
  if (c.status === 'error') return shotNote(c.page);
  return c.page.capture_error?.startsWith('unavailable: ') ? 'Unavailable' : 'Preview unavailable';
}

/** One card per web service; hosts without any usable service get a single `error` card. */
function PreviewCard({ c, onOpen, refresh, onRefresh }: {
  c: WebPreviewCard;
  onOpen?: () => void;
  refresh?: 'queued' | string;
  onRefresh?: () => void;
}) {
  const p = c.page;
  const to = `/devices/${c.device_uuid}/web`;
  const note = shotNote(p);
  return (
    <article className="host-card" data-status={c.status}>
      {onOpen ? (
        <button type="button" className="shot-img" onClick={onOpen} title="Open full preview"
          aria-label={`Open preview of ${c.hostname ?? c.ip}`}>
          <LazyShot src={thumbUrl(p)} alt={p.title ?? endpointUrl(p)} />
        </button>
      ) : (
        <Link to={to} className="shot-img shot-ph" title={note}><span>{noPreviewLabel(c)}</span></Link>
      )}
      <div className="shot-meta">
        <div className="spread">
          <Link to={to} className="shot-title host-card-name">{c.hostname ?? c.ip}</Link>
          <HttpBadge status={p.http_status} rtsp={isRtspPage(p)} />
        </div>
        <div className="mono small muted shot-title" title={endpointUrl(p)}>
          {c.hostname && p.host_used !== c.ip ? `${c.ip} · ` : ''}{endpointUrl(p)}
        </div>
        <div className="small shot-title" title={p.title ?? undefined}>{p.title ?? <span className="muted">Untitled</span>}</div>
        <div>{c.ports.map((port) => <span className="chip" key={port}>{port}</span>)}</div>
        <div className="row wrap gap-2">
          {c.has_login && <span className="badge low">login page</span>}
          {p.tls_verified === false && <span className="badge outline">TLS unverified</span>}
          {c.status !== 'ok' && <span className="badge outline" title={note}>{c.status === 'error' ? 'no web application' : 'no preview'}</span>}
        </div>
        <div className="spread muted small">
          <span title={`Captured ${fmtTime(c.captured_at, true)}`}>
            {c.page_count > 0 && <>{c.page_count} live page{c.page_count === 1 ? '' : 's'} · </>}captured {relTime(c.captured_at)}
          </span>
          {onRefresh && (
            <button type="button" className="btn ghost sm" disabled={!!refresh} onClick={onRefresh}
              title={refresh && refresh !== 'queued' ? refresh : 'Capture this device again (new screenshot)'}>
              {refresh === 'queued' ? 'Refreshing…' : 'Refresh'}
            </button>
          )}
        </div>
      </div>
    </article>
  );
}

function SkeletonCard() {
  return (
    <div className="host-card" aria-hidden="true">
      <div className="shot-img"><span className="shot-skeleton" /></div>
      <div className="shot-meta">
        <span className="skeleton-bar" style={{ width: '60%' }} />
        <span className="skeleton-bar" style={{ width: '80%' }} />
        <span className="skeleton-bar" style={{ width: '40%' }} />
      </div>
    </div>
  );
}

export default function WebHosts() {
  // Filters live in the URL (q, network, port, scheme, status, archived) so reload, Back and shared links keep them.
  const { isAdmin } = useApp();
  const [sp, setSp] = useSearchParams();
  const filters = useMemo(() => filtersFromParams(sp), [sp]);
  const networks = useApi<Network[]>('/networks', { include_archived: filters.archived ? 'true' : undefined });
  const [qInput, setQInput] = useState(filters.q);
  const [items, setItems] = useState<WebPreviewCard[] | null>(null);
  const [meta, setMeta] = useState<Omit<WebPreviewPage, 'items'> | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [refreshing, setRefreshing] = useState<Record<string, string>>({});
  const seq = useRef(0);
  const query = JSON.stringify(previewQuery(filters, 1));

  // From the URL at call time (not this render's copy): the debounced search must not undo a filter clicked meanwhile.
  const update = (patch: Partial<WebFilters>, replace = false) => setSp((cur) => withFilters(cur, patch), { replace });

  // Search box -> URL after a short pause; Back/links -> search box.
  useEffect(() => { setQInput(filters.q); }, [filters.q]);
  useEffect(() => {
    if (qInput === filters.q) return;
    const t = window.setTimeout(() => update({ q: qInput }, true), 300);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qInput]);

  // Filters changed: start over from the first page.
  useEffect(() => {
    const my = ++seq.current;
    setItems(null);
    setOpen(null);
    setError(null);
    get<WebPreviewPage>('/web-previews', JSON.parse(query))
      .then(({ items: first, ...rest }) => {
        if (my !== seq.current) return;
        setItems(first);
        setMeta(rest);
      })
      .catch((e) => { if (my === seq.current) setError(e.message || String(e)); });
  }, [query]);

  const loadMore = async () => {
    if (!meta || loadingMore) return;
    const my = seq.current;
    setLoadingMore(true);
    try {
      const { items: more, ...rest } = await get<WebPreviewPage>('/web-previews', previewQuery(filters, meta.page + 1));
      if (my !== seq.current) return;
      setItems((cur) => {
        const seen = new Set((cur ?? []).map((c) => c.key));
        return [...(cur ?? []), ...more.filter((c) => !seen.has(c.key))];
      });
      setMeta(rest);
    } catch (e: any) {
      if (my === seq.current) setError(e.message || String(e));
    } finally {
      setLoadingMore(false);
    }
  };

  // Refresh: capture the device again, wait for the job, then swap in that device's new cards.
  const refreshCard = useCallback(async (c: WebPreviewCard) => {
    setRefreshing((r) => ({ ...r, [c.device_uuid]: 'queued' }));
    try {
      let { capture: job } = await post<{ capture: WebCapture }>('/web-captures', { device_uuids: [c.device_uuid], scope: 'web' });
      while (ACTIVE_CAPTURE.has(job.status)) {
        await new Promise((r) => window.setTimeout(r, 3000));
        job = await get<WebCapture>(`/web-captures/${job.id}`);
      }
      const fresh = await get<WebPreviewPage>('/web-previews', {
        q: c.ip, page_size: 200, include_archived: filters.archived ? 'true' : undefined,
      });
      const mine = fresh.items.filter((x) => x.device_uuid === c.device_uuid);
      setItems((cur) => {
        if (!cur) return cur;
        const at = cur.findIndex((x) => x.device_uuid === c.device_uuid);
        const rest = cur.filter((x) => x.device_uuid !== c.device_uuid);
        rest.splice(at < 0 ? rest.length : at, 0, ...mine);
        return rest;
      });
      setRefreshing((r) => Object.fromEntries(Object.entries(r).filter(([k]) => k !== c.device_uuid)));
    } catch (e: any) {
      setRefreshing((r) => ({ ...r, [c.device_uuid]: `Refresh failed: ${e.message || e}` }));
    }
  }, [filters.archived]);

  const withShot = (items ?? []).filter((c) => c.status === 'ok');
  const counts = meta?.counts;
  const countAll = counts ? counts.ok + counts.no_preview + counts.error : null;
  const filtered = !!(filters.q || filters.network || filters.port || filters.scheme) || (countAll ?? 0) > 0;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Web interfaces</h1>
          <p>HTTP(S) and RTSP services from the latest Web Capture - one card per service, previews first. RDP and VNC desktops are under <Link to="/remote">Remote</Link>.</p>
        </div>
        <div className="row wrap">
          <label className="check small" title="Hosts of networks archived in Settings > Networks are hidden by default">
            <input type="checkbox" checked={filters.archived} onChange={(e) => update({ archived: e.target.checked })} />Show archived networks
          </label>
          <input type="search" aria-label="Search web interfaces" placeholder="Search host, IP, title…" value={qInput}
            onChange={(e) => setQInput(e.target.value)} style={{ width: 240 }} />
        </div>
      </div>
      <div className="row wrap web-filters">
        <select aria-label="Network" value={filters.network ?? ''} onChange={(e) => update({ network: e.target.value ? Number(e.target.value) : null })}>
          <option value="">All networks</option>
          {(networks.data ?? []).map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
        </select>
        <select aria-label="Scheme" value={filters.scheme ?? ''} onChange={(e) => update({ scheme: (e.target.value || null) as WebFilters['scheme'] })}>
          <option value="">HTTP and HTTPS</option><option value="http">HTTP</option><option value="https">HTTPS</option>
        </select>
        <input type="number" aria-label="Port" placeholder="Port" min={1} max={65535} value={filters.port ?? ''} style={{ width: 96 }}
          onChange={(e) => update({ port: e.target.value ? Number(e.target.value) : null }, true)} />
        <div className="row" style={{ gap: 4 }}>
          {STATUS_CHIPS.map((s) => {
            const n = counts ? (s.id ? counts[s.id] : countAll) : null;
            return (
              <button key={s.label} type="button" className={`btn sm toggle${filters.status === s.id ? ' on' : ''}`}
                aria-pressed={filters.status === s.id} onClick={() => update({ status: s.id })}>
                {s.label}{n != null && <span className="muted"> ({n})</span>}
              </button>
            );
          })}
        </div>
      </div>
      <ErrorBox error={error} />
      {!items ? (
        error ? null : <div className="host-grid" aria-busy="true">{Array.from({ length: 8 }, (_, i) => <SkeletonCard key={i} />)}</div>
      ) : !items.length ? (
        <Card>
          <span className="muted">
            {filtered ? 'No web service matches these filters.' : <>No captures yet. Start one from <Link to="/scans?tab=web-captures">Scans → Web captures</Link> or from a device page.</>}
          </span>
        </Card>
      ) : (
        <>
          <div className="host-grid">
            {items.map((c) => (
              <PreviewCard key={c.key} c={c}
                onOpen={c.status === 'ok' ? () => setOpen(withShot.indexOf(c)) : undefined}
                refresh={refreshing[c.device_uuid]}
                onRefresh={isAdmin ? () => refreshCard(c) : undefined} />
            ))}
          </div>
          {meta && (
            <div className="row web-more">
              <span className="muted small">Showing {items.length} of {meta.total}</span>
              {items.length < meta.total && (
                <button type="button" className="btn" onClick={loadMore} disabled={loadingMore}>
                  {loadingMore ? 'Loading…' : 'Load more'}
                </button>
              )}
            </div>
          )}
        </>
      )}
      {open != null && withShot[open] && (
        <Lightbox pages={withShot.map((c) => c.page)} index={open} onIndex={setOpen} onClose={() => setOpen(null)} />
      )}
    </>
  );
}
