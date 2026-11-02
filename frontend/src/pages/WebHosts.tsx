import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { get, post } from '../api';
import { useApp } from '../context';
import { HttpBadge, LazyShot, Lightbox, endpointUrl, isRtspPage, shotNote, thumbUrl } from '../components/WebShots';
import { Card, ErrorBox } from '../components/ui';
import type { Network, WebCapture, WebPreviewCard, WebPreviewPage } from '../types';
import { fmtTime, relTime, useApi } from '../util';
import {
  ATTENTION_RISK, EXPOSURE_INFO, STALE_DAYS, type PreviewStatus, type WebFilters, ageDays, captureAgeText, filterUpdater,
  filtersFromParams, hasFilters, pageTitle, previewQuery, withFilters,
} from '../webGallery';

const STATUS_CHIPS: { id: PreviewStatus | null; label: string; title: string }[] = [
  { id: null, label: 'All', title: 'Every web service of the latest capture' },
  { id: 'ok', label: 'Screenshot', title: 'A working page with a screenshot' },
  { id: 'no_preview', label: 'No screenshot', title: 'A working page whose screenshot failed or was skipped' },
  { id: 'error', label: 'No usable page', title: 'Nothing usable answered: an error, blank or default page, or a redirect elsewhere' },
];
const ACTIVE_CAPTURE = new Set(['queued', 'running']);
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** Re-capture of one device: still running, or why the last attempt failed. */
type Recapture = { running: true } | { running: false; error: string };

/** One card per web service; hosts without any usable service get a single `error` card. */
function PreviewCard({ c, onOpen, recapture, onRecapture }: {
  c: WebPreviewCard;
  onOpen?: () => void;
  recapture?: Recapture;
  onRecapture?: () => void;
}) {
  const p = c.page;
  const to = `/devices/${c.device_uuid}/web`;
  const name = c.hostname ?? c.ip;
  const title = pageTitle(p.title);
  // The worst finding gets the band when it needs attention; the rest are badges
  const flag = c.risk >= ATTENTION_RISK ? c.exposure[0] : undefined;
  // A default page already says so in the no-screenshot placeholder
  const badges = c.exposure.filter((f) => f !== flag && !(f === 'default_page' && !onOpen));
  const stale = ageDays(c.captured_at) > STALE_DAYS;
  return (
    <article className="host-card" data-status={c.status} data-risk={flag ? EXPOSURE_INFO[flag].severity : undefined}>
      {onOpen ? (
        <button type="button" className="shot-img" onClick={onOpen} data-card={c.key}
          aria-label={`Open screenshot of ${name}${title ? `, ${title}` : ''}`}>
          <LazyShot src={thumbUrl(p)} alt="" />
        </button>
      ) : (
        <div className="shot-img shot-ph"><span>{shotNote(p)}</span></div>
      )}
      {flag && (
        <p className="exposure-band" title={EXPOSURE_INFO[flag].hint}>
          <strong>{EXPOSURE_INFO[flag].label}</strong> <span>{EXPOSURE_INFO[flag].short}</span>
        </p>
      )}
      <div className="shot-meta">
        <div className="spread">
          {/* The screenshot button is the card's tab stop; the lightbox links to the device page */}
          <h2 className="host-card-h">
            <Link to={to} className="shot-title host-card-name" tabIndex={onOpen ? -1 : undefined}>{name}</Link>
          </h2>
          <span className="row host-card-badges">
            {c.is_new && <span className="badge accent" title="Not in this device's previous capture">New</span>}
            <HttpBadge status={p.http_status} rtsp={isRtspPage(p)} />
          </span>
        </div>
        <div className="mono small muted shot-title" title={endpointUrl(p)}>
          {c.hostname && p.host_used !== c.ip ? `${c.ip} · ` : ''}{endpointUrl(p)}
        </div>
        {title ? <div className="small shot-title" title={title}>{title}</div>
          : p.server_header && <div className="small muted shot-title" title={`Server header: ${p.server_header}`}>{p.server_header}</div>}
        <div className="row wrap host-card-tags">
          {c.ports.map((port) => <span className="chip" key={port}>{port}</span>)}
          {c.has_login && flag !== 'cleartext_login' && flag !== 'login_unverified_tls' && <span className="badge outline">login page</span>}
          {badges.map((f) => (
            <span key={f} className={`badge ${EXPOSURE_INFO[f].severity}`} title={EXPOSURE_INFO[f].hint}>{EXPOSURE_INFO[f].label}</span>
          ))}
        </div>
        <div className="spread small">
          <span className={stale ? 'stale' : 'muted'}
            title={`Captured ${fmtTime(c.captured_at, true)}${stale ? ` - older than ${STALE_DAYS} days` : ''}`}>
            {c.page_count > 1 && <>{c.page_count} pages · </>}captured {relTime(c.captured_at)}
          </span>
          {onRecapture && (
            <button type="button" className="btn ghost sm" disabled={recapture?.running} onClick={onRecapture}
              title="Take new screenshots of this device's web services">
              {recapture?.running ? 'Re-capturing…' : recapture ? 'Retry' : 'Re-capture'}
            </button>
          )}
        </div>
        {recapture && !recapture.running && <p className="small recapture-error">Re-capture failed: {recapture.error}</p>}
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
  // Filters live in the URL (q, network, port, scheme, status, attention, new, sort, archived) so reload, Back and shared links keep them.
  const { isAdmin } = useApp();
  const [sp, setSp] = useSearchParams();
  const filters = useMemo(() => filtersFromParams(sp), [sp]);
  const networks = useApi<Network[]>('/networks', { include_archived: filters.archived ? 'true' : undefined });
  const [qInput, setQInput] = useState(filters.q);
  const [portInput, setPortInput] = useState(filters.port?.toString() ?? '');
  const [items, setItems] = useState<WebPreviewCard[] | null>(null);
  const [meta, setMeta] = useState<Omit<WebPreviewPage, 'items'> | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<number | null>(null);
  const [recaptures, setRecaptures] = useState<Record<string, Recapture>>({});
  // Screen-reader announcements: result counts and re-capture outcomes
  const [announce, setAnnounce] = useState('');
  const seq = useRef(0);
  // Set when the lightbox steps past the last loaded screenshot: advance once more have loaded
  const pendingNext = useRef(false);
  const query = JSON.stringify(previewQuery(filters, 1));

  useEffect(() => {
    const prev = document.title;
    document.title = 'Web interfaces · PortReveal';
    return () => { document.title = prev; };
  }, []);

  // Latest params at commit time (ref, not a captured copy): the debounced search must not undo a filter clicked meanwhile.
  const spRef = useRef(sp);
  spRef.current = sp;
  const update = filterUpdater(() => spRef.current, setSp);

  // Search box and port field -> URL after a short pause; Back/links -> the fields.
  useEffect(() => { setQInput(filters.q); }, [filters.q]);
  useEffect(() => {
    if (qInput === filters.q) return;
    const t = window.setTimeout(() => update({ q: qInput }, true), 300);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qInput]);
  useEffect(() => { setPortInput(filters.port?.toString() ?? ''); }, [filters.port]);
  useEffect(() => {
    const n = Number(portInput);
    const port = portInput && Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
    if (port === filters.port || (portInput && port == null)) return;
    const t = window.setTimeout(() => update({ port }, true), 400);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [portInput]);

  // Filters changed: start over from the first page.
  useEffect(() => {
    const my = ++seq.current;
    setItems(null);
    setOpen(null);
    setError(null);
    pendingNext.current = false;
    get<WebPreviewPage>('/web-previews', JSON.parse(query))
      .then(({ items: first, ...rest }) => {
        if (my !== seq.current) return;
        setItems(first);
        setMeta(rest);
        setAnnounce(plural(rest.total, 'web service', 'web services'));
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
      pendingNext.current = false;
      if (my === seq.current) setError(e.message || String(e));
    } finally {
      setLoadingMore(false);
    }
  };

  // Re-capture: capture the device again, wait for the job, then swap in that device's new cards.
  const recapture = useCallback(async (c: WebPreviewCard) => {
    const name = c.hostname ?? c.ip;
    setRecaptures((r) => ({ ...r, [c.device_uuid]: { running: true } }));
    setAnnounce(`Re-capturing ${name}`);
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
      setRecaptures((r) => Object.fromEntries(Object.entries(r).filter(([k]) => k !== c.device_uuid)));
      setAnnounce(`${name} re-captured`);
    } catch (e: any) {
      const msg = e.message || String(e);
      setRecaptures((r) => ({ ...r, [c.device_uuid]: { running: false, error: msg } }));
      setAnnounce(`Re-capture of ${name} failed: ${msg}`);
    }
  }, [filters.archived]);

  const withShot = (items ?? []).filter((c) => c.status === 'ok');
  const counts = meta?.counts;
  const countAll = counts ? counts.ok + counts.no_preview + counts.error : null;
  const narrowed = hasFilters(filters);
  const oldest = meta?.captured_range ? ageDays(meta.captured_range[0]) : 0;

  useEffect(() => {
    if (!pendingNext.current || open == null) return;
    if (withShot.length > open + 1) {
      pendingNext.current = false;
      setOpen(open + 1);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items]);

  const clearFilters = () => {
    setSp(withFilters(spRef.current, {
      q: '', network: null, port: null, scheme: null, status: null, attention: false, fresh: false, archived: false,
    }));
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Web interfaces</h1>
          <p className="web-intro">HTTP(S) and RTSP services found by Web Capture, one card per service, worst exposure first. RDP and VNC desktops are under <Link to="/remote">Remote</Link>.</p>
          {meta && (narrowed || (countAll ?? 0) > 0) && (
            <p className="web-summary">
              {meta.attention > 0
                ? <strong className="attention">{plural(meta.attention, 'service needs', 'services need')} attention</strong>
                : <span>No service flagged for attention</span>}
              {meta.new > 0 && <> · {meta.new} new since last capture</>}
              {meta.captured_range && (
                <> · <span className={oldest > STALE_DAYS ? 'stale' : undefined}
                  title={oldest > STALE_DAYS ? `Some captures are older than ${STALE_DAYS} days` : undefined}>
                  {captureAgeText(meta.captured_range)}</span></>
              )}
            </p>
          )}
        </div>
      </div>
      <div className="web-filters">
        <input type="search" aria-label="Search web interfaces" placeholder="Search host, IP, title…" value={qInput}
          onChange={(e) => setQInput(e.target.value)} className="web-search" />
        <select aria-label="Network" value={filters.network ?? ''} onChange={(e) => update({ network: e.target.value ? Number(e.target.value) : null })}>
          <option value="">All networks</option>
          {(networks.data ?? []).map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
        </select>
        <select aria-label="Scheme" value={filters.scheme ?? ''} onChange={(e) => update({ scheme: (e.target.value || null) as WebFilters['scheme'] })}>
          <option value="">HTTP and HTTPS</option><option value="http">HTTP</option><option value="https">HTTPS</option>
        </select>
        <input type="number" aria-label="Port" placeholder="Port" min={1} max={65535} value={portInput} className="web-port"
          onChange={(e) => setPortInput(e.target.value)} />
        <select aria-label="Sort" value={filters.sort} onChange={(e) => update({ sort: e.target.value as WebFilters['sort'] })}>
          <option value="risk">Riskiest first</option>
          <option value="name">Host name</option>
          <option value="oldest">Oldest capture</option>
        </select>
        <label className="check small" title="Hosts of networks archived in Settings > Networks are hidden by default">
          <input type="checkbox" checked={filters.archived} onChange={(e) => update({ archived: e.target.checked })} />Archived networks
        </label>
      </div>
      <div className="row wrap web-chips">
        <div className="row wrap web-chip-group" role="group" aria-label="Screenshot">
          {STATUS_CHIPS.map((s) => {
            const n = counts ? (s.id ? counts[s.id] : countAll) : null;
            return (
              <button key={s.label} type="button" className={`btn sm toggle${filters.status === s.id ? ' on' : ''}`}
                aria-pressed={filters.status === s.id} title={s.title} onClick={() => update({ status: s.id })}>
                {s.label}{n != null && <span className="muted"> ({n})</span>}
              </button>
            );
          })}
        </div>
        <div className="row wrap web-chip-group" role="group" aria-label="Highlights">
          <button type="button" className={`btn sm toggle${filters.attention ? ' on' : ''}`} aria-pressed={filters.attention}
            title="Services with a medium or high exposure finding" onClick={() => update({ attention: !filters.attention })}>
            Needs attention{meta && <span className={meta.attention ? 'attention' : 'muted'}> ({meta.attention})</span>}
          </button>
          <button type="button" className={`btn sm toggle${filters.fresh ? ' on' : ''}`} aria-pressed={filters.fresh}
            title="Services the device did not have in its previous capture" onClick={() => update({ fresh: !filters.fresh })}>
            New since last capture{meta && <span className="muted"> ({meta.new})</span>}
          </button>
        </div>
      </div>
      <p className="sr-only" role="status" aria-live="polite">{announce}</p>
      <ErrorBox error={error} />
      {!items ? (
        error ? null : <div className="host-grid" aria-busy="true">{Array.from({ length: 8 }, (_, i) => <SkeletonCard key={i} />)}</div>
      ) : !items.length ? (
        <Card>
          <div className="row wrap web-empty">
            <span className="muted">
              {narrowed || (countAll ?? 0) > 0
                ? 'No web service matches these filters.'
                : <>No captures yet. Start one from <Link to="/scans?tab=web-captures">Scans → Web captures</Link> or from a device page.</>}
            </span>
            {narrowed && <button type="button" className="btn sm" onClick={clearFilters}>Clear filters</button>}
          </div>
        </Card>
      ) : (
        <>
          <div className="host-grid">
            {items.map((c) => (
              <PreviewCard key={c.key} c={c}
                onOpen={c.status === 'ok' ? () => setOpen(withShot.indexOf(c)) : undefined}
                recapture={recaptures[c.device_uuid]}
                onRecapture={isAdmin ? () => recapture(c) : undefined} />
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
        <Lightbox pages={withShot.map((c) => c.page)} index={open} onIndex={setOpen} onClose={() => setOpen(null)}
          total={counts?.ok}
          onEnd={() => { pendingNext.current = true; void loadMore(); }}
          focusOnClose={(i) => withShot[i] && document.querySelector<HTMLElement>(`[data-card="${CSS.escape(withShot[i].key)}"]`)}
          side={(i) => {
            const c = withShot[i];
            if (!c) return null;
            return (
              <>
                {c.exposure.map((f) => (
                  <p key={f} className={`exposure-note ${EXPOSURE_INFO[f].severity}`}>
                    <strong>{EXPOSURE_INFO[f].label}.</strong> {EXPOSURE_INFO[f].hint}
                  </p>
                ))}
                {c.is_new && <div><span className="badge accent">New since last capture</span></div>}
                <p className="small" style={{ margin: 0 }}>
                  Device <Link to={`/devices/${c.device_uuid}/web`}>{c.hostname ?? c.ip}</Link>
                  <span className="muted"> · all pages and capture history</span>
                </p>
              </>
            );
          }} />
      )}
    </>
  );
}
