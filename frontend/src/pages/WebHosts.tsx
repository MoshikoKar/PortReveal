import { Link, useSearchParams } from 'react-router-dom';
import { HttpBadge, endpointUrl, isRtspPage, isUsefulShot, shotNote, shotUrl } from '../components/WebShots';
import { Card, ErrorBox, Loading, Pager } from '../components/ui';
import type { WebHost, WebHostPage, WebService } from '../types';
import { WEB_HOSTS_PAGE_SIZE, relTime, useApi } from '../util';

/** A host is a real "web app" if its latest capture produced at least one usable web service. */
const isApp = (h: WebHost) => h.services.length > 0;

type NoAppKind = 'default' | 'error' | 'redirect' | 'no_response' | 'blank' | 'other';

const NO_APP_FILTERS: { id: NoAppKind; label: string }[] = [
  { id: 'default', label: 'Default server pages' },
  { id: 'error', label: 'Errors' },
  { id: 'redirect', label: 'Redirects' },
  { id: 'no_response', label: 'No response' },
  { id: 'blank', label: 'Blank pages' },
  { id: 'other', label: 'Other' },
];

/** Why this host has no usable web application (general rules, not per-IP). */
function noAppKind(h: WebHost): NoAppKind {
  const p = h.hero;
  const reason = (p.error_reason ?? p.capture_error ?? '').toLowerCase();
  if (reason.startsWith('default server page')) return 'default';
  if (reason === 'blank page' || reason.startsWith('blank page')) return 'blank';
  if (
    p.external_redirect
    || reason === 'redirect'
    || reason.startsWith('redirect')
    || (p.http_status != null && p.http_status >= 300 && p.http_status < 400)
  ) {
    return 'redirect';
  }
  if (p.http_status == null || reason.includes('no http response') || reason === 'no response') {
    return 'no_response';
  }
  if (reason.startsWith('error page') || p.http_status >= 400) return 'error';
  return 'other';
}

function noAppLabel(h: WebHost): string {
  const note = shotNote(h.hero);
  const title = h.hero.title?.trim();
  if (title && note && !note.toLowerCase().includes(title.toLowerCase()) && title !== note) {
    return `${title} — ${note}`;
  }
  return title || note;
}

/** One card per web service, so every app on a host is visible without opening the host. */
function ServiceCard({ h, s, index }: { h: WebHost; s: WebService; index: number }) {
  const p = s.page;
  const total = h.services.length;
  return (
    <Link to={`/devices/${h.device_uuid}/web`} className="host-card">
      {isUsefulShot(p) ? (
        <div className="shot-img"><img src={shotUrl(p)} alt="" loading="lazy" /></div>
      ) : (
        <div className="shot-img shot-ph"><span>{p.screenshot_status === 'captured' ? 'No screenshot' : shotNote(p)}</span></div>
      )}
      <div className="shot-meta">
        <div className="spread">
          <strong className="shot-title">{h.hostname ?? h.ip}</strong>
          <HttpBadge status={p.http_status} rtsp={isRtspPage(p)} />
        </div>
        <div className="mono small muted shot-title" title={endpointUrl(p)}>
          {h.hostname && p.host_used !== h.ip ? `${h.ip} · ` : ''}{endpointUrl(p)}
        </div>
        <div className="small shot-title" title={p.title ?? undefined}>{p.title ?? <span className="muted">Untitled</span>}</div>
        <div>{s.ports.map((port) => <span className="chip" key={port}>{port}</span>)}</div>
        <div className="row wrap" style={{ gap: 6 }}>
          {s.has_login && <span className="badge low">login page</span>}
          {p.tls_verified === false && <span className="badge outline">TLS unverified</span>}
        </div>
        <div className="muted small">
          {total > 1 && <>service {index + 1} of {total} · </>}
          {s.page_count} live page{s.page_count === 1 ? '' : 's'} · {relTime(p.captured_at)}
        </div>
      </div>
    </Link>
  );
}

export default function WebHosts() {
  // Filter state lives in the URL (q, noapp=1, hide=kind,kind, page) so reload, Back and shared links keep it.
  const [sp, setSp] = useSearchParams();
  const page = Math.max(1, Number(sp.get('page')) || 1);
  const { data, error } = useApi<WebHostPage>('/web-hosts', { kind: 'web', page, page_size: WEB_HOSTS_PAGE_SIZE }, 15000);
  const q = sp.get('q') ?? '';
  // Hidden by default: default server pages, errors, blank shells, redirects, no-response
  const showNoApp = sp.get('noapp') === '1';
  const hidden = new Set((sp.get('hide') ?? '').split(','));
  const noAppFilters = Object.fromEntries(NO_APP_FILTERS.map((f) => [f.id, !hidden.has(f.id)])) as Record<NoAppKind, boolean>;
  const update = (patch: Record<string, string | null>, replace = false) => {
    const next = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setSp(next, { replace });
  };

  const needle = q.trim().toLowerCase();
  const matches = (...values: unknown[]) =>
    !needle || values.some((v) => v != null && String(v).toLowerCase().includes(needle));

  // Services of the same host stay next to each other (hosts keep the API's order)
  const cards = (data?.hosts ?? []).filter(isApp).flatMap((h) =>
    h.services
      .map((s, index) => ({ h, s, index }))
      .filter(({ s }) => matches(h.hostname, h.ip, s.page.title, s.page.server_header, s.ports.join(' '), endpointUrl(s.page))));
  const noApp = (data?.hosts ?? []).filter((h) =>
    !isApp(h) && matches(h.hostname, h.ip, h.hero.title, h.hero.server_header, h.ports.join(' '), h.hero.error_reason, shotNote(h.hero)));

  const noAppGrouped = (() => {
    const groups = Object.fromEntries(NO_APP_FILTERS.map((f) => [f.id, [] as WebHost[]])) as Record<NoAppKind, WebHost[]>;
    for (const h of noApp) {
      groups[noAppKind(h)].push(h);
    }
    return groups;
  })();

  const visibleNoAppCount = NO_APP_FILTERS.reduce(
    (n, f) => n + (noAppFilters[f.id] ? noAppGrouped[f.id].length : 0),
    0,
  );

  const toggleFilter = (id: NoAppKind) => {
    const hide = NO_APP_FILTERS.filter((f) => (f.id === id ? noAppFilters[f.id] : !noAppFilters[f.id])).map((f) => f.id);
    update({ hide: hide.join(',') || null });
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Web interfaces</h1>
          <p>HTTP(S) and RTSP services from the latest Web Capture — one card per service. RDP and VNC desktops are under <Link to="/remote">Remote</Link>. Default server pages, errors, blank pages and redirects are set aside.</p>
        </div>
        <input type="search" placeholder="Filter by host, IP, title, port…" value={q} onChange={(e) => update({ q: e.target.value || null }, true)} style={{ width: 260 }} />
      </div>
      <ErrorBox error={error} />
      {!data ? <Loading /> : !data.hosts.length ? (
        <Card>
          <span className="muted">No captures yet. Start one from <Link to="/scans?tab=web-captures">Scans → Web captures</Link> or from a device page.</span>
        </Card>
      ) : (
        <>
          {cards.length > 0 ? (
            <div className="host-grid">
              {cards.map(({ h, s, index }) => <ServiceCard key={`${h.device_uuid}:${s.scheme}:${s.port}`} h={h} s={s} index={index} />)}
            </div>
          ) : (
            <Card><span className="muted">{q ? 'No web application matches the filter.' : 'No host is serving a web application in the latest captures.'}</span></Card>
          )}

          {noApp.length > 0 && (
            <Card
              title={`No web application — ${noApp.length} host${noApp.length === 1 ? '' : 's'}`}
              flush
              actions={<button className="btn sm ghost" aria-expanded={showNoApp} onClick={() => update({ noapp: showNoApp ? null : '1' })}>{showNoApp ? 'Hide' : 'Show'}</button>}
            >
              {showNoApp && (
                <>
                  <div className="row wrap" style={{ gap: 6, padding: '10px 14px', borderBottom: '1px solid var(--border, #333)' }}>
                    <span className="muted small" style={{ marginRight: 4 }}>Show:</span>
                    {NO_APP_FILTERS.map((f) => {
                      const count = noAppGrouped[f.id].length;
                      if (!count) return null;
                      return (
                        <button
                          key={f.id}
                          type="button"
                          className={`btn sm toggle${noAppFilters[f.id] ? ' on' : ''}`}
                          onClick={() => toggleFilter(f.id)}
                          aria-pressed={noAppFilters[f.id]}
                        >
                          {f.label} ({count})
                        </button>
                      );
                    })}
                  </div>
                  {visibleNoAppCount === 0 ? (
                    <div className="muted small" style={{ padding: 14 }}>All categories are filtered out.</div>
                  ) : (
                    NO_APP_FILTERS.map((f) => {
                      const rows = noAppGrouped[f.id];
                      if (!noAppFilters[f.id] || !rows.length) return null;
                      return (
                        <div key={f.id}>
                          <div className="muted small" style={{ padding: '10px 14px 4px', fontWeight: 600 }}>
                            {f.label} — {rows.length}
                          </div>
                          <table>
                            <thead><tr><th>Host</th><th>Ports</th><th>Answered with</th><th /></tr></thead>
                            <tbody>
                              {rows.map((h) => (
                                <tr key={h.device_uuid} className="clickable" onClick={() => { window.location.href = `/devices/${h.device_uuid}/web`; }}>
                                  <td>
                                    <Link to={`/devices/${h.device_uuid}/web`} onClick={(e) => e.stopPropagation()}>{h.hostname ?? h.ip}</Link>
                                    {h.hostname && <div className="mono small muted">{h.ip}</div>}
                                  </td>
                                  <td>{h.ports.map((p) => <span className="chip" key={p}>{p}</span>)}</td>
                                  <td>
                                    <HttpBadge status={h.hero.http_status} />{' '}
                                    <span className="small muted">{noAppLabel(h)}</span>
                                  </td>
                                  <td className="right"><span className="muted small">{relTime(h.captured_at)}</span></td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      );
                    })
                  )}
                </>
              )}
            </Card>
          )}
        </>
      )}
      {data && data.total > WEB_HOSTS_PAGE_SIZE && (
        <Pager page={page} pageSize={WEB_HOSTS_PAGE_SIZE} total={data.total} onPage={(p) => update({ page: p > 1 ? String(p) : null })} />
      )}
    </>
  );
}
