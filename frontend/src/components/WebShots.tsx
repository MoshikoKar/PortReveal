import { useEffect, useState } from 'react';
import { RtspLivePlayer, liveStreamUrl } from './RtspLivePlayer';
import type { WebPage, WebPageKind } from '../types';
import { fmtTime } from '../util';

export const KIND_LABELS: Record<WebPageKind, string> = {
  home: 'Home', login: 'Login', register: 'Register', other: 'Page', stream: 'Stream',
};

export const shotUrl = (p: WebPage) => `/api/web-pages/${p.id}/screenshot`;

export const isRtspPage = (p: WebPage) =>
  p.can_live === true || p.kind === 'stream' || p.scheme === 'rtsp' || p.scheme === 'rtsps';

/** A screenshot worth showing: captured, and not of an error page (older captures kept those). */
export const isUsefulShot = (p: WebPage) => p.has_screenshot && !p.error_reason;

export function pathOf(url: string | null): string {
  if (!url) return '/';
  try {
    const u = new URL(url);
    return `${u.pathname}${u.search}` || '/';
  } catch {
    return url;
  }
}

function hostOf(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

/** The address a person would open for this endpoint (browser or RTSP client). */
export function endpointUrl(p: WebPage): string {
  if (isRtspPage(p)) return p.final_url || p.url;
  const def = (p.scheme === 'https' && p.port === 443) || (p.scheme === 'http' && p.port === 80);
  return `${p.scheme}://${p.host_used}${def ? '' : `:${p.port}`}/`;
}

export function HttpBadge({ status, rtsp }: { status: number | null; rtsp?: boolean }) {
  if (rtsp) return <span className="badge outline">RTSP</span>;
  if (status == null) return <span className="badge outline">no response</span>;
  const cls = status < 300 ? 'ok' : status < 400 ? 'low' : status === 401 || status === 403 ? 'medium' : 'high';
  return <span className={`badge ${cls}`}>HTTP {status}</span>;
}

/** Why a page has no screenshot, in words. */
export function shotNote(p: WebPage): string {
  if (isRtspPage(p)) {
    if (p.capture_error === 'ffmpeg unavailable') return 'ffmpeg unavailable at capture time';
    if (p.screenshot_status === 'failed') return p.capture_error ?? 'RTSP frame failed';
    if (p.screenshot_status === 'skipped') return p.capture_error ?? 'No RTSP frame';
    return p.capture_error ?? 'No RTSP frame';
  }
  if (p.external_redirect) return `Redirects outside the target${hostOf(p.redirect_target) ? ` (${hostOf(p.redirect_target)})` : ''}`;
  if (p.http_status != null && p.http_status >= 300 && p.http_status < 400) {
    const t = p.redirect_target ? hostOf(p.redirect_target) ?? pathOf(p.redirect_target) : null;
    return t ? `Redirects to ${t}` : 'Redirect';
  }
  if (p.http_status === 401 || p.http_status === 403) return 'Authentication required';
  if (p.error_reason?.startsWith('default server page')) {
    const m = p.error_reason.match(/\(([^)]+)\)/);
    return m ? `${m[1]} default page — no app here` : 'Default server page';
  }
  if (p.http_status == null) return 'No response';
  if (p.error_reason === 'blank page') return 'Blank page — nothing shown';
  if (p.error_reason) return 'Error page';
  if (p.capture_error === 'Chromium unavailable') return 'Browser unavailable at capture time';
  if (p.screenshot_status === 'not_requested') return 'Not captured (screenshot limit)';
  if (p.screenshot_status === 'failed') return p.capture_error ?? 'Screenshot failed';
  return p.capture_error ?? 'No screenshot';
}

/** Page flags shown next to the status. */
export function PageFlags({ p }: { p: WebPage }) {
  return (
    <>
      {p.external_redirect && <span className="badge medium" title={p.redirect_target ?? undefined}>external redirect</span>}
      {p.tls_verified === false && <span className="badge outline" title="Certificate was not verified">TLS unverified</span>}
    </>
  );
}

export function ShotTile({ p, onOpen }: { p: WebPage; onOpen?: () => void }) {
  const finalPath = pathOf(p.final_url);
  const redirected = p.final_url && p.final_url !== p.url;
  const rtsp = isRtspPage(p);
  return (
    <article className="shot">
      {isUsefulShot(p) ? (
        <button className="shot-img" onClick={onOpen} title={rtsp ? 'Open stream' : 'Open preview'}>
          {/* width/height only hint the 16:10 tile ratio; CSS sizes the image. */}
          <img src={shotUrl(p)} alt={p.title ?? p.url} loading="lazy" decoding="async" width={320} height={200} />
        </button>
      ) : (
        <div className="shot-img shot-ph"><span>{shotNote(p)}</span></div>
      )}
      <div className="shot-meta">
        <div className="row wrap" style={{ gap: 6 }}>
          <span className="badge accent">{KIND_LABELS[p.kind] ?? p.kind}</span>
          <HttpBadge status={p.http_status} rtsp={rtsp} />
          <PageFlags p={p} />
        </div>
        <div className="shot-title" title={p.title ?? undefined}>{p.title ?? <span className="muted">Untitled</span>}</div>
        <div className="mono small muted shot-path" title={p.url}>
          {rtsp ? (p.final_url || p.url) : <>{pathOf(p.url)}{redirected && <> → {hostOf(p.final_url) !== hostOf(p.url) ? p.final_url : finalPath}</>}</>}
        </div>
      </div>
    </article>
  );
}

export function Lightbox({ pages, index, onIndex, onClose }: {
  pages: WebPage[]; index: number; onIndex: (i: number) => void; onClose: () => void;
}) {
  const p = pages[index];
  const [showLive, setShowLive] = useState(false);
  const go = (d: number) => onIndex((index + d + pages.length) % pages.length);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
      else if (e.key === 'ArrowRight') go(1);
      else if (e.key === 'ArrowLeft') go(-1);
    };
    window.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  });

  useEffect(() => { setShowLive(false); }, [p?.id]);

  if (!p) return null;
  const live = p.final_url ?? p.url;
  const rtsp = isRtspPage(p);

  return (
    <div className="lightbox" role="dialog" aria-label={rtsp ? 'Stream preview' : 'Screenshot preview'}>
      <div className="lightbox-stage" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
        {rtsp && showLive ? (
          <div className="rtsp-lightbox-feed">
            <RtspLivePlayer
              src={liveStreamUrl(p.id)}
              label={p.title ?? 'RTSP'}
              posterUrl={p.has_screenshot ? shotUrl(p) : null}
              autoStart
            />
          </div>
        ) : p.has_screenshot ? (
          <img src={shotUrl(p)} alt={p.title ?? p.url} decoding="async" />
        ) : (
          <div className="rtsp-ph" style={{ minWidth: 320, minHeight: 200 }}><span>{shotNote(p)}</span></div>
        )}
        {pages.length > 1 && (
          <>
            <button className="lightbox-nav prev" onClick={() => go(-1)} aria-label="Previous">‹</button>
            <button className="lightbox-nav next" onClick={() => go(1)} aria-label="Next">›</button>
          </>
        )}
      </div>
      <aside className="lightbox-side">
        <div className="spread">
          <span className="muted small">{index + 1} / {pages.length}</span>
          <button className="btn ghost sm" onClick={onClose} aria-label="Close">✕</button>
        </div>
        <h2 style={{ overflowWrap: 'anywhere' }}>{p.title ?? 'Untitled page'}</h2>
        <div className="row wrap" style={{ gap: 6 }}>
          <span className="badge accent">{KIND_LABELS[p.kind] ?? p.kind}</span>
          <HttpBadge status={p.http_status} rtsp={rtsp} />
          <PageFlags p={p} />
        </div>
        <dl className="dl compact">
          <dt>Host</dt><dd className="mono">{p.ip}:{p.port}</dd>
          <dt>URL</dt><dd className="mono small">{p.url}</dd>
          {p.final_url && p.final_url !== p.url && <><dt>Landed on</dt><dd className="mono small">{p.final_url}</dd></>}
          {p.server_header && <><dt>Server</dt><dd>{p.server_header}</dd></>}
          {p.content_type && <><dt>Content type</dt><dd className="small">{p.content_type}</dd></>}
          <dt>Captured</dt><dd>{fmtTime(p.captured_at, true)}</dd>
        </dl>
        <div className="row wrap">
          {rtsp ? (
            <button className="btn sm primary" onClick={() => setShowLive((v) => !v)}>
              {showLive ? 'Show still' : 'Watch live'}
            </button>
          ) : (
            <a className="btn sm" href={live} target="_blank" rel="noreferrer">Open live site ↗</a>
          )}
          {p.has_screenshot && (
            <a className="btn sm ghost" href={shotUrl(p)} target="_blank" rel="noreferrer">Full-size image</a>
          )}
        </div>
        <div className="muted small">← → to browse · Esc to close</div>
      </aside>
    </div>
  );
}
