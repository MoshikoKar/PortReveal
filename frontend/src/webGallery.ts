/** Web gallery (/web): filter state <-> URL, API query, and lazy preview loading. Browser-free so it is unit tested. */

export type PreviewStatus = 'ok' | 'no_preview' | 'error';
export const PREVIEW_STATUSES: PreviewStatus[] = ['ok', 'no_preview', 'error'];
export const WEB_PREVIEWS_PAGE_SIZE = 36;
/** The gallery opens on cards with a preview; `status=all` in the URL lists every card. */
export const DEFAULT_STATUS: PreviewStatus = 'ok';

export interface WebFilters {
  q: string;
  network: number | null;
  port: number | null;
  scheme: 'http' | 'https' | null;
  /** null = every status. */
  status: PreviewStatus | null;
  archived: boolean;
}

const intParam = (v: string | null, max: number): number | null => {
  const n = Number(v);
  return v && Number.isInteger(n) && n >= 1 && n <= max ? n : null;
};

/** Filters from the URL; unknown or malformed values are ignored (shared links never break the page). */
export function filtersFromParams(sp: URLSearchParams): WebFilters {
  const scheme = sp.get('scheme');
  const status = sp.get('status');
  return {
    q: sp.get('q') ?? '',
    network: intParam(sp.get('network'), Number.MAX_SAFE_INTEGER),
    port: intParam(sp.get('port'), 65535),
    scheme: scheme === 'http' || scheme === 'https' ? scheme : null,
    status: status === 'all' ? null
      : PREVIEW_STATUSES.includes(status as PreviewStatus) ? (status as PreviewStatus) : DEFAULT_STATUS,
    archived: sp.get('archived') === '1',
  };
}

/**
 * A copy of `sp` with the given filters set; other params are kept. Empty/null values are removed,
 * except status: null (every status) is written as `status=all`, and the default is left out.
 */
export function withFilters(sp: URLSearchParams, patch: Partial<WebFilters>): URLSearchParams {
  const next = new URLSearchParams(sp);
  for (const [k, v] of Object.entries(patch)) {
    const s = k === 'status'
      ? (v == null ? 'all' : v === DEFAULT_STATUS ? '' : String(v)) // the default stays out of the URL
      : typeof v === 'boolean' ? (v ? '1' : '') : v == null ? '' : String(v);
    if (s) next.set(k, s);
    else next.delete(k);
  }
  return next;
}

/** Query for GET /api/web-previews. */
export function previewQuery(f: WebFilters, page: number, pageSize = WEB_PREVIEWS_PAGE_SIZE): Record<string, string | number> {
  const q: Record<string, string | number> = { page, page_size: pageSize };
  if (f.q.trim()) q.q = f.q.trim();
  if (f.network != null) q.network_id = f.network;
  if (f.port != null) q.port = f.port;
  if (f.scheme) q.scheme = f.scheme;
  if (f.status) q.status = f.status;
  if (f.archived) q.include_archived = 'true';
  return q;
}

type ObserverCtor = new (cb: IntersectionObserverCallback, opts?: IntersectionObserverInit) => {
  observe(el: Element): void;
  disconnect(): void;
};

/**
 * Call `onVisible` once, when `el` comes within `rootMargin` of the viewport; returns a cleanup.
 * Without IntersectionObserver (very old browsers) the preview loads right away.
 */
export function observeWhenVisible(
  el: Element,
  onVisible: () => void,
  rootMargin = '200px',
  Observer: ObserverCtor | undefined = (globalThis as { IntersectionObserver?: ObserverCtor }).IntersectionObserver,
): () => void {
  if (!Observer) {
    onVisible();
    return () => {};
  }
  let done = false;
  const io = new Observer((entries) => {
    if (done || !entries.some((e) => e.isIntersecting)) return;
    done = true;
    io.disconnect();
    onVisible();
  }, { rootMargin });
  io.observe(el);
  return () => io.disconnect();
}
