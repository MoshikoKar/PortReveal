/** Web gallery (/web): filter state <-> URL, API query, exposure wording and lazy preview loading. Browser-free so it is unit tested. */
import type { WebExposure } from './types';

export type PreviewStatus = 'ok' | 'no_preview' | 'error';
export const PREVIEW_STATUSES: PreviewStatus[] = ['ok', 'no_preview', 'error'];
export const WEB_PREVIEWS_PAGE_SIZE = 36;
export type WebSort = 'risk' | 'name' | 'oldest';
const SORTS: WebSort[] = ['risk', 'name', 'oldest'];
/** Captures older than this are flagged as stale. */
export const STALE_DAYS = 7;

export interface WebFilters {
  q: string;
  network: number | null;
  port: number | null;
  scheme: 'http' | 'https' | null;
  /** null = every status (the default). */
  status: PreviewStatus | null;
  /** Only cards with a medium or high exposure finding. */
  attention: boolean;
  /** Only services the device did not have in its previous capture. */
  fresh: boolean;
  sort: WebSort;
  archived: boolean;
}

/** URL key of each filter whose name differs. */
const URL_KEYS: Partial<Record<keyof WebFilters, string>> = { fresh: 'new' };

const intParam = (v: string | null, max: number): number | null => {
  const n = Number(v);
  return v && Number.isInteger(n) && n >= 1 && n <= max ? n : null;
};

/** Filters from the URL; unknown or malformed values are ignored (shared links never break the page). */
export function filtersFromParams(sp: URLSearchParams): WebFilters {
  const scheme = sp.get('scheme');
  const status = sp.get('status');
  const sort = sp.get('sort');
  return {
    q: sp.get('q') ?? '',
    network: intParam(sp.get('network'), Number.MAX_SAFE_INTEGER),
    port: intParam(sp.get('port'), 65535),
    scheme: scheme === 'http' || scheme === 'https' ? scheme : null,
    // Older links carry status=all (the gallery used to open on previews only): same as no status
    status: PREVIEW_STATUSES.includes(status as PreviewStatus) ? (status as PreviewStatus) : null,
    attention: sp.get('attention') === '1',
    fresh: sp.get('new') === '1',
    sort: SORTS.includes(sort as WebSort) ? (sort as WebSort) : 'risk',
    archived: sp.get('archived') === '1',
  };
}

/** A copy of `sp` with the given filters set; other params are kept. Empty, null and default values are removed. */
export function withFilters(sp: URLSearchParams, patch: Partial<WebFilters>): URLSearchParams {
  const next = new URLSearchParams(sp);
  for (const [k, v] of Object.entries(patch)) {
    const key = URL_KEYS[k as keyof WebFilters] ?? k;
    const s = typeof v === 'boolean' ? (v ? '1' : '') : v == null || (k === 'sort' && v === 'risk') ? '' : String(v);
    if (s) next.set(key, s);
    else next.delete(key);
  }
  return next;
}

/**
 * Filter updater that patches the params current at commit time (read through `current()`), not the
 * copy a closure captured: react-router's `setSearchParams(prev => ...)` passes the params of the render
 * that created the setter, so a debounced search would undo a filter clicked while it was pending.
 */
export function filterUpdater(
  current: () => URLSearchParams,
  set: (next: URLSearchParams, opts: { replace: boolean }) => void,
): (patch: Partial<WebFilters>, replace?: boolean) => void {
  return (patch, replace = false) => set(withFilters(current(), patch), { replace });
}

/** Query for GET /api/web-previews. */
export function previewQuery(f: WebFilters, page: number, pageSize = WEB_PREVIEWS_PAGE_SIZE): Record<string, string | number> {
  const q: Record<string, string | number> = { page, page_size: pageSize };
  if (f.q.trim()) q.q = f.q.trim();
  if (f.network != null) q.network_id = f.network;
  if (f.port != null) q.port = f.port;
  if (f.scheme) q.scheme = f.scheme;
  if (f.status) q.status = f.status;
  if (f.attention) q.attention = 'true';
  if (f.fresh) q.new = 'true';
  if (f.sort !== 'risk') q.sort = f.sort;
  if (f.archived) q.include_archived = 'true';
  return q;
}

/** True when any filter narrows the gallery (sort only reorders it). */
export function hasFilters(f: WebFilters): boolean {
  return !!(f.q || f.network || f.port || f.scheme || f.status || f.attention || f.fresh || f.archived);
}

/** Cards at or above this risk weight need attention (the server's ATTENTION_RISK). */
export const ATTENTION_RISK = 2;

/**
 * What each exposure finding means, in an operator's words: `short` is the one-line consequence on a
 * card, `hint` adds what to do about it.
 */
export const EXPOSURE_INFO: Record<WebExposure, { label: string; severity: 'high' | 'medium' | 'low'; short: string; hint: string }> = {
  cleartext_login: {
    label: 'Cleartext login', severity: 'high', short: 'Passwords cross the network unencrypted.',
    hint: 'Sign-in over plain HTTP: passwords cross the network unencrypted. Serve it over HTTPS or limit who can reach it.',
  },
  open_stream: {
    label: 'Open camera stream', severity: 'high', short: 'Anyone on this network can watch it.',
    hint: 'The RTSP stream played without a password, so anyone on this network can watch it. Set a password on the device.',
  },
  login_unverified_tls: {
    label: 'Login, untrusted certificate', severity: 'medium', short: 'Users learn to click through certificate warnings.',
    hint: 'Sign-in over HTTPS with a certificate that could not be verified, so users learn to click through warnings. Install a trusted certificate.',
  },
  tls_unverified: {
    label: 'Untrusted certificate', severity: 'low', short: 'Self-signed, expired or issued for another name.',
    hint: 'The HTTPS certificate could not be verified (self-signed, expired or issued for another name).',
  },
  default_page: {
    label: 'Default server page', severity: 'low', short: 'A web server runs with nothing configured.',
    hint: 'A web server answers with its out-of-the-box page. If nothing should be served here, turn it off.',
  },
};

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '–', mdash: '—', copy: '©', reg: '®', trade: '™',
};

/** A captured page title for display: HTML entities decoded, whitespace collapsed; null when nothing is left. */
export function pageTitle(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const decoded = raw.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] !== '#') return NAMED_ENTITIES[e.toLowerCase()] ?? m;
    const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : Number(e.slice(1));
    return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : m;
  });
  return decoded.replace(/\s+/g, ' ').trim() || null;
}

/** Whole days since `iso`. */
export function ageDays(iso: string, now = Date.now()): number {
  return Math.max(0, Math.floor((now - new Date(iso).getTime()) / 86_400_000));
}

/** "Captured today" / "Captured 3 days ago" / "Captures 4–27 days old" for the listed cards. */
export function captureAgeText(range: [string, string], now = Date.now()): string {
  const newest = ageDays(range[1], now);
  const oldest = ageDays(range[0], now);
  if (newest === oldest) return `Captured ${oldest === 0 ? 'today' : `${oldest} day${oldest === 1 ? '' : 's'} ago`}`;
  return `Captures ${newest}–${oldest} days old`;
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
