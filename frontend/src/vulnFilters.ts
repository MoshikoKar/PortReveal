/** Pure helpers for the vulnerabilities dashboard's URL-synced filters (shareable links): every
 * card/facet/chart segment on the page sets or toggles one of these keys, matching GET /api/vulns'
 * query params 1:1 so the same filter object can feed both the summary cards and the list below.
 */

/** URL/query keys shared by the dashboard, findings list, CSV export, and print report.
 *  Free-text ``q`` / ``only_hidden`` are managed separately (search bar + Clear all). */
export const VULN_FILTER_KEYS = [
  'severity', 'kev', 'epss_min', 'network_id', 'service', 'port', 'os_name', 'device_type',
  'state', 'cve_age', 'exposure_duration', 'risk_band', 'vendor', 'product',
  'cve_id', 'device_uuid', 'new_since',
] as const;

export type VulnFilterKey = typeof VULN_FILTER_KEYS[number];

export type VulnFilters = Partial<Record<VulnFilterKey, string>>;

/** Read every known filter key out of a URLSearchParams (e.g. from useSearchParams()). */
export function parseVulnFilters(sp: URLSearchParams): VulnFilters {
  const out: VulnFilters = {};
  for (const key of VULN_FILTER_KEYS) {
    const value = sp.get(key);
    if (value) out[key] = value;
  }
  return out;
}

/** Filters, plus paging/sort, as a plain object ready for useApi()'s params. */
export function buildVulnQuery(filters: VulnFilters, extra?: Record<string, string | number | undefined>) {
  return { ...filters, ...extra };
}

/** Set one filter, clicking the same value again clears it; always drops `page` (filters changed). */
export function setVulnFilter(sp: URLSearchParams, key: VulnFilterKey, value: string | undefined): URLSearchParams {
  const next = new URLSearchParams(sp);
  if (value) next.set(key, value);
  else next.delete(key);
  next.delete('page');
  return next;
}

/** Toggle one filter: set it, or clear it if it's already set to this exact value. */
export function toggleVulnFilter(sp: URLSearchParams, key: VulnFilterKey, value: string): URLSearchParams {
  const next = new URLSearchParams(sp);
  if (next.get(key) === value) next.delete(key);
  else next.set(key, value);
  next.delete('page');
  return next;
}

export function clearVulnFilters(sp: URLSearchParams): URLSearchParams {
  const next = new URLSearchParams(sp);
  for (const key of VULN_FILTER_KEYS) next.delete(key);
  next.delete('q');
  next.delete('only_hidden');
  next.delete('page');
  return next;
}

/** Live query string from the address bar (not React Router's render-captured searchParams). */
export function liveSearchParams(): URLSearchParams {
  if (typeof window === 'undefined') return new URLSearchParams();
  return new URLSearchParams(window.location.search);
}

/**
 * Apply a findings-search term onto `prev` without dropping other filters.
 * Callers must pass **live** params (`liveSearchParams()` / `window.location.search`):
 * react-router 7's `setSp(prev => …)` feeds a render-captured snapshot, which is stale after
 * Clear all / facet clicks during the debounce window.
 * Trims `qInput`; whitespace-only clears search. Returns null when `q` is already in sync.
 */
export function applyVulnSearchQ(prev: URLSearchParams, qInput: string): URLSearchParams | null {
  const q = qInput.trim();
  if ((prev.get('q') ?? '') === q) return null;
  const next = new URLSearchParams(prev);
  if (q) next.set('q', q);
  else {
    next.delete('q');
    next.delete('only_hidden');
  }
  next.delete('page');
  return next;
}

/** Merge in-progress (possibly not-yet-debounced) search text into a filter URL update. */
export function withPendingVulnSearchQ(sp: URLSearchParams, qInput: string): URLSearchParams {
  const next = new URLSearchParams(sp);
  const q = qInput.trim();
  if (q) next.set('q', q);
  else {
    next.delete('q');
    // Keep only_hidden only when a real q remains; otherwise drop it with the search.
    next.delete('only_hidden');
  }
  return next;
}

/** True when URL `q` changed outside this box's last write (back/forward/shared link). */
export function shouldResyncVulnQInput(urlQ: string, lastWrittenQ: string): boolean {
  return urlQ !== lastWrittenQ;
}

/** Drop state-redundant hidden_reasons that duplicate the state pill (Dismissed / Potential). */
export function displayHiddenReasons(state: string, reasons: string[] | undefined): string[] {
  if (!reasons?.length) return [];
  return reasons.filter((r) => {
    if (r === 'Dismissed' && state === 'dismissed') return false;
    if (r === 'Potential (hidden)' && state === 'potential') return false;
    return true;
  });
}

/** A shareable `/vulnerabilities?...` link for a given filter set (e.g. from a top-list row). */
export function vulnFilterLink(filters: VulnFilters): string {
  const params = new URLSearchParams();
  for (const key of VULN_FILTER_KEYS) {
    const value = filters[key];
    if (value) params.set(key, value);
  }
  const qs = params.toString();
  return qs ? `/vulnerabilities?${qs}` : '/vulnerabilities';
}

/** Split a summary facet key (`vendor:product` or `unknown`) into URL filter params. */
export function splitVendorProductKey(key: string): { vendor: string; product?: string } {
  if (key === 'unknown') return { vendor: 'unknown' };
  const i = key.indexOf(':');
  if (i < 0) return { vendor: key };
  return { vendor: key.slice(0, i), product: key.slice(i + 1) };
}

/** True when the current URL filters select this vendor/product facet bucket. */
export function vendorProductFacetActive(filters: VulnFilters, key: string): boolean {
  const { vendor, product } = splitVendorProductKey(key);
  if (filters.vendor !== vendor) return false;
  return product ? filters.product === product : !filters.product;
}

/** Toggle a vendor/product facet bucket: sets both params (or only vendor=unknown), clears on re-click. */
export function toggleVendorProductFilter(sp: URLSearchParams, key: string): URLSearchParams {
  const { vendor, product } = splitVendorProductKey(key);
  const next = new URLSearchParams(sp);
  const active = next.get('vendor') === vendor && (product ? next.get('product') === product : !next.get('product'));
  if (active) {
    next.delete('vendor');
    next.delete('product');
  } else {
    next.set('vendor', vendor);
    if (product) next.set('product', product);
    else next.delete('product');
  }
  next.delete('page');
  return next;
}

/** Severity-by-network cell: toggle the (network_id, severity) pair together. */
export function toggleHeatmapCell(
  sp: URLSearchParams,
  networkId: number | null,
  severity: string,
): URLSearchParams {
  const netKey = networkId != null ? String(networkId) : 'unassigned';
  const next = new URLSearchParams(sp);
  const active = next.get('network_id') === netKey && next.get('severity') === severity;
  if (active) {
    next.delete('network_id');
    next.delete('severity');
  } else {
    next.set('network_id', netKey);
    next.set('severity', severity);
  }
  next.delete('page');
  return next;
}

/** Scroll the findings table into view after a dashboard filter click. */
export function scrollToVulnFindings(): void {
  requestAnimationFrame(() => {
    document.getElementById('vuln-findings')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

export const VULN_FINDINGS_HASH = '#vuln-findings';

/** Deep-link hash scroll runs once per arrival key (search + hash), not on every summary poll. */
export function shouldScrollVulnFindingsHash(
  hash: string,
  arrivalKey: string,
  alreadyScrolledKey: string | null,
): boolean {
  return hash === VULN_FINDINGS_HASH && alreadyScrolledKey !== arrivalKey;
}

/** Strip ``#vuln-findings`` from an href (pathname + search only) for history.replaceState. */
export function clearVulnFindingsHash(href: string): string {
  const url = new URL(href, 'http://local.invalid');
  if (url.hash !== VULN_FINDINGS_HASH) {
    return `${url.pathname}${url.search}${url.hash}`;
  }
  return `${url.pathname}${url.search}`;
}

const FILTER_KEY_LABELS: Record<VulnFilterKey, string> = {
  severity: 'severity',
  kev: 'KEV',
  epss_min: 'EPSS ≥',
  network_id: 'network',
  service: 'service',
  port: 'port',
  os_name: 'OS',
  device_type: 'device type',
  state: 'state',
  cve_age: 'CVE age',
  exposure_duration: 'exposure duration',
  risk_band: 'risk band',
  vendor: 'vendor',
  product: 'product',
  cve_id: 'CVE',
  device_uuid: 'device',
  new_since: 'new since',
};

const AGE_VALUE_LABELS: Record<string, string> = {
  under_30d: '< 30 days',
  '30_90d': '30-90 days',
  '90_365d': '90 days - 1 year',
  over_365d: '> 1 year',
  unknown: 'unknown',
};

function titleCase(value: string): string {
  if (!value) return value;
  return value.charAt(0).toUpperCase() + value.slice(1);
}

/** Optional lookup tables so chips can show network names / device IPs instead of raw ids. */
export interface VulnFilterLabelContext {
  networkNames?: Record<string, string>;
  deviceLabels?: Record<string, string>;
}

/** Human-readable value for a filter chip (e.g. under_30d → "< 30 days", network 1 → "Mock Lab"). */
export function formatVulnFilterValue(
  key: VulnFilterKey,
  value: string,
  ctx: VulnFilterLabelContext = {},
): string {
  switch (key) {
    case 'cve_age':
    case 'exposure_duration':
      return AGE_VALUE_LABELS[value] ?? value;
    case 'network_id':
      if (value === 'unassigned') return 'Unassigned';
      return ctx.networkNames?.[value] ?? value;
    case 'device_uuid':
      return ctx.deviceLabels?.[value] ?? value;
    case 'state':
    case 'severity':
    case 'risk_band':
      return titleCase(value);
    case 'kev':
      return value === 'true' ? 'yes' : value === 'false' ? 'no' : value;
    case 'epss_min': {
      const n = Number(value);
      if (!Number.isFinite(n)) return value;
      return `${Math.round(n * 100)}%`;
    }
    case 'new_since':
      return value === 'scan' ? 'last scan' : value === 'db' ? 'last DB update' : value;
    default:
      return value;
  }
}

/** Full chip label: "exposure duration: < 30 days". */
export function formatVulnFilterChip(
  key: VulnFilterKey,
  value: string,
  ctx: VulnFilterLabelContext = {},
): string {
  return `${FILTER_KEY_LABELS[key]}: ${formatVulnFilterValue(key, value, ctx)}`;
}

/** Human-readable summary of active filters for the print report header (empty → "All networks"). */
export function formatVulnFilterSummary(
  filters: VulnFilters,
  ctx: VulnFilterLabelContext = {},
): string {
  const parts = (Object.entries(filters) as [VulnFilterKey, string][])
    .filter(([, v]) => !!v)
    .map(([key, value]) => formatVulnFilterChip(key, value, ctx));
  return parts.length ? parts.join(' · ') : 'All networks (no filters)';
}

/** Print-report filter line including search / only-hidden notes. */
export function formatVulnPrintFilterLine(
  filters: VulnFilters,
  ctx: VulnFilterLabelContext = {},
  opts: { searchQ?: string; onlyHidden?: boolean } = {},
): string {
  const base = formatVulnFilterSummary(filters, ctx);
  const searchQ = opts.searchQ?.trim();
  if (!searchQ) return base;
  const bits = [`Search: "${searchQ}"`, opts.onlyHidden ? 'Only hidden' : 'Includes hidden'];
  return base === 'All networks (no filters)' ? bits.join(' · ') : `${base} · ${bits.join(' · ')}`;
}

/** Sanitize a token for download filenames (matches backend ``sanitize_filename_part`` intent). */
export function sanitizeFilenamePart(value: string, maxLen = 40): string {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');
  return (slug || 'filtered').slice(0, maxLen);
}

/** Local calendar day as ``YYYYMMDD`` (matches server ``datetime.now().strftime("%Y%m%d")``). */
export function localFilenameDay(now: Date = new Date()): string {
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  return `${y}${m}${d}`;
}

/** Client-side CSV filename hint; the server Content-Disposition is preferred when present. */
export function vulnExportFilename(filters: VulnFilters, ctx: VulnFilterLabelContext = {}): string {
  const day = localFilenameDay();
  const parts: string[] = [];
  if (filters.network_id === 'unassigned') parts.push('unassigned');
  else if (filters.network_id) {
    parts.push(sanitizeFilenamePart(ctx.networkNames?.[filters.network_id] ?? `net${filters.network_id}`));
  }
  if (filters.device_uuid) {
    parts.push(sanitizeFilenamePart(`device-${filters.device_uuid.slice(0, 8)}`));
  }
  if (filters.cve_id) parts.push(sanitizeFilenamePart(filters.cve_id));
  if (filters.kev === 'true') parts.push('kev');
  else if (filters.kev === 'false') parts.push('not-kev');
  if (filters.severity) parts.push(sanitizeFilenamePart(filters.severity));
  if (filters.state) parts.push(sanitizeFilenamePart(filters.state));
  const slug = parts.length ? parts.join('_') : 'all';
  return `vulns_${slug}_${day}.csv`;
}

/** Toggle network scope only (heatmap row label / network facet), without touching severity. */
export function toggleNetworkFilter(sp: URLSearchParams, networkId: number | null): URLSearchParams {
  const netKey = networkId != null ? String(networkId) : 'unassigned';
  return toggleVulnFilter(sp, 'network_id', netKey);
}
