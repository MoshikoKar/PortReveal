/** Pure helpers for the vulnerabilities dashboard's URL-synced filters (shareable links): every
 * card/facet/chart segment on the page sets or toggles one of these keys, matching GET /api/vulns'
 * query params 1:1 so the same filter object can feed both the summary cards and the list below.
 */

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
  next.delete('page');
  return next;
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
      return value === 'true' ? 'yes' : value;
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
