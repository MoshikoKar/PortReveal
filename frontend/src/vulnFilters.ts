/** Pure helpers for the vulnerabilities dashboard's URL-synced filters (shareable links): every
 * card/facet/chart segment on the page sets or toggles one of these keys, matching GET /api/vulns'
 * query params 1:1 so the same filter object can feed both the summary cards and the list below.
 */

export const VULN_FILTER_KEYS = [
  'severity', 'kev', 'epss_min', 'network_id', 'service', 'port', 'os_name', 'device_type',
  'state', 'cve_age', 'exposure_duration', 'risk_band',
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
