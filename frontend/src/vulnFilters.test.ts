import { describe, expect, it } from 'vitest';
import {
  buildVulnQuery, clearVulnFilters, formatVulnFilterChip, formatVulnFilterSummary,
  formatVulnFilterValue, parseVulnFilters, setVulnFilter, splitVendorProductKey,
  toggleHeatmapCell, toggleNetworkFilter, toggleVulnFilter, toggleVendorProductFilter,
  vendorProductFacetActive, vulnExportFilename, vulnFilterLink,
} from './vulnFilters';

describe('parseVulnFilters', () => {
  it('only reads known filter keys', () => {
    const sp = new URLSearchParams('severity=critical&kev=true&page=2&sort=cvss');
    expect(parseVulnFilters(sp)).toEqual({ severity: 'critical', kev: 'true' });
  });

  it('skips empty values', () => {
    const sp = new URLSearchParams('severity=&kev=true');
    expect(parseVulnFilters(sp)).toEqual({ kev: 'true' });
  });

  it('returns an empty object with no filters set', () => {
    expect(parseVulnFilters(new URLSearchParams())).toEqual({});
  });
});

describe('buildVulnQuery', () => {
  it('merges filters with extra params', () => {
    expect(buildVulnQuery({ severity: 'high' }, { page: 2, page_size: 50 }))
      .toEqual({ severity: 'high', page: 2, page_size: 50 });
  });
});

describe('setVulnFilter', () => {
  it('sets a filter and drops the page param', () => {
    const sp = new URLSearchParams('page=3');
    const next = setVulnFilter(sp, 'severity', 'critical');
    expect(next.get('severity')).toBe('critical');
    expect(next.get('page')).toBeNull();
  });

  it('clears the filter when given undefined', () => {
    const sp = new URLSearchParams('severity=critical');
    expect(setVulnFilter(sp, 'severity', undefined).get('severity')).toBeNull();
  });

  it('leaves other filters untouched', () => {
    const sp = new URLSearchParams('kev=true');
    const next = setVulnFilter(sp, 'severity', 'high');
    expect(next.get('kev')).toBe('true');
    expect(next.get('severity')).toBe('high');
  });
});

describe('toggleVulnFilter', () => {
  it('sets a filter that is not already set', () => {
    const next = toggleVulnFilter(new URLSearchParams(), 'severity', 'critical');
    expect(next.get('severity')).toBe('critical');
  });

  it('clears a filter already set to the same value (click again to remove)', () => {
    const sp = new URLSearchParams('severity=critical');
    expect(toggleVulnFilter(sp, 'severity', 'critical').get('severity')).toBeNull();
  });

  it('replaces a filter set to a different value', () => {
    const sp = new URLSearchParams('severity=critical');
    expect(toggleVulnFilter(sp, 'severity', 'high').get('severity')).toBe('high');
  });
});

describe('clearVulnFilters', () => {
  it('drops every known filter but keeps unrelated params', () => {
    const sp = new URLSearchParams('severity=critical&kev=true&sort=cvss&page=2');
    const next = clearVulnFilters(sp);
    expect(next.get('severity')).toBeNull();
    expect(next.get('kev')).toBeNull();
    expect(next.get('sort')).toBe('cvss');
    expect(next.get('page')).toBeNull();
  });
});

describe('vulnFilterLink', () => {
  it('builds a shareable link with only the given filters', () => {
    expect(vulnFilterLink({ severity: 'critical', kev: 'true' })).toBe('/vulnerabilities?severity=critical&kev=true');
  });

  it('returns the bare path with no filters', () => {
    expect(vulnFilterLink({})).toBe('/vulnerabilities');
  });
});

describe('risk_band filter', () => {
  it('round-trips through parse / toggle / clear', () => {
    const set = toggleVulnFilter(new URLSearchParams(), 'risk_band', 'high');
    expect(parseVulnFilters(set)).toEqual({ risk_band: 'high' });
    expect(vulnFilterLink({ risk_band: 'high' })).toBe('/vulnerabilities?risk_band=high');
    expect(toggleVulnFilter(set, 'risk_band', 'high').get('risk_band')).toBeNull();
    expect(clearVulnFilters(set).get('risk_band')).toBeNull();
  });
});

describe('vendor / product facet filters', () => {
  it('splits vendor:product and unknown keys', () => {
    expect(splitVendorProductKey('apache:httpd')).toEqual({ vendor: 'apache', product: 'httpd' });
    expect(splitVendorProductKey('unknown')).toEqual({ vendor: 'unknown' });
  });

  it('toggles both URL params from a facet key', () => {
    const set = toggleVendorProductFilter(new URLSearchParams(), 'apache:httpd');
    expect(parseVulnFilters(set)).toEqual({ vendor: 'apache', product: 'httpd' });
    expect(vendorProductFacetActive(parseVulnFilters(set), 'apache:httpd')).toBe(true);
    expect(vendorProductFacetActive(parseVulnFilters(set), 'nginx:nginx')).toBe(false);
    const cleared = toggleVendorProductFilter(set, 'apache:httpd');
    expect(cleared.get('vendor')).toBeNull();
    expect(cleared.get('product')).toBeNull();
  });

  it('toggles the unknown bucket with vendor only', () => {
    const set = toggleVendorProductFilter(new URLSearchParams(), 'unknown');
    expect(parseVulnFilters(set)).toEqual({ vendor: 'unknown' });
    expect(vendorProductFacetActive(parseVulnFilters(set), 'unknown')).toBe(true);
  });

  it('is cleared by clearVulnFilters', () => {
    const sp = new URLSearchParams('vendor=apache&product=httpd&page=2');
    const next = clearVulnFilters(sp);
    expect(next.get('vendor')).toBeNull();
    expect(next.get('product')).toBeNull();
    expect(next.get('page')).toBeNull();
  });
});

describe('cve_id / device_uuid / new_since filters', () => {
  it('round-trips through parse / toggle / clear', () => {
    const cve = toggleVulnFilter(new URLSearchParams(), 'cve_id', 'CVE-2024-1111');
    expect(parseVulnFilters(cve)).toEqual({ cve_id: 'CVE-2024-1111' });
    expect(toggleVulnFilter(cve, 'cve_id', 'CVE-2024-1111').get('cve_id')).toBeNull();

    const device = toggleVulnFilter(new URLSearchParams(), 'device_uuid', 'abc');
    expect(parseVulnFilters(device)).toEqual({ device_uuid: 'abc' });

    const since = toggleVulnFilter(new URLSearchParams(), 'new_since', 'scan');
    expect(parseVulnFilters(since)).toEqual({ new_since: 'scan' });
    expect(vulnFilterLink({ new_since: 'db' })).toBe('/vulnerabilities?new_since=db');
  });
});

describe('toggleHeatmapCell', () => {
  it('sets network_id + severity together and clears both on re-click', () => {
    const set = toggleHeatmapCell(new URLSearchParams(), 7, 'high');
    expect(set.get('network_id')).toBe('7');
    expect(set.get('severity')).toBe('high');
    const cleared = toggleHeatmapCell(set, 7, 'high');
    expect(cleared.get('network_id')).toBeNull();
    expect(cleared.get('severity')).toBeNull();
  });

  it('uses the unassigned sentinel for devices with no network', () => {
    const set = toggleHeatmapCell(new URLSearchParams(), null, 'low');
    expect(set.get('network_id')).toBe('unassigned');
    expect(set.get('severity')).toBe('low');
  });
});

describe('formatVulnFilterChip', () => {
  it('uses human labels for age buckets, state, risk band, and network names', () => {
    expect(formatVulnFilterChip('exposure_duration', 'under_30d'))
      .toBe('exposure duration: < 30 days');
    expect(formatVulnFilterChip('cve_age', '30_90d')).toBe('CVE age: 30-90 days');
    expect(formatVulnFilterChip('state', 'confirmed')).toBe('state: Confirmed');
    expect(formatVulnFilterChip('risk_band', 'high')).toBe('risk band: High');
    expect(formatVulnFilterChip('severity', 'critical')).toBe('severity: Critical');
    expect(formatVulnFilterChip('network_id', '1', { networkNames: { '1': 'Mock Lab' } }))
      .toBe('network: Mock Lab');
    expect(formatVulnFilterChip('network_id', 'unassigned')).toBe('network: Unassigned');
    expect(formatVulnFilterValue('epss_min', '0.1')).toBe('10%');
    expect(formatVulnFilterChip('new_since', 'scan')).toBe('new since: last scan');
    expect(formatVulnFilterChip('device_uuid', 'abc', { deviceLabels: { abc: '10.0.0.1' } }))
      .toBe('device: 10.0.0.1');
    expect(formatVulnFilterChip('kev', 'false')).toBe('KEV: no');
  });
});

describe('formatVulnFilterSummary / vulnExportFilename / toggleNetworkFilter', () => {
  it('summarizes active filters for the print report header', () => {
    expect(formatVulnFilterSummary({})).toBe('All networks (no filters)');
    expect(formatVulnFilterSummary(
      { network_id: '1', kev: 'true' },
      { networkNames: { '1': 'Lab Alpha' } },
    )).toBe('network: Lab Alpha · KEV: yes');
  });

  it('builds a sanitized CSV filename with filter context', () => {
    const name = vulnExportFilename(
      { network_id: '1', severity: 'critical' },
      { networkNames: { '1': 'Lab Alpha' } },
    );
    expect(name).toMatch(/^vulns_lab-alpha_critical_\d{8}\.csv$/);
  });

  it('toggles network scope without touching severity', () => {
    const set = toggleNetworkFilter(new URLSearchParams('severity=high'), 3);
    expect(set.get('network_id')).toBe('3');
    expect(set.get('severity')).toBe('high');
    const cleared = toggleNetworkFilter(set, 3);
    expect(cleared.get('network_id')).toBeNull();
    expect(cleared.get('severity')).toBe('high');
  });
});
