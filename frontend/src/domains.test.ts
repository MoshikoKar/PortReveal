import { describe, expect, it } from 'vitest';
import {
  activeFilterCount, checkLookupInput, currentPhase, domainBody, draftFromDomain, emptyDraft, formatDuration, formatEta,
  formatPercent, formatRate, hostingLabel, keyPayload, keyPlaceholder, lookupView, patchParams, phaseCounter,
  phaseSummaryTip, problemPhases, SCAN_POLL_MS, scanPollMs, splitList, stepperItems, subdomainQuery, wildcardTip,
} from './domains';
import { eventColumns } from './eventColumns';
import type { ChangeEvent, Domain, DomainScanPhase, LookupResult } from './types';

const result = (over: Partial<LookupResult> = {}): LookupResult => ({
  hostname: 'test.example.com', domain_id: 1, domain: 'example.com',
  internal: { a: ['192.0.2.10'], aaaa: [], cname: [] }, public: { a: ['198.51.100.10'], aaaa: [], cname: [] },
  ips: ['192.0.2.10', '198.51.100.10'], exposure: 'both', wildcard: false, flags: [], hosting: [], in_inventory: false,
  ...over,
});

describe('subdomain table filters', () => {
  it('maps URL params to the API query with defaults', () => {
    expect(subdomainQuery(new URLSearchParams(''), 100)).toEqual({
      q: undefined, exposure: undefined, status: 'active', source: undefined, flag: undefined, wildcard: undefined,
      sort: 'name', page: 1, page_size: 100,
    });
    const q = subdomainQuery(new URLSearchParams('q=vpn&exposure=external&source=passive&wildcard=1&sort=-last_seen&page=3&status=all'), 50);
    expect(q).toMatchObject({ q: 'vpn', exposure: 'external', source: 'passive', wildcard: true, sort: '-last_seen', page: 3, status: 'all' });
  });

  it('drops empty values and resets the page on any filter change', () => {
    const sp = new URLSearchParams('exposure=external&page=4');
    expect(patchParams(sp, { exposure: undefined }).toString()).toBe('');
    expect(patchParams(sp, { source: 'axfr' }).get('page')).toBeNull();
    expect(patchParams(sp, { page: '5' }).get('page')).toBe('5');
    expect(patchParams(sp, { page: '5' }).get('exposure')).toBe('external');
  });

  it('counts active filters (default status does not count)', () => {
    expect(activeFilterCount(new URLSearchParams('status=active'))).toBe(0);
    expect(activeFilterCount(new URLSearchParams('q=a&flag=internal_name_exposed&status=gone'))).toBe(3);
  });

  it('labels hosting and wildcard tooltips', () => {
    expect(hostingLabel({ ip: '192.0.2.10', kind: 'network', network: 'Lab', device_uuid: 'u', device_label: 'web01', asn: null, as_org: null }))
      .toBe('Lab · web01');
    expect(hostingLabel({ ip: '198.51.100.1', kind: 'external', network: null, device_uuid: null, device_label: null, asn: 64500, as_org: 'Example Hosting' }))
      .toBe('external · AS64500 Example Hosting');
    expect(hostingLabel({ ip: '10.1.2.3', kind: 'private', network: null, device_uuid: null, device_label: null, asn: null, as_org: null }))
      .toBe('private (unmanaged range)');
    expect(wildcardTip('example.com', { internal: [], public: ['198.51.100.99'] })).toContain('public: 198.51.100.99');
  });
});

describe('lookup UI states', () => {
  it('validates the host name against the configured domains before calling the API', () => {
    expect(checkLookupInput('', ['example.com'])).toMatch(/Enter a host name/);
    expect(checkLookupInput('https://test.example.com', ['example.com'])).toMatch(/host name only/);
    expect(checkLookupInput('bad_.example.com.x-', ['example.com'])).toBe('Not a valid host name');
    expect(checkLookupInput('test.example.org', ['example.com'])).toMatch(/not inside a configured domain/);
    expect(checkLookupInput('notexample.com', ['example.com'])).toMatch(/not inside/);
    expect(checkLookupInput(' Test.Example.com. ', ['example.com'])).toBeNull();
  });

  it('derives busy / message / actions per state', () => {
    expect(lookupView({ status: 'idle' })).toMatchObject({ busy: false, message: null, canAdd: false, canPortScan: false });
    expect(lookupView({ status: 'loading' })).toMatchObject({ busy: true, canAdd: false });
    expect(lookupView({ status: 'invalid', message: 'x' })).toMatchObject({ error: true, message: 'x' });
    expect(lookupView({ status: 'error', message: 'boom' })).toMatchObject({ error: true, message: 'boom', canPortScan: false });
    expect(lookupView({ status: 'done', result: result() })).toMatchObject({ canAdd: true, canPortScan: true, message: null });
    expect(lookupView({ status: 'done', result: result({ in_inventory: true }) }).canAdd).toBe(false);
    const nx = lookupView({ status: 'done', result: result({ ips: [], exposure: 'unresolved' }) });
    expect(nx.canPortScan).toBe(false);
    expect(nx.message).toMatch(/does not resolve/);
  });
});

describe('domain form', () => {
  it('builds the API body from the draft', () => {
    const d = { ...emptyDraft(), name: ' example.com ', wordlist_mode: 'custom' as const, custom_words: 'www\nvpn, mail',
      axfr_enabled: true, axfr_servers: '192.0.2.53', internal_resolvers: '' };
    const body = domainBody(d);
    expect(body).toMatchObject({ name: 'example.com', custom_words: ['www', 'vpn', 'mail'], axfr_servers: ['192.0.2.53'],
      internal_resolvers: [], public_resolvers: ['1.1.1.1', '8.8.8.8'], wordlist_id: null, notes: null });
    expect(domainBody({ ...d, axfr_enabled: false }).axfr_servers).toEqual([]);
    expect(splitList(' a, b;c\n d ')).toEqual(['a', 'b', 'c', 'd']);
  });

  it('round-trips a stored domain', () => {
    const dom = {
      id: 3, name: 'example.com', enabled: true, notes: null, wordlist_mode: 'library', wordlist_id: 7, wordlist_name: 'subs',
      custom_words: [], passive_enabled: true, axfr_enabled: false, axfr_servers: [], internal_resolvers: ['192.0.2.53'],
      public_resolvers: ['198.51.100.53'], schedule: { enabled: true, time: '02:00', days: [1] },
    } as unknown as Domain;
    expect(domainBody(draftFromDomain(dom))).toMatchObject({ wordlist_mode: 'library', wordlist_id: 7,
      internal_resolvers: ['192.0.2.53'], public_resolvers: ['198.51.100.53'], schedule: { enabled: true, time: '02:00', days: [1] } });
  });
});

describe('settings key masking', () => {
  it('only ever shows the masked hint', () => {
    expect(keyPlaceholder({ set: false, masked: '' })).toBe('not set');
    expect(keyPlaceholder({ set: true, masked: '••••cdef' })).toBe('••••cdef (unchanged)');
    expect(keyPlaceholder({ set: true, masked: '' })).toBe('•••• (unchanged)');
  });

  it('sends null to keep, empty to clear, the value to replace', () => {
    expect(keyPayload(null, false)).toBeNull();
    expect(keyPayload('   ', false)).toBeNull();
    expect(keyPayload(' new-key ', false)).toBe('new-key');
    expect(keyPayload('ignored', true)).toBe('');
  });
});

describe('domain change events', () => {
  const ev = (over: Partial<ChangeEvent>): ChangeEvent => ({
    id: 1, created_at: '2026-10-01T00:00:00Z', scan_id: null, device_uuid: null, device_label: 'leak.example.com',
    event_type: 'internal_name_exposed', severity: 'high', ip: '10.1.2.3', protocol: null, port: null, old_value: null,
    new_value: '10.1.2.3', message: 'leak.example.com: internal name visible publicly', notify: true, notified_at: null,
    domain_id: 1, hostname: 'leak.example.com', ...over,
  });

  it('renders domain events in the Change column', () => {
    expect(eventColumns(ev({})).changeText).toBe('visible publicly 10.1.2.3');
    expect(eventColumns(ev({ event_type: 'subdomain_exposure_changed', old_value: 'internal', new_value: 'both' })).changeText)
      .toBe('exposure internal → both');
    expect(eventColumns(ev({ event_type: 'zone_transfer_open', new_value: 'ns1.example.com (198.51.100.1)' })).changeText)
      .toBe('AXFR open on ns1.example.com (198.51.100.1)');
    expect(eventColumns(ev({ event_type: 'subdomain_ip_changed', old_value: '198.51.100.10', new_value: '198.51.100.11' })).change)
      .toEqual({ from: '198.51.100.10', to: '198.51.100.11' });
  });
});

const phase = (over: Partial<DomainScanPhase>): DomainScanPhase => ({
  key: 'passive', label: 'Passive (subfinder)', status: 'pending', started_at: null, finished_at: null, processed: 0,
  total: null, found: 0, queries: 0, unit: null, reason: null, duration_s: null, rate: null, eta_s: null, ...over,
});

describe('running scan progress', () => {
  const phases = [
    phase({ key: 'passive', status: 'done', duration_s: 42, found: 17 }),
    phase({ key: 'wordlist_internal', label: 'Wordlist (dnsx internal)', status: 'running', processed: 12340, total: 20000,
      unit: 'candidates', found: 9, queries: 37020, rate: 58.4, eta_s: 131, duration_s: 634 }),
    phase({ key: 'wordlist_public', label: 'Wordlist (dnsx public)' }),
    phase({ key: 'axfr', label: 'Zone transfer (authorized)', status: 'skipped', reason: 'turned off for this domain' }),
    phase({ key: 'resolve', label: 'Resolve & classify', status: 'failed', reason: 'cancelled' }),
  ];

  it('renders one step per phase with its status', () => {
    const items = stepperItems(phases);
    expect(items.map((i) => [i.key, i.status, i.mark, i.badge])).toEqual([
      ['passive', 'done', '✓', 'ok'],
      ['wordlist_internal', 'running', '●', 'accent'],
      ['wordlist_public', 'pending', '○', 'outline'],
      ['axfr', 'skipped', '–', 'outline'],
      ['resolve', 'failed', '✕', 'high'],
    ]);
    expect(items[0].title).toBe('done · 42 s · 17 found');
    expect(items[3].title).toBe('skipped · turned off for this domain');
    expect(items[4].title).toContain('cancelled');
    expect(stepperItems(null)).toEqual([]);
  });

  it('formats the current phase counters, percent, rate and ETA', () => {
    const cur = currentPhase(phases)!;
    expect(cur.key).toBe('wordlist_internal');
    expect(phaseCounter(cur)).toBe('12,340 / 20,000 candidates');
    expect(phaseCounter(phase({ found: 37 }))).toBe('37 found');
    expect(formatPercent(0.617)).toBe('61%');
    expect(formatPercent(0.034)).toBe('3.4%');
    expect(formatPercent(1.5)).toBe('100%');
    expect(formatPercent(null)).toBe('0%');
    expect(formatRate(58.4)).toBe('58 queries/s');
    expect(formatRate(2.25)).toBe('2.3 queries/s');
    expect(formatRate(null)).toBe('');
    expect(formatEta(131)).toBe('ETA 2 min');
    expect(formatEta(null)).toBe('');
    expect(formatDuration(42)).toBe('42 s');
    expect(formatDuration(4980)).toBe('1 h 23 min');
    expect(formatDuration(-1)).toBe('-');
  });

  it('summarises phases for the scan history', () => {
    expect(phaseSummaryTip(phases).split('\n')[0]).toBe('Passive (subfinder): done (42 s)');
    expect(phaseSummaryTip(phases)).toContain('Zone transfer (authorized): skipped - turned off for this domain');
    expect(problemPhases(phases).map((p) => p.key)).toEqual(['resolve']);
    expect(problemPhases([phase({ key: 'resolve', status: 'done', reason: 'public resolver: 3 name(s) timed out / failed' })])).toHaveLength(1);
  });

  it('polls only while a scan is queued or running', () => {
    expect(scanPollMs({ status: 'running' })).toBe(SCAN_POLL_MS);
    expect(scanPollMs({ status: 'queued' })).toBe(SCAN_POLL_MS);
    expect(SCAN_POLL_MS).toBeGreaterThanOrEqual(2000);
    expect(SCAN_POLL_MS).toBeLessThanOrEqual(3000);
    for (const status of ['completed', 'partial', 'failed', 'cancelled'] as const) expect(scanPollMs({ status })).toBeUndefined();
    expect(scanPollMs(null)).toBeUndefined();
  });
});
