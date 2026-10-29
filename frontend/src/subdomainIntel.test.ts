import { createElement, type ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import {
  PortsCell, ScoreCell, SubdomainPortsCard, SubdomainScoreBadges, SubdomainVulnsCard, SubdomainWebCard,
} from './components/SubdomainIntel';
import { collapseHistory, webPreviewHref } from './domains';
import type { Subdomain, SubdomainDetail, SubdomainHistoryRow, WebPage } from './types';

// Text separators (`<!-- -->`) differ between React versions; tests match the visible text.
const html = (el: ReactElement) => renderToStaticMarkup(createElement(MemoryRouter, null, el)).replace(/<!-- -->/g, '');

function sub(over: Partial<Subdomain> = {}): Subdomain {
  return {
    id: 7, domain_id: 3, name: 'www.example.com', exposure: 'external', records: {}, records_summary: 'A',
    ips: ['198.51.100.10'], hosting: [], sources: ['passive'], wildcard: false, flags: [], device_uuid: null,
    status: 'active', unverified: false, in_progress: false, missed_scans: 0, last_verified_at: null,
    first_seen: '2026-10-01T00:00:00Z', last_seen: '2026-10-02T00:00:00Z',
    linked_devices: 0, exposure_score: null, risk_score: null, combined_score: null, open_ports_count: null,
    vulns_count: null, worst_severity: null, has_web_preview: false, web_device_uuid: null,
    ...over,
  };
}

function detail(over: Partial<SubdomainDetail> = {}): SubdomainDetail {
  return {
    ...sub(), domain_name: 'example.com', devices: [], ports: [], web_pages: [], last_scan: null,
    vulns: { total: 0, by_severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, top: [] },
    ...over,
  };
}

const device = {
  uuid: 'dev-1', label: 'web01.example.com', ip: '198.51.100.10', exposure_score: 72, risk_score: 40,
  combined_score: 55, risk_scored_at: '2026-10-02T00:00:00Z', last_port_scan_at: '2026-10-02T00:00:00Z',
  open_ports_count: 1, vulnerabilities: 1,
};

function page(over: Partial<WebPage> = {}): WebPage {
  return {
    id: 11, uuid: 'p-11', capture_id: 1, device_id: 1, device_uuid: 'dev-1', device_port_id: null, ip: '198.51.100.10',
    port: 443, scheme: 'https', host_used: 'www.example.com', kind: 'home', url: 'https://www.example.com/very/long/path',
    final_url: null, redirect_target: null, external_redirect: false, http_status: 200, title: 'Welcome',
    content_type: 'text/html', server_header: null, tls_verified: true, screenshot_status: 'captured',
    has_screenshot: true, error_reason: null, capture_error: null, auth_scheme: null,
    captured_at: '2026-10-02T00:00:00Z', can_live: false,
    ...over,
  } as WebPage;
}

describe('inventory score / ports cells', () => {
  it('renders score badges, and "-" when not scored', () => {
    expect(html(createElement(ScoreCell, { score: 72, kind: 'exposure' }))).toMatch(/class="badge high"[^>]*>72</);
    expect(html(createElement(ScoreCell, { score: 45, kind: 'combined' }))).toMatch(/Combined score 45/);
    expect(html(createElement(ScoreCell, { score: 5, kind: 'risk' }))).toMatch(/class="badge ok"/);
    const none = html(createElement(ScoreCell, { score: null, kind: 'combined' }));
    expect(none).toContain('>-<');
    expect(none).not.toContain('badge');
  });

  it('shows the open-port count and a web link only when a preview exists', () => {
    expect(html(createElement(PortsCell, { s: sub() }))).toContain('>-<');
    const filled = html(createElement(PortsCell, { s: sub({ open_ports_count: 12, has_web_preview: true, web_device_uuid: 'dev-1' }) }));
    expect(filled).toContain('12 open');
    expect(filled).toContain('href="/devices/dev-1/web"');
    expect(html(createElement(PortsCell, { s: sub({ open_ports_count: 0 }) }))).not.toContain('subdomain-web-link');
    // Host-name page without a device: the subdomain page's Web card
    expect(webPreviewHref(sub({ has_web_preview: true }))).toBe('/domains/3/subdomains/7#web');
  });

  it('header badges: scores, port count and worst-severity vulnerability count', () => {
    const out = html(createElement(SubdomainScoreBadges, { s: sub({ exposure_score: 72, risk_score: 40, combined_score: 55, open_ports_count: 3, vulns_count: 2, worst_severity: 'critical' }) }));
    expect(out).toContain('3 open');
    expect(out).toMatch(/class="badge high"[^>]*>2 vulns</);
  });
});

describe('subdomain detail cards', () => {
  it('ports: "Not scanned yet" without a device, rows with device / banner / open links when filled', () => {
    const empty = html(createElement(SubdomainPortsCard, { s: detail(), scanAction: createElement('button', null, 'Port scan now') }));
    expect(empty).toContain('Not scanned yet');
    expect(empty).toContain('Port scan now');

    const filled = html(createElement(SubdomainPortsCard, { s: detail({
      devices: [device],
      ports: [
        { protocol: 'tcp', port: 443, is_open: true, service: 'https', product: 'nginx', version: '1.25', closed_at: null,
          device_uuid: 'dev-1', device_label: 'web01.example.com', ip: '198.51.100.10', banner: 'HTTP/1.1 200 OK',
          has_preview: true, url: 'https://www.example.com/' },
        { protocol: 'tcp', port: 23, is_open: false, service: 'telnet', product: null, version: null, closed_at: '2026-10-01T00:00:00Z',
          device_uuid: 'dev-1', device_label: 'web01.example.com', ip: '198.51.100.10', banner: null, has_preview: false, url: null },
      ],
    }) }));
    expect(filled).toContain('1 open port');
    expect(filled).toContain('nginx');
    expect(filled).toContain('title="HTTP/1.1 200 OK"');
    expect(filled).toContain('href="/devices/dev-1/web"');
    expect(filled).toContain('href="https://www.example.com/" target="_blank"');
    expect(filled).not.toContain('telnet'); // closed ports hidden until toggled
    expect(filled).toContain('show 1 closed');
  });

  it('web: empty state with capture action, thumbnails and full-width URL table when filled', () => {
    const empty = html(createElement(SubdomainWebCard, { pages: [], onOpen: () => {}, captureAction: createElement('button', null, 'Capture web interfaces') }));
    expect(empty).toContain('No web capture yet');
    expect(empty).toContain('Capture web interfaces');
    const filled = html(createElement(SubdomainWebCard, { pages: [page()], onOpen: () => {} }));
    expect(filled).toContain('subdomain-web-grid');
    expect(filled).toContain('/api/web-pages/11/screenshot');
    expect(filled).toContain('class="sd-web-url');
    expect(filled).toContain('title="https://www.example.com/very/long/path"');
  });

  it('vulnerabilities: not scanned / none / severity summary and top findings', () => {
    expect(html(createElement(SubdomainVulnsCard, { s: detail() }))).toContain('Not scanned yet');
    expect(html(createElement(SubdomainVulnsCard, { s: detail({ devices: [device] }) }))).toContain('No vulnerabilities matched');
    const filled = html(createElement(SubdomainVulnsCard, { s: detail({
      devices: [device],
      vulns: {
        total: 2, by_severity: { critical: 1, high: 0, medium: 1, low: 0, unknown: 0 },
        top: [{ cve_id: 'CVE-2026-0001', severity: 'critical', cvss_base: 9.8, kev: true, state: 'confirmed', port: 443,
          protocol: 'tcp', product: 'nginx', version: '1.25', device_uuid: 'dev-1' }],
      },
    }) }));
    expect(filled).toContain('critical 1');
    expect(filled).toContain('href="/vulnerabilities/CVE-2026-0001"');
    expect(filled).toContain('href="/vulnerabilities?device_uuid=dev-1"');
    expect(filled).toContain('KEV');
  });
});

describe('records history', () => {
  const row = (scan_id: number, a: string[]): SubdomainHistoryRow => ({
    scan_id, scan_status: 'completed', at: '2026-10-01T00:00:00Z', exposure: 'external',
    records: { public: { a, aaaa: [], cname: [] } }, ips: a, sources: ['passive'], wildcard: false, flags: [],
  });

  it('folds identical consecutive scans into the row where the answer first appeared', () => {
    // Newest first, as the API returns them
    const out = collapseHistory([row(5, ['198.51.100.2']), row(4, ['198.51.100.2']), row(3, ['198.51.100.1']),
      row(2, ['198.51.100.1']), row(1, ['198.51.100.1'])]);
    expect(out.map((x) => [x.row.scan_id, x.unchanged])).toEqual([[4, 1], [1, 2]]);
    expect(collapseHistory([])).toEqual([]);
  });
});
