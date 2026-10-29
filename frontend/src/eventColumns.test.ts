import { describe, expect, it } from 'vitest';
import { eventColumns } from './eventColumns';
import type { ChangeEvent, EventType } from './types';

const ev = (event_type: EventType | string, over: Partial<ChangeEvent> = {}): ChangeEvent => ({
  id: 1, created_at: '2026-01-01T00:00:00Z', scan_id: 7, device_uuid: 'u-1', device_label: 'host-a.example.test',
  event_type: event_type as EventType, severity: 'info', ip: '10.0.0.10', protocol: null, port: null,
  old_value: null, new_value: null, message: 'placeholder message', notify: true, notified_at: null,
  ...over,
});

describe('eventColumns', () => {
  it('port opened: port chip, "opened" + service', () => {
    const c = eventColumns(ev('port_opened', { protocol: 'tcp', port: 443, new_value: 'https' }));
    expect(c.port).toBe('TCP/443');
    expect(c.change).toEqual({ verb: 'opened', note: 'https' });
    expect(c.changeText).toBe('opened https');
  });

  it('port closed: "closed" + the service that was there', () => {
    const c = eventColumns(ev('port_closed', { protocol: 'udp', port: 161, old_value: 'snmp' }));
    expect(c.port).toBe('UDP/161');
    expect(c.changeText).toBe('closed snmp');
  });

  it('service detected', () => {
    const c = eventColumns(ev('service_detected', { protocol: 'tcp', port: 22, new_value: 'ssh' }));
    expect(c.port).toBe('TCP/22');
    expect(c.changeText).toBe('detected ssh');
  });

  it('service changed: old -> new', () => {
    const c = eventColumns(ev('service_changed', { protocol: 'tcp', port: 8080, old_value: 'http-proxy', new_value: 'http' }));
    expect(c.change).toEqual({ from: 'http-proxy', to: 'http' });
    expect(c.changeText).toBe('http-proxy → http');
  });

  it('version changed: old -> new', () => {
    const c = eventColumns(ev('version_changed', { protocol: 'tcp', port: 22, old_value: 'placeholder-sshd 1.0', new_value: 'placeholder-sshd 2.0' }));
    expect(c.changeText).toBe('placeholder-sshd 1.0 → placeholder-sshd 2.0');
  });

  it('banner changed: old -> new with the port', () => {
    const c = eventColumns(ev('banner_changed', { protocol: 'tcp', port: 443, old_value: 'banner one', new_value: 'banner two' }));
    expect(c.port).toBe('TCP/443');
    expect(c.change).toEqual({ from: 'banner one', to: 'banner two' });
  });

  it('OS changed: old -> new, no port', () => {
    const c = eventColumns(ev('os_changed', { old_value: 'Linux 5', new_value: 'Linux 6' }));
    expect(c.port).toBeNull();
    expect(c.changeText).toBe('Linux 5 → Linux 6');
  });

  it('IP changed: shows only the previous address (the new one is under the device)', () => {
    const c = eventColumns(ev('ip_changed', { old_value: '10.0.0.9', new_value: '10.0.0.10' }));
    expect(c.ip).toBe('10.0.0.10');
    expect(c.changeText).toBe('from 10.0.0.9');
    expect(c.changeText).not.toContain('10.0.0.10');
  });

  it('device new: "first seen" with its open ports', () => {
    const c = eventColumns(ev('device_discovered', { new_value: 'TCP/22, TCP/443' }));
    expect(c.port).toBeNull();
    expect(c.changeText).toBe('first seen open TCP/22, TCP/443');
  });

  it('device not detected', () => {
    const c = eventColumns(ev('device_disappeared'));
    expect(c.port).toBeNull();
    expect(c.changeText).toBe('not detected');
  });

  it('device reappeared', () => {
    expect(eventColumns(ev('device_reappeared')).changeText).toBe('reappeared');
  });

  it('tag added / removed: the tag', () => {
    expect(eventColumns(ev('tag_added', { new_value: 'printer' })).changeText).toBe('printer');
    expect(eventColumns(ev('tag_removed', { old_value: 'printer' })).changeText).toBe('printer');
  });

  it('watch match / policy violation / monitor change: the saved search name', () => {
    expect(eventColumns(ev('watch_match', { new_value: 'Placeholder watch' })).changeText).toBe('Placeholder watch');
    expect(eventColumns(ev('policy_violation', { new_value: 'Placeholder policy' })).changeText).toBe('Placeholder policy');
    const m = eventColumns(ev('monitor_change', { protocol: 'tcp', port: 443, new_value: 'Placeholder monitor' }));
    expect(m.port).toBe('TCP/443');
    expect(m.changeText).toBe('Placeholder monitor');
  });

  it('geo mismatch: where it resolved and what was expected', () => {
    const c = eventColumns(ev('geo_mismatch', { old_value: 'IL', new_value: 'US AS64500' }));
    expect(c.changeText).toBe('US AS64500 expected IL');
  });

  it('CVE watchlist match: CVE, state, CVSS, KEV; port from the detail', () => {
    const detail = { cve_id: 'CVE-2024-0001', port: 443, protocol: 'tcp', state: 'confirmed', cvss: 9.8, kev: true };
    const c = eventColumns(ev('cve_watch_match', { old_value: JSON.stringify(detail), new_value: 'CVE-2024-0001' }));
    expect(c.port).toBe('TCP/443');
    expect(c.change).toMatchObject({ cve: 'CVE-2024-0001', note: 'confirmed · CVSS 9.8', kev: true });
    expect(c.changeText).toBe('CVE-2024-0001 · confirmed · CVSS 9.8 · KEV');
  });

  it('outside configured networks: recorded only', () => {
    expect(eventColumns(ev('port_opened', { notify: false })).recordedOnly).toBe(true);
    expect(eventColumns(ev('port_opened')).recordedOnly).toBe(false);
  });

  it('IP is not repeated when the device label already is the IP', () => {
    expect(eventColumns(ev('device_disappeared', { device_label: '10.0.0.10' })).ip).toBeNull();
    expect(eventColumns(ev('device_disappeared')).ip).toBe('10.0.0.10');
  });

  it('unknown type falls back to the event message', () => {
    const c = eventColumns(ev('future_type', { port: 443, protocol: 'tcp' }));
    expect(c.change).toEqual({ to: 'placeholder message' });
    expect(c.changeText).toBe('placeholder message');
    expect(c.port).toBe('TCP/443');
  });
});
