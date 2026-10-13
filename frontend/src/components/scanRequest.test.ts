import { describe, expect, it } from 'vitest';
import { scanReady, scanRequestBody, scanStartHint, type ScanForm } from './scanRequest';

const base: ScanForm = { type: 'standard', mode: 'networks', selected: [], targets: '' };
const idle = { unavailable: false, busy: false };

describe('scan dialog', () => {
  it('needs a target for the chosen mode', () => {
    expect(scanReady(base)).toBe(false);
    expect(scanReady({ ...base, selected: [1] })).toBe(true);
    expect(scanReady({ ...base, mode: 'targets', targets: '   ' })).toBe(false);
    expect(scanReady({ ...base, mode: 'targets', targets: '10.0.0.0/24' })).toBe(true);
    expect(scanReady({ ...base, mode: 'devices' })).toBe(false);
    expect(scanReady({ ...base, mode: 'devices', deviceUuids: ['u1'] })).toBe(true);
  });

  it('explains why Start is disabled', () => {
    expect(scanStartHint(base, idle)).toBe('Select at least one network');
    expect(scanStartHint({ ...base, mode: 'targets' }, idle)).toBe('Enter targets');
    expect(scanStartHint({ ...base, mode: 'devices' }, idle)).toBe('Select at least one device');
    const ready = { ...base, selected: [1] };
    expect(scanStartHint(ready, { unavailable: true, unavailableMessage: 'nmap missing', busy: false })).toBe('nmap missing');
    expect(scanStartHint(ready, { unavailable: true, busy: false })).toBe('Scanner unavailable');
    expect(scanStartHint(ready, { unavailable: false, busy: true })).toBe('Starting scan…');
    expect(scanStartHint(ready, idle)).toBeUndefined();
  });

  it('sends exactly one target kind, even after switching modes', () => {
    const touched = { ...base, selected: [3, 4], targets: '10.0.0.1', deviceUuids: ['u1'] };
    expect(scanRequestBody(touched)).toEqual({ scan_type: 'standard', network_ids: [3, 4] });
    expect(scanRequestBody({ ...touched, mode: 'targets', type: 'full' })).toEqual({ scan_type: 'full', targets: '10.0.0.1' });
    expect(scanRequestBody({ ...touched, mode: 'devices', criteria: 'port:22' }))
      .toEqual({ scan_type: 'standard', device_uuids: ['u1'], criteria: 'port:22' });
  });
});
