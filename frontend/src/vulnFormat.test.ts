import { describe, expect, it } from 'vitest';
import { dismissBusyKey, findingRowKey, formatCvss, formatEpss, formatEpssPct } from './vulnFormat';

describe('formatCvss', () => {
  it('formats one decimal place', () => {
    expect(formatCvss(9.8)).toBe('9.8');
    expect(formatCvss(5)).toBe('5.0');
  });

  it('uses a hyphen when missing', () => {
    expect(formatCvss(null)).toBe('-');
    expect(formatCvss(undefined)).toBe('-');
  });
});

describe('formatEpss', () => {
  it('renders a percent label', () => {
    expect(formatEpss(0.42)).toBe('EPSS 42%');
  });

  it('is empty when missing (inline badge path)', () => {
    expect(formatEpss(null)).toBe('');
  });
});

describe('formatEpssPct', () => {
  it('renders a bare percent for table cells', () => {
    expect(formatEpssPct(0.1)).toBe('10%');
    expect(formatEpssPct(null)).toBe('-');
  });
});

describe('findingRowKey / dismissBusyKey', () => {
  it('builds stable keys', () => {
    expect(findingRowKey({ cve_id: 'CVE-1', device_uuid: 'u', protocol: 'tcp', port: 22 }))
      .toBe('CVE-1|u|tcp|22');
    expect(dismissBusyKey('u', 'CVE-1')).toBe('u:CVE-1');
  });
});
