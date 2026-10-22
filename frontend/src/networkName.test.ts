import { describe, expect, it } from 'vitest';
import {
  NETWORK_NAME_HINT,
  NETWORK_NAME_MAX,
  NETWORK_NAME_MAX_MSG,
  isLegacyNetworkName,
  networkNameError,
  trimNetworkName,
} from './networkName';

describe('trimNetworkName', () => {
  it('strips whitespace and BOM like String.trim', () => {
    expect(trimNetworkName('  Office  ')).toBe('Office');
    expect(trimNetworkName('\ufeffOffice\ufeff')).toBe('Office');
  });
});

describe('networkNameError', () => {
  it('accepts English letters, digits, spaces and - _ . ( )', () => {
    expect(networkNameError('Office LAN')).toBeNull();
    expect(networkNameError('Lab-1_v2.0 (HQ)')).toBeNull();
    expect(networkNameError('  Trimmed  ')).toBeNull();
    expect(networkNameError(`  ${'a'.repeat(NETWORK_NAME_MAX)}  `)).toBeNull();
  });

  it('rejects Hebrew, emoji and other symbols', () => {
    expect(networkNameError('רשת')).toBe(NETWORK_NAME_HINT);
    expect(networkNameError('Lab 🌐')).toBe(NETWORK_NAME_HINT);
    expect(networkNameError('Lab@Home')).toBe(NETWORK_NAME_HINT);
    expect(networkNameError('Lab#1')).toBe(NETWORK_NAME_HINT);
  });

  it('applies the length limit after trimming', () => {
    expect(networkNameError('a'.repeat(NETWORK_NAME_MAX + 1))).toBe(NETWORK_NAME_MAX_MSG);
    expect(networkNameError(`  ${'a'.repeat(NETWORK_NAME_MAX + 1)}  `)).toBe(NETWORK_NAME_MAX_MSG);
  });

  it('ignores empty input (Save already requires a name)', () => {
    expect(networkNameError('')).toBeNull();
    expect(networkNameError('   ')).toBeNull();
    expect(networkNameError('\ufeff')).toBeNull();
  });
});

describe('isLegacyNetworkName', () => {
  it('detects non-English stored names', () => {
    expect(isLegacyNetworkName('רשת ישנה')).toBe(true);
    expect(isLegacyNetworkName('Office LAN')).toBe(false);
    expect(isLegacyNetworkName('')).toBe(false);
  });
});
