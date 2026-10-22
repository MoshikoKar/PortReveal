import { describe, expect, it } from 'vitest';
import { NETWORK_NAME_HINT, networkNameError } from './networkName';

describe('networkNameError', () => {
  it('accepts English letters, digits, spaces and - _ . ( )', () => {
    expect(networkNameError('Office LAN')).toBeNull();
    expect(networkNameError('Lab-1_v2.0 (HQ)')).toBeNull();
    expect(networkNameError('  Trimmed  ')).toBeNull();
  });

  it('rejects Hebrew, emoji and other symbols', () => {
    expect(networkNameError('רשת')).toBe(NETWORK_NAME_HINT);
    expect(networkNameError('Lab 🌐')).toBe(NETWORK_NAME_HINT);
    expect(networkNameError('Lab@Home')).toBe(NETWORK_NAME_HINT);
    expect(networkNameError('Lab#1')).toBe(NETWORK_NAME_HINT);
  });

  it('ignores empty input (Save already requires a name)', () => {
    expect(networkNameError('')).toBeNull();
    expect(networkNameError('   ')).toBeNull();
  });
});
