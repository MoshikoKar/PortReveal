import { describe, expect, it } from 'vitest';
import { EVENT_LABELS, EVENT_SHORT_LABELS } from './util';

describe('event column badge labels', () => {
  it('has a short label for every event type', () => {
    expect(Object.keys(EVENT_SHORT_LABELS).sort()).toEqual(Object.keys(EVENT_LABELS).sort());
  });

  it('keeps every badge label short enough to show in full (never truncated)', () => {
    for (const label of Object.values(EVENT_SHORT_LABELS)) {
      expect(label.length).toBeGreaterThan(0);
      expect(label.length).toBeLessThanOrEqual(14);
    }
  });

  it('uses the requested short forms', () => {
    expect(EVENT_SHORT_LABELS.banner_changed).toBe('Banner');
    expect(EVENT_SHORT_LABELS.device_discovered).toBe('New device');
    expect(EVENT_SHORT_LABELS.port_opened).toBe('Port opened');
  });
});
