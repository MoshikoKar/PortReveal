import { describe, expect, it } from 'vitest';
import type { EventType } from '../../types';
import {
  DEFAULT_NOTIFICATION_SECTION,
  digestTypeLocked,
  eventFilterSummary,
  isNotificationSection,
  notificationSectionFromPath,
  NOTIFICATION_SECTIONS,
  urlHost,
} from './notificationsLogic';

describe('notification sections', () => {
  it('lists the four inner tabs in order', () => {
    expect(NOTIFICATION_SECTIONS.map((s) => s.id)).toEqual([
      'general', 'email', 'webhooks', 'cve-watchlist',
    ]);
    expect(DEFAULT_NOTIFICATION_SECTION).toBe('general');
  });

  it('validates section ids and parses paths', () => {
    expect(isNotificationSection('email')).toBe(true);
    expect(isNotificationSection('recipients')).toBe(false);
    expect(notificationSectionFromPath('/settings/notifications/webhooks')).toBe('webhooks');
    expect(notificationSectionFromPath('/settings/notifications')).toBe(null);
    expect(notificationSectionFromPath('/settings/networks')).toBe(null);
  });
});

describe('digest always-included types', () => {
  const always: EventType[] = ['watch_match', 'policy_violation', 'monitor_change', 'cve_watch_match'];

  it('locks ALWAYS_NOTIFY_TYPES and leaves optional types editable', () => {
    expect(digestTypeLocked(always, 'watch_match')).toBe(true);
    expect(digestTypeLocked(always, 'cve_watch_match')).toBe(true);
    expect(digestTypeLocked(always, 'port_opened')).toBe(false);
    expect(digestTypeLocked(always, 'device_discovered')).toBe(false);
  });
});

describe('webhook display helpers', () => {
  it('shows host only and summarizes event filters', () => {
    expect(urlHost('https://hooks.example.com/path?x=1')).toBe('hooks.example.com');
    expect(eventFilterSummary([], {})).toBe('All events');
    expect(eventFilterSummary(['port_opened'], { port_opened: 'Port opened' })).toBe('Port opened');
    expect(eventFilterSummary(
      ['port_opened', 'port_closed', 'watch_match'],
      { port_opened: 'Port opened', port_closed: 'Port closed', watch_match: 'Watch match' },
    )).toBe('3 event types');
  });
});
