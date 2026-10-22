import type { EventType } from '../../types';

export const NOTIFICATION_SECTIONS = [
  { id: 'general', label: 'General' },
  { id: 'email', label: 'Email' },
  { id: 'webhooks', label: 'Webhooks' },
  { id: 'cve-watchlist', label: 'CVE Watchlist' },
] as const;

export type NotificationSection = (typeof NOTIFICATION_SECTIONS)[number]['id'];

/** Default inner tab when visiting /settings/notifications with no section. */
export const DEFAULT_NOTIFICATION_SECTION: NotificationSection = 'general';

export function isNotificationSection(id: string | undefined): id is NotificationSection {
  return !!id && NOTIFICATION_SECTIONS.some((s) => s.id === id);
}

export function digestTypeLocked(always: EventType[], t: EventType): boolean {
  return always.includes(t);
}

export function notificationSectionFromPath(pathname: string): NotificationSection | null {
  const m = pathname.match(/\/settings\/notifications\/([^/]+)/);
  return isNotificationSection(m?.[1]) ? m[1] : null;
}

export function urlHost(url: string): string {
  try {
    return new URL(url).host || url;
  } catch {
    return url;
  }
}

export function eventFilterSummary(types: EventType[], labels: Record<string, string>): string {
  if (!types.length) return 'All events';
  if (types.length <= 2) return types.map((t) => labels[t] || t).join(', ');
  return `${types.length} event types`;
}
