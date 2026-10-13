import { useCallback, useEffect, useRef, useState } from 'react';
import { get } from './api';
import type { EventType } from './types';

const pad = (n: number) => String(n).padStart(2, '0');

export function fmtTime(iso: string | null | undefined, withSeconds = false): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const base = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return withSeconds ? `${base}:${pad(d.getSeconds())}` : base;
}

export function fmtShortTime(iso: string): string {
  const d = new Date(iso);
  const today = new Date();
  if (d.toDateString() === today.toDateString()) return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function relTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  const future = diff < 0;
  const s = Math.abs(diff);
  let out: string;
  if (s < 60) out = `${Math.round(s)}s`;
  else if (s < 3600) out = `${Math.round(s / 60)}m`;
  else if (s < 86400) out = `${Math.round(s / 3600)}h`;
  else out = `${Math.round(s / 86400)}d`;
  return future ? `in ${out}` : `${out} ago`;
}

export function duration(start: string | null, end: string | null): string {
  if (!start) return '—';
  const s = Math.max(0, ((end ? new Date(end) : new Date()).getTime() - new Date(start).getTime()) / 1000);
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
}

/** Must match backend runner disc_weight for standard/full scans. */
const SCAN_DISCOVERY_WEIGHT = 0.2;

/** Stage-local 0..1 for labels. Overall `progress` stays weighted for the bar. */
export function scanStageFraction(s: {
  scan_type: string;
  stage: string | null;
  progress: number;
}): number {
  const p = Math.min(1, Math.max(0, s.progress ?? 0));
  const stage = (s.stage || '').toLowerCase();
  if (stage.startsWith('discovery')) {
    if (s.scan_type === 'discovery') return p;
    return Math.min(1, p / SCAN_DISCOVERY_WEIGHT);
  }
  if (stage.includes('port') || stage.includes('service')) {
    return Math.min(1, Math.max(0, (p - SCAN_DISCOVERY_WEIGHT) / (1 - SCAN_DISCOVERY_WEIGHT)));
  }
  return p;
}

export const EVENT_LABELS: Record<EventType, string> = {
  device_discovered: 'New device',
  device_disappeared: 'Device not detected',
  device_reappeared: 'Device reappeared',
  ip_changed: 'IP changed',
  port_opened: 'Port opened',
  port_closed: 'Port closed',
  service_detected: 'Service detected',
  service_changed: 'Service changed',
  version_changed: 'Version changed',
  tag_added: 'Tag added',
  tag_removed: 'Tag removed',
  watch_match: 'Watch match',
  policy_violation: 'Policy violation',
  banner_changed: 'Banner changed',
};

export const SCAN_TYPE_LABELS = { discovery: 'Discovery', standard: 'Standard', full: 'Full port' } as const;

/** Mirrors backend NETWORK_ZONES / CRITICALITY_LEVELS / exposure thresholds. */
export const NETWORK_ZONES = ['servers', 'users', 'iot', 'dmz', 'management', 'guest', 'lab'] as const;
export const CRITICALITY_LEVELS = ['low', 'medium', 'high', 'critical'] as const;
export const SCORE_HIGH = 60;
export const SCORE_MEDIUM = 30;

export function scoreLevel(score: number): 'high' | 'medium' | 'low' {
  return score >= SCORE_HIGH ? 'high' : score >= SCORE_MEDIUM ? 'medium' : 'low';
}

/** Mirrors backend quote_value: quote a query value containing spaces, commas, quotes or parentheses. */
export function quoteValue(value: string): string {
  if (value && !/[\s",()|]/.test(value) && !value.startsWith('-')) return value;
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** Append a term to a query, skipping it when already present. */
export function addTerm(q: string, term: string): string {
  const cur = q.trim();
  if (!cur) return term;
  return cur.includes(term) ? cur : `${cur} ${term}`;
}

export const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

/** Requests in flight by key (e.g. `delete-12`), so their buttons stay disabled until each settles.
 *  `track` ignores a key that is already in flight, which also absorbs double clicks. */
export function useInFlight() {
  const [keys, setKeys] = useState<ReadonlySet<string>>(() => new Set());
  const live = useRef(new Set<string>());
  const pending = useCallback((key: string) => keys.has(key), [keys]);
  const track = useCallback(async (key: string, fn: () => Promise<unknown>) => {
    if (live.current.has(key)) return;
    live.current.add(key);
    setKeys(new Set(live.current));
    try {
      await fn();
    } finally {
      live.current.delete(key);
      setKeys(new Set(live.current));
    }
  }, []);
  return { pending, track };
}

/** Hosts per /web-hosts request. The Web and Remote pages filter on the client, so pages are large. */
export const WEB_HOSTS_PAGE_SIZE = 500;

/** Fetch a GET endpoint, optionally polling. Re-fetches when path/params change. */
export function useApi<T>(path: string | null, params?: Record<string, any>, pollMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(!!path);
  const key = JSON.stringify(params ?? {});
  const seq = useRef(0);

  const load = useCallback(async () => {
    if (!path) return;
    const my = ++seq.current;
    try {
      const res = await get<T>(path, JSON.parse(key));
      if (my === seq.current) {
        setData(res);
        setError(null);
      }
    } catch (e: any) {
      if (my === seq.current) setError(e.message || String(e));
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, [path, key]);

  useEffect(() => {
    setLoading(true);
    load();
    if (!pollMs) return;
    const t = window.setInterval(() => {
      if (document.visibilityState === 'visible') load();
    }, pollMs);
    return () => window.clearInterval(t);
  }, [load, pollMs]);

  return { data, error, loading, reload: load, setData };
}
