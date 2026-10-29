// Domain scans: labels, filter <-> URL mapping, lookup states and settings-key payloads (pure helpers).
import type {
  Domain, DomainPhaseStatus, DomainSchedule, DomainScanJob, DomainScanPhase, DomainWordlistMode, Exposure, HostingEntry,
  LookupResult, MaskedKey, SubdomainFlag, SubdomainSource,
} from './types';

export const EXPOSURE_LABELS: Record<Exposure, string> = {
  external: 'External', internal: 'Internal', both: 'Both', unresolved: 'Unresolved',
};
/** Badge class per exposure (reuses the existing badge palette). */
export const EXPOSURE_BADGE: Record<Exposure, string> = {
  external: 'accent', internal: 'outline', both: 'medium', unresolved: 'outline',
};
export const EXPOSURE_TIPS: Record<Exposure, string> = {
  external: 'Resolves on the public resolvers only',
  internal: 'Resolves on the internal resolvers only',
  both: 'Resolves on both (split DNS)',
  unresolved: 'Known (zone transfer / added manually) but resolves nowhere right now',
};
export const SOURCE_LABELS: Record<SubdomainSource, string> = {
  passive: 'Passive', wordlist: 'Wordlist', axfr: 'AXFR', manual: 'Manual',
};
export const SOURCE_TIPS: Record<SubdomainSource, string> = {
  passive: 'Found by subfinder in public passive sources (attacker view)',
  wordlist: 'Found by dnsx wordlist brute force (attacker view)',
  axfr: 'Listed in a zone transfer (ground truth)',
  manual: 'Added from a manual lookup',
};
export const FLAG_LABELS: Record<SubdomainFlag, string> = {
  internal_authorized: 'Internal (authorized)',
  internal_name_exposed: 'Internal name exposed',
  private_ip_public: 'Private IP in public DNS',
};
export const FLAG_TIPS: Record<SubdomainFlag, string> = {
  internal_authorized: 'Found only through the authorized zone transfer: an outside attacker did not find it',
  internal_name_exposed: 'In the zone transfer and visible publicly while it resolves to internal ranges',
  private_ip_public: 'The public answer contains a private address or one inside a configured network',
};
export const FLAG_BADGE: Record<SubdomainFlag, string> = {
  internal_authorized: 'outline', internal_name_exposed: 'high', private_ip_public: 'high',
};

export const DEFAULT_PUBLIC_RESOLVERS = ['1.1.1.1', '8.8.8.8'];

export function wildcardTip(domain: string, wildcard: { internal: string[]; public: string[] } | null | undefined): string {
  const views = (['internal', 'public'] as const)
    .filter((v) => wildcard?.[v]?.length)
    .map((v) => `${v}: ${wildcard![v].join(', ')}`);
  const base = `Answer matches the wildcard *.${domain}; the name may not really exist.`;
  return views.length ? `${base} Wildcard answers - ${views.join('; ')}` : base;
}

export function hostingLabel(h: HostingEntry): string {
  if (h.kind === 'network') return h.device_label ? `${h.network ?? 'network'} · ${h.device_label}` : (h.network ?? 'configured network');
  if (h.kind === 'private') return 'private (unmanaged range)';
  const provider = [h.asn ? `AS${h.asn}` : null, h.as_org].filter(Boolean).join(' ');
  return provider ? `external · ${provider}` : 'external';
}

// --- inventory filters (URL search params <-> API params) -----------------------------------------
export const SUBDOMAIN_FILTER_KEYS = ['q', 'exposure', 'status', 'source', 'flag', 'wildcard', 'sort', 'page'] as const;
export type SubdomainFilterKey = (typeof SUBDOMAIN_FILTER_KEYS)[number];

export function subdomainQuery(sp: URLSearchParams, pageSize: number): Record<string, string | number | boolean | undefined> {
  const val = (k: SubdomainFilterKey) => sp.get(k) || undefined;
  return {
    q: val('q'),
    exposure: val('exposure'),
    status: val('status') ?? 'active',
    source: val('source'),
    flag: val('flag'),
    wildcard: val('wildcard') === '1' ? true : undefined,
    sort: val('sort') ?? 'name',
    page: Number(sp.get('page') || 1),
    page_size: pageSize,
  };
}

/** Next search params after a filter change: empty values drop the key; any change but paging resets the page. */
export function patchParams(sp: URLSearchParams, patch: Partial<Record<SubdomainFilterKey, string | undefined>>): URLSearchParams {
  const next = new URLSearchParams(sp);
  for (const [k, v] of Object.entries(patch)) {
    if (v) next.set(k, v);
    else next.delete(k);
  }
  if (!('page' in patch)) next.delete('page');
  return next;
}

export function activeFilterCount(sp: URLSearchParams): number {
  return (['q', 'exposure', 'source', 'flag', 'wildcard'] as const).filter((k) => sp.get(k)).length
    + (sp.get('status') && sp.get('status') !== 'active' ? 1 : 0);
}

// --- manual lookup ------------------------------------------------------------------------------------------
export type LookupState =
  | { status: 'idle' }
  | { status: 'invalid'; message: string }
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'done'; result: LookupResult };

// Same rules as the API (core/domains/validate.py): LDH labels, alphabetic or punycode top-level label.
const HOST_RE = /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

/** Client-side pre-check (the API validates again): a host name inside one of the configured domains. */
export function checkLookupInput(raw: string, domains: string[]): string | null {
  const name = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!name) return 'Enter a host name, for example test.example.com';
  if (/[\s/:@]/.test(name)) return 'Enter a host name only (no URL, port or spaces)';
  // Internationalized names are left to the API (it converts them to punycode).
  if (/^[\x20-\x7e]+$/.test(name) && !HOST_RE.test(name)) return 'Not a valid host name';
  const inside = domains.some((d) => name === d || name.endsWith(`.${d}`));
  return inside ? null : `${name} is not inside a configured domain (${domains.join(', ') || 'none configured'})`;
}

export interface LookupView { busy: boolean; message: string | null; error: boolean; canAdd: boolean; canPortScan: boolean }

export function lookupView(state: LookupState): LookupView {
  switch (state.status) {
    case 'idle': return { busy: false, message: null, error: false, canAdd: false, canPortScan: false };
    case 'invalid': return { busy: false, message: state.message, error: true, canAdd: false, canPortScan: false };
    case 'loading': return { busy: true, message: 'Resolving…', error: false, canAdd: false, canPortScan: false };
    case 'error': return { busy: false, message: state.message, error: true, canAdd: false, canPortScan: false };
    case 'done': {
      const r = state.result;
      const message = r.ips.length ? null : `${r.hostname} does not resolve on the internal or the public resolvers.`;
      return { busy: false, message, error: false, canAdd: !r.in_inventory, canPortScan: r.ips.length > 0 };
    }
  }
}

// --- add / edit domain ----------------------------------------------------------------------------------------
export interface DomainDraft {
  id?: number;
  name: string;
  enabled: boolean;
  wordlist_mode: DomainWordlistMode;
  wordlist_id: number | null;
  custom_words: string;
  passive_enabled: boolean;
  axfr_enabled: boolean;
  axfr_servers: string;
  internal_resolvers: string;
  public_resolvers: string;
  schedule: DomainSchedule;
  notes: string;
}

export const splitList = (text: string): string[] => text.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);

export function emptyDraft(): DomainDraft {
  return {
    name: '', enabled: true, wordlist_mode: 'none', wordlist_id: null, custom_words: '', passive_enabled: true,
    axfr_enabled: false, axfr_servers: '', internal_resolvers: '', public_resolvers: DEFAULT_PUBLIC_RESOLVERS.join(', '),
    schedule: { enabled: false, time: '03:30', days: [0, 1, 2, 3, 4, 5, 6] }, notes: '',
  };
}

export function draftFromDomain(d: Domain): DomainDraft {
  return {
    id: d.id, name: d.name, enabled: d.enabled, wordlist_mode: d.wordlist_mode, wordlist_id: d.wordlist_id,
    custom_words: d.custom_words.join('\n'), passive_enabled: d.passive_enabled, axfr_enabled: d.axfr_enabled,
    axfr_servers: d.axfr_servers.join(', '), internal_resolvers: d.internal_resolvers.join(', '),
    public_resolvers: d.public_resolvers.join(', '), schedule: { ...d.schedule }, notes: d.notes ?? '',
  };
}

export function domainBody(d: DomainDraft) {
  return {
    name: d.name.trim(),
    enabled: d.enabled,
    wordlist_mode: d.wordlist_mode,
    wordlist_id: d.wordlist_mode === 'library' ? d.wordlist_id : null,
    custom_words: d.wordlist_mode === 'custom' ? splitList(d.custom_words) : [],
    passive_enabled: d.passive_enabled,
    axfr_enabled: d.axfr_enabled,
    axfr_servers: d.axfr_enabled ? splitList(d.axfr_servers) : [],
    internal_resolvers: splitList(d.internal_resolvers),
    public_resolvers: splitList(d.public_resolvers),
    schedule: d.schedule,
    notes: d.notes.trim() || null,
  };
}

// --- settings: provider keys (write-only) -------------------------------------------------------------------
/** What the key field shows: the server's masked hint, never the key. */
export function keyPlaceholder(k: MaskedKey | undefined): string {
  if (!k?.set) return 'not set';
  return `${k.masked || '••••'} (unchanged)`;
}

/** PUT value for one key: null keeps the stored key, '' clears it, anything else replaces it. */
export function keyPayload(edited: string | null, cleared: boolean): string | null {
  if (cleared) return '';
  if (edited === null || edited.trim() === '') return null;
  return edited.trim();
}

// --- running scan progress ------------------------------------------------------------------------------------
/** Poll the scan status every 2.5 s only while a scan is queued or running; null stops polling. */
export const SCAN_POLL_MS = 2500;
export function scanPollMs(scan: Pick<DomainScanJob, 'status'> | null | undefined): number | undefined {
  return scan && (scan.status === 'queued' || scan.status === 'running') ? SCAN_POLL_MS : undefined;
}

export function formatPercent(fraction: number | null | undefined): string {
  const pct = Math.max(0, Math.min(1, fraction ?? 0)) * 100;
  return `${pct < 10 && pct > 0 ? pct.toFixed(1) : Math.floor(pct)}%`;
}

/** "45 s", "3 min", "1 h 20 min"; null/negative -> '-'. */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return '-';
  const s = Math.round(seconds);
  if (s < 60) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  return `${Math.floor(m / 60)} h${m % 60 ? ` ${m % 60} min` : ''}`;
}

export const formatEta = (seconds: number | null | undefined) => (seconds == null ? '' : `ETA ${formatDuration(seconds)}`);

export function formatRate(rate: number | null | undefined): string {
  if (!rate) return '';
  return `${rate >= 10 ? Math.round(rate).toLocaleString('en-US') : rate.toFixed(1)} queries/s`;
}

/** "12,340 / 20,000 candidates" (or "37 names" when the total is unknown). */
export function phaseCounter(p: Pick<DomainScanPhase, 'processed' | 'total' | 'unit' | 'found'>): string {
  const unit = p.unit ?? '';
  if (p.total != null && p.total > 0) return `${p.processed.toLocaleString('en-US')} / ${p.total.toLocaleString('en-US')} ${unit}`.trim();
  return p.found ? `${p.found.toLocaleString('en-US')} found` : '';
}

export const PHASE_BADGE: Record<DomainPhaseStatus, string> = {
  pending: 'outline', running: 'accent', done: 'ok', skipped: 'outline', failed: 'high',
};
const PHASE_MARK: Record<DomainPhaseStatus, string> = { pending: '○', running: '●', done: '✓', skipped: '–', failed: '✕' };

export interface StepperItem { key: string; label: string; status: DomainPhaseStatus; mark: string; badge: string; title: string }

/** One step per phase: mark + badge class + tooltip (status, reason, duration, found). */
export function stepperItems(phases: DomainScanPhase[] | null | undefined): StepperItem[] {
  return (phases ?? []).map((p) => {
    const bits = [p.status, p.reason, p.duration_s != null && p.status !== 'pending' ? formatDuration(p.duration_s) : null,
      p.found ? `${p.found.toLocaleString('en-US')} found` : null].filter(Boolean);
    return { key: p.key, label: p.label, status: p.status, mark: PHASE_MARK[p.status], badge: PHASE_BADGE[p.status], title: bits.join(' · ') };
  });
}

export function currentPhase(phases: DomainScanPhase[] | null | undefined): DomainScanPhase | null {
  return (phases ?? []).find((p) => p.status === 'running') ?? null;
}

/** Scan history tooltip: final duration and outcome of every phase. */
export function phaseSummaryTip(phases: DomainScanPhase[] | null | undefined): string {
  return (phases ?? []).map((p) => `${p.label}: ${p.status}${p.duration_s != null && p.status !== 'skipped' && p.status !== 'pending' ? ` (${formatDuration(p.duration_s)})` : ''}${p.reason ? ` - ${p.reason}` : ''}`).join('\n');
}

export function problemPhases(phases: DomainScanPhase[] | null | undefined): DomainScanPhase[] {
  return (phases ?? []).filter((p) => p.status === 'failed' || (p.status === 'done' && !!p.reason && p.key === 'resolve'));
}
