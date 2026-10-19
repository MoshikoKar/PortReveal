import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import type { ChangeEvent, DeviceStatus, ScanStatus } from '../types';
import { EVENT_LABELS, scoreLevel } from '../util';

export function Card({ title, actions, children, flush, className, id }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; flush?: boolean; className?: string; id?: string;
}) {
  return (
    <section id={id} className={`card ${className ?? ''}`}>
      {(title || actions) && (
        <div className="card-head">
          {typeof title === 'string' ? <h2>{title}</h2> : title}
          {actions && <div className="row">{actions}</div>}
        </div>
      )}
      <div className={`card-body ${flush ? 'flush' : ''}`}>{children}</div>
    </section>
  );
}

export function Kpi({ label, value, sub, color, onClick, active }: {
  label: string; value: ReactNode; sub?: ReactNode; color?: string; onClick?: () => void; active?: boolean;
}) {
  return (
    <div
      className={`kpi ${onClick ? 'link' : ''} ${active ? 'active' : ''}`}
      style={{ ['--kpi-color' as any]: color }}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); } } : undefined}
      aria-pressed={onClick ? !!active : undefined}
    >
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {sub !== undefined && <div className="sub">{sub}</div>}
    </div>
  );
}

const DEVICE_STATUS: Record<DeviceStatus, [string, string]> = {
  active: ['ok', 'Active'],
  unknown: ['medium', 'Unconfirmed'],
  not_detected: ['high', 'Not detected'],
};

export function DeviceStatusBadge({ status, failed }: { status: DeviceStatus; failed?: boolean }) {
  const [cls, label] = DEVICE_STATUS[status] ?? ['', status];
  const statusBadge = (
    <span className={`badge ${cls}`} title={status === 'unknown' ? 'Missed by the latest scan; not yet confirmed gone' : undefined}>
      <span className="dot" />{label}
    </span>
  );
  if (!failed) return statusBadge;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, lineHeight: 1 }}>
      {statusBadge}
      <span className="badge medium" title="The last port/service scan of this host failed or timed out">Scan failed</span>
    </span>
  );
}

const SCAN_STATUS: Record<ScanStatus, string> = {
  queued: 'outline', running: 'accent', completed: 'ok', partial: 'medium', failed: 'high', cancelled: 'outline',
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span className={`badge ${SCAN_STATUS[status]} ${status === 'running' ? 'pulse' : ''}`}>
      {status === 'running' && <span className="dot" />}{status}
    </span>
  );
}

export function SeverityBadge({ ev }: { ev: ChangeEvent }) {
  return <span className={`badge ${ev.severity}`}>{EVENT_LABELS[ev.event_type] ?? ev.event_type}</span>;
}

const SCORE_CLASS = { high: 'high', medium: 'medium', low: 'ok' } as const;

/** Exposure score 0-100 (computed from stored scan data, not a vulnerability rating). */
export function ScoreBadge({ score }: { score: number | null | undefined }) {
  const s = score ?? 0;
  return <span className={`badge ${SCORE_CLASS[scoreLevel(s)]}`} title={`Exposure score ${s} / 100`}>{s}</span>;
}

/** Risk (CVE-based) or combined score 0-100 - same 60/30 scale as exposure. */
export function RiskBadge({ score, kind = 'risk' }: { score: number | null | undefined; kind?: 'risk' | 'combined' }) {
  const s = score ?? 0;
  const label = kind === 'risk' ? 'Risk score' : 'Combined score';
  return <span className={`badge ${SCORE_CLASS[scoreLevel(s)]}`} title={`${label} ${s} / 100`}>{s}</span>;
}

const VULN_JOB_STATUS: Record<string, [string, string]> = {
  queued: ['outline', 'Vulnerability check queued'],
  running: ['accent', 'Vulnerability check running'],
  completed: ['ok', 'Vulnerability check completed'],
  partial: ['medium', 'Vulnerability check partially completed'],
  failed: ['high', 'Vulnerability check failed'],
  cancelled: ['outline', 'Vulnerability check cancelled'],
};

export function VulnJobBadge({ status }: { status: string | null | undefined }) {
  if (!status) return null;
  const [cls, label] = VULN_JOB_STATUS[status] ?? ['outline', status];
  return (
    <span className={`badge ${cls} ${status === 'running' ? 'pulse' : ''}`} title={label}>
      {status === 'running' && <span className="dot" />}{label}
    </span>
  );
}

const IP_ASSIGNMENT: Record<string, [string, string, string]> = {
  static: ['ok', 'Static', 'This IP has stayed on this device for a while'],
  dynamic: ['medium', 'Dynamic', 'This device has recently used more than one IP (DHCP-style)'],
  unknown: ['outline', 'Unknown', 'Not enough address history yet to tell'],
};

export function IpAssignmentBadge({ value }: { value: string | null | undefined }) {
  if (!value) return null;
  const [cls, label, title] = IP_ASSIGNMENT[value] ?? ['outline', value, undefined as unknown as string];
  return <span className={`badge ${cls}`} title={title}>{label}</span>;
}

// MACs come from ARP and local names from L2 broadcast discovery, so routed/VPN devices legitimately lack them.
const ARP_SOURCE_HINT = "To get MACs for a routed site, set that site's router as the ARP source in Settings > Networks.";
const NO_MAC_TIP = `MAC addresses come from ARP, which only reaches the scanner's own L2 segment. Routed and unprivileged scans cannot see them - this is expected, not an error. ${ARP_SOURCE_HINT}`;
const NO_MAC_VPN_TIP = `This device is reached over a site-to-site VPN (a routed path). ARP does not cross it, so no MAC address is available - this is expected, not an error. ${ARP_SOURCE_HINT}`;

const MAC_SOURCES: Record<string, [string, string]> = {
  snmp: ['router ARP', "Read from the site router's ARP table over SNMP (the scanner is not on this device's L2 segment)"],
  netbios: ['NetBIOS', "Reported by the device itself in its NetBIOS reply (the scanner is not on this device's L2 segment)"],
};

/** Where a MAC came from when it was not the scanner's own ARP. Renders nothing for local ARP. */
export function MacSourceBadge({ source }: { source: string | null | undefined }) {
  const meta = source ? MAC_SOURCES[source] : undefined;
  if (!meta) return null;
  return <span className="badge outline" style={{ marginLeft: 6 }} title={meta[1]}>{meta[0]}</span>;
}

export function macSourceTitle(source: string | null | undefined): string | undefined {
  return source ? MAC_SOURCES[source]?.[1] : undefined;
}
export const NO_NAME_TIP = 'No reverse-DNS (PTR) record and no local discovery name (mDNS/NetBIOS/SSDP).';
export const NO_NAME_VPN_TIP = `${NO_NAME_TIP} Local discovery is L2-only and does not cross a site-to-site VPN, so only DNS can name this device.`;

/** Empty state for a missing MAC: says why instead of a bare dash. Never shows a guessed MAC. */
export function NoMac({ vpn, className }: { vpn?: boolean; className?: string }) {
  return (
    <span className={`muted ${className ?? ''}`} title={vpn ? NO_MAC_VPN_TIP : NO_MAC_TIP}>
      {vpn ? '- (not available over VPN)' : '- (not on scanner L2 segment)'}
    </span>
  );
}

export function MockBadge({ mode }: { mode: string | null }) {
  if (mode !== 'mock') return null;
  return <span className="badge medium" title="Produced by the mock scanner (simulated data)">SIMULATED</span>;
}

export function ErrorBox({ error }: { error: string | null | undefined }) {
  if (!error) return null;
  return <div className="alert error">{error}</div>;
}

export function Loading() {
  return <div className="empty"><span className="spinner" /></div>;
}

/** Placeholder rows shown while a list table loads, so the page keeps its shape. */
export function SkeletonRows({ cols, rows = 6 }: { cols: number; rows?: number }) {
  return (
    <div className="table-wrap" aria-busy="true" aria-label="Loading">
      <table className="skeleton">
        <tbody>
          {Array.from({ length: rows }, (_, r) => (
            <tr key={r}>
              {Array.from({ length: cols }, (_, c) => (
                <td key={c}><span className="skeleton-bar" style={{ width: `${45 + ((r * 7 + c * 13) % 45)}%` }} /></td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Sortable column header: a real button (keyboard focusable) inside the `th`, which carries `aria-sort`. */
export function SortTh({ active, desc, onSort, className, children }: {
  active: boolean; desc: boolean; onSort: () => void; className?: string; children: ReactNode;
}) {
  return (
    <th className={className} aria-sort={active ? (desc ? 'descending' : 'ascending') : 'none'}>
      <button type="button" className="th-sort" onClick={onSort}>
        {children}{active && <span aria-hidden>{desc ? '↓' : '↑'}</span>}
      </button>
    </th>
  );
}

type SortValue = string | number | boolean | null | undefined;

/** Compare two cell values: empty values last, numbers numerically, text with numeric collation
 *  (so CVE ids and IPs order by their digit runs: 10.0.0.9 before 10.0.0.10). */
function compareSortValues(a: SortValue, b: SortValue): number {
  const empty = (v: SortValue) => v == null || v === '';
  if (empty(a) || empty(b)) return empty(a) ? (empty(b) ? 0 : 1) : -1;
  if (typeof a === 'string' || typeof b === 'string') {
    return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
  }
  return Number(a) - Number(b);
}

/** Client-side column sort for small, fully loaded tables (server-paged tables sort in the API).
 *  Rows keep their source order until a header is clicked; clicking again flips the direction.
 *  `descFirst` columns (scores, counts) start largest-first. Empty values always sort last. */
export function useClientSort<T, K extends string>(
  rows: T[], keys: Record<K, (row: T) => SortValue>, descFirst: readonly NoInfer<K>[] = [],
) {
  const [sort, setSort] = useState<{ key: K; desc: boolean } | null>(null);
  const sorted = useMemo(() => {
    if (!sort) return rows;
    const get = keys[sort.key];
    return [...rows].sort((a, b) => {
      const va = get(a);
      const vb = get(b);
      const cmp = compareSortValues(va, vb);
      // Keep empties last in both directions.
      if (va == null || va === '' || vb == null || vb === '') return cmp;
      return sort.desc ? -cmp : cmp;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `keys` is a fresh literal each render; its getters are pure
  }, [rows, sort]);
  const th = (key: K, label: ReactNode, className?: string) => (
    <SortTh key={key} className={className} active={sort?.key === key} desc={!!sort?.desc}
      onSort={() => setSort((s) => (s?.key === key ? { key, desc: !s.desc } : { key, desc: descFirst.includes(key) }))}>
      {label}
    </SortTh>
  );
  return { rows: sorted, th };
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Pager({ page, pageSize, total, onPage }: {
  page: number; pageSize: number; total: number; onPage: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (total <= pageSize) return <div className="pager"><span>{total} item{total === 1 ? '' : 's'}</span></div>;
  return (
    <div className="pager">
      <span>
        {(page - 1) * pageSize + 1}-{Math.min(page * pageSize, total)} of {total}
      </span>
      <div className="row">
        <button className="btn sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
        <span>Page {page} / {pages}</span>
        <button className="btn sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
      </div>
    </div>
  );
}

/** Caps a fully loaded list at `size` rows. Longer lists get a "See all" toggle that switches to
 *  paging through every row, still `size` at a time. `actions` goes in the card head, so paging
 *  never changes the card's height (cards sharing a grid row stay level). */
export function useRowLimit<T>(items: T[], size = 10) {
  const [paging, setPaging] = useState(false);
  const [page, setPage] = useState(1);
  const total = items.length;
  const pages = Math.max(1, Math.ceil(total / size));
  const current = paging ? Math.min(page, pages) : 1;
  const rows = items.slice((current - 1) * size, current * size);
  const actions = total > size ? (
    <>
      {paging && (
        <span className="mini-pager">
          <button type="button" className="btn sm ghost" disabled={current <= 1} aria-label="Previous page"
            onClick={() => setPage(current - 1)}>‹</button>
          <span>{(current - 1) * size + 1}-{Math.min(current * size, total)} of {total}</span>
          <button type="button" className="btn sm ghost" disabled={current >= pages} aria-label="Next page"
            onClick={() => setPage(current + 1)}>›</button>
        </span>
      )}
      <button type="button" className="btn sm ghost" aria-expanded={paging}
        onClick={() => { setPaging(!paging); setPage(1); }}>
        {paging ? `Top ${size}` : `See all ${total}`}
      </button>
    </>
  ) : null;
  return { rows, actions };
}

/** True when closing may proceed: nothing unsaved, or the user agreed to discard it. */
export function confirmDiscard(dirty: boolean | undefined): boolean {
  return !dirty || confirm('Discard unsaved changes?');
}

/** Tell a parent (Settings, the setup wizard) whenever a child's unsaved-edits state flips. */
export function useReportDirty(dirty: boolean, onDirtyChange?: (dirty: boolean) => void) {
  useEffect(() => {
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);
}

/** React Router stamps every history entry it creates with its position (`idx`). */
const historyIdx = (state: unknown): number | null => {
  const idx = (state as { idx?: unknown } | null)?.idx;
  return typeof idx === 'number' ? idx : null;
};

/** Active Back/Forward guards; each returns true when it swallowed the pop. */
const popGuards = new Set<(e: PopStateEvent) => boolean>();

// Registered when this module loads (main.tsx imports it through ErrorBoundary), i.e. before <BrowserRouter>
// attaches its own popstate listener. Listeners on window run in registration order (a capture flag does not
// put a later one first, checked in Chrome), so this is what lets a guard stop a pop before the router sees it.
if (typeof window !== 'undefined') {
  window.addEventListener('popstate', (e) => {
    for (const guard of popGuards) {
      if (guard(e)) {
        e.stopImmediatePropagation();
        return;
      }
    }
  }, true);
}

/** Browser Back/Forward guard while `when` holds (`message` defaults to the confirmDiscard prompt).
 *  `<BrowserRouter>` has no `useBlocker` (data routers only). If the user declines, the pop is swallowed
 *  (the router never sees it, so nothing unmounts) and the browser is sent back to the entry it left. */
export function useHistoryGuard(when: boolean, message?: string) {
  const { key } = useLocation();
  useEffect(() => {
    if (!when) return;
    const here = historyIdx(window.history.state);
    const guard = (e: PopStateEvent) => {
      const to = historyIdx(e.state);
      if (here == null || to == null) return false;
      // Our own restore landing back here: the router never left, so it must not see this pop either.
      if (to === here) return true;
      if (message ? confirm(message) : confirmDiscard(true)) return false;
      window.history.go(here - to);
      return true;
    };
    popGuards.add(guard);
    return () => { popGuards.delete(guard); };
  }, [when, message, key]);
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((el) => el.getClientRects().length > 0);
}

/** `dirty`: the form has unsaved edits, so backdrop/✕/Escape close asks before discarding them.
 *  Consumers' own Cancel buttons should check `confirmDiscard(dirty)` the same way.
 *  Keyboard: focus moves into the dialog on open, Tab cycles inside it, Escape closes, and focus
 *  returns to the element that opened it. Body scroll is locked while it is open. */
export function Modal({ title, onClose, children, footer, dirty }: {
  title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; dirty?: boolean;
}) {
  const requestClose = () => confirmDiscard(dirty) && onClose();
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const el = ref.current;
    if (el && !el.contains(document.activeElement)) {
      // First form field if there is one, otherwise the dialog itself (not the ✕ button).
      const field = el.querySelector<HTMLElement>('.card-body input:not([disabled]), .card-body select:not([disabled]), .card-body textarea:not([disabled])');
      (field ?? el).focus();
    }
    // The page behind the backdrop must not scroll while the dialog is open (same as Lightbox).
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = prevOverflow;
      if (opener?.isConnected) opener.focus();
    };
  }, []);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      requestClose();
      return;
    }
    if (e.key !== 'Tab' || !ref.current) return;
    const items = focusables(ref.current);
    if (!items.length) {
      e.preventDefault();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === ref.current)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return (
    <div className="modal-back" onMouseDown={(e) => e.target === e.currentTarget && requestClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} ref={ref} onKeyDown={onKeyDown}>
        <div className="card-head">
          <h2 id={titleId}>{title}</h2>
          <button className="btn ghost sm" onClick={requestClose} aria-label="Close" title="Close">✕</button>
        </div>
        <div className="card-body stack">{children}</div>
        {footer && <div className="card-head" style={{ borderTop: '1px solid var(--border)', borderBottom: 0, justifyContent: 'flex-end' }}>{footer}</div>}
      </div>
    </div>
  );
}

export function Progress({ value }: { value: number }) {
  return <div className="progress"><div style={{ width: `${Math.round(Math.min(1, Math.max(0, value)) * 100)}%` }} /></div>;
}

type ChipPort = { port: number; protocol: string; service: string | null; product?: string | null; version?: string | null };

function chipTitle(p: ChipPort): string | undefined {
  const productVersion = [p.product, p.version].filter(Boolean).join(' ');
  if (productVersion) return p.service ? `${productVersion} (${p.service})` : productVersion;
  return p.service ?? undefined;
}

export function PortChips({ ports, max = 8 }: { ports: ChipPort[]; max?: number }) {
  if (!ports.length) return <span className="muted">-</span>;
  return (
    <span>
      {ports.slice(0, max).map((p) => (
        <span className="chip" key={`${p.protocol}${p.port}`} title={chipTitle(p)}>{p.port}</span>
      ))}
      {ports.length > max && <span className="muted small">+{ports.length - max}</span>}
    </span>
  );
}
