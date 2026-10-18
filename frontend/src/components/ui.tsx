import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode } from 'react';
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

export function Kpi({ label, value, sub, color, onClick }: {
  label: string; value: ReactNode; sub?: ReactNode; color?: string; onClick?: () => void;
}) {
  return (
    <div className={`kpi ${onClick ? 'link' : ''}`} style={{ ['--kpi-color' as any]: color }} onClick={onClick}>
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

/** Exposure score 0–100 (computed from stored scan data, not a vulnerability rating). */
export function ScoreBadge({ score }: { score: number | null | undefined }) {
  const s = score ?? 0;
  return <span className={`badge ${SCORE_CLASS[scoreLevel(s)]}`} title={`Exposure score ${s} / 100`}>{s}</span>;
}

/** Risk (CVE-based) or combined score 0-100 — same 60/30 scale as exposure. */
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
        {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
      </span>
      <div className="row">
        <button className="btn sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
        <span>Page {page} / {pages}</span>
        <button className="btn sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
      </div>
    </div>
  );
}

/** True when closing may proceed: nothing unsaved, or the user agreed to discard it. */
export function confirmDiscard(dirty: boolean | undefined): boolean {
  return !dirty || confirm('Discard unsaved changes?');
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
  if (!ports.length) return <span className="muted">—</span>;
  return (
    <span>
      {ports.slice(0, max).map((p) => (
        <span className="chip" key={`${p.protocol}${p.port}`} title={chipTitle(p)}>{p.port}</span>
      ))}
      {ports.length > max && <span className="muted small">+{ports.length - max}</span>}
    </span>
  );
}
