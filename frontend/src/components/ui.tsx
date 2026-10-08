import type { ReactNode } from 'react';
import type { ChangeEvent, DeviceStatus, ScanStatus } from '../types';
import { EVENT_LABELS } from '../util';

export function Card({ title, actions, children, flush, className }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; flush?: boolean; className?: string;
}) {
  return (
    <section className={`card ${className ?? ''}`}>
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
  return (
    <span className="row" style={{ gap: 6 }}>
      <span className={`badge ${cls}`} title={status === 'unknown' ? 'Missed by the latest scan; not yet confirmed gone' : undefined}>
        <span className="dot" />{label}
      </span>
      {failed && <span className="badge medium" title="The last port/service scan of this host failed or timed out">Scan failed</span>}
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

export function Modal({ title, onClose, children, footer }: {
  title: string; onClose: () => void; children: ReactNode; footer?: ReactNode;
}) {
  return (
    <div className="modal-back" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-label={title}>
        <div className="card-head">
          <h2>{title}</h2>
          <button className="btn ghost sm" onClick={onClose} aria-label="Close">✕</button>
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

export function PortChips({ ports, max = 8 }: { ports: { port: number; protocol: string; service: string | null }[]; max?: number }) {
  if (!ports.length) return <span className="muted">—</span>;
  return (
    <span>
      {ports.slice(0, max).map((p) => (
        <span className="chip" key={`${p.protocol}${p.port}`} title={p.service ?? undefined}>{p.port}</span>
      ))}
      {ports.length > max && <span className="muted small">+{ports.length - max}</span>}
    </span>
  );
}
