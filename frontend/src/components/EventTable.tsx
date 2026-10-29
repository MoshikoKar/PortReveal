import { Fragment, type ReactNode, type Ref } from 'react';
import { Link } from 'react-router-dom';
import { eventColumns, type ChangeParts } from '../eventColumns';
import type { ChangeEvent } from '../types';
import { fmtShortTime, fmtTime } from '../util';
import { SeverityBadge } from './ui';

function ChangeCell({ c, title }: { c: ChangeParts; title: string }) {
  // Pure "old → new": the old side truncates first so the new value stays readable.
  if (c.from != null && !c.cve && !c.verb && !c.note) {
    return (
      <span className="event-change-text event-diff" title={title}>
        <span className="muted event-from">{c.from}</span><span className="muted">→</span>
        <span className="event-to">{c.to}</span>
      </span>
    );
  }
  const parts: ReactNode[] = [];
  if (c.cve) parts.push(<Link className="mono" to={`/vulnerabilities/${encodeURIComponent(c.cve)}`}>{c.cve}</Link>);
  if (c.verb) parts.push(c.verb);
  if (c.from != null) parts.push(<span className="muted">{c.from} →</span>);
  if (c.to) parts.push(<span className={c.mono ? 'mono' : undefined}>{c.to}</span>);
  if (c.note) parts.push(<span className="muted">{c.cve ? `· ${c.note}` : c.note}</span>);
  return (
    <span className="event-change-text" title={title}>
      {parts.map((p, i) => <Fragment key={i}>{i > 0 && ' '}{p}</Fragment>)}
      {c.kev && <span className="badge high event-kev">KEV</span>}
    </span>
  );
}

const BELL_OFF = (
  <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M13.7 21a2 2 0 0 1-3.4 0" /><path d="M18 8a6 6 0 0 0-9.3-5" /><path d="M6.3 6.3A6 6 0 0 0 6 8c0 7-3 9-3 9h14" /><path d="M2 2l20 20" />
  </svg>
);

/**
 * Change events as Time · Event · Device (name, IP below) · Port · Change [· Scan]. Domain-scan events
 * have no device: the Device column shows the host name and links to its domain. Shared by the
 * Changes page and the dashboard's Recent changes card; the column content comes from eventColumns().
 * `compact` is the dashboard form: short times, no Scan column, "no alert" as an icon.
 */
export function EventTable({ events, compact, tableRef }: {
  events: ChangeEvent[];
  compact?: boolean;
  tableRef?: Ref<HTMLTableElement>;
}) {
  return (
    <table ref={tableRef} className={`event-table${compact ? ' dash-table compact' : ''}`}>
      <thead>
        <tr>
          <th>Time</th><th>Event</th><th className="event-device">Device</th><th>Port</th>
          <th className="event-change">Change</th>{!compact && <th className="right">Scan</th>}
        </tr>
      </thead>
      <tbody>
        {events.map((e) => {
          const col = eventColumns(e);
          return (
            <tr key={e.id}>
              <td className="muted" title={fmtTime(e.created_at, true)}>{compact ? fmtShortTime(e.created_at) : fmtTime(e.created_at)}</td>
              <td><SeverityBadge ev={e} /></td>
              <td className="event-device">
                <div className="event-device-cell">
                  <span className="cell-ellipsis" title={e.device_label ?? undefined}>
                    {e.device_uuid ? <Link to={`/devices/${e.device_uuid}`}>{e.device_label}</Link>
                      : e.domain_id != null ? <Link to={`/domains/${e.domain_id}`}>{e.device_label}</Link> : e.device_label}
                  </span>
                  {col.ip && <span className="cell-ellipsis mono small muted" title={col.ip}>{col.ip}</span>}
                </div>
              </td>
              <td>{col.port ? <span className="chip new">{col.port}</span> : <span className="muted">-</span>}</td>
              <td className="event-change">
                <div className="event-change-cell">
                  <ChangeCell c={col.change} title={col.changeText} />
                  {col.recordedOnly && (compact ? (
                    <span className="muted event-no-alert" title="No alert sent" aria-label="No alert sent">{BELL_OFF}</span>
                  ) : (
                    <span className="badge outline" title="Recorded without an alert: the device is outside the configured networks">recorded only</span>
                  ))}
                </div>
              </td>
              {!compact && (
                <td className="right small">
                  {e.scan_id != null ? `#${e.scan_id}` : <span className="muted">-</span>}
                  {e.notified_at && <span className="muted event-emailed" title={`Emailed ${fmtTime(e.notified_at)}`} aria-label="Emailed">✉</span>}
                </td>
              )}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
