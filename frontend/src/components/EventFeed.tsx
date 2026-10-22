import { Link } from 'react-router-dom';
import type { ChangeEvent } from '../types';
import { fmtShortTime, fmtTime } from '../util';
import { Empty, SeverityBadge } from './ui';

export function EventFeed({ events, empty = 'No changes recorded yet.' }: { events: ChangeEvent[]; empty?: string }) {
  if (!events.length) return <Empty>{empty}</Empty>;
  return (
    <ul className="feed">
      {events.map((e) => (
        <li key={e.id}>
          <span className="time" title={fmtTime(e.created_at, true)}>{fmtShortTime(e.created_at)}</span>
          <span><SeverityBadge ev={e} /></span>
          <span className="msg">
            {e.device_uuid ? <Link to={`/devices/${e.device_uuid}`}>{e.device_label}</Link> : e.device_label}
            <span className="muted"> - </span>
            <EventDetail ev={e} />
            {!e.notify && <span className="muted small" title="Recorded without email (device outside configured networks)"> · no alert</span>}
          </span>
        </li>
      ))}
    </ul>
  );
}

type WatchDetail = {
  cve_id?: string;
  device_uuid?: string;
  hostname?: string | null;
  ip?: string | null;
  port?: number;
  protocol?: string;
  state?: string;
  cvss?: number | null;
  kev?: boolean;
};

function parseWatchDetail(ev: ChangeEvent): WatchDetail | null {
  if (ev.event_type !== 'cve_watch_match' || !ev.old_value) return null;
  try {
    const parsed = JSON.parse(ev.old_value) as WatchDetail;
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

export function EventDetail({ ev }: { ev: ChangeEvent }) {
  const port = ev.port != null ? <span className="chip new">{(ev.protocol || 'tcp').toUpperCase()}/{ev.port}</span> : null;
  switch (ev.event_type) {
    case 'port_opened':
      return <span>{port} opened <span className="muted">{ev.new_value}</span></span>;
    case 'port_closed':
      return <span>{port} closed <span className="muted">{ev.old_value}</span></span>;
    case 'service_changed':
    case 'version_changed':
      return <span>{port} {ev.old_value} <span className="muted">→</span> {ev.new_value}</span>;
    case 'service_detected':
      return <span>{port} {ev.new_value}</span>;
    case 'ip_changed':
      return <span className="mono">{ev.old_value} <span className="muted">→</span> {ev.new_value}</span>;
    case 'os_changed':
      return <span>{ev.old_value} <span className="muted">→</span> {ev.new_value}</span>;
    case 'device_discovered':
      return <span><span className="mono">{ev.ip}</span>{ev.new_value && <span className="muted"> · {ev.new_value}</span>}</span>;
    case 'watch_match':
    case 'policy_violation':
      return <span>{ev.new_value ?? ev.message}</span>;
    case 'cve_watch_match': {
      // Device is shown by the parent feed / Changes Device column — do not duplicate it here.
      const detail = parseWatchDetail(ev);
      const cveId = detail?.cve_id;
      const stateLabel = detail?.state === 'potential' ? 'potential' : 'confirmed';
      return (
        <span>
          {cveId ? (
            <Link className="mono" to={`/vulnerabilities/${encodeURIComponent(cveId)}`}>{cveId}</Link>
          ) : (
            <span className="mono">{ev.new_value ?? ev.message}</span>
          )}
          {detail && (
            <>
              <span className="muted"> · {stateLabel}</span>
              {detail.port != null && (
                <>
                  {' '}
                  <span className="chip new">{(detail.protocol || 'tcp').toUpperCase()}/{detail.port}</span>
                </>
              )}
              {detail.cvss != null && <span className="muted"> · CVSS {detail.cvss}</span>}
              {detail.kev && <span className="badge high" style={{ marginLeft: 6 }}>KEV</span>}
            </>
          )}
          {!detail && ev.new_value && <span className="muted"> · {ev.new_value}</span>}
        </span>
      );
    }
    case 'monitor_change':
      return <span>{ev.new_value}{port && <> {port}</>}</span>;
    case 'geo_mismatch':
      return <span>{ev.message}</span>;
    default:
      return <span className="mono">{ev.ip}</span>;
  }
}
