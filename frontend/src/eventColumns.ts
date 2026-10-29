import type { ChangeEvent } from './types';

/**
 * What the Change column shows, as parts the table renders in order:
 * [CVE link] verb [from →] to [note] [KEV]. `from` and `note` render muted.
 */
export interface ChangeParts {
  cve?: string;
  verb?: string;
  from?: string;
  to?: string;
  note?: string;
  /** Values are addresses/identifiers: render monospace. */
  mono?: boolean;
  kev?: boolean;
}

/** One change event split into the Changes table / Recent changes columns. */
export interface EventColumns {
  /** IP shown under the device; null when the device label already is that IP. */
  ip: string | null;
  /** "TCP/443", or null when the event is not about a port. */
  port: string | null;
  change: ChangeParts;
  /** The complete Change text (tooltips, exports): never truncated. */
  changeText: string;
  /** Recorded without an alert (device outside the configured networks). */
  recordedOnly: boolean;
}

type CveDetail = { cve_id?: string; port?: number; protocol?: string; state?: string; cvss?: number | null; kev?: boolean };

function cveDetail(ev: ChangeEvent): CveDetail | null {
  if (!ev.old_value) return null;
  try {
    const parsed = JSON.parse(ev.old_value) as CveDetail;
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

const portLabel = (protocol: string | null | undefined, port: number | null | undefined) =>
  port != null ? `${(protocol || 'tcp').toUpperCase()}/${port}` : null;

const clean = (v: string | null | undefined) => (v ?? '').trim() || undefined;

function changeParts(ev: ChangeEvent): ChangeParts {
  const oldV = clean(ev.old_value);
  const newV = clean(ev.new_value);
  switch (ev.event_type) {
    case 'port_opened':
      return { verb: 'opened', note: newV };
    case 'port_closed':
      return { verb: 'closed', note: oldV };
    case 'service_detected':
      return { verb: 'detected', note: newV };
    case 'service_changed':
    case 'version_changed':
    case 'banner_changed':
    case 'os_changed':
      return { from: oldV ?? '-', to: newV ?? '-' };
    case 'ip_changed':
      // The new address is the device's IP (Device column); show only where it moved from.
      return { verb: 'from', to: oldV, mono: true };
    case 'device_discovered':
      return { verb: 'first seen', note: newV && `open ${newV}` };
    case 'device_disappeared':
      return { verb: 'not detected' };
    case 'device_reappeared':
      return { verb: 'reappeared' };
    case 'tag_added':
      return { to: newV };
    case 'tag_removed':
      return { to: oldV };
    case 'watch_match':
    case 'policy_violation':
    case 'monitor_change':
      return { to: newV ?? ev.message };
    case 'geo_mismatch':
      return { to: newV ?? ev.message, note: oldV && `expected ${oldV}` };
    case 'cve_watch_match': {
      const d = cveDetail(ev);
      if (!d?.cve_id) return { to: newV ?? ev.message, mono: true };
      const note = [d.state === 'potential' ? 'potential' : 'confirmed', d.cvss != null ? `CVSS ${d.cvss}` : null]
        .filter(Boolean).join(' · ');
      return { cve: d.cve_id, note, kev: !!d.kev };
    }
    default:
      return { to: ev.message };
  }
}

/** Plain-text form of the Change parts, in reading order. */
export function changePartsText(c: ChangeParts): string {
  const text = [
    c.cve, c.verb, c.from != null ? `${c.from} → ${c.to ?? '-'}` : c.to, c.note && (c.cve ? `· ${c.note}` : c.note),
  ].filter(Boolean).join(' ');
  return c.kev ? `${text} · KEV` : text;
}

export function eventColumns(ev: ChangeEvent): EventColumns {
  const change = changeParts(ev);
  const port = ev.event_type === 'cve_watch_match'
    ? portLabel(ev.protocol ?? cveDetail(ev)?.protocol, ev.port ?? cveDetail(ev)?.port)
    : portLabel(ev.protocol, ev.port);
  return {
    ip: ev.ip && ev.ip !== ev.device_label ? ev.ip : null,
    port,
    change,
    changeText: changePartsText(change) || ev.message,
    recordedOnly: !ev.notify,
  };
}
