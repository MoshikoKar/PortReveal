// Settings > Overview: what is on, off or failing, per settings section. Also feeds the section rail's markers.
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { get } from '../../api';
import { Card, Loading } from '../../components/ui';
import type {
  DiscoverySettings, GeoSettings, LdapSettings, Network, NotificationSettings, RecipientGroup, ScheduleSettings,
  SystemStatus, User, VulnSettings, VulnStatus, WebCaptureSettings,
} from '../../types';
import { DAYS, relTime } from '../../util';

export interface SettingsStatusData {
  networks?: Network[];
  schedule?: ScheduleSettings;
  webCapture?: WebCaptureSettings;
  discovery?: DiscoverySettings;
  geo?: GeoSettings;
  vuln?: VulnSettings;
  vulnStatus?: VulnStatus;
  notifications?: NotificationSettings;
  groups?: RecipientGroup[];
  ldap?: LdapSettings;
  users?: User[];
  retention?: { days: number; domain_scan_days: number };
}

const quiet = async <T,>(path: string): Promise<T | undefined> => {
  try {
    return await get<T>(path);
  } catch {
    return undefined;
  }
};

/** Loads every section's saved state. Viewers only get the endpoints they may read. */
export function useSettingsStatus(isAdmin: boolean) {
  const [data, setData] = useState<SettingsStatusData | null>(null);
  const seq = useRef(0);
  const reload = useCallback(async () => {
    const n = ++seq.current;
    const networks = quiet<Network[]>('/networks');
    const admin = isAdmin
      ? await Promise.all([
          quiet<ScheduleSettings>('/settings/schedule'),
          quiet<WebCaptureSettings>('/settings/web-capture'),
          quiet<DiscoverySettings>('/settings/discovery'),
          quiet<GeoSettings>('/settings/geo'),
          quiet<VulnSettings>('/settings/vuln'),
          quiet<VulnStatus>('/settings/vuln/status'),
          quiet<NotificationSettings>('/settings/notifications'),
          quiet<RecipientGroup[]>('/recipient-groups'),
          quiet<LdapSettings>('/settings/ldap'),
          quiet<User[]>('/users'),
          quiet<{ days: number; domain_scan_days: number }>('/settings/retention'),
        ])
      : [];
    const [schedule, webCapture, discovery, geo, vuln, vulnStatus, notifications, groups, ldap, users, retention] = admin;
    const next = { networks: await networks, schedule, webCapture, discovery, geo, vuln, vulnStatus, notifications, groups, ldap, users, retention };
    if (n === seq.current) setData(next as SettingsStatusData);
  }, [isAdmin]);
  useEffect(() => {
    reload();
  }, [reload]);
  return { data, reload };
}

/** ok: working as set. info: a fact, not a state. off: deliberately off. warn: off or incomplete in a way that costs coverage. issue: failing. */
export type Tone = 'ok' | 'info' | 'off' | 'warn' | 'issue';
export interface SectionState {
  tone: Tone;
  /** Badge text on the overview row. */
  label: string;
  detail: string;
  /** Marker next to the section in the rail; omitted when the section is fine. */
  short?: string;
}

const dayList = (days: number[]) => (days.length === 7 ? 'every day' : days.map((d) => DAYS[d]).join(', '));
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function sectionStates(d: SettingsStatusData | null, system: SystemStatus | null): Record<string, SectionState> {
  const out: Record<string, SectionState> = {};
  if (d?.networks) {
    const live = d.networks.filter((n) => !n.archived_at);
    const on = live.filter((n) => n.enabled).length;
    const paused = live.length - on;
    out.networks = on
      ? { tone: 'ok', label: 'On', detail: `${plural(on, 'network')} scanned${paused ? `, ${paused} paused` : ''}` }
      : { tone: 'issue', label: 'None', short: 'Issue', detail: 'No enabled network, so nothing is scanned. Add or enable one under Networks.' };
  }
  const schedule = d?.schedule ?? system?.scans.schedule;
  if (schedule) {
    if (!schedule.enabled) {
      out.schedule = { tone: 'warn', label: 'Off', short: 'Off', detail: 'Networks are scanned only when someone starts a scan by hand.' };
    } else if (!schedule.days.length) {
      out.schedule = { tone: 'warn', label: 'No days', short: 'Off', detail: 'Scheduled scanning is on, but no day is selected.' };
    } else {
      const next = d?.schedule?.next_run ?? system?.scans.next_scheduled;
      out.schedule = { tone: 'ok', label: 'On', detail: `${schedule.time}, ${dayList(schedule.days)}${next ? ` · next run ${relTime(next)}` : ''}` };
    }
  }
  if (system) {
    const sc = system.scanner;
    out['scan-profiles'] = sc.mode === 'nmap'
      ? { tone: 'ok', label: 'nmap', detail: `nmap ${sc.nmap_version ?? ''}, ${sc.privileged ? 'privileged' : 'unprivileged (no OS fingerprinting)'}` }
      : sc.mode === 'mock'
        ? { tone: 'warn', label: 'Simulated', detail: 'The mock scanner is active: results are generated, not observed.' }
        : { tone: 'issue', label: 'Unavailable', short: 'Issue', detail: sc.message };

    const problems: string[] = [];
    if (system.app.status !== 'ok') problems.push(`Application status is ${system.app.status}`);
    if (!system.app.worker_running) problems.push('The scan worker is stopped');
    if (!system.app.scheduler_running) problems.push('The scheduler is stopped');
    if (!system.database.ok) problems.push(`Database: ${system.database.message}`);
    const { last_failed: failed, last_successful: okScan } = system.scans;
    if (failed && (!okScan || failed.id > okScan.id)) problems.push(`The last scan failed ${relTime(failed.finished_at)}`);
    out.health = problems.length
      ? { tone: 'issue', label: 'Problem', short: 'Issue', detail: problems.join(' · ') }
      : { tone: 'ok', label: 'OK', detail: `v${system.app.version} · last successful scan ${okScan?.finished_at ? relTime(okScan.finished_at) : 'never'}` };
  }
  if (d?.webCapture) {
    out['web-capture'] = d.webCapture.enabled
      ? { tone: 'ok', label: 'On', detail: d.webCapture.auto_after_scan ? 'Captures run after standard and full scans' : 'Manual capture jobs only' }
      : { tone: 'off', label: 'Off', short: 'Off', detail: 'No screenshots of web, RTSP, RDP or VNC interfaces are taken.' };
  }
  if (d?.discovery) {
    const src = [d.discovery.mdns && 'mDNS', d.discovery.ssdp && 'SSDP', d.discovery.netbios && 'NetBIOS'].filter(Boolean).join(', ');
    out.discovery = d.discovery.enabled
      ? { tone: 'ok', label: 'On', detail: src ? `Listening via ${src}` : 'On, but no source is selected' }
      : { tone: 'off', label: 'Off', short: 'Off', detail: 'Device names announced on the LAN are not collected.' };
  }
  if (d?.geo) {
    out.geo = d.geo.country_db_loaded
      ? { tone: 'ok', label: 'Ready', detail: 'Checks devices on networks that have expected countries' }
      : { tone: 'off', label: 'Not ready', short: 'Off', detail: d.geo.offline_mode ? 'Offline mode is on and no country database is loaded.' : 'The country database has not been downloaded yet.' };
  }
  if (d?.vuln) {
    const feeds = d.vulnStatus?.feeds ?? [];
    const failing = feeds.find((f) => f.last_error);
    const synced = feeds.filter((f) => f.last_synced_at).map((f) => f.last_synced_at as string).sort().pop();
    out.vulnerabilities = !d.vuln.enabled
      ? { tone: 'off', label: 'Off', short: 'Off', detail: 'Services are not matched against known CVEs.' }
      : failing
        ? { tone: 'issue', label: 'Feed error', short: 'Issue', detail: `${failing.source.toUpperCase()}: ${failing.last_error}` }
        : !synced
          ? { tone: 'warn', label: 'Not synced', short: 'Check', detail: 'On, but no vulnerability feed has been downloaded yet.' }
          : { tone: 'ok', label: 'On', detail: `${(d.vulnStatus?.cve_count ?? 0).toLocaleString()} CVEs cached · last sync ${relTime(synced)}` };
  }
  if (d?.notifications) {
    const groupsOn = (d.groups ?? []).filter((g) => g.enabled);
    const failing = groupsOn.find((g) => g.last_error);
    out.notifications = !d.notifications.enabled
      ? { tone: 'warn', label: 'Digest off', short: 'Off', detail: 'No daily digest email is sent.' }
      : failing
        ? { tone: 'issue', label: 'Delivery failed', short: 'Issue', detail: `${failing.name}: ${failing.last_error_friendly || failing.last_error}` }
        : { tone: 'ok', label: 'On', detail: `Digest via ${d.notifications.smtp_host} · ${plural(groupsOn.length, 'recipient group')} on` };
  }
  if (d?.ldap) {
    out.authentication = d.ldap.enabled
      ? { tone: 'ok', label: 'On', detail: 'Directory accounts can sign in; local accounts remain as a fallback' }
      : { tone: 'off', label: 'Local only', detail: 'Only local accounts can sign in.' };
  }
  if (d?.users) {
    const active = d.users.filter((u) => u.is_active);
    out.users = { tone: 'info', label: plural(active.length, 'user'), detail: `${plural(active.filter((u) => u.role === 'admin').length, 'administrator')} · ${active.filter((u) => u.role !== 'admin').length} read-only` };
  }
  if (d?.retention) {
    out.retention = { tone: 'info', label: `${d.retention.days} days`, detail: `History is kept ${d.retention.days} days, domain scans ${d.retention.domain_scan_days} days` };
  }
  return out;
}

const BADGE: Record<Tone, string> = { ok: 'ok', info: 'outline', off: 'outline', warn: 'medium', issue: 'high' };

export function SettingsOverview({ groups, states, loaded }: {
  groups: { label: string; sections: { id: string; label: string }[] }[];
  states: Record<string, SectionState>;
  loaded: boolean;
}) {
  if (!loaded) return <Loading />;
  const flat = groups.flatMap((g) => g.sections);
  const attention = flat.filter((s) => states[s.id] && (states[s.id].tone === 'warn' || states[s.id].tone === 'issue'));
  return (
    <div className="stack">
      {attention.length ? (
        <div className="alert warn overview-summary">
          <strong>{attention.length === 1 ? '1 setting needs attention' : `${attention.length} settings need attention`}</strong>
          <ul>
            {attention.map((s) => (
              <li key={s.id}><Link to={`/settings/${s.id}`}>{s.label}</Link>: {states[s.id].detail}</li>
            ))}
          </ul>
        </div>
      ) : (
        <div className="alert ok overview-summary">Scanning, alerts and the system are running as configured.</div>
      )}
      <Card title="Configuration" flush>
        {groups.map((g) => {
          const rows = g.sections.filter((s) => states[s.id]);
          if (!rows.length) return null;
          return (
            <section key={g.label} aria-label={g.label}>
              <div className="card-subhead">{g.label}</div>
              <ul className="status-list">
                {rows.map((s) => {
                  const st = states[s.id];
                  return (
                    <li key={s.id} className="status-row">
                      <Link className="status-name" to={`/settings/${s.id}`}>{s.label}</Link>
                      <span className="status-detail">{st.detail}</span>
                      <span className={`badge ${BADGE[st.tone]}`}>{st.label}</span>
                    </li>
                  );
                })}
              </ul>
            </section>
          );
        })}
      </Card>
    </div>
  );
}
