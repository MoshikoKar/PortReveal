// Schedule, scan profile, notifications, LDAP and retention forms.
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { post, put } from '../../api';
import { Card, ErrorBox, Loading, useReportDirty } from '../../components/ui';
import type { DiscoverySettings, EventType, LdapSettings, NotificationSettings, PresenceSettings, ScanSettings, ScheduleSettings, VulnSettings, VulnStatus, WebCaptureSettings } from '../../types';
import { DAYS, EVENT_LABELS, fmtTime, relTime, useApi } from '../../util';

function useForm<T>(path: string) {
  const res = useApi<T>(path);
  const [form, setForm] = useState<T | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const inFlight = useRef(false); // blocks a second click that lands before `saving` re-renders the button
  useEffect(() => {
    if (res.data) setForm(res.data);
  }, [res.data]);
  const save = async (body: unknown, okText = 'Saved.') => {
    if (inFlight.current) return false;
    inFlight.current = true;
    setSaving(true);
    setMsg(null);
    try {
      const out = await put<T>(path, body);
      res.setData(out);
      setMsg({ ok: true, text: okText });
      return true;
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
      return false;
    } finally {
      inFlight.current = false;
      setSaving(false);
    }
  };
  // Unsaved edits: the working copy differs from what the server last returned.
  const dirty = !!form && !!res.data && JSON.stringify(form) !== JSON.stringify(res.data);
  return { ...res, form, setForm, msg, setMsg, save, saving, dirty };
}

function Msg({ msg }: { msg: { ok: boolean; text: string } | null }) {
  if (!msg) return null;
  return <div className={`alert ${msg.ok ? 'ok' : 'error'}`}>{msg.text}</div>;
}

function Num({ label, value, onChange, hint, min, max }: {
  label: string; value: number; onChange: (v: number) => void; hint?: ReactNode; min?: number; max?: number;
}) {
  return (
    <label className="field">{label}
      <input type="number" value={value} min={min} max={max} onChange={(e) => onChange(Number(e.target.value))} />
      {hint && <span className="hint">{hint}</span>}
    </label>
  );
}

// ---------------------------------------------------------------- schedule
export function ScheduleForm({ onSaved, onDirtyChange }: { onSaved?: () => void; onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<ScheduleSettings>('/settings/schedule');
  useReportDirty(f.dirty, onDirtyChange);
  if (!f.form) return <Card title="Scan schedule"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  return (
    <Card title="Scan schedule">
      <div className="stack">
        <div className="muted small">
          Every enabled network is scanned once per day at this server-local time. By default a fast discovery pass
          runs first so new hosts are registered before the standard service scan. Changes apply immediately (no restart).
        </div>
        <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => f.setForm({ ...s, enabled: e.target.checked })} />Scheduled scanning enabled</label>
        <label className="check">
          <input type="checkbox" checked={s.discovery_before_standard}
            onChange={(e) => f.setForm({ ...s, discovery_before_standard: e.target.checked })} />
          Run discovery before the standard scan
        </label>
        <div className="row wrap">
          <label className="field">Time (HH:MM)<input type="time" value={s.time} onChange={(e) => f.setForm({ ...s, time: e.target.value })} /></label>
          <div className="field"><span>Days</span>
            <div className="row wrap" style={{ gap: 8 }}>
              {DAYS.map((d, i) => (
                <label className="check small" key={d}>
                  <input type="checkbox" checked={s.days.includes(i)} onChange={(e) => f.setForm({ ...s, days: e.target.checked ? [...s.days, i].sort() : s.days.filter((x) => x !== i) })} />{d}
                </label>
              ))}
            </div>
          </div>
        </div>
        <div className="muted small">Next run: {f.data?.next_run ? `${fmtTime(f.data.next_run)} (${relTime(f.data.next_run)})` : 'not scheduled'}</div>
        <Msg msg={f.msg} />
        <div><button className="btn primary" disabled={f.saving} onClick={async () => { if (await f.save({ enabled: s.enabled, time: s.time, days: s.days, discovery_before_standard: s.discovery_before_standard })) onSaved?.(); }}>Save schedule</button></div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------- presence
export function PresenceForm({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<PresenceSettings>('/settings/presence');
  useReportDirty(f.dirty, onDirtyChange);
  if (!f.form) return <Card title="Daytime presence"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  return (
    <Card title="Daytime presence">
      <div className="stack">
        <div className="muted small">
          Quick discovery-only scans during working hours (no port scan, no web capture). A device counts one absence day
          only when the night scan and every presence scan that day missed it; any sighting resets the count. Disappeared /
          reappeared emails are sent only after this many consecutive absence days.
        </div>
        <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => f.setForm({ ...s, enabled: e.target.checked })} />Presence scans and correlated absence enabled</label>
        <div className="row wrap">
          {s.times.map((t, i) => (
            <label className="field" key={i}>Presence time {i + 1} (HH:MM)
              <input type="time" value={t} onChange={(e) => f.setForm({ ...s, times: s.times.map((x, j) => (j === i ? e.target.value : x)) })} />
            </label>
          ))}
          <Num label="Absence days before email" value={s.absence_days} min={1} max={30} onChange={(v) => f.setForm({ ...s, absence_days: v })} hint="Consecutive days missed by both night and daytime scans" />
          <div className="field"><span>Days</span>
            <div className="row wrap" style={{ gap: 8 }}>
              {DAYS.map((d, i) => (
                <label className="check small" key={d}>
                  <input type="checkbox" checked={s.days.includes(i)} onChange={(e) => f.setForm({ ...s, days: e.target.checked ? [...s.days, i].sort() : s.days.filter((x) => x !== i) })} />{d}
                </label>
              ))}
            </div>
          </div>
        </div>
        <div className="muted small">Next presence scan: {f.data?.next_run ? `${fmtTime(f.data.next_run)} (${relTime(f.data.next_run)})` : 'not scheduled'}</div>
        <Msg msg={f.msg} />
        <div><button className="btn primary" disabled={f.saving} onClick={() => f.save({ enabled: s.enabled, times: s.times, days: s.days, absence_days: s.absence_days })}>Save presence</button></div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------- scan profile
export function ScanProfileForm({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<ScanSettings>('/settings/scan');
  useReportDirty(f.dirty, onDirtyChange);
  if (!f.form) return <Card title="Scan profiles"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  const set = (patch: Partial<ScanSettings>) => f.setForm({ ...s, ...patch });
  return (
    <Card title="Scan profiles">
      <div className="stack">
        <div className="grid three">
          <div className="alert"><strong>Discovery</strong><div className="muted small">nmap -sn with ARP, ICMP echo/timestamp and TCP SYN/ACK probes. Hosts that ignore ping are still found via TCP.</div></div>
          <div className="alert"><strong>Standard (daily)</strong><div className="muted small">Discovery, then the top {s.top_ports} TCP ports with safe service/version detection (-sV) on live hosts only.</div></div>
          <div className="alert"><strong>Full port scan</strong><div className="muted small">All 65,535 TCP ports with -sV. Manual only, for selected hosts, ranges or networks.</div></div>
        </div>
        <div className="muted small">No exploitation, brute force, authentication attempts or intrusive NSE scripts are ever used. Raw nmap arguments are not configurable.</div>
        <div className="form-grid">
          <Num label="Common TCP ports (standard scan)" value={s.top_ports} min={100} max={10000} onChange={(v) => set({ top_ports: v })} hint="nmap --top-ports, 100–10000" />
          <label className="field">Timing
            <select value={s.timing} onChange={(e) => set({ timing: e.target.value as ScanSettings['timing'] })}>
              <option value="polite">Polite (T2) – slowest, gentlest</option>
              <option value="normal">Normal (T3) – default</option>
              <option value="fast">Fast (T4) – reliable LANs</option>
            </select>
          </label>
          <Num label="Parallel nmap processes" value={s.parallelism} min={1} max={16} onChange={(v) => set({ parallelism: v })} hint="Upper bound on concurrent nmap processes" />
          <Num label="Discovery chunk size" value={s.discovery_chunk_size} min={16} max={16384} onChange={(v) => set({ discovery_chunk_size: v })} hint="Addresses per discovery process (/16 = 64 chunks of 1024)" />
          <Num label="Hosts per service-scan batch" value={s.port_batch_size} min={1} max={256} onChange={(v) => set({ port_batch_size: v })} />
          <Num label="Host timeout – standard (min)" value={s.host_timeout_minutes} min={1} max={240} onChange={(v) => set({ host_timeout_minutes: v })} hint="One slow host can never block the scan" />
          <Num label="Host timeout – full (min)" value={s.full_host_timeout_minutes} min={5} max={720} onChange={(v) => set({ full_host_timeout_minutes: v })} />
          <Num label="Missed scans before 'not detected'" value={s.disappear_after_missed} min={1} max={30} onChange={(v) => set({ disappear_after_missed: v })} hint="Consecutive complete scans; avoids false 'disappeared' alerts" />
          <Num label="Mass-change guard (%)" value={s.mass_change_guard_percent} min={10} max={100} onChange={(v) => set({ mass_change_guard_percent: v })} hint="Skip removals when more than this share would vanish at once" />
          <Num label="Keep raw XML (days)" value={s.raw_retention_days} min={1} max={90} onChange={(v) => set({ raw_retention_days: v })} />
          <Num label="OS refresh interval (days)" value={s.os_refresh_days} min={1} max={90} onChange={(v) => set({ os_refresh_days: v })} hint="Re-run -O only when the last guess is older than this" />
          <Num label="OS min accuracy to display as certain" value={s.os_min_accuracy_display} min={0} max={100} onChange={(v) => set({ os_min_accuracy_display: v })} hint="Below this the UI labels the guess uncertain (default 85)" />
        </div>
        {s.os_detection_enabled_notice && (
          <div className="alert ok">
            OS detection was turned on for this install (one-time migration). Full fingerprinting needs
            privileged nmap (raw sockets / NET_RAW / Npcap). You can turn it off below.
            <div style={{ marginTop: 8 }}>
              <button type="button" className="btn sm" onClick={() => f.save({ ...s, os_detection_enabled_notice: false })}>
                Dismiss notice
              </button>
            </div>
          </div>
        )}
        <div className="row wrap">
          <label className="check" title="Requires a privileged nmap (raw sockets) and sends one UDP probe to a closed port as part of the fingerprint; without privileges this is skipped automatically and the OS is guessed from service/banner data instead.">
            <input type="checkbox" checked={s.os_detection} onChange={(e) => set({ os_detection: e.target.checked })} />
            OS detection (-O, requires privileged nmap; sends one UDP probe to a closed port)
          </label>
          <label className="check"><input type="checkbox" checked={s.keep_raw_xml} onChange={(e) => set({ keep_raw_xml: e.target.checked })} />Keep raw nmap XML temporarily for troubleshooting</label>
        </div>
        <Msg msg={f.msg} />
        <div><button className="btn primary" disabled={f.saving} onClick={() => f.save(s)}>Save scan settings</button></div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------- web capture
export function WebCaptureForm({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<WebCaptureSettings>('/settings/web-capture');
  useReportDirty(f.dirty, onDirtyChange);
  if (!f.form) return <Card title="Web capture"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  const set = (patch: Partial<WebCaptureSettings>) => f.setForm({ ...s, ...patch });
  return (
    <Card title="Web capture">
      <div className="stack">
        <div className="muted small">
          Inventory enrichment for HTTP(S), RTSP, RDP and VNC UIs. Jobs can be started manually or queued
          automatically after a standard/full scan. Not a vulnerability scanner.
          HTTP needs Chromium (<code>playwright install chromium</code>); RTSP/VNC need <code>ffmpeg</code>;
          RDP needs FreeRDP (<code>wfreerdp</code> on Windows host production, <code>xfreerdp</code> in Linux Docker).
        </div>
        <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => set({ enabled: e.target.checked })} />Enable new Web Capture jobs</label>
        <label className="check">
          <input type="checkbox" checked={s.auto_after_scan} disabled={!s.enabled}
            onChange={(e) => set({ auto_after_scan: e.target.checked })} />
          Auto-capture after standard/full scans
        </label>
        <label className="check">
          <input type="checkbox" checked={s.auto_only_new_or_changed} disabled={!s.enabled || !s.auto_after_scan}
            onChange={(e) => set({ auto_only_new_or_changed: e.target.checked })} />
          Only new/changed or never-captured web hosts (recommended)
        </label>
        <div className="form-grid">
          <Num label="Max addresses per job" value={s.max_addresses} min={1} max={4096} onChange={(v) => set({ max_addresses: v })} />
          <Num label="Max web endpoints per job" value={s.max_endpoints} min={1} max={1024} onChange={(v) => set({ max_endpoints: v })} />
          <Num label="Max pages per endpoint" value={s.max_pages_per_endpoint} min={1} max={10} onChange={(v) => set({ max_pages_per_endpoint: v })} />
          <Num label="App-discovery paths" value={s.max_discovery_paths} min={0} max={200} onChange={(v) => set({ max_discovery_paths: v })} hint="When '/' is an error or a server's default page, try this many common app paths (0 = off)" />
          <Num label="Max screenshots per job" value={s.max_screenshots_per_job} min={0} max={512} onChange={(v) => set({ max_screenshots_per_job: v })} />
          <Num label="Max HTTP response (bytes)" value={s.max_response_bytes} min={8000} max={5000000} onChange={(v) => set({ max_response_bytes: v })} />
          <Num label="Max job time (min)" value={s.max_job_minutes} min={1} max={240} onChange={(v) => set({ max_job_minutes: v })} />
          <Num label="HTTP timeout (sec)" value={s.http_timeout_seconds} min={1} max={60} onChange={(v) => set({ http_timeout_seconds: v })} />
          <Num label="Browser timeout (sec)" value={s.browser_timeout_seconds} min={3} max={120} onChange={(v) => set({ browser_timeout_seconds: v })} />
          <Num label="Page settle time (sec)" value={s.page_settle_seconds} min={0} max={60} onChange={(v) => set({ page_settle_seconds: v })} hint="Max wait after load for delayed redirects and slow rendering before the screenshot; still-blank pages are skipped" />
        </div>
        <label className="field">Discovery wordlist file
          <input type="text" value={s.discovery_wordlist} placeholder="built-in list"
            onChange={(e) => set({ discovery_wordlist: e.target.value })} />
          <span className="hint">Optional path to a newline-delimited list of paths (absolute, or relative to the data dir). Leave blank for the built-in list.</span>
        </label>
        <Msg msg={f.msg} />
        <div><button className="btn primary" disabled={f.saving} onClick={() => f.save(s)}>Save Web Capture settings</button></div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------- notifications
export function NotificationsForm({ part = 'all', onSaved, onDirtyChange }: {
  part?: 'all' | 'smtp' | 'recipients'; onSaved?: () => void; onDirtyChange?: (dirty: boolean) => void;
}) {
  const f = useForm<NotificationSettings>('/settings/notifications');
  const [password, setPassword] = useState<string | null>(null);
  const [recipientsText, setRecipientsText] = useState<string | null>(null);
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [testTo, setTestTo] = useState('');
  const recipientsDirty = recipientsText !== null && recipientsText !== (f.form?.recipients ?? []).join('\n');
  useReportDirty(f.dirty || password !== null || recipientsDirty, onDirtyChange);
  if (!f.form) return <Card title="Email notifications"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  const set = (patch: Partial<NotificationSettings>) => f.setForm({ ...s, ...patch });
  const recipients = recipientsText ?? s.recipients.join('\n');

  const body = () => ({
    enabled: s.enabled, smtp_host: s.smtp_host, smtp_port: s.smtp_port, security: s.security, username: s.username,
    ...(password !== null ? { password } : {}), sender: s.sender,
    recipients: recipients.split(/[\s,;]+/).filter(Boolean), event_types: s.event_types, digest_time: s.digest_time,
  });
  const save = async () => {
    if (await f.save(body())) {
      setPassword(null);
      setRecipientsText(null);
      onSaved?.();
    }
  };
  const test = async () => {
    setTestMsg(null);
    if (!(await f.save(body(), 'Saved.'))) return;
    try {
      const r = await post<{ ok: boolean; message: string }>('/settings/notifications/test', { recipient: testTo || null });
      setTestMsg({ ok: r.ok, text: r.message });
    } catch (e: any) {
      setTestMsg({ ok: false, text: e.message });
    }
  };

  const showSmtp = part !== 'recipients';
  const showRecipients = part !== 'smtp';
  return (
    <Card title={part === 'recipients' ? 'Email recipients' : part === 'smtp' ? 'SMTP relay' : 'Email notifications'}>
      <div className="stack">
        {showSmtp && (
          <>
            <div className="muted small">Uses an internal SMTP relay (default port 25, no authentication). Sends one categorized HTML summary email per day at the configured local time.</div>
            <div className="form-grid">
              <label className="field">SMTP host / IP<input type="text" value={s.smtp_host} onChange={(e) => set({ smtp_host: e.target.value })} placeholder="smtp-relay.corp.local" /></label>
              <Num label="Port" value={s.smtp_port} min={1} max={65535} onChange={(v) => set({ smtp_port: v })} />
              <label className="field">Security
                <select value={s.security} onChange={(e) => set({ security: e.target.value as NotificationSettings['security'] })}>
                  <option value="none">None (internal relay)</option><option value="starttls">STARTTLS</option><option value="ssl">SSL/TLS</option>
                </select>
              </label>
              <label className="field">Sender<input type="text" value={s.sender} onChange={(e) => set({ sender: e.target.value })} /></label>
              <label className="field">Username (optional)<input type="text" value={s.username} onChange={(e) => set({ username: e.target.value })} autoComplete="off" /></label>
              <label className="field">Password (optional)
                <input type="password" value={password ?? ''} placeholder={s.password_set ? '•••••• (unchanged)' : ''} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
              </label>
            </div>
          </>
        )}
        {showRecipients && (
          <>
            <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => set({ enabled: e.target.checked })} />Send email notifications</label>
            <label className="field">Recipients
              <textarea rows={3} value={recipients} onChange={(e) => setRecipientsText(e.target.value)} placeholder={'it-team@corp.local\nsoc@corp.local'} />
              <span className="hint">One address per line (or comma separated).</span>
            </label>
            {part === 'all' && (
              <div className="field"><span>Notify on</span>
                <div className="row wrap" style={{ gap: 14 }}>
                  {s.available_event_types.map((t: EventType) => (
                    <label key={t} className="check small">
                      <input type="checkbox" checked={s.event_types.includes(t)} onChange={(e) => set({ event_types: e.target.checked ? [...s.event_types, t] : s.event_types.filter((x) => x !== t) })} />
                      {EVENT_LABELS[t]}
                    </label>
                  ))}
                </div>
              </div>
            )}
            {part === 'all' && (
              <div className="form-grid">
                <label className="field">Daily summary time (HH:MM)
                  <input type="time" value={s.digest_time} onChange={(e) => set({ digest_time: e.target.value })} />
                  <span className="hint">Server-local time. Pending changes since the last send are grouped into one HTML email.</span>
                </label>
              </div>
            )}
          </>
        )}
        <Msg msg={f.msg} />
        {testMsg && <div className={`alert ${testMsg.ok ? 'ok' : 'error'}`}>{testMsg.text}</div>}
        <div className="row">
          <button className="btn primary" onClick={save} disabled={f.saving}>Save</button>
          {showSmtp && (
            <>
              <input type="email" placeholder="test recipient (default: all recipients)" value={testTo} onChange={(e) => setTestTo(e.target.value)} style={{ minWidth: 260 }} />
              <button className="btn" onClick={test} disabled={!s.smtp_host || f.saving}>Save & send test email</button>
            </>
          )}
        </div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------- LDAP
export function LdapForm({ onSaved, onDirtyChange }: { onSaved?: () => void; onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<LdapSettings>('/settings/ldap');
  const [password, setPassword] = useState<string | null>(null);
  useReportDirty(f.dirty || password !== null, onDirtyChange);
  const [testUser, setTestUser] = useState('');
  const [testPass, setTestPass] = useState('');
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [testing, setTesting] = useState(false);
  if (!f.form) return <Card title="LDAP / Active Directory"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  const set = (patch: Partial<LdapSettings>) => f.setForm({ ...s, ...patch });
  const body = () => {
    const { bind_password_set: _ignored, ...rest } = s;
    void _ignored;
    return { ...rest, ...(password !== null ? { bind_password: password } : {}) };
  };
  const test = async () => {
    if (testing) return;
    setTestMsg(null);
    setTesting(true);
    try {
      const r = await post<{ ok: boolean; message: string }>('/settings/ldap/test', { ...body(), test_username: testUser || null, test_password: testPass || null });
      setTestMsg({ ok: r.ok, text: r.message });
    } catch (e: any) {
      setTestMsg({ ok: false, text: e.message });
    } finally {
      setTesting(false);
    }
  };
  return (
    <Card title="LDAP / Active Directory">
      <div className="stack">
        <div className="muted small">Optional. Local accounts always keep working as fallback administrator access. Role mapping: members of the admin group become administrators; others (or members of the viewer group, if set) become read-only viewers.</div>
        <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => set({ enabled: e.target.checked })} />Enable LDAP login</label>
        <div className="form-grid">
          <label className="field">Server URI<input type="text" value={s.server_uri} onChange={(e) => set({ server_uri: e.target.value })} placeholder="ldaps://dc01.corp.local" /></label>
          <label className="field">Bind DN (service account)<input type="text" value={s.bind_dn} onChange={(e) => set({ bind_dn: e.target.value })} placeholder="CN=svc-portreveal,OU=Service,DC=corp,DC=local" /></label>
          <label className="field">Bind password<input type="password" value={password ?? ''} placeholder={s.bind_password_set ? '•••••• (unchanged)' : ''} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" /></label>
          <label className="field">User base DN<input type="text" value={s.user_base_dn} onChange={(e) => set({ user_base_dn: e.target.value })} placeholder="OU=Users,DC=corp,DC=local" /></label>
          <label className="field">User filter<input type="text" value={s.user_filter} onChange={(e) => set({ user_filter: e.target.value })} /><span className="hint">Must contain {'{username}'}</span></label>
          <label className="field">Admin group DN<input type="text" value={s.admin_group_dn} onChange={(e) => set({ admin_group_dn: e.target.value })} placeholder="CN=PortReveal-Admins,OU=Groups,DC=corp,DC=local" /></label>
          <label className="field">Viewer group DN (optional)<input type="text" value={s.viewer_group_dn} onChange={(e) => set({ viewer_group_dn: e.target.value })} /></label>
          <Num label="Timeout (seconds)" value={s.timeout_seconds} min={1} max={60} onChange={(v) => set({ timeout_seconds: v })} />
        </div>
        <div className="row wrap">
          <label className="check"><input type="checkbox" checked={s.start_tls} onChange={(e) => set({ start_tls: e.target.checked })} />Use STARTTLS</label>
          <label className="check"><input type="checkbox" checked={s.verify_tls} onChange={(e) => set({ verify_tls: e.target.checked })} />Verify TLS certificate</label>
        </div>
        <div className="row wrap">
          <input type="text" placeholder="test username (optional)" value={testUser} onChange={(e) => setTestUser(e.target.value)} />
          <input type="password" placeholder="test password" value={testPass} onChange={(e) => setTestPass(e.target.value)} autoComplete="new-password" />
          <button className="btn" onClick={test} disabled={!s.server_uri || testing}>{testing ? 'Testing…' : 'Test connection'}</button>
        </div>
        {testMsg && <div className={`alert ${testMsg.ok ? 'ok' : 'error'}`}>{testMsg.text}</div>}
        <Msg msg={f.msg} />
        <div><button className="btn primary" disabled={f.saving} onClick={async () => { if (await f.save(body())) { setPassword(null); onSaved?.(); } }}>Save LDAP settings</button></div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------- vulnerability feed (risk scoring)
const VULN_SOURCES: { id: 'nvd' | 'kev' | 'epss'; label: string; hint: string }[] = [
  { id: 'nvd', label: 'NVD', hint: 'CVE records, CVSS and CPE matches (core source)' },
  { id: 'kev', label: 'CISA KEV', hint: 'Flags CVEs known to be exploited in the wild' },
  { id: 'epss', label: 'FIRST EPSS', hint: 'Exploitation-probability score, used to weight risk' },
];

const VULN_STATUS_POLL_RUNNING_MS = 5000;
const VULN_STATUS_POLL_IDLE_MS = 60000;

function VulnFeedStatusPanel({ status }: { status: VulnStatus | null }) {
  if (!status) return null;
  const label = (id: string) => VULN_SOURCES.find((s) => s.id === id)?.label ?? id;
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="row wrap small" style={{ gap: 12 }}>
        <span><strong>Local CVE cache:</strong> {status.cve_count.toLocaleString()} CVEs</span>
        {status.sync_running ? <span className="badge medium">sync running</span> : <span className="badge outline">idle</span>}
      </div>
      {!status.feeds.length ? (
        <div className="muted small">No feed has been synced yet.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Feed</th><th>Last successful sync</th><th className="right">Records</th><th>Status</th></tr></thead>
            <tbody>
              {status.feeds.map((fd) => (
                <tr key={fd.source}>
                  <td>{label(fd.source)}</td>
                  <td title={fd.last_synced_at ? fmtTime(fd.last_synced_at) : undefined}>
                    {fd.last_synced_at ? relTime(fd.last_synced_at) : <span className="muted">never</span>}
                  </td>
                  <td className="right">{fd.record_count.toLocaleString()}</td>
                  <td className="small">
                    {fd.source === 'nvd' && fd.mirror_complete === false && (
                      <div>Yearly mirror in progress: next year {fd.mirror_next_year ?? status.mirror_start_year}</div>
                    )}
                    {fd.last_error ? <><span className="badge high">error</span> <span className="muted">{fd.last_error}</span></> : <span className="badge ok">ok</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function VulnForm({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<VulnSettings>('/settings/vuln');
  const [apiKey, setApiKey] = useState<string | null>(null);
  useReportDirty(f.dirty || apiKey !== null, onDirtyChange);
  const [syncMsg, setSyncMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [statusPoll, setStatusPoll] = useState(VULN_STATUS_POLL_IDLE_MS);
  const status = useApi<VulnStatus>('/settings/vuln/status', undefined, statusPoll);
  // Keep last good status while a poll is in flight so a refresh does not flash "idle".
  const [stickyStatus, setStickyStatus] = useState<VulnStatus | null>(null);
  useEffect(() => {
    if (status.data) setStickyStatus(status.data);
  }, [status.data]);
  const viewStatus = status.data ?? stickyStatus;
  const running = !!viewStatus?.sync_running;
  useEffect(() => {
    setStatusPoll(running ? VULN_STATUS_POLL_RUNNING_MS : VULN_STATUS_POLL_IDLE_MS);
  }, [running]);
  if (!f.form) return <Card title="Vulnerability scoring"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  const set = (patch: Partial<VulnSettings>) => f.setForm({ ...s, ...patch });
  const body = () => {
    const { nvd_api_key_set: _ignored, ...rest } = s;
    void _ignored;
    return { ...rest, ...(apiKey !== null ? { nvd_api_key: apiKey } : {}) };
  };
  const save = async () => {
    if (await f.save(body())) setApiKey(null);
  };
  const syncNow = async () => {
    if (syncing) return;
    setSyncing(true);
    setSyncMsg(null);
    try {
      const r = await post<{ ok: boolean; message: string }>('/settings/vuln/sync');
      setSyncMsg({ ok: r.ok, text: r.message });
      status.reload();
    } catch (e: any) {
      setSyncMsg({ ok: false, text: e.message });
    } finally {
      setSyncing(false);
    }
  };
  return (
    <Card title="Vulnerability scoring">
      <div className="stack">
        <div className="muted small">
          Risk scoring matches each device's identified product/version (CPE) against a local cache of known
          vulnerabilities. Off by default. No information about this network is ever sent out — only a plain
          HTTP download of public NVD / CISA KEV / FIRST EPSS data files, on a weekly schedule. Works fully
          without an NVD API key; adding one only raises the request rate limit.
        </div>
        <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => set({ enabled: e.target.checked })} />Enable vulnerability risk scoring</label>
        <div className="field"><span>Sources</span>
          <div className="row wrap" style={{ gap: 14 }}>
            {VULN_SOURCES.map((src) => (
              <label key={src.id} className="check small" title={src.hint}>
                <input type="checkbox" checked={s.sources.includes(src.id)} disabled={!s.enabled}
                  onChange={(e) => set({ sources: e.target.checked ? [...s.sources, src.id] : s.sources.filter((x) => x !== src.id) })} />
                {src.label}
              </label>
            ))}
          </div>
        </div>
        <div className="form-grid">
          <Num label="Sync interval (hours)" value={s.sync_interval_hours} min={24} max={720} onChange={(v) => set({ sync_interval_hours: v })} hint="Default 168 = weekly" />
          <label className="field">Sync time (HH:MM)<input type="time" value={s.sync_time} onChange={(e) => set({ sync_time: e.target.value })} /></label>
          <label className="field">NVD API key (optional)
            <input type="password" value={apiKey ?? ''} placeholder={s.nvd_api_key_set ? '•••••• (unchanged)' : 'not set — public rate limit applies'}
              onChange={(e) => setApiKey(e.target.value)} autoComplete="new-password" />
          </label>
          <Num label="Min CVSS to display" value={s.min_cvss_display} min={0} max={10} onChange={(v) => set({ min_cvss_display: v })} />
          <Num label="EPSS high-probability threshold" value={s.epss_high_threshold} min={0} max={1} onChange={(v) => set({ epss_high_threshold: v })}
            hint="EPSS score (0-1) above which a finding counts as high exploitation probability" />
        </div>
        <div className="row wrap">
          <label className="check"><input type="checkbox" checked={s.offline_mode} onChange={(e) => set({ offline_mode: e.target.checked })} />Offline mode (no feed downloads; import with <code>npm run cli -- vuln-import PATH</code>)</label>
          <label className="check"><input type="checkbox" checked={s.include_potential} onChange={(e) => set({ include_potential: e.target.checked })} />Show "potential" matches (imprecise version), not just confirmed</label>
          <label className="check" title="Safe/discovery nmap scripts only (SCRIPT_ALLOWLIST) — never vulners, never intrusive categories">
            <input type="checkbox" checked={s.scripts_enabled} onChange={(e) => set({ scripts_enabled: e.target.checked })} />
            Run allow-listed nmap scripts as a secondary signal
          </label>
        </div>
        <Msg msg={f.msg} />
        <VulnFeedStatusPanel status={viewStatus} />
        {running && (
          <div className="muted small">
            First-time NVD import downloads several years of public CVE feeds in the background.
            Refreshing the page is safe — it does not cancel the sync. Leave this tab open or come back later;
            progress updates every few seconds.
          </div>
        )}
        {syncMsg && <div className={`alert ${syncMsg.ok ? 'ok' : 'error'}`}>{syncMsg.text}</div>}
        <div className="row">
          <button className="btn primary" disabled={f.saving} onClick={save}>Save</button>
          <button className="btn" onClick={syncNow} disabled={!s.enabled || s.offline_mode || syncing || running}
            title="Download the public NVD / CISA KEV / FIRST EPSS feeds into the local cache now">
            {syncing ? 'Starting…' : running ? 'Sync running…' : 'Sync feeds now'}
          </button>
        </div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------- local discovery (mDNS/SSDP/NetBIOS)
export function DiscoveryForm({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<DiscoverySettings>('/settings/discovery');
  useReportDirty(f.dirty, onDirtyChange);
  if (!f.form) return <Card title="Local device-name discovery"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  const set = (patch: Partial<DiscoverySettings>) => f.setForm({ ...s, ...patch });
  return (
    <Card title="Local device-name discovery">
      <div className="stack">
        <div className="muted small">
          A local-only, LAN-bound channel that strengthens device-type classification with names
          devices already announce. Default on is only the cheap passive path: mDNS/Bonjour listen.
          SSDP/UPnP (one multicast M-SEARCH) and NetBIOS (short unicast queries, rotated across
          large inventories) are opt-in. Nothing ever leaves the LAN, and this never runs an nmap
          UDP scan (<code>-sU</code> stays banned everywhere else). Heard names persist and age
          out instead of being cleared when a single pass misses a host.
        </div>
        <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => set({ enabled: e.target.checked })} />Enable local discovery</label>
        <div className="row wrap">
          <label className="check small"><input type="checkbox" checked={s.mdns} disabled={!s.enabled} onChange={(e) => set({ mdns: e.target.checked })} />mDNS / Bonjour (passive)</label>
          <label className="check small"><input type="checkbox" checked={s.ssdp} disabled={!s.enabled} onChange={(e) => set({ ssdp: e.target.checked })} />SSDP / UPnP (active M-SEARCH)</label>
          <label className="check small"><input type="checkbox" checked={s.netbios} disabled={!s.enabled} onChange={(e) => set({ netbios: e.target.checked })} />NetBIOS (active queries)</label>
        </div>
        <Num label="Timeout per source (seconds)" value={s.timeout_seconds} min={0.5} max={15}
          onChange={(v) => set({ timeout_seconds: v })} hint="mDNS/SSDP listen window; NetBIOS uses a shorter fixed window" />
        <Msg msg={f.msg} />
        <div><button className="btn primary" disabled={f.saving} onClick={() => f.save(s)}>Save</button></div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------- retention
export function RetentionForm({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<{ days: number }>('/settings/retention');
  useReportDirty(f.dirty, onDirtyChange);
  const [runMsg, setRunMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [running, setRunning] = useState(false);
  if (!f.form) return <Card title="Retention"><ErrorBox error={f.error} /><Loading /></Card>;
  const savedDays = f.data?.days ?? f.form.days;
  const runCleanup = async () => {
    if (running) return;
    const unsaved = f.form && f.form.days !== savedDays ? ` (the unsaved value of ${f.form.days} days is not used)` : '';
    if (!confirm(
      `Run the retention cleanup now?\n\nThis permanently deletes events, scans, daily snapshots and audit log entries older than ${savedDays} days, `
      + `and forgets devices not seen in that period${unsaved}. This cannot be undone.`,
    )) return;
    setRunMsg(null);
    setRunning(true);
    try {
      const r = await post<{ deleted: Record<string, number> }>('/settings/retention/run');
      setRunMsg({ ok: true, text: `Cleanup done: ${Object.entries(r.deleted).map(([k, v]) => `${v} ${k}`).join(', ')}` });
    } catch (e: any) {
      setRunMsg({ ok: false, text: `Cleanup failed: ${e.message}` });
    } finally {
      setRunning(false);
    }
  };
  return (
    <Card title="Retention">
      <div className="stack">
        <div className="muted small">
          History (events, scans, daily snapshots, audit log) older than this is deleted by a daily cleanup at 03:15. Devices not seen for the
          whole period are forgotten. Raw nmap XML is never kept long-term.
        </div>
        <div className="row wrap">
          <Num label="Keep history (days)" value={f.form.days} min={7} max={3650} onChange={(v) => f.setForm({ days: v })} />
        </div>
        <Msg msg={f.msg} />
        <Msg msg={runMsg} />
        <div className="row">
          <button className="btn primary" disabled={f.saving} onClick={() => f.save(f.form)}>Save</button>
          <button className="btn danger" onClick={runCleanup} disabled={running}>{running ? 'Cleaning up…' : 'Run cleanup now'}</button>
        </div>
      </div>
    </Card>
  );
}
