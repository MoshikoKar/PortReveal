// Schedule, scan profile, notifications, LDAP and retention forms.
import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { Link } from 'react-router-dom';
import { post, put } from '../../api';
import { Card, ErrorBox, Loading, useReportDirty } from '../../components/ui';
import { keyPayload, keyPlaceholder } from '../../domains';
import type { CdnAsnEntry, DiscoverySettings, DomainDiscoverySettings, GeoSettings, LdapSettings, NotificationSettings, PresenceSettings, ScanSettings, ScheduleSettings, VulnSettings, VulnStatus, WebCaptureSettings, WordlistLibrary } from '../../types';
import { DAYS, fmtTime, relTime, useApi } from '../../util';
import { discoveryOptions, effectiveSelection } from '../../wordlists';
import { Field, Num, SaveBar, SettingsForm, savedMsg, useRefreshSettingsStatus, type SaveMsg } from './formKit';

function useForm<T>(path: string) {
  const res = useApi<T>(path);
  const refreshStatus = useRefreshSettingsStatus();
  const [form, setForm] = useState<T | null>(null);
  const [msg, setMsg] = useState<SaveMsg>(null);
  const [saving, setSaving] = useState(false);
  const inFlight = useRef(false); // blocks a second click that lands before `saving` re-renders the button
  useEffect(() => {
    if (res.data) setForm(res.data);
  }, [res.data]);
  const save = async (body: unknown, okText?: string) => {
    if (inFlight.current) return false;
    inFlight.current = true;
    setSaving(true);
    setMsg(null);
    try {
      const out = await put<T>(path, body);
      res.setData(out);
      setMsg(okText ? { ok: true, text: okText } : savedMsg());
      refreshStatus();
      return true;
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
      return false;
    } finally {
      inFlight.current = false;
      setSaving(false);
    }
  };
  const revert = () => {
    if (res.data) setForm(res.data);
  };
  // Unsaved edits: the working copy differs from what the server last returned.
  const dirty = !!form && !!res.data && JSON.stringify(form) !== JSON.stringify(res.data);
  return { ...res, form, setForm, msg, setMsg, save, saving, dirty, revert };
}

/** Setup wizard only; Settings forms report through the SaveBar. */
function Msg({ msg }: { msg: SaveMsg }) {
  if (!msg) return null;
  return <div className={`alert ${msg.ok ? 'ok' : 'error'}`} role={msg.ok ? 'status' : 'alert'}>{msg.text}</div>;
}

function DayPicker({ days, onChange }: { days: number[]; onChange: (days: number[]) => void }) {
  return (
    <fieldset className="field">
      <legend>Days</legend>
      <div className="row wrap" style={{ gap: 8 }}>
        {DAYS.map((d, i) => (
          <label className="check small" key={d}>
            <input type="checkbox" checked={days.includes(i)} onChange={(e) => onChange(e.target.checked ? [...days, i].sort() : days.filter((x) => x !== i))} />{d}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

// ---------------------------------------------------------------- schedule
export function ScheduleForm({ onSaved, onDirtyChange }: { onSaved?: () => void; onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<ScheduleSettings>('/settings/schedule');
  useReportDirty(f.dirty, onDirtyChange);
  if (!f.form) return <Card title="Scan schedule"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  const save = async () => { if (await f.save({ enabled: s.enabled, time: s.time, days: s.days, discovery_before_standard: s.discovery_before_standard })) onSaved?.(); };
  return (
    <Card title="Scan schedule">
      <SettingsForm onSave={save}>
        <div className="muted small measure">
          Every enabled network is scanned once per day at this server-local time. By default a fast discovery pass
          runs first so new hosts are registered before the standard service scan. Changes apply as soon as they are saved (no restart).
        </div>
        <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => f.setForm({ ...s, enabled: e.target.checked })} />Scheduled scanning enabled</label>
        <label className="check">
          <input type="checkbox" checked={s.discovery_before_standard}
            onChange={(e) => f.setForm({ ...s, discovery_before_standard: e.target.checked })} />
          Run discovery before the standard scan
        </label>
        <div className="row wrap" style={{ alignItems: 'flex-start' }}>
          <Field label="Time (HH:MM)">{(p) => <input {...p} type="time" value={s.time} onChange={(e) => f.setForm({ ...s, time: e.target.value })} />}</Field>
          <DayPicker days={s.days} onChange={(days) => f.setForm({ ...s, days })} />
        </div>
        {f.data && !f.data.enabled ? (
          <div className="alert warn">
            Scheduled scanning is off. Networks are scanned only when someone starts a scan by hand, so changes are not detected on their own.
          </div>
        ) : (
          <div className="muted small">Next run: {f.data?.next_run ? `${fmtTime(f.data.next_run)} (${relTime(f.data.next_run)})` : 'not scheduled (no days selected)'}</div>
        )}
        <SaveBar dirty={f.dirty} saving={f.saving} msg={f.msg} onRevert={f.revert} alwaysEnabled={!!onSaved} />
      </SettingsForm>
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
      <SettingsForm onSave={() => f.save({ enabled: s.enabled, times: s.times, days: s.days, absence_days: s.absence_days })}>
        <div className="muted small measure">
          Quick discovery-only scans during working hours (no port scan, no web capture). A device counts one absence day
          only when the night scan and every presence scan that day missed it; any sighting resets the count. Disappeared /
          reappeared emails are sent only after this many consecutive absence days.
        </div>
        <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => f.setForm({ ...s, enabled: e.target.checked })} />Presence scans and correlated absence enabled</label>
        <div className="form-grid">
          {s.times.map((t, i) => (
            <Field key={i} label={`Presence time ${i + 1} (HH:MM)`}>
              {(p) => <input {...p} type="time" value={t} onChange={(e) => f.setForm({ ...s, times: s.times.map((x, j) => (j === i ? e.target.value : x)) })} />}
            </Field>
          ))}
          <Num label="Absence days before email" value={s.absence_days} min={1} max={30} onChange={(v) => f.setForm({ ...s, absence_days: v })} hint="Consecutive days missed by both night and daytime scans" />
          <DayPicker days={s.days} onChange={(days) => f.setForm({ ...s, days })} />
        </div>
        <div className="muted small">Next presence scan: {f.data?.next_run ? `${fmtTime(f.data.next_run)} (${relTime(f.data.next_run)})` : 'not scheduled'}</div>
        <SaveBar dirty={f.dirty} saving={f.saving} msg={f.msg} onRevert={f.revert} />
      </SettingsForm>
    </Card>
  );
}

// ---------------------------------------------------------------- scan profile
export function ScanProfileForm({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<ScanSettings>('/settings/scan');
  useReportDirty(f.dirty, onDirtyChange);
  if (!f.form) return <Card title="Scanner tuning"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  const set = (patch: Partial<ScanSettings>) => f.setForm({ ...s, ...patch });
  return (
    <Card title="Scanner tuning">
      <SettingsForm onSave={() => f.save(s)}>
        <dl className="profile-defs">
          <div><dt>Discovery</dt><dd>nmap -sn with ARP, ICMP echo/timestamp and TCP SYN/ACK probes. Hosts that ignore ping are still found via TCP.</dd></div>
          <div><dt>Standard (daily)</dt><dd>Discovery, then the top {s.top_ports} TCP ports with safe service/version detection (-sV) on live hosts only.</dd></div>
          <div><dt>Full port scan</dt><dd>All 65,535 TCP ports with -sV. Manual only, for selected hosts, ranges or networks.</dd></div>
        </dl>
        <div className="muted small">No exploitation, brute force, authentication attempts or intrusive NSE scripts are ever used. Raw nmap arguments are not configurable.</div>

        <fieldset className="settings-group">
          <legend>Coverage and speed</legend>
          <div className="form-grid">
            <Num label="Common TCP ports (standard scan)" value={s.top_ports} min={100} max={10000} onChange={(v) => set({ top_ports: v })} hint="nmap --top-ports, 100-10000" />
            <Field label="Timing">
              {(p) => (
                <select {...p} value={s.timing} onChange={(e) => set({ timing: e.target.value as ScanSettings['timing'] })}>
                  <option value="polite">Polite (T2) - slowest, gentlest</option>
                  <option value="normal">Normal (T3) - default</option>
                  <option value="fast">Fast (T4) - reliable LANs</option>
                </select>
              )}
            </Field>
            <Num label="Parallel nmap processes" value={s.parallelism} min={1} max={16} onChange={(v) => set({ parallelism: v })} hint="Upper bound on concurrent nmap processes" />
          </div>
        </fieldset>

        <fieldset className="settings-group">
          <legend>Change detection</legend>
          <div className="form-grid">
            <Num label="Missed scans before 'not detected'" value={s.disappear_after_missed} min={1} max={30} onChange={(v) => set({ disappear_after_missed: v })} hint="Consecutive complete scans; avoids false 'disappeared' alerts" />
            <Num label="Mass-change guard (%)" value={s.mass_change_guard_percent} min={10} max={100} onChange={(v) => set({ mass_change_guard_percent: v })} hint="Skip removals when more than this share would vanish at once" />
          </div>
        </fieldset>

        <fieldset className="settings-group">
          <legend>OS detection</legend>
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
          <label className="check" title="Requires a privileged nmap (raw sockets) and sends one UDP probe to a closed port as part of the fingerprint; without privileges this is skipped automatically and the OS is guessed from service/banner data instead.">
            <input type="checkbox" checked={s.os_detection} onChange={(e) => set({ os_detection: e.target.checked })} />
            OS detection (-O, requires privileged nmap; sends one UDP probe to a closed port)
          </label>
          <div className="form-grid">
            <Num label="OS refresh interval (days)" value={s.os_refresh_days} min={1} max={90} disabled={!s.os_detection} onChange={(v) => set({ os_refresh_days: v })} hint="Re-run -O only when the last guess is older than this" />
            <Num label="OS min accuracy to display as certain" value={s.os_min_accuracy_display} min={0} max={100} onChange={(v) => set({ os_min_accuracy_display: v })} hint="Below this the UI labels the guess uncertain (default 85)" />
          </div>
        </fieldset>

        <details className="settings-advanced">
          <summary>Advanced tuning</summary>
          <div className="stack">
            <div className="form-grid">
              <Num label="Discovery chunk size" value={s.discovery_chunk_size} min={16} max={16384} onChange={(v) => set({ discovery_chunk_size: v })} hint="Addresses per discovery process (/16 = 64 chunks of 1024)" />
              <Num label="Hosts per service-scan batch" value={s.port_batch_size} min={1} max={256} onChange={(v) => set({ port_batch_size: v })} />
              <Num label="Host timeout - standard (min)" value={s.host_timeout_minutes} min={1} max={240} onChange={(v) => set({ host_timeout_minutes: v })} hint="One slow host can never block the scan" />
              <Num label="Host timeout - full (min)" value={s.full_host_timeout_minutes} min={5} max={720} onChange={(v) => set({ full_host_timeout_minutes: v })} />
            </div>
            <label className="check"><input type="checkbox" checked={s.keep_raw_xml} onChange={(e) => set({ keep_raw_xml: e.target.checked })} />Keep raw nmap XML temporarily for troubleshooting</label>
            <div className="form-grid">
              <Num label="Keep raw XML (days)" value={s.raw_retention_days} min={1} max={90} disabled={!s.keep_raw_xml} onChange={(v) => set({ raw_retention_days: v })} />
            </div>
          </div>
        </details>
        <SaveBar dirty={f.dirty} saving={f.saving} msg={f.msg} onRevert={f.revert} />
      </SettingsForm>
    </Card>
  );
}

// ---------------------------------------------------------------- web capture
export function WebCaptureForm({ onDirtyChange, wordlists = null }: {
  onDirtyChange?: (dirty: boolean) => void; wordlists?: WordlistLibrary | null;
}) {
  const f = useForm<WebCaptureSettings>('/settings/web-capture');
  useReportDirty(f.dirty, onDirtyChange);
  if (!f.form) return <Card title="Web capture"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  const set = (patch: Partial<WebCaptureSettings>) => f.setForm({ ...s, ...patch });
  // Lists deleted since this form loaded are dropped; with none left it shows (and saves) the built-in list.
  const sel = effectiveSelection({ builtin: s.discovery_builtin, ids: s.discovery_wordlist_ids }, wordlists);
  const selCount = (sel.builtin ? 1 : 0) + sel.ids.length;
  const toggleList = (id: number | null, on: boolean) => set(id == null
    ? { discovery_builtin: on, discovery_wordlist_ids: sel.ids }
    : { discovery_builtin: sel.builtin, discovery_wordlist_ids: on ? [...sel.ids, id] : sel.ids.filter((i) => i !== id) });
  return (
    <Card title="Web capture">
      <SettingsForm onSave={() => f.save({ ...s, discovery_builtin: sel.builtin, discovery_wordlist_ids: sel.ids })}>
        <div className="muted small measure">
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

        <fieldset className="settings-group">
          <legend>Limits per job</legend>
          <div className="form-grid">
            <Num label="Max addresses per job" value={s.max_addresses} min={1} max={4096} onChange={(v) => set({ max_addresses: v })} />
            <Num label="Max web endpoints per job" value={s.max_endpoints} min={1} max={1024} onChange={(v) => set({ max_endpoints: v })} />
            <Num label="Max pages per endpoint" value={s.max_pages_per_endpoint} min={1} max={10} onChange={(v) => set({ max_pages_per_endpoint: v })} />
            <Num label="Max screenshots per job" value={s.max_screenshots_per_job} min={0} max={512} onChange={(v) => set({ max_screenshots_per_job: v })} />
            <Num label="Max job time (min)" value={s.max_job_minutes} min={1} max={240} onChange={(v) => set({ max_job_minutes: v })} />
          </div>
        </fieldset>

        <fieldset className="settings-group">
          <legend>App discovery</legend>
          <div className="form-grid">
            <Num label="App-discovery paths" value={s.max_discovery_paths} min={0} max={500} onChange={(v) => set({ max_discovery_paths: v })} hint="When '/' is an error or a server's default page, try this many paths from the selected discovery wordlists (0 = off; max 500)" />
          </div>
          <div className="field" role="group" aria-labelledby="discovery-wordlists-label" aria-describedby="discovery-wordlists-hint">
            <span id="discovery-wordlists-label">Discovery wordlists</span>
            <div className="row wrap" style={{ gap: '0 16px' }}>
              {discoveryOptions(wordlists).map((o) => {
                const on = o.id == null ? sel.builtin : sel.ids.includes(o.id);
                return (
                  <label key={o.id ?? 'builtin'} className="check">
                    <input type="checkbox" checked={on} disabled={on && selCount === 1}
                      onChange={(e) => toggleList(o.id, e.target.checked)} />
                    {o.label}
                  </label>
                );
              })}
            </div>
            <span className="hint measure" id="discovery-wordlists-hint">
              Paths tried by app discovery (max 500 per endpoint). Several lists are merged in turn (built-in first),
              so each one contributes to the first App-discovery paths tried. Longer path lists are kept, but only
              their first 500 entries are candidates. Upload and manage lists under <Link to="/settings/wordlists">Wordlists</Link>.
            </span>
          </div>
        </fieldset>

        <details className="settings-advanced">
          <summary>Advanced tuning</summary>
          <div className="form-grid">
            <Num label="Max HTTP response (bytes)" value={s.max_response_bytes} min={8000} max={5000000} onChange={(v) => set({ max_response_bytes: v })} />
            <Num label="HTTP timeout (sec)" value={s.http_timeout_seconds} min={1} max={60} onChange={(v) => set({ http_timeout_seconds: v })} />
            <Num label="Browser timeout (sec)" value={s.browser_timeout_seconds} min={3} max={120} onChange={(v) => set({ browser_timeout_seconds: v })} />
            <Num label="Page settle time (sec)" value={s.page_settle_seconds} min={0} max={60} onChange={(v) => set({ page_settle_seconds: v })} hint="Max wait after load for delayed redirects and slow rendering before the screenshot; still-blank pages are skipped" />
          </div>
        </details>
        <SaveBar dirty={f.dirty} saving={f.saving} msg={f.msg} onRevert={f.revert} />
      </SettingsForm>
    </Card>
  );
}

// ---------------------------------------------------------------- notifications (Setup wizard only)
/** SMTP / recipients steps in the Setup wizard. Full notification settings live under Settings > Notifications. */
export function NotificationsForm({ part = 'smtp', onSaved, onDirtyChange }: {
  part?: 'smtp' | 'recipients'; onSaved?: () => void; onDirtyChange?: (dirty: boolean) => void;
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

  const body = () => (part === 'smtp'
    ? {
        smtp_host: s.smtp_host, smtp_port: s.smtp_port, security: s.security, username: s.username,
        ...(password !== null ? { password } : {}), sender: s.sender,
      }
    : {
        enabled: s.enabled,
        recipients: recipients.split(/[\s,;]+/).filter(Boolean),
      });
  const save = async () => {
    if (await f.save(body(), 'Saved.')) {
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

  return (
    <Card title={part === 'recipients' ? 'Email recipients' : 'SMTP relay'}>
      <div className="stack">
        {part === 'smtp' && (
          <>
            <div className="muted small">Uses an internal SMTP relay (default port 25, no authentication). Sends one categorized HTML summary email per day at the configured local time.</div>
            <div className="form-grid">
              <label className="field">SMTP host / IP<input type="text" value={s.smtp_host} onChange={(e) => set({ smtp_host: e.target.value })} placeholder="smtp-relay.example.com" /></label>
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
        {part === 'recipients' && (
          <>
            <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => set({ enabled: e.target.checked })} />Send email notifications</label>
            <Field label="Recipients" hint="One address per line (or comma separated).">
              {(p) => <textarea {...p} rows={3} value={recipients} onChange={(e) => setRecipientsText(e.target.value)} placeholder={'it-team@example.com\nsoc@example.com'} />}
            </Field>
          </>
        )}
        <Msg msg={f.msg} />
        {testMsg && <div className={`alert ${testMsg.ok ? 'ok' : 'error'}`} role="status">{testMsg.text}</div>}
        <div className="row">
          <button className="btn primary" onClick={save} disabled={f.saving}>Save</button>
          {part === 'smtp' && (
            <>
              <input type="email" aria-label="Test recipient" placeholder="test recipient (default: all recipients)" value={testTo} onChange={(e) => setTestTo(e.target.value)} style={{ minWidth: 260 }} />
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
  // Enter in the test fields runs the test, not the form's Save.
  const testOnEnter = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    if (s.server_uri) test();
  };
  const save = async () => { if (await f.save(body())) { setPassword(null); onSaved?.(); } };
  return (
    <Card title="LDAP / Active Directory">
      <SettingsForm onSave={save}>
        <div className="muted small measure">Optional. Local accounts always keep working as fallback administrator access. Role mapping: members of the admin group become administrators; others (or members of the viewer group, if set) become read-only viewers.</div>
        <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => set({ enabled: e.target.checked })} />Enable LDAP login</label>
        <div className="form-grid">
          <Field label="Server URI">{(p) => <input {...p} type="text" value={s.server_uri} onChange={(e) => set({ server_uri: e.target.value })} placeholder="ldaps://dc01.corp.local" />}</Field>
          <Field label="Bind DN (service account)">{(p) => <input {...p} type="text" value={s.bind_dn} onChange={(e) => set({ bind_dn: e.target.value })} placeholder="CN=svc-portreveal,OU=Service,DC=corp,DC=local" />}</Field>
          <Field label="Bind password">{(p) => <input {...p} type="password" value={password ?? ''} placeholder={s.bind_password_set ? '•••••• (unchanged)' : ''} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />}</Field>
          <Field label="User base DN">{(p) => <input {...p} type="text" value={s.user_base_dn} onChange={(e) => set({ user_base_dn: e.target.value })} placeholder="OU=Users,DC=corp,DC=local" />}</Field>
          <Field label="User filter" hint={<>Must contain {'{username}'}</>}>{(p) => <input {...p} type="text" value={s.user_filter} onChange={(e) => set({ user_filter: e.target.value })} />}</Field>
          <Field label="Admin group DN">{(p) => <input {...p} type="text" value={s.admin_group_dn} onChange={(e) => set({ admin_group_dn: e.target.value })} placeholder="CN=PortReveal-Admins,OU=Groups,DC=corp,DC=local" />}</Field>
          <Field label="Viewer group DN (optional)">{(p) => <input {...p} type="text" value={s.viewer_group_dn} onChange={(e) => set({ viewer_group_dn: e.target.value })} />}</Field>
          <Num label="Timeout (seconds)" value={s.timeout_seconds} min={1} max={60} onChange={(v) => set({ timeout_seconds: v })} />
        </div>
        <div className="row wrap">
          <label className="check"><input type="checkbox" checked={s.start_tls} onChange={(e) => set({ start_tls: e.target.checked })} />Use STARTTLS</label>
          <label className="check"><input type="checkbox" checked={s.verify_tls} onChange={(e) => set({ verify_tls: e.target.checked })} />Verify TLS certificate</label>
        </div>
        <fieldset className="settings-group">
          <legend>Test with the values above (nothing is saved)</legend>
          <div className="row wrap">
            <input type="text" aria-label="Test username (optional)" placeholder="test username (optional)" value={testUser} onChange={(e) => setTestUser(e.target.value)} onKeyDown={testOnEnter} />
            <input type="password" aria-label="Test password" placeholder="test password" value={testPass} onChange={(e) => setTestPass(e.target.value)} onKeyDown={testOnEnter} autoComplete="new-password" />
            <button type="button" className="btn" onClick={test} disabled={!s.server_uri || testing}>{testing ? 'Testing…' : 'Test connection'}</button>
          </div>
          {testMsg && <div className={`alert ${testMsg.ok ? 'ok' : 'error'}`} role="status">{testMsg.text}</div>}
        </fieldset>
        <SaveBar dirty={f.dirty || password !== null} saving={f.saving} msg={f.msg} alwaysEnabled={!!onSaved}
          onRevert={() => { f.revert(); setPassword(null); }} />
      </SettingsForm>
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
      <SettingsForm onSave={save}>
        <div className="muted small measure">
          Risk scoring matches each device's identified product/version (CPE) against a local cache of known
          vulnerabilities. Off by default. No information about this network is ever sent out - only a plain
          HTTP download of public NVD / CISA KEV / FIRST EPSS data files, on a weekly schedule. Works fully
          without an NVD API key; adding one only raises the request rate limit.
        </div>
        <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => set({ enabled: e.target.checked })} />Enable vulnerability risk scoring</label>
        <fieldset className="field">
          <legend>Sources</legend>
          <div className="row wrap" style={{ gap: 14 }}>
            {VULN_SOURCES.map((src) => (
              <label key={src.id} className="check small" title={src.hint}>
                <input type="checkbox" checked={s.sources.includes(src.id)} disabled={!s.enabled}
                  onChange={(e) => set({ sources: e.target.checked ? [...s.sources, src.id] : s.sources.filter((x) => x !== src.id) })} />
                {src.label}
              </label>
            ))}
          </div>
        </fieldset>
        <div className="form-grid">
          <Num label="Sync interval (hours)" value={s.sync_interval_hours} min={24} max={720} onChange={(v) => set({ sync_interval_hours: v })} hint="Default 168 = weekly" />
          <Field label="Sync time (HH:MM)">{(p) => <input {...p} type="time" value={s.sync_time} onChange={(e) => set({ sync_time: e.target.value })} />}</Field>
          <Field label="NVD API key (optional)">
            {(p) => (
              <input {...p} type="password" value={apiKey ?? ''} placeholder={s.nvd_api_key_set ? '•••••• (unchanged)' : 'not set - public rate limit applies'}
                onChange={(e) => setApiKey(e.target.value)} autoComplete="new-password" />
            )}
          </Field>
          <Num label="Min CVSS to display" value={s.min_cvss_display} min={0} max={10} onChange={(v) => set({ min_cvss_display: v })} />
        </div>
        <div className="row wrap">
          <label className="check"><input type="checkbox" checked={s.include_potential} onChange={(e) => set({ include_potential: e.target.checked })} />Show "potential" matches (imprecise version), not just confirmed</label>
        </div>

        <fieldset className="settings-group">
          <legend>Feed status</legend>
          <VulnFeedStatusPanel status={viewStatus} />
          {running && (
            <div className="muted small measure">
              First-time NVD import downloads several years of public CVE feeds in the background.
              Refreshing the page is safe - it does not cancel the sync. Leave this tab open or come back later;
              progress updates every few seconds.
            </div>
          )}
          {syncMsg && <div className={`alert ${syncMsg.ok ? 'ok' : 'error'}`} role="status">{syncMsg.text}</div>}
          <div>
            <button type="button" className="btn" onClick={syncNow} disabled={!f.data?.enabled || f.data.offline_mode || syncing || running}
              title="Download the public NVD / CISA KEV / FIRST EPSS feeds into the local cache now">
              {syncing ? 'Starting…' : running ? 'Sync running…' : 'Sync feeds now'}
            </button>
          </div>
        </fieldset>

        <details className="settings-advanced">
          <summary>Advanced</summary>
          <div className="stack">
            <div className="form-grid">
              <Num label="EPSS high-probability threshold" value={s.epss_high_threshold} min={0} max={1} onChange={(v) => set({ epss_high_threshold: v })}
                hint="EPSS score (0-1) above which a finding counts as high exploitation probability" />
            </div>
            <label className="check"><input type="checkbox" checked={s.offline_mode} onChange={(e) => set({ offline_mode: e.target.checked })} />Offline mode (no feed downloads; import with <code>npm run cli -- vuln-import PATH</code>)</label>
            <label className="check" title="Safe/discovery nmap scripts only (SCRIPT_ALLOWLIST) - never vulners, never intrusive categories">
              <input type="checkbox" checked={s.scripts_enabled} onChange={(e) => set({ scripts_enabled: e.target.checked })} />
              Run allow-listed nmap scripts as a secondary signal
            </label>
          </div>
        </details>
        <SaveBar dirty={f.dirty || apiKey !== null} saving={f.saving} msg={f.msg}
          onRevert={() => { f.revert(); setApiKey(null); }} />
      </SettingsForm>
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
      <SettingsForm onSave={() => f.save(s)}>
        <div className="muted small measure">
          A local-only, LAN-bound channel that strengthens device-type classification with names
          devices already announce. Default on is only the cheap passive path: mDNS/Bonjour listen.
          SSDP/UPnP (one multicast M-SEARCH) and NetBIOS (short unicast queries, rotated across
          large inventories) are opt-in. Nothing ever leaves the LAN, and this never runs an nmap
          UDP scan (<code>-sU</code> stays banned everywhere else). Heard names persist and age
          out instead of being cleared when a single pass misses a host.
        </div>
        <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => set({ enabled: e.target.checked })} />Enable local discovery</label>
        <fieldset className="field">
          <legend>Sources</legend>
          <div className="row wrap">
            <label className="check small"><input type="checkbox" checked={s.mdns} disabled={!s.enabled} onChange={(e) => set({ mdns: e.target.checked })} />mDNS / Bonjour (passive)</label>
            <label className="check small"><input type="checkbox" checked={s.ssdp} disabled={!s.enabled} onChange={(e) => set({ ssdp: e.target.checked })} />SSDP / UPnP (active M-SEARCH)</label>
            <label className="check small"><input type="checkbox" checked={s.netbios} disabled={!s.enabled} onChange={(e) => set({ netbios: e.target.checked })} />NetBIOS (active queries)</label>
          </div>
        </fieldset>
        <div className="form-grid">
          <Num label="Timeout per source (seconds)" value={s.timeout_seconds} min={0.5} max={15} disabled={!s.enabled}
            onChange={(v) => set({ timeout_seconds: v })} hint="mDNS/SSDP listen window; NetBIOS uses a shorter fixed window" />
        </div>
        <SaveBar dirty={f.dirty} saving={f.saving} msg={f.msg} onRevert={f.revert} />
      </SettingsForm>
    </Card>
  );
}

// ---------------------------------------------------------------- geo (expected-country mismatch)
export function GeoForm({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<GeoSettings>('/settings/geo');
  useReportDirty(f.dirty, onDirtyChange);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<{ ok: boolean; text: string } | null>(null);
  if (!f.form) return <Card title="Geo mismatch"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  const set = (patch: Partial<GeoSettings>) => f.setForm({ ...s, ...patch });
  const save = () => f.save({
    cache_ttl_hours: s.cache_ttl_hours,
    offline_mode: s.offline_mode,
    maxmind_country_path: s.maxmind_country_path,
    cdn_asns: s.cdn_asns.filter((r) => r.asn >= 1),
  });
  const syncNow = async () => {
    if (syncing) return;
    setSyncing(true);
    setSyncMsg(null);
    try {
      const out = await post<{ ok: boolean; message: string }>('/settings/geo/sync');
      setSyncMsg({ ok: true, text: out.message });
      f.reload();
    } catch (e: any) {
      setSyncMsg({ ok: false, text: e.message });
    } finally {
      setSyncing(false);
    }
  };
  const setAsn = (i: number, patch: Partial<CdnAsnEntry>) => {
    const next = s.cdn_asns.map((row, idx) => idx === i ? { ...row, ...patch } : row);
    set({ cdn_asns: next });
  };
  const addAsn = () => set({ cdn_asns: [...s.cdn_asns, { asn: 0, label: '' }] });
  const dropAsn = (i: number) => set({ cdn_asns: s.cdn_asns.filter((_, idx) => idx !== i) });
  const saved = f.data ?? s;
  return (
    <Card title="Geo mismatch">
      <SettingsForm onSave={save}>
        <div className="muted small measure">
          After each scan, devices on networks with expected countries are checked: published DNS names
          and public IPs are geolocated locally (never private addresses). A country outside the list is
          flagged. Default database is DB-IP Lite Country + ASN, downloaded automatically (no API key).
        </div>
        <div className="alert">
          Expected countries are set per network. Edit a network under <Link to="/settings/networks">Networks</Link> to set them; networks without any are not checked.
        </div>

        <fieldset className="settings-group">
          <legend>Databases</legend>
          <div className="muted small">{s.attribution}</div>
          <div className="row wrap">
            <span className={`badge ${saved.country_db_loaded ? 'ok' : 'outline'}`}>country DB {saved.country_db_loaded ? 'loaded' : 'missing'}</span>
            <span className={`badge ${saved.asn_db_loaded ? 'ok' : 'outline'}`}>ASN DB {saved.asn_db_loaded ? 'loaded' : 'missing'}</span>
            {saved.maxmind_loaded && <span className="badge ok">MaxMind override loaded</span>}
            {saved.sync_running && <span className="badge medium">sync running</span>}
          </div>
          {saved.feeds.map((feed) => (
            <div key={feed.source} className="muted small">
              {feed.source}: {feed.file_month ?? 'never'} {feed.last_synced_at ? `(${relTime(feed.last_synced_at)})` : ''}
              {feed.last_error && <span className="badge high" style={{ marginLeft: 6 }}>{feed.last_error}</span>}
            </div>
          ))}
          {syncMsg && <div className={`alert ${syncMsg.ok ? 'ok' : 'error'}`} role="status">{syncMsg.text}</div>}
          <div>
            <button type="button" className="btn" onClick={syncNow} disabled={saved.offline_mode || syncing || saved.sync_running}>
              {syncing ? 'Starting…' : saved.sync_running ? 'Sync running…' : 'Sync DB-IP now'}
            </button>
          </div>
        </fieldset>

        <label className="check">
          <input type="checkbox" checked={s.offline_mode} onChange={(e) => set({ offline_mode: e.target.checked })} />
          Offline mode (do not download DB-IP files)
        </label>
        <div className="form-grid">
          <Num label="DNS / geo cache TTL (hours)" value={s.cache_ttl_hours} min={1} max={168}
            onChange={(v) => set({ cache_ttl_hours: v })} hint="Unchanged names are not re-resolved until this expires" />
          <Field label="Optional MaxMind GeoLite2 Country path" hint="Operator-supplied file only. Never required; DB-IP remains the default.">
            {(p) => (
              <input {...p} type="text" value={s.maxmind_country_path} onChange={(e) => set({ maxmind_country_path: e.target.value })}
                placeholder="relative to the data dir, or absolute" />
            )}
          </Field>
        </div>
        <div className="field" role="group" aria-labelledby="cdn-asns-label" aria-describedby="cdn-asns-hint">
          <span id="cdn-asns-label">CDN / anycast ASNs</span>
          <span className="hint" id="cdn-asns-hint">Mismatches on these ASNs are still flagged, at lower severity, as CDN edge location not origin.</span>
          {s.cdn_asns.map((row, i) => (
            <div className="row wrap" key={`${row.asn}-${i}`} style={{ gap: 8, marginTop: 6 }}>
              <input type="number" min={1} value={row.asn || ''} placeholder="ASN" style={{ width: 120 }} aria-label={`ASN, row ${i + 1}`}
                onChange={(e) => setAsn(i, { asn: Number(e.target.value) || 0 })} />
              <input type="text" value={row.label} placeholder="label" maxLength={80} aria-label={`Label, row ${i + 1}`}
                onChange={(e) => setAsn(i, { label: e.target.value })} />
              <button type="button" className="btn ghost sm" onClick={() => dropAsn(i)}
                aria-label={row.asn ? `Remove ASN ${row.asn}` : `Remove row ${i + 1}`}>Remove</button>
            </div>
          ))}
          <div style={{ marginTop: 8 }}><button type="button" className="btn sm" onClick={addAsn}>Add ASN</button></div>
        </div>
        <SaveBar dirty={f.dirty} saving={f.saving} msg={f.msg} onRevert={f.revert} />
      </SettingsForm>
    </Card>
  );
}

// ---------------------------------------------------------------- retention
export function RetentionForm({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<{ days: number; domain_scan_days: number }>('/settings/retention');
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
      <SettingsForm onSave={() => f.save(f.form)}>
        <div className="muted small measure">
          History (events, scans, daily snapshots, audit log) older than this is deleted by a daily cleanup at 03:15. Devices not seen for the
          whole period are forgotten. Raw nmap XML is never kept long-term.
        </div>
        <div className="form-grid">
          <Num label="Keep history (days)" value={f.form.days} min={7} max={3650} onChange={(v) => f.setForm({ ...f.form!, days: v })} />
          <Num label="Keep domain scan history (days)" value={f.form.domain_scan_days} min={7} max={3650}
            onChange={(v) => f.setForm({ ...f.form!, domain_scan_days: v })}
            hint="Domain scans and their per-scan snapshots; subdomains gone this long leave the inventory" />
        </div>
        <SaveBar dirty={f.dirty} saving={f.saving} msg={f.msg} onRevert={f.revert} />
        <fieldset className="settings-group danger-zone">
          <legend>Clean up now</legend>
          <div className="muted small measure">
            Runs the daily cleanup immediately with the saved value ({savedDays} days). Deleted history cannot be restored.
          </div>
          {runMsg && <div className={`alert ${runMsg.ok ? 'ok' : 'error'}`} role="status">{runMsg.text}</div>}
          <div><button type="button" className="btn danger" onClick={runCleanup} disabled={running}>{running ? 'Cleaning up…' : 'Run cleanup now'}</button></div>
        </fieldset>
      </SettingsForm>
    </Card>
  );
}

// ---------------------------------------------------------------- domain discovery (Domain scans)
const KEY_FIELDS = [
  ['virustotal', 'VirusTotal'], ['securitytrails', 'SecurityTrails'], ['shodan', 'Shodan'], ['other', 'Other provider key'],
] as const;
type KeyName = (typeof KEY_FIELDS)[number][0];
const NO_EDITS: Record<KeyName, string | null> = { virustotal: null, securitytrails: null, shodan: null, other: null };
const NO_CLEARS: Record<KeyName, boolean> = { virustotal: false, securitytrails: false, shodan: false, other: false };

export function DomainDiscoveryForm({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const f = useForm<DomainDiscoverySettings>('/settings/domain-discovery');
  // Keys are write-only: what was typed (null = untouched) and which stored keys to clear.
  const [edited, setEdited] = useState<Record<KeyName, string | null>>(NO_EDITS);
  const [cleared, setCleared] = useState<Record<KeyName, boolean>>(NO_CLEARS);
  const keysDirty = Object.values(edited).some((v) => v) || Object.values(cleared).some(Boolean);
  useReportDirty(f.dirty || keysDirty, onDirtyChange);
  if (!f.form) return <Card title="Domain discovery"><ErrorBox error={f.error} /><Loading /></Card>;
  const s = f.form;
  const set = (patch: Partial<DomainDiscoverySettings>) => f.setForm({ ...s, ...patch });
  const save = async () => {
    const { keys: _keys, ...rest } = s;
    void _keys;
    const body: Record<string, unknown> = { ...rest };
    for (const [name] of KEY_FIELDS) body[`${name}_key`] = keyPayload(edited[name], cleared[name]);
    if (await f.save(body)) {
      setEdited(NO_EDITS);
      setCleared(NO_CLEARS);
    }
  };
  return (
    <Card title="Domain discovery">
      <SettingsForm onSave={save}>
        <div className="muted small measure">
          Domain scans run in their own queue and never use the network-scan worker; a network scan always goes first.
          The DNS rate limit covers every query of a scan so internal DNS servers are not overloaded.
        </div>
        <fieldset className="settings-group">
          <legend>Rate and time limits</legend>
          <div className="form-grid">
            <Num label="Concurrent domain scans" value={s.concurrency} min={1} max={4} onChange={(v) => set({ concurrency: v })} />
            <Num label="DNS queries per second" value={s.dns_rate_per_second} min={1} max={500} onChange={(v) => set({ dns_rate_per_second: v })} />
            <Num label="DNS timeout (s)" value={s.dns_timeout_seconds} min={0.5} max={30} onChange={(v) => set({ dns_timeout_seconds: v })} />
            <Num label="Zone transfer timeout (s)" value={s.axfr_timeout_seconds} min={1} max={120} onChange={(v) => set({ axfr_timeout_seconds: v })} />
            <Num label="subfinder time limit (min)" value={s.subfinder_timeout_minutes} min={1} max={120} onChange={(v) => set({ subfinder_timeout_minutes: v })} />
            <Num label="dnsx time limit (min)" value={s.dnsx_timeout_minutes} min={1} max={240} onChange={(v) => set({ dnsx_timeout_minutes: v })} />
            <Num label="Scan time limit (min)" value={s.max_job_minutes} min={5} max={1440} onChange={(v) => set({ max_job_minutes: v })} />
            <Num label="Max wordlist entries" value={s.max_wordlist_entries} min={1} max={1000000} onChange={(v) => set({ max_wordlist_entries: v })} />
          </div>
        </fieldset>
        <fieldset className="settings-group">
          <legend>New addresses</legend>
          <label className="check"><input type="checkbox" checked={s.auto_port_scan} onChange={(e) => set({ auto_port_scan: e.target.checked })} />Port-scan new addresses automatically</label>
          <div className="form-grid">
            <Field label="Port scan profile">
              {(p) => (
                <select {...p} value={s.port_scan_type} disabled={!s.auto_port_scan} onChange={(e) => set({ port_scan_type: e.target.value as DomainDiscoverySettings['port_scan_type'] })}>
                  <option value="discovery">Discovery</option><option value="standard">Standard</option><option value="full">Full port</option>
                </select>
              )}
            </Field>
          </div>
        </fieldset>
        <fieldset className="settings-group">
          <legend>Passive source API keys (optional)</legend>
          <div className="muted small measure">
            Optional API keys for subfinder's passive sources. Everything works without them. Keys are stored encrypted,
            never shown again and only written to a temporary file while subfinder runs.
          </div>
          <div className="key-grid">
            {KEY_FIELDS.map(([name, label]) => (
              <Field key={name} label={label}
                hint={s.keys[name].set && (
                  <label className="check small"><input type="checkbox" checked={cleared[name]} onChange={(e) => setCleared({ ...cleared, [name]: e.target.checked })} />Remove stored key</label>
                )}>
                {(p) => (
                  <input {...p} type="password" autoComplete="new-password" value={edited[name] ?? ''} disabled={cleared[name]}
                    placeholder={cleared[name] ? 'will be removed' : keyPlaceholder(s.keys[name])} data-testid={`key-${name}`}
                    onChange={(e) => setEdited({ ...edited, [name]: e.target.value })} />
                )}
              </Field>
            ))}
            <Field label="Other provider name" hint="subfinder provider name for the key above">
              {(p) => <input {...p} type="text" value={s.other_provider} placeholder="e.g. chaos" spellCheck={false} onChange={(e) => set({ other_provider: e.target.value })} />}
            </Field>
          </div>
        </fieldset>
        <SaveBar dirty={f.dirty || keysDirty} saving={f.saving} msg={f.msg}
          onRevert={() => { f.revert(); setEdited(NO_EDITS); setCleared(NO_CLEARS); }} />
      </SettingsForm>
    </Card>
  );
}
