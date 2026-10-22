/** Settings > Notifications: General / Email / Webhooks / CVE Watchlist inner tabs. */
import { useEffect, useState, type MouseEvent } from 'react';
import { NavLink, Navigate, useParams } from 'react-router-dom';
import { del, patch, post, put } from '../../api';
import { Card, Empty, ErrorBox, Loading, Modal, SkeletonRows, confirmDiscard, useReportDirty } from '../../components/ui';
import type { EventType, NotificationSettings, WebhookEndpoint, WebhookTestResult } from '../../types';
import { EVENT_LABELS, relTime, useApi } from '../../util';
import {
  DEFAULT_NOTIFICATION_SECTION,
  eventFilterSummary as summarizeEvents,
  isNotificationSection,
  NOTIFICATION_SECTIONS,
  urlHost,
} from './notificationsLogic';

export {
  DEFAULT_NOTIFICATION_SECTION,
  digestTypeLocked,
  isNotificationSection,
  notificationSectionFromPath,
  NOTIFICATION_SECTIONS,
  type NotificationSection,
} from './notificationsLogic';

const EVENT_CATEGORIES: { title: string; types: EventType[] }[] = [
  { title: 'Devices', types: ['device_discovered', 'device_disappeared', 'device_reappeared', 'ip_changed'] },
  { title: 'Ports', types: ['port_opened', 'port_closed'] },
  { title: 'Services', types: ['service_detected', 'service_changed', 'version_changed', 'banner_changed', 'os_changed'] },
  { title: 'Tags', types: ['tag_added', 'tag_removed'] },
  { title: 'Watches', types: ['watch_match', 'policy_violation', 'monitor_change'] },
  { title: 'Geo', types: ['geo_mismatch'] },
  { title: 'CVE', types: ['cve_watch_match'] },
];

function Msg({ msg }: { msg: { ok: boolean; text: string } | null }) {
  if (!msg) return null;
  return <div className={`alert ${msg.ok ? 'ok' : 'error'}`}>{msg.text}</div>;
}

function eventFilterSummary(types: EventType[]): string {
  return summarizeEvents(types, EVENT_LABELS);
}

export function NotificationsSettings({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const { section: raw } = useParams<{ section?: string }>();
  const section = isNotificationSection(raw) ? raw : null;
  const [dirty, setDirty] = useState(false);
  useReportDirty(dirty, onDirtyChange);

  useEffect(() => {
    setDirty(false);
  }, [section]);

  if (!raw) return <Navigate to={`/settings/notifications/${DEFAULT_NOTIFICATION_SECTION}`} replace />;
  if (!section) return <Navigate to={`/settings/notifications/${DEFAULT_NOTIFICATION_SECTION}`} replace />;

  const onSectionClick = (e: MouseEvent<HTMLAnchorElement>, id: string) => {
    if (id === section) return;
    if (!confirmDiscard(dirty)) e.preventDefault();
  };

  return (
    <div className="stack">
      <nav className="tabs" aria-label="Notification settings">
        {NOTIFICATION_SECTIONS.map((s) => (
          <NavLink
            key={s.id}
            to={`/settings/notifications/${s.id}`}
            onClick={(e) => onSectionClick(e, s.id)}
          >
            {s.label}
          </NavLink>
        ))}
      </nav>
      {section === 'general' && <GeneralTab onDirtyChange={setDirty} />}
      {section === 'email' && <EmailTab onDirtyChange={setDirty} />}
      {section === 'webhooks' && <WebhooksTab onDirtyChange={setDirty} />}
      {section === 'cve-watchlist' && <CveWatchlistTab onDirtyChange={setDirty} />}
    </div>
  );
}

// --- General -----------------------------------------------------------------
function GeneralTab({ onDirtyChange }: { onDirtyChange: (d: boolean) => void }) {
  const res = useApi<NotificationSettings>('/settings/notifications');
  const [form, setForm] = useState<NotificationSettings | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [saving, setSaving] = useState(false);
  useEffect(() => { if (res.data) setForm(res.data); }, [res.data]);
  const dirty = !!form && !!res.data && (
    form.enabled !== res.data.enabled || form.webhooks_enabled !== res.data.webhooks_enabled
  );
  useReportDirty(dirty, onDirtyChange);

  const save = async () => {
    if (!form || saving) return;
    setSaving(true);
    setMsg(null);
    try {
      const out = await put<NotificationSettings>('/settings/notifications', {
        enabled: form.enabled,
        webhooks_enabled: form.webhooks_enabled,
      });
      res.setData(out);
      setForm(out);
      setMsg({ ok: true, text: 'Saved.' });
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
    } finally {
      setSaving(false);
    }
  };

  if (!form) return <Card title="General"><ErrorBox error={res.error} /><Loading /></Card>;

  return (
    <Card title="Channels">
      <div className="stack">
        <div className="muted small">
          Master switches for outbound channels. In-app events and the Changes feed are always recorded.
        </div>
        <label className="check">
          <input type="checkbox" checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
          Email digest
        </label>
        <span className="hint">Daily HTML summary at the configured local time (configure SMTP on the Email tab).</span>
        <label className="check">
          <input type="checkbox" checked={form.webhooks_enabled}
            onChange={(e) => setForm({ ...form, webhooks_enabled: e.target.checked })} />
          Webhooks
        </label>
        <span className="hint">Outbound HTTP posts to configured endpoints. CVE watchlist has an additional per-channel toggle.</span>
        <label className="check" title="Always on">
          <input type="checkbox" checked disabled />
          In-app events
        </label>
        <span className="hint">Always on — inventory changes appear in Changes and related feeds.</span>

        <details className="notif-explain">
          <summary>Which events count as alerts?</summary>
          <div className="muted small stack" style={{ gap: 6, marginTop: 8 }}>
            <p>
              Each network has a notify mode: <strong>alert</strong> (create an event and notify),
              {' '}<strong>record</strong> (create an event, no outbound notify), or <strong>silent</strong> (no event).
            </p>
            <p>
              Email digests and webhooks (by default) only send <strong>alert</strong> events
              (<code>notify=true</code>). Webhooks can opt into record events per endpoint.
            </p>
          </div>
        </details>
        <Msg msg={msg} />
        <div><button className="btn primary" disabled={saving || !dirty} onClick={save}>{saving ? 'Saving…' : 'Save'}</button></div>
      </div>
    </Card>
  );
}

// --- Email -------------------------------------------------------------------
function EmailTab({ onDirtyChange }: { onDirtyChange: (d: boolean) => void }) {
  const res = useApi<NotificationSettings>('/settings/notifications');
  const [form, setForm] = useState<NotificationSettings | null>(null);
  const [password, setPassword] = useState<string | null>(null);
  const [recipientsText, setRecipientsText] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [testTo, setTestTo] = useState('');
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  useEffect(() => { if (res.data) setForm(res.data); }, [res.data]);

  const recipientsDirty = recipientsText !== null && recipientsText !== (form?.recipients ?? []).join('\n');
  const formDirty = !!form && !!res.data && JSON.stringify({
    ...form, available_event_types: undefined, always_notify_types: undefined, password_set: undefined,
    watchlist_email_enabled: undefined, watchlist_webhooks_enabled: undefined, webhooks_enabled: undefined,
  }) !== JSON.stringify({
    ...res.data, available_event_types: undefined, always_notify_types: undefined, password_set: undefined,
    watchlist_email_enabled: undefined, watchlist_webhooks_enabled: undefined, webhooks_enabled: undefined,
  });
  const dirty = formDirty || password !== null || recipientsDirty;
  useReportDirty(dirty, onDirtyChange);

  if (!form) return <Card title="Email"><ErrorBox error={res.error} /><Loading /></Card>;

  const always = new Set(form.always_notify_types || []);
  const recipients = recipientsText ?? form.recipients.join('\n');
  const set = (patch: Partial<NotificationSettings>) => setForm({ ...form, ...patch });

  const body = () => ({
    enabled: form.enabled,
    smtp_host: form.smtp_host,
    smtp_port: form.smtp_port,
    security: form.security,
    username: form.username,
    ...(password !== null ? { password } : {}),
    sender: form.sender,
    recipients: recipients.split(/[\s,;]+/).filter(Boolean),
    event_types: form.event_types,
    digest_time: form.digest_time,
  });

  const save = async () => {
    if (saving) return;
    setSaving(true);
    setMsg(null);
    try {
      const out = await put<NotificationSettings>('/settings/notifications', body());
      res.setData(out);
      setForm(out);
      setPassword(null);
      setRecipientsText(null);
      setMsg({ ok: true, text: 'Saved.' });
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
    } finally {
      setSaving(false);
    }
  };

  const testConnection = async () => {
    setTestMsg(null);
    setTesting(true);
    try {
      // Save first so the test uses the values on screen.
      const out = await put<NotificationSettings>('/settings/notifications', body());
      res.setData(out);
      setForm(out);
      setPassword(null);
      setRecipientsText(null);
      const r = await post<{ ok: boolean; message: string }>('/settings/notifications/test', {
        recipient: testTo || null,
      });
      setTestMsg({ ok: r.ok, text: r.message });
    } catch (e: any) {
      setTestMsg({ ok: false, text: e.message });
    } finally {
      setTesting(false);
    }
  };

  const toggleType = (t: EventType, on: boolean) => {
    if (always.has(t)) return;
    set({
      event_types: on
        ? [...new Set([...form.event_types, t])]
        : form.event_types.filter((x) => x !== t),
    });
  };

  return (
    <Card title="Email digest">
      <div className="stack">
        <div className="muted small">
          One categorized HTML summary per day via an internal SMTP relay (default port 25, no authentication).
        </div>
        <div className="form-grid">
          <label className="field">SMTP host / IP
            <input type="text" value={form.smtp_host} onChange={(e) => set({ smtp_host: e.target.value })}
              placeholder="smtp-relay.example.com" />
          </label>
          <label className="field">Port
            <input type="number" min={1} max={65535} value={form.smtp_port}
              onChange={(e) => set({ smtp_port: Number(e.target.value) })} />
          </label>
          <label className="field">Security
            <select value={form.security} onChange={(e) => set({ security: e.target.value as NotificationSettings['security'] })}>
              <option value="none">None (internal relay)</option>
              <option value="starttls">STARTTLS</option>
              <option value="ssl">SSL/TLS</option>
            </select>
          </label>
          <label className="field">Sender
            <input type="text" value={form.sender} onChange={(e) => set({ sender: e.target.value })} />
          </label>
          <label className="field">Username (optional)
            <input type="text" value={form.username} onChange={(e) => set({ username: e.target.value })} autoComplete="off" />
          </label>
          <label className="field">Password (optional)
            <input type="password" value={password ?? ''} placeholder={form.password_set ? '•••••• (unchanged)' : ''}
              onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
          </label>
        </div>
        <label className="check">
          <input type="checkbox" checked={form.enabled} onChange={(e) => set({ enabled: e.target.checked })} />
          Send email notifications
        </label>
        <label className="field">Recipients
          <textarea rows={3} value={recipients} onChange={(e) => setRecipientsText(e.target.value)}
            placeholder={'it-team@example.com\nsoc@example.com'} />
          <span className="hint">One address per line (or comma separated).</span>
        </label>
        <label className="field">Daily summary time (HH:MM)
          <input type="time" value={form.digest_time} onChange={(e) => set({ digest_time: e.target.value })} />
          <span className="hint">Server-local time. Pending alert events since the last send are grouped into one HTML email.</span>
        </label>

        <div className="field">
          <span>Digest event types</span>
          <div className="stack" style={{ gap: 10, marginTop: 6 }}>
            {EVENT_CATEGORIES.map((cat) => {
              const types = cat.types.filter((t) => form.available_event_types.includes(t) || always.has(t));
              if (!types.length) return null;
              return (
                <details key={cat.title} className="notif-explain">
                  <summary>{cat.title}</summary>
                  <div className="row wrap" style={{ gap: 14, marginTop: 8 }}>
                    {types.map((t) => {
                      const locked = always.has(t);
                      const checked = locked || form.event_types.includes(t);
                      return (
                        <label key={t} className="check small" title={locked ? 'Always included in the digest' : undefined}>
                          <input type="checkbox" checked={checked} disabled={locked}
                            onChange={(e) => toggleType(t, e.target.checked)} />
                          {EVENT_LABELS[t]}
                          {locked && <span className="hint"> (always included)</span>}
                        </label>
                      );
                    })}
                  </div>
                </details>
              );
            })}
          </div>
          <span className="hint" style={{ marginTop: 8, display: 'block' }}>
            Watch matches, policy violations, monitor changes, and CVE watchlist matches are always included in the
            digest when they have not already been emailed immediately. Other types are optional.
          </span>
        </div>

        <Msg msg={msg} />
        {testMsg && <div className={`alert ${testMsg.ok ? 'ok' : 'error'}`}>{testMsg.text}</div>}
        <div className="row wrap">
          <button className="btn primary" onClick={save} disabled={saving || testing}>{saving ? 'Saving…' : 'Save'}</button>
          <input type="email" placeholder="test recipient (default: all recipients)" value={testTo}
            onChange={(e) => setTestTo(e.target.value)} style={{ minWidth: 260 }} />
          <button className="btn" onClick={testConnection} disabled={!form.smtp_host || saving || testing}>
            {testing ? 'Testing…' : 'Test connection'}
          </button>
        </div>
      </div>
    </Card>
  );
}

// --- Webhooks ----------------------------------------------------------------
type WebhookDraft = {
  id?: number;
  name: string;
  url: string;
  enabled: boolean;
  event_types: EventType[];
  include_record_events: boolean;
  rotate_secret: boolean;
};

function emptyDraft(): WebhookDraft {
  return { name: '', url: '', enabled: true, event_types: [], include_record_events: false, rotate_secret: true };
}

function WebhooksTab({ onDirtyChange }: { onDirtyChange: (d: boolean) => void }) {
  const { data, error, loading, reload } = useApi<WebhookEndpoint[]>('/webhooks');
  const [draft, setDraft] = useState<WebhookDraft | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [revealedSecret, setRevealedSecret] = useState<{ name: string; secret: string } | null>(null);
  const [testResult, setTestResult] = useState<{ id: number; result: WebhookTestResult } | null>(null);
  const [pending, setPending] = useState<string | null>(null);

  const draftDirty = !!draft && (
    !!draft.name.trim() || !!draft.url.trim() || draft.event_types.length > 0 || draft.include_record_events
    || (draft.id != null)
  );
  useReportDirty(!!draft && draftDirty, onDirtyChange);

  const closeDraft = () => confirmDiscard(!!draft) && setDraft(null);

  const openEdit = (h: WebhookEndpoint) => {
    setSaveError(null);
    setDraft({
      id: h.id,
      name: h.name,
      url: h.url,
      enabled: h.enabled,
      event_types: [...h.event_types],
      include_record_events: h.include_record_events,
      rotate_secret: false,
    });
  };

  const saveDraft = async () => {
    if (!draft || saving) return;
    setSaving(true);
    setSaveError(null);
    try {
      const payload = {
        name: draft.name.trim(),
        url: draft.url.trim(),
        enabled: draft.enabled,
        event_types: draft.event_types.length ? draft.event_types : null,
        include_record_events: draft.include_record_events,
        rotate_secret: draft.rotate_secret,
      };
      let out: WebhookEndpoint;
      if (draft.id != null) {
        out = await patch<WebhookEndpoint>(`/webhooks/${draft.id}`, payload);
      } else {
        out = await post<WebhookEndpoint>('/webhooks', payload);
      }
      setDraft(null);
      if (out.secret) setRevealedSecret({ name: out.name, secret: out.secret });
      reload();
    } catch (e: any) {
      setSaveError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const toggleEnabled = async (h: WebhookEndpoint) => {
    const key = `en-${h.id}`;
    if (pending === key) return;
    setPending(key);
    setActionError(null);
    try {
      await patch(`/webhooks/${h.id}`, { enabled: !h.enabled });
      reload();
    } catch (e: any) {
      setActionError(e.message);
    } finally {
      setPending(null);
    }
  };

  const remove = async (h: WebhookEndpoint) => {
    if (!confirm(`Delete webhook “${h.name}”? This cannot be undone.`)) return;
    const key = `del-${h.id}`;
    if (pending === key) return;
    setPending(key);
    setActionError(null);
    try {
      await del(`/webhooks/${h.id}`);
      reload();
    } catch (e: any) {
      setActionError(e.message);
    } finally {
      setPending(null);
    }
  };

  const sendTest = async (h: WebhookEndpoint) => {
    const key = `test-${h.id}`;
    if (pending === key) return;
    setPending(key);
    setActionError(null);
    setTestResult(null);
    try {
      const result = await post<WebhookTestResult>(`/webhooks/${h.id}/test`);
      setTestResult({ id: h.id, result });
      reload();
    } catch (e: any) {
      setActionError(e.message);
    } finally {
      setPending(null);
    }
  };

  const toggleDraftType = (t: EventType, on: boolean) => {
    if (!draft) return;
    setDraft({
      ...draft,
      event_types: on ? [...draft.event_types, t] : draft.event_types.filter((x) => x !== t),
    });
  };

  return (
    <Card
      title="Webhooks"
      flush
      actions={
        <button className="btn primary sm" onClick={() => { setDraft(emptyDraft()); setSaveError(null); }}>
          Add webhook
        </button>
      }
    >
      <div className="card-body muted small" style={{ borderBottom: '1px solid var(--border)' }}>
        POST signed JSON to your SIEM or automation. By default only alert events (<code>notify=true</code>) are
        delivered; enable “Include record events” on an endpoint to also receive record-mode events. The General tab
        master switch must be on.
      </div>
      <ErrorBox error={error || actionError} />
      {revealedSecret && (
        <div className="card-body">
          <div className="alert ok stack" style={{ gap: 8 }}>
            <div>Signing secret for “{revealedSecret.name}”. Copy it now — it is not shown again.</div>
            <div className="row wrap">
              <code className="query-preview grow" style={{ userSelect: 'all' }}>{revealedSecret.secret}</code>
              <button className="btn ghost sm" onClick={() => setRevealedSecret(null)}>Done</button>
            </div>
          </div>
        </div>
      )}
      {loading && !data ? <SkeletonRows cols={6} /> : !data?.length ? (
        <Empty>No webhooks yet.</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Host</th>
                <th>Enabled</th>
                <th>Events</th>
                <th>Last success</th>
                <th>Last error</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.map((h) => (
                <tr key={h.id} className={!h.enabled ? 'dim' : undefined}>
                  <td><strong>{h.name}</strong></td>
                  <td className="mono small">{urlHost(h.url)}</td>
                  <td>
                    <label className="check small">
                      <input type="checkbox" checked={h.enabled} disabled={pending === `en-${h.id}`}
                        onChange={() => toggleEnabled(h)} aria-label={`Enable ${h.name}`} />
                    </label>
                  </td>
                  <td className="small">{eventFilterSummary(h.event_types)}</td>
                  <td className="small nowrap">{h.last_success_at ? relTime(h.last_success_at) : '—'}</td>
                  <td className="small">
                    {h.last_error
                      ? <span className="badge high" title={h.last_error}>{h.last_error.slice(0, 48)}</span>
                      : '—'}
                    {testResult?.id === h.id && (
                      <div className={`alert ${testResult.result.ok ? 'ok' : 'error'}`} style={{ marginTop: 4 }}>
                        Test: {testResult.result.ok ? `OK (${testResult.result.latency_ms} ms)` : testResult.result.error}
                      </div>
                    )}
                  </td>
                  <td className="right">
                    <div className="row wrap" style={{ justifyContent: 'flex-end', gap: 4 }}>
                      <button className="btn sm" disabled={!!pending} onClick={() => sendTest(h)}>
                        {pending === `test-${h.id}` ? 'Sending…' : 'Send test'}
                      </button>
                      <button className="btn sm" onClick={() => openEdit(h)}>Edit</button>
                      <button className="btn danger sm" disabled={pending === `del-${h.id}`} onClick={() => remove(h)}>
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {draft && (
        <Modal
          title={draft.id != null ? 'Edit webhook' : 'Add webhook'}
          onClose={closeDraft}
          dirty={draftDirty}
          footer={
            <>
              <button className="btn ghost" onClick={closeDraft}>Cancel</button>
              <button className="btn primary" onClick={saveDraft}
                disabled={saving || !draft.name.trim() || !draft.url.trim()}>
                {saving ? 'Saving…' : 'Save'}
              </button>
            </>
          }
        >
          <div className="stack">
            <label className="field">Name
              <input type="text" value={draft.name} maxLength={120}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="SIEM" />
            </label>
            <label className="field">URL
              <input type="url" value={draft.url} maxLength={2000}
                onChange={(e) => setDraft({ ...draft, url: e.target.value })}
                placeholder="https://hooks.example.com/portreveal" />
            </label>
            <label className="check">
              <input type="checkbox" checked={draft.enabled}
                onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />
              Enabled
            </label>
            <label className="check">
              <input type="checkbox" checked={draft.include_record_events}
                onChange={(e) => setDraft({ ...draft, include_record_events: e.target.checked })} />
              Include record events (notify=false)
            </label>
            <span className="hint">Off by default — only alert-mode events are sent, matching email.</span>
            <label className="check">
              <input type="checkbox" checked={draft.rotate_secret}
                onChange={(e) => setDraft({ ...draft, rotate_secret: e.target.checked })} />
              {draft.id != null ? 'Rotate signing secret' : 'Generate signing secret'}
            </label>
            <span className="hint">Secret is shown once after save, then never again.</span>

            <div className="field">
              <span>Event types</span>
              <span className="hint" style={{ display: 'block', marginBottom: 6 }}>
                Leave all unchecked to receive every type (still subject to the notify-flag rule above).
              </span>
              {EVENT_CATEGORIES.map((cat) => (
                <details key={cat.title} className="notif-explain">
                  <summary>{cat.title}</summary>
                  <div className="row wrap" style={{ gap: 12, marginTop: 8 }}>
                    {cat.types.map((t) => (
                      <label key={t} className="check small">
                        <input type="checkbox" checked={draft.event_types.includes(t)}
                          onChange={(e) => toggleDraftType(t, e.target.checked)} />
                        {EVENT_LABELS[t]}
                      </label>
                    ))}
                  </div>
                </details>
              ))}
            </div>
            <ErrorBox error={saveError} />
          </div>
        </Modal>
      )}
    </Card>
  );
}

// --- CVE Watchlist -----------------------------------------------------------
function CveWatchlistTab({ onDirtyChange }: { onDirtyChange: (d: boolean) => void }) {
  const res = useApi<NotificationSettings>('/settings/notifications');
  const [form, setForm] = useState<NotificationSettings | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [saving, setSaving] = useState(false);
  useEffect(() => { if (res.data) setForm(res.data); }, [res.data]);
  const dirty = !!form && !!res.data && (
    form.watchlist_email_enabled !== res.data.watchlist_email_enabled
    || form.watchlist_webhooks_enabled !== res.data.watchlist_webhooks_enabled
  );
  useReportDirty(dirty, onDirtyChange);

  const save = async () => {
    if (!form || saving) return;
    setSaving(true);
    setMsg(null);
    try {
      const out = await put<NotificationSettings>('/settings/notifications', {
        watchlist_email_enabled: form.watchlist_email_enabled,
        watchlist_webhooks_enabled: form.watchlist_webhooks_enabled,
      });
      res.setData(out);
      setForm(out);
      setMsg({ ok: true, text: 'Saved.' });
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
    } finally {
      setSaving(false);
    }
  };

  if (!form) return <Card title="CVE watchlist alerts"><ErrorBox error={res.error} /><Loading /></Card>;

  const emailReady = form.enabled && !!form.smtp_host.trim() && form.recipients.length > 0;

  return (
    <Card title="CVE watchlist alerts">
      <div className="stack">
        <div className="muted small">
          In-app events are always recorded when a watched CVE appears. Use these toggles for outbound delivery.
          Immediate email marks events as notified so they are not repeated in the daily digest; if immediate
          email is off or fails, the digest still includes them.
        </div>
        <label className="check small" title={!emailReady ? 'Turn on email notifications and configure SMTP first' : undefined}>
          <input
            type="checkbox"
            checked={emailReady ? form.watchlist_email_enabled : false}
            disabled={!emailReady}
            onChange={(e) => setForm({ ...form, watchlist_email_enabled: e.target.checked })}
          />
          Immediate email (does not wait for the daily digest)
        </label>
        {!emailReady && (
          <span className="hint">
            Enable email notifications and configure SMTP host + recipients on the Email tab to use immediate watchlist email.
          </span>
        )}
        <label className="check small">
          <input type="checkbox" checked={form.watchlist_webhooks_enabled}
            onChange={(e) => setForm({ ...form, watchlist_webhooks_enabled: e.target.checked })} />
          Webhooks (respects each endpoint&apos;s event-type filter)
        </label>
        <Msg msg={msg} />
        <div><button className="btn primary" disabled={saving || !dirty} onClick={save}>{saving ? 'Saving…' : 'Save'}</button></div>
      </div>
    </Card>
  );
}

