/** Settings > Notifications: General / Email / Webhooks / CVE Watchlist inner tabs. */
import { useEffect, useState, type MouseEvent } from 'react';
import { NavLink, Navigate, useParams } from 'react-router-dom';
import { del, patch, post, put } from '../../api';
import { Card, Empty, ErrorBox, Loading, Modal, SkeletonRows, confirmDiscard, useReportDirty } from '../../components/ui';
import type {
  EventType,
  Network,
  NotificationSettings,
  RecipientDeliveryMode,
  RecipientDestKind,
  RecipientGroup,
  RecipientGroupTestResult,
  RecipientMinSeverity,
  WebhookEndpoint,
  WebhookTestResult,
} from '../../types';
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
      {section === 'recipients' && <RecipientsTab onDirtyChange={setDirty} />}
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
              Notify behaviour is derived from inventory state: before a network has a baseline,
              changes are <strong>silent</strong> (no event). With a baseline they are
              {' '}<strong>alerts</strong> (<code>notify=true</code>). Hosts outside any network are
              {' '}<strong>recorded</strong> only (<code>notify=false</code>, no outbound notify).
            </p>
            <p>
              Email digests and webhooks (by default) only send alert events. Webhooks can opt into
              record events per endpoint.
            </p>
          </div>
        </details>
        <Msg msg={msg} />
        <div><button className="btn primary" disabled={saving || !dirty} onClick={save}>{saving ? 'Saving…' : 'Save'}</button></div>
      </div>
    </Card>
  );
}

// --- Email (SMTP only; recipients live on the Recipients tab) ----------------
function EmailTab({ onDirtyChange }: { onDirtyChange: (d: boolean) => void }) {
  const res = useApi<NotificationSettings>('/settings/notifications');
  const [form, setForm] = useState<NotificationSettings | null>(null);
  const [password, setPassword] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [testTo, setTestTo] = useState('');
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  useEffect(() => { if (res.data) setForm(res.data); }, [res.data]);

  const formDirty = !!form && !!res.data && JSON.stringify({
    smtp_host: form.smtp_host, smtp_port: form.smtp_port, security: form.security,
    username: form.username, sender: form.sender, enabled: form.enabled,
  }) !== JSON.stringify({
    smtp_host: res.data.smtp_host, smtp_port: res.data.smtp_port, security: res.data.security,
    username: res.data.username, sender: res.data.sender, enabled: res.data.enabled,
  });
  const dirty = formDirty || password !== null;
  useReportDirty(dirty, onDirtyChange);

  if (!form) return <Card title="Email"><ErrorBox error={res.error} /><Loading /></Card>;

  const set = (patch: Partial<NotificationSettings>) => setForm({ ...form, ...patch });

  const save = async () => {
    if (saving) return;
    setSaving(true);
    setMsg(null);
    try {
      const out = await put<NotificationSettings>('/settings/notifications', {
        enabled: form.enabled,
        smtp_host: form.smtp_host,
        smtp_port: form.smtp_port,
        security: form.security,
        username: form.username,
        sender: form.sender,
        ...(password !== null ? { password } : {}),
      });
      res.setData(out);
      setForm(out);
      setPassword(null);
      setMsg({ ok: true, text: 'Saved.' });
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
    } finally {
      setSaving(false);
    }
  };

  const testConnection = async () => {
    if (!testTo.trim()) {
      setTestMsg({ ok: false, text: 'Enter a test recipient address.' });
      return;
    }
    setTestMsg(null);
    setTesting(true);
    try {
      const r = await post<{ ok: boolean; message: string }>('/settings/notifications/test', {
        smtp_host: form.smtp_host,
        smtp_port: form.smtp_port,
        security: form.security,
        username: form.username,
        sender: form.sender,
        recipient: testTo.trim(),
        ...(password !== null ? { password } : {}),
      });
      setTestMsg({ ok: r.ok, text: r.message });
    } catch (e: any) {
      setTestMsg({ ok: false, text: e.message });
    } finally {
      setTesting(false);
    }
  };

  return (
    <Card title="Email">
      <div className="stack">
        <div className="muted small">
          SMTP relay used by recipient groups and CVE watchlist email. Audience addresses and digest
          schedules live on the <strong>Recipients</strong> tab.
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
          Enable SMTP (also toggles the default Email digest group)
        </label>
        <Msg msg={msg} />
        {testMsg && <div className={`alert ${testMsg.ok ? 'ok' : 'error'}`}>{testMsg.text}</div>}
        <div className="row wrap">
          <button className="btn primary" onClick={save} disabled={saving || testing || !dirty}>
            {saving ? 'Saving…' : 'Save'}
          </button>
          <input type="email" placeholder="test recipient" value={testTo}
            onChange={(e) => setTestTo(e.target.value)} style={{ minWidth: 220 }} />
          <button className="btn" onClick={testConnection} disabled={!form.smtp_host || saving || testing}>
            {testing ? 'Testing…' : 'Test connection'}
          </button>
        </div>
      </div>
    </Card>
  );
}

// --- Recipients (channels) ---------------------------------------------------
type DestDraft = {
  key: string;
  id?: number;
  kind: RecipientDestKind;
  enabled: boolean;
  target: string;
  webhook_id: number | '';
  url: string;
  url_hint: string | null;
  has_url: boolean;
};

type GroupDraft = {
  id?: number;
  name: string;
  enabled: boolean;
  is_default: boolean;
  event_types: EventType[];
  min_severity: RecipientMinSeverity;
  network_ids: number[];
  delivery_mode: RecipientDeliveryMode;
  digest_time: string;
  max_per_hour: number;
  dedupe_seconds: number;
  quiet_start: string;
  quiet_end: string;
  quiet_bypass_critical: boolean;
  destinations: DestDraft[];
};

let destKeySeq = 0;
function nextDestKey() {
  destKeySeq += 1;
  return `d${destKeySeq}`;
}

function emptyGroupDraft(): GroupDraft {
  return {
    name: '',
    enabled: true,
    is_default: false,
    event_types: [],
    min_severity: 'info',
    network_ids: [],
    delivery_mode: 'daily',
    digest_time: '08:00',
    max_per_hour: 20,
    dedupe_seconds: 300,
    quiet_start: '',
    quiet_end: '',
    quiet_bypass_critical: true,
    destinations: [],
  };
}

function groupFromApi(g: RecipientGroup): GroupDraft {
  return {
    id: g.id,
    name: g.name,
    enabled: g.enabled,
    is_default: g.is_default,
    event_types: [...g.event_types],
    min_severity: g.min_severity,
    network_ids: [...(g.network_ids || [])],
    delivery_mode: g.delivery_mode,
    digest_time: g.digest_time || '08:00',
    max_per_hour: g.max_per_hour,
    dedupe_seconds: g.dedupe_seconds,
    quiet_start: g.quiet_start || '',
    quiet_end: g.quiet_end || '',
    quiet_bypass_critical: g.quiet_bypass_critical,
    destinations: g.destinations.map((d) => ({
      key: nextDestKey(),
      id: d.id,
      kind: d.kind,
      enabled: d.enabled,
      target: d.target || '',
      webhook_id: d.webhook_id ?? '',
      url: '',
      url_hint: d.url_hint,
      has_url: d.has_url,
    })),
  };
}

function groupSnapshot(d: GroupDraft) {
  return {
    id: d.id ?? null,
    name: d.name,
    enabled: d.enabled,
    event_types: d.event_types,
    min_severity: d.min_severity,
    network_ids: d.network_ids,
    delivery_mode: d.delivery_mode,
    digest_time: d.digest_time,
    max_per_hour: d.max_per_hour,
    dedupe_seconds: d.dedupe_seconds,
    quiet_start: d.quiet_start,
    quiet_end: d.quiet_end,
    quiet_bypass_critical: d.quiet_bypass_critical,
    destinations: d.destinations.map((x) => ({
      id: x.id ?? null,
      kind: x.kind,
      enabled: x.enabled,
      target: x.target,
      webhook_id: x.webhook_id,
      url: x.url,
      has_url: x.has_url,
    })),
  };
}

function deliveryStatusLine(g: RecipientGroup): { text: string; tone: 'ok' | 'warn' | 'muted'; title?: string } {
  if (g.last_error) {
    const when = g.last_error_at ? ` · ${relTime(g.last_error_at)}` : '';
    return {
      text: `${g.last_error_friendly || 'Delivery failed'}${when}`,
      tone: 'warn',
      title: g.last_error,
    };
  }
  if (g.last_success_at) return { text: `Last delivery ${relTime(g.last_success_at)}`, tone: 'ok' };
  return { text: 'No deliveries yet', tone: 'muted' };
}

function RecipientsTab({ onDirtyChange }: { onDirtyChange: (d: boolean) => void }) {
  const { data, error, loading, reload } = useApi<RecipientGroup[]>('/recipient-groups');
  const networks = useApi<Network[]>('/networks');
  const hooks = useApi<WebhookEndpoint[]>('/webhooks');
  const [draft, setDraft] = useState<GroupDraft | null>(null);
  const [draftBase, setDraftBase] = useState<GroupDraft | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: number; result: RecipientGroupTestResult } | null>(null);
  const [pending, setPending] = useState<string | null>(null);

  const draftDirty = !!draft && !!draftBase
    && JSON.stringify(groupSnapshot(draft)) !== JSON.stringify(groupSnapshot(draftBase));
  useReportDirty(draftDirty, onDirtyChange);

  const closeDraft = () => { setDraft(null); setDraftBase(null); };

  const openCreate = () => {
    const d = emptyGroupDraft();
    setSaveError(null);
    setDraft(d);
    setDraftBase(JSON.parse(JSON.stringify(d)));
  };

  const openEdit = (g: RecipientGroup) => {
    const d = groupFromApi(g);
    setSaveError(null);
    setDraft(d);
    setDraftBase(JSON.parse(JSON.stringify(d)));
  };

  const saveDraft = async () => {
    if (!draft || saving) return;
    setSaving(true);
    setSaveError(null);
    try {
      const destinations = draft.destinations.map((d) => {
        const row: Record<string, unknown> = {
          kind: d.kind,
          enabled: d.enabled,
        };
        if (d.id != null) row.id = d.id;
        if (d.kind === 'email') row.target = d.target.trim();
        if (d.kind === 'webhook') row.webhook_id = d.webhook_id === '' ? null : Number(d.webhook_id);
        if (d.kind === 'slack' || d.kind === 'teams') {
          if (d.url.trim()) row.url = d.url.trim();
        }
        return row;
      });
      const payload = {
        name: draft.name.trim(),
        enabled: draft.enabled,
        event_types: draft.event_types.length ? draft.event_types : null,
        min_severity: draft.min_severity,
        network_ids: draft.network_ids.length ? draft.network_ids : null,
        delivery_mode: draft.delivery_mode,
        digest_time: draft.delivery_mode === 'daily' ? draft.digest_time || '08:00' : null,
        max_per_hour: draft.max_per_hour,
        dedupe_seconds: draft.dedupe_seconds,
        quiet_start: draft.quiet_start || null,
        quiet_end: draft.quiet_end || null,
        quiet_bypass_critical: draft.quiet_bypass_critical,
        destinations,
      };
      if (draft.id != null) {
        await patch(`/recipient-groups/${draft.id}`, payload);
      } else {
        await post('/recipient-groups', payload);
      }
      closeDraft();
      reload();
    } catch (e: any) {
      setSaveError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const toggleEnabled = async (g: RecipientGroup) => {
    const key = `en-${g.id}`;
    if (pending === key) return;
    setPending(key);
    setActionError(null);
    try {
      await patch(`/recipient-groups/${g.id}`, { enabled: !g.enabled });
      reload();
    } catch (e: any) {
      setActionError(e.message);
    } finally {
      setPending(null);
    }
  };

  const remove = async (g: RecipientGroup) => {
    if (g.is_default) return;
    if (!confirm(`Delete recipient group “${g.name}”? This cannot be undone.`)) return;
    const key = `del-${g.id}`;
    if (pending === key) return;
    setPending(key);
    setActionError(null);
    try {
      await del(`/recipient-groups/${g.id}`);
      reload();
    } catch (e: any) {
      setActionError(e.message);
    } finally {
      setPending(null);
    }
  };

  const sendTest = async (g: RecipientGroup) => {
    const key = `test-${g.id}`;
    if (pending === key) return;
    setPending(key);
    setActionError(null);
    setTestResult(null);
    try {
      const result = await post<RecipientGroupTestResult>(`/recipient-groups/${g.id}/test`);
      setTestResult({ id: g.id, result });
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

  const toggleNetwork = (id: number, on: boolean) => {
    if (!draft) return;
    setDraft({
      ...draft,
      network_ids: on ? [...draft.network_ids, id] : draft.network_ids.filter((x) => x !== id),
    });
  };

  const addDestination = (kind: RecipientDestKind) => {
    if (!draft) return;
    setDraft({
      ...draft,
      destinations: [
        ...draft.destinations,
        {
          key: nextDestKey(),
          kind,
          enabled: true,
          target: '',
          webhook_id: '',
          url: '',
          url_hint: null,
          has_url: false,
        },
      ],
    });
  };

  const updateDest = (key: string, patch: Partial<DestDraft>) => {
    if (!draft) return;
    setDraft({
      ...draft,
      destinations: draft.destinations.map((d) => (d.key === key ? { ...d, ...patch } : d)),
    });
  };

  const removeDest = (key: string) => {
    if (!draft) return;
    setDraft({ ...draft, destinations: draft.destinations.filter((d) => d.key !== key) });
  };

  return (
    <Card
      title="Recipients"
      flush
      actions={
        <button className="btn primary sm" onClick={openCreate}>Add group</button>
      }
    >
      <div className="card-body muted small" style={{ borderBottom: '1px solid var(--border)' }}>
        Audience channels control <strong>what</strong> each group receives, <strong>how</strong> it is delivered,
        {' '}<strong>when</strong>, and <strong>how much</strong>. New groups default to a daily digest — use immediate
        only for critical events and the CVE watchlist. Overflow past the hourly cap rolls into the next digest
        (never dropped). Slack and Teams webhook URLs are stored as secrets and never shown in full.
      </div>
      <ErrorBox error={error || actionError} />
      {loading && !data ? <SkeletonRows cols={4} /> : !data?.length ? (
        <Empty>No recipient groups yet.</Empty>
      ) : (
        <div className="stack" style={{ gap: 0 }}>
          {data.map((g) => (
            <div
              key={g.id}
              className={`recipient-group-card${!g.enabled ? ' dim' : ''}`}
              data-testid={`recipient-group-${g.id}`}
            >
              <div className="row wrap" style={{ justifyContent: 'space-between', gap: 12, alignItems: 'flex-start' }}>
                <div className="stack" style={{ gap: 4, flex: 1, minWidth: 0 }}>
                  <div className="row wrap" style={{ gap: 8, alignItems: 'center' }}>
                    <strong>{g.name}</strong>
                    {g.is_default && <span className="badge">Default</span>}
                    <span className="badge muted">{g.delivery_mode}</span>
                    {(g.destination_kinds || []).map((k) => (
                      <span key={k} className="badge muted" title={k}>{k}</span>
                    ))}
                  </div>
                  <div className="muted small" data-testid="group-summary">{g.summary}</div>
                  <div className="small">
                    {testResult?.id === g.id ? (
                      <span className={testResult.result.ok ? 'ok' : 'error'}>
                        Test: {testResult.result.ok ? 'OK' : (testResult.result.error || 'failed')}
                      </span>
                    ) : (() => {
                      const st = deliveryStatusLine(g);
                      return (
                        <span
                          className={st.tone === 'warn' ? 'recipient-status-error' : undefined}
                          style={{ color: st.tone === 'warn' ? 'var(--danger)' : 'var(--text-2)' }}
                          title={st.title}
                        >
                          {st.text}
                        </span>
                      );
                    })()}
                  </div>
                </div>
                <div className="row wrap" style={{ gap: 6, alignItems: 'center' }}>
                  <label className="check small">
                    <input
                      type="checkbox"
                      checked={g.enabled}
                      disabled={pending === `en-${g.id}`}
                      onChange={() => toggleEnabled(g)}
                      aria-label={`Enable ${g.name}`}
                    />
                    Enabled
                  </label>
                  <button className="btn sm" disabled={!!pending} onClick={() => sendTest(g)}>
                    {pending === `test-${g.id}` ? 'Sending…' : 'Send test'}
                  </button>
                  <button className="btn sm" onClick={() => openEdit(g)}>Edit</button>
                  {!g.is_default && (
                    <button className="btn danger sm" disabled={pending === `del-${g.id}`} onClick={() => remove(g)}>
                      Delete
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {draft && (
        <Modal
          title={draft.id != null ? 'Edit recipient group' : 'Add recipient group'}
          onClose={closeDraft}
          dirty={draftDirty}
          footer={
            <>
              <button className="btn ghost" onClick={() => confirmDiscard(draftDirty) && closeDraft()}>Cancel</button>
              <button
                className="btn primary"
                onClick={saveDraft}
                disabled={saving || !draft.name.trim()}
              >
                {saving ? 'Saving…' : 'Save'}
              </button>
            </>
          }
        >
          <div className="stack">
            <label className="field">Name
              <input
                type="text"
                value={draft.name}
                maxLength={120}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })}
                placeholder="SOC"
              />
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={draft.enabled}
                onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
              />
              Enabled
            </label>

            <h3 className="recipient-section-title">WHAT</h3>
            <div className="field">
              <span>Event types</span>
              <span className="hint" style={{ display: 'block', marginBottom: 6 }}>
                Leave all unchecked to include every type (still alert-only).
              </span>
              {EVENT_CATEGORIES.map((cat) => {
                const selected = cat.types.filter((t) => draft.event_types.includes(t)).length;
                return (
                  <details key={cat.title} className="notif-explain">
                    <summary>{cat.title}{selected ? ` (${selected} selected)` : ''}</summary>
                    <div className="row wrap" style={{ gap: 12, marginTop: 8 }}>
                      {cat.types.map((t) => (
                        <label key={t} className="check small">
                          <input
                            type="checkbox"
                            checked={draft.event_types.includes(t)}
                            onChange={(e) => toggleDraftType(t, e.target.checked)}
                          />
                          {EVENT_LABELS[t]}
                        </label>
                      ))}
                    </div>
                  </details>
                );
              })}
            </div>

            <label className="field">Minimum severity
              <select
                value={draft.min_severity}
                onChange={(e) => setDraft({ ...draft, min_severity: e.target.value as RecipientMinSeverity })}
              >
                <option value="info">All severities</option>
                <option value="low">Low and above</option>
                <option value="medium">Medium and above</option>
                <option value="high">Critical / High only</option>
              </select>
            </label>

            <div className="field">
              <span>Network scope</span>
              <span className="hint" style={{ display: 'block', marginBottom: 6 }}>
                Leave all unchecked for every network.
              </span>
              <div className="row wrap" style={{ gap: 12 }}>
                {(networks.data || []).map((n) => (
                  <label key={n.id} className="check small">
                    <input
                      type="checkbox"
                      checked={draft.network_ids.includes(n.id)}
                      onChange={(e) => toggleNetwork(n.id, e.target.checked)}
                    />
                    {n.name}
                  </label>
                ))}
                {!networks.data?.length && <span className="muted small">No networks yet.</span>}
              </div>
            </div>

            <h3 className="recipient-section-title">HOW</h3>
            <div className="field">
              <span>Destinations</span>
              <div className="row wrap" style={{ gap: 6, marginBottom: 8 }}>
                <button type="button" className="btn sm" onClick={() => addDestination('email')}>+ Email</button>
                <button type="button" className="btn sm" onClick={() => addDestination('webhook')}>+ Webhook</button>
                <button type="button" className="btn sm" onClick={() => addDestination('slack')}>+ Slack</button>
                <button type="button" className="btn sm" onClick={() => addDestination('teams')}>+ Teams</button>
              </div>
              {!draft.destinations.length && (
                <div className="muted small" style={{ marginBottom: 8 }}>Add at least one destination to deliver.</div>
              )}
              {draft.destinations.map((d) => (
                <div key={d.key} className="notif-explain" style={{ marginBottom: 8 }}>
                  <div className="row wrap" style={{ justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
                    <strong style={{ textTransform: 'capitalize' }}>{d.kind}</strong>
                    <div className="row" style={{ gap: 8 }}>
                      <label className="check small">
                        <input
                          type="checkbox"
                          checked={d.enabled}
                          onChange={(e) => updateDest(d.key, { enabled: e.target.checked })}
                        />
                        On
                      </label>
                      <button type="button" className="btn ghost sm" onClick={() => removeDest(d.key)}>Remove</button>
                    </div>
                  </div>
                  {d.kind === 'email' && (
                    <label className="field">Address
                      <input
                        type="email"
                        value={d.target}
                        onChange={(e) => updateDest(d.key, { target: e.target.value })}
                        placeholder="soc@example.com"
                      />
                    </label>
                  )}
                  {d.kind === 'webhook' && (
                    <label className="field">Existing webhook
                      <select
                        value={d.webhook_id === '' ? '' : String(d.webhook_id)}
                        onChange={(e) => updateDest(d.key, {
                          webhook_id: e.target.value === '' ? '' : Number(e.target.value),
                        })}
                      >
                        <option value="">Select…</option>
                        {(hooks.data || []).map((h) => (
                          <option key={h.id} value={h.id}>{h.name} ({urlHost(h.url)})</option>
                        ))}
                      </select>
                    </label>
                  )}
                  {(d.kind === 'slack' || d.kind === 'teams') && (
                    <label className="field">Incoming webhook URL
                      <input
                        type="password"
                        value={d.url}
                        autoComplete="new-password"
                        onChange={(e) => updateDest(d.key, { url: e.target.value })}
                        placeholder={d.has_url ? (d.url_hint || '•••• (unchanged)') : 'https://hooks.example.com/…'}
                      />
                      <span className="hint">
                        {d.has_url
                          ? `Stored secret${d.url_hint ? ` (${d.url_hint})` : ''}. Leave blank to keep.`
                          : 'Stored encrypted; never returned in full.'}
                      </span>
                    </label>
                  )}
                </div>
              ))}
            </div>

            <h3 className="recipient-section-title">WHEN</h3>
            <label className="field">Delivery
              <select
                value={draft.delivery_mode}
                onChange={(e) => setDraft({ ...draft, delivery_mode: e.target.value as RecipientDeliveryMode })}
              >
                <option value="daily">Daily digest (recommended)</option>
                <option value="hourly">Hourly batch</option>
                <option value="immediate">Immediate</option>
              </select>
              {draft.delivery_mode === 'immediate' && (
                <span className="hint">Recommended for Critical / CVE watchlist only. Events in one delivery round are batched into a single message per destination.</span>
              )}
            </label>
            {draft.delivery_mode === 'daily' && (
              <label className="field">Digest time (HH:MM, server local)
                <input
                  type="time"
                  value={draft.digest_time}
                  onChange={(e) => setDraft({ ...draft, digest_time: e.target.value })}
                />
              </label>
            )}

            <h3 className="recipient-section-title">HOW MUCH</h3>
            <details className="notif-explain">
              <summary>Advanced (rate cap, dedupe{(draft.delivery_mode === 'daily') ? '' : ', quiet hours'})</summary>
              <div className="form-grid" style={{ marginTop: 10 }}>
                <label className="field">Max messages / hour
                  <input
                    type="number"
                    min={1}
                    max={500}
                    value={draft.max_per_hour}
                    onChange={(e) => setDraft({ ...draft, max_per_hour: Number(e.target.value) || 1 })}
                  />
                  <span className="hint">Overflow rolls into the next digest.</span>
                </label>
                <label className="field">Dedupe window (seconds)
                  <input
                    type="number"
                    min={0}
                    max={86400}
                    value={draft.dedupe_seconds}
                    onChange={(e) => setDraft({ ...draft, dedupe_seconds: Number(e.target.value) || 0 })}
                  />
                </label>
                {(draft.delivery_mode === 'immediate' || draft.delivery_mode === 'hourly') && (
                  <>
                    <label className="field">Quiet hours start
                      <input
                        type="time"
                        value={draft.quiet_start}
                        onChange={(e) => setDraft({ ...draft, quiet_start: e.target.value })}
                      />
                    </label>
                    <label className="field">Quiet hours end
                      <input
                        type="time"
                        value={draft.quiet_end}
                        onChange={(e) => setDraft({ ...draft, quiet_end: e.target.value })}
                      />
                    </label>
                  </>
                )}
              </div>
              {(draft.delivery_mode === 'immediate' || draft.delivery_mode === 'hourly') && (
                <label className="check" style={{ marginTop: 8 }}>
                  <input
                    type="checkbox"
                    checked={draft.quiet_bypass_critical}
                    onChange={(e) => setDraft({ ...draft, quiet_bypass_critical: e.target.checked })}
                  />
                  Critical / CVE watchlist may bypass quiet hours
                </label>
              )}
            </details>

            <ErrorBox error={saveError} />
          </div>
        </Modal>
      )}
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
  /** Optional paste-your-own secret; shown once after save, never listed again. */
  custom_secret: string;
};

function emptyDraft(): WebhookDraft {
  return {
    name: '', url: '', enabled: true, event_types: [], include_record_events: false,
    rotate_secret: true, custom_secret: '',
  };
}

function draftSnapshot(d: WebhookDraft) {
  return {
    id: d.id ?? null,
    name: d.name,
    url: d.url,
    enabled: d.enabled,
    event_types: d.event_types,
    include_record_events: d.include_record_events,
    rotate_secret: d.rotate_secret,
    custom_secret: d.custom_secret,
  };
}

function WebhooksTab({ onDirtyChange }: { onDirtyChange: (d: boolean) => void }) {
  const { data, error, loading, reload } = useApi<WebhookEndpoint[]>('/webhooks');
  const [draft, setDraft] = useState<WebhookDraft | null>(null);
  const [draftBase, setDraftBase] = useState<WebhookDraft | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [revealedSecret, setRevealedSecret] = useState<{ name: string; secret: string } | null>(null);
  const [testResult, setTestResult] = useState<{ id: number; result: WebhookTestResult } | null>(null);
  const [pending, setPending] = useState<string | null>(null);

  const draftDirty = !!draft && !!draftBase
    && JSON.stringify(draftSnapshot(draft)) !== JSON.stringify(draftSnapshot(draftBase));
  useReportDirty(draftDirty, onDirtyChange);

  // Modal already confirms when dirty; Cancel mirrors that. Closing after confirm just clears state.
  const closeDraft = () => { setDraft(null); setDraftBase(null); };

  const openCreate = () => {
    const d = emptyDraft();
    setSaveError(null);
    setDraft(d);
    setDraftBase({ ...d, event_types: [...d.event_types] });
  };

  const openEdit = (h: WebhookEndpoint) => {
    const d: WebhookDraft = {
      id: h.id,
      name: h.name,
      url: h.url,
      enabled: h.enabled,
      event_types: [...h.event_types],
      include_record_events: h.include_record_events,
      rotate_secret: false,
      custom_secret: '',
    };
    setSaveError(null);
    setDraft(d);
    setDraftBase({ ...d, event_types: [...d.event_types] });
  };

  const saveDraft = async () => {
    if (!draft || saving) return;
    setSaving(true);
    setSaveError(null);
    try {
      const pasted = draft.custom_secret.trim();
      const payload: Record<string, unknown> = {
        name: draft.name.trim(),
        url: draft.url.trim(),
        enabled: draft.enabled,
        event_types: draft.event_types.length ? draft.event_types : null,
        include_record_events: draft.include_record_events,
      };
      if (pasted) {
        payload.secret = pasted;
      } else if (draft.rotate_secret) {
        payload.rotate_secret = true;
      }
      let out: WebhookEndpoint;
      if (draft.id != null) {
        out = await patch<WebhookEndpoint>(`/webhooks/${draft.id}`, payload);
      } else {
        out = await post<WebhookEndpoint>('/webhooks', payload);
      }
      closeDraft();
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
        <button className="btn primary sm" onClick={openCreate}>Add webhook</button>
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
                  <td>
                    <strong>{h.name}</strong>
                    {h.group_managed && (
                      <span className="badge muted" style={{ marginLeft: 6 }} title="Receives only events routed by a recipient group">
                        Group
                      </span>
                    )}
                  </td>
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
                    {testResult?.id === h.id ? (
                      <div className={`alert ${testResult.result.ok ? 'ok' : 'error'}`}>
                        Test: {testResult.result.ok ? `OK (${testResult.result.latency_ms} ms)` : testResult.result.error}
                      </div>
                    ) : h.last_error ? (
                      <span className="badge high" title={[h.last_error, h.last_error_at ? relTime(h.last_error_at) : ''].filter(Boolean).join(' · ')}>
                        {h.last_error.slice(0, 48)}
                        {h.last_error_at ? ` · ${relTime(h.last_error_at)}` : ''}
                      </span>
                    ) : '—'}
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
              <button className="btn ghost" onClick={() => confirmDiscard(draftDirty) && closeDraft()}>Cancel</button>
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
                onChange={(e) => {
                  setDraft({ ...draft, url: e.target.value });
                  if (saveError) setSaveError(null);
                }}
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
              <input
                type="checkbox"
                checked={draft.rotate_secret && !draft.custom_secret.trim()}
                disabled={!!draft.custom_secret.trim()}
                onChange={(e) => setDraft({ ...draft, rotate_secret: e.target.checked })}
              />
              {draft.id != null ? 'Rotate signing secret' : 'Generate signing secret'}
            </label>
            <label className="field">Or paste your own secret (optional)
              <input
                type="password"
                value={draft.custom_secret}
                maxLength={200}
                autoComplete="new-password"
                placeholder={draft.id != null ? 'Leave blank to keep current' : ''}
                onChange={(e) => setDraft({
                  ...draft,
                  custom_secret: e.target.value,
                  rotate_secret: e.target.value.trim() ? false : draft.rotate_secret,
                })}
              />
              <span className="hint">Shown once after save, then never again.</span>
            </label>

            <div className="field">
              <span>Event types</span>
              <span className="hint" style={{ display: 'block', marginBottom: 6 }}>
                Leave all unchecked to receive every type (still subject to the notify-flag rule above).
              </span>
              {EVENT_CATEGORIES.map((cat) => {
                const selected = cat.types.filter((t) => draft.event_types.includes(t)).length;
                return (
                  <details key={cat.title} className="notif-explain">
                    <summary>{cat.title}{selected ? ` (${selected} selected)` : ''}</summary>
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
                );
              })}
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

