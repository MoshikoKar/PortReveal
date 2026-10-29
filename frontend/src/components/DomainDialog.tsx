import { useState } from 'react';
import { post, put } from '../api';
import { type DomainDraft, domainBody } from '../domains';
import type { Domain, WordlistLibrary } from '../types';
import { DAYS, useApi } from '../util';
import { ErrorBox, Modal } from './ui';

/** Add / edit one domain (admin). Wordlists come from the existing library (subdomain lists only). */
export function DomainDialog({ initial, onClose, onSaved }: {
  initial: DomainDraft; onClose: () => void; onSaved: (d: Domain) => void;
}) {
  const [draft, setDraft] = useState<DomainDraft>(initial);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lib = useApi<WordlistLibrary>('/wordlists');
  const lists = (lib.data?.items ?? []).filter((w) => w.kind === 'subdomains');
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  const set = (patch: Partial<DomainDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const setSchedule = (patch: Partial<DomainDraft['schedule']>) => setDraft((d) => ({ ...d, schedule: { ...d.schedule, ...patch } }));
  const canSave = !!draft.name.trim() && (draft.wordlist_mode !== 'library' || draft.wordlist_id != null);

  const save = async () => {
    if (saving || !canSave) return;
    setSaving(true);
    setError(null);
    try {
      const body = domainBody(draft);
      const out = draft.id ? await put<Domain>(`/domains/${draft.id}`, body) : await post<Domain>('/domains', body);
      onSaved(out);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      title={draft.id ? `Edit ${initial.name}` : 'Add domain'}
      onClose={onClose}
      dirty={dirty}
      footer={<>
        <button className="btn ghost" onClick={onClose}>Cancel</button>
        <button className="btn primary" onClick={save} disabled={saving || !canSave}
          title={canSave ? undefined : 'Enter the domain name (and pick a wordlist when "From library" is selected)'}>
          {saving ? 'Saving…' : 'Save'}
        </button>
      </>}
    >
      <label className="field">Domain
        <input type="text" value={draft.name} onChange={(e) => set({ name: e.target.value })} placeholder="example.com"
          autoComplete="off" spellCheck={false} data-testid="domain-name" />
        <span className="hint">The zone to inventory. Internationalized names are stored as punycode.</span>
      </label>
      <label className="check"><input type="checkbox" checked={draft.enabled} onChange={(e) => set({ enabled: e.target.checked })} />Enabled (scheduled scans run only for enabled domains)</label>

      <fieldset className="stack" style={{ gap: 8 }}>
        <legend className="small muted">Discovery</legend>
        <label className="check" title="subfinder: certificate transparency, search engines and other public sources">
          <input type="checkbox" checked={draft.passive_enabled} onChange={(e) => set({ passive_enabled: e.target.checked })} />
          Passive enumeration (subfinder)
        </label>
        <label className="field">Wordlist brute force (dnsx)
          <select value={draft.wordlist_mode} onChange={(e) => set({ wordlist_mode: e.target.value as DomainDraft['wordlist_mode'] })}>
            <option value="none">None</option>
            <option value="library">From the Wordlists library</option>
            <option value="custom">Type subdomains</option>
          </select>
        </label>
        {draft.wordlist_mode === 'library' && (
          <label className="field">Subdomain wordlist
            <select value={draft.wordlist_id ?? ''} onChange={(e) => set({ wordlist_id: e.target.value ? Number(e.target.value) : null })}>
              <option value="">Select a list…</option>
              {lists.map((w) => <option key={w.id} value={w.id}>{w.name} ({w.entries.toLocaleString()} entries)</option>)}
            </select>
            <span className="hint">{lists.length ? 'Lists of type "subdomains" from Settings → Web capture → Wordlists.' : 'No subdomain lists yet: upload one under Settings → Web capture → Wordlists.'}</span>
          </label>
        )}
        {draft.wordlist_mode === 'custom' && (
          <label className="field">Subdomains to try
            <textarea rows={4} value={draft.custom_words} onChange={(e) => set({ custom_words: e.target.value })} placeholder={'www\nvpn\nmail\ndev.api'} spellCheck={false} />
            <span className="hint">One label per line, relative to the domain (www → www.example.com).</span>
          </label>
        )}
        <label className="check" title="Authorized AXFR from your internal DNS servers: the ground truth to compare the attacker view against">
          <input type="checkbox" checked={draft.axfr_enabled} onChange={(e) => set({ axfr_enabled: e.target.checked })} />
          Zone transfer (AXFR) from internal DNS
        </label>
        {draft.axfr_enabled && (
          <label className="field">Zone transfer servers
            <input type="text" value={draft.axfr_servers} onChange={(e) => set({ axfr_servers: e.target.value })} placeholder="192.0.2.53" spellCheck={false} />
            <span className="hint">IP addresses, comma separated. Empty: the internal resolvers below.</span>
          </label>
        )}
      </fieldset>

      <fieldset className="stack" style={{ gap: 8 }}>
        <legend className="small muted">Resolvers</legend>
        <label className="field">Internal resolvers
          <input type="text" value={draft.internal_resolvers} onChange={(e) => set({ internal_resolvers: e.target.value })} placeholder="system resolver" spellCheck={false} />
          <span className="hint">Empty: the DNS servers configured on this host.</span>
        </label>
        <label className="field">Public resolvers
          <input type="text" value={draft.public_resolvers} onChange={(e) => set({ public_resolvers: e.target.value })} placeholder="1.1.1.1, 8.8.8.8" spellCheck={false} />
        </label>
      </fieldset>

      <fieldset className="stack" style={{ gap: 8 }}>
        <legend className="small muted">Schedule</legend>
        <label className="check"><input type="checkbox" checked={draft.schedule.enabled} onChange={(e) => setSchedule({ enabled: e.target.checked })} />Scan on a schedule</label>
        {draft.schedule.enabled && (
          <>
            <label className="field">Time (server local)
              <input type="time" value={draft.schedule.time} onChange={(e) => setSchedule({ time: e.target.value })} />
            </label>
            <div className="row wrap" style={{ gap: 6 }}>
              {DAYS.map((label, i) => (
                <button key={label} type="button" className={`btn sm toggle ${draft.schedule.days.includes(i) ? 'on' : ''}`}
                  aria-pressed={draft.schedule.days.includes(i)}
                  onClick={() => setSchedule({ days: draft.schedule.days.includes(i) ? draft.schedule.days.filter((d) => d !== i) : [...draft.schedule.days, i].sort() })}>
                  {label}
                </button>
              ))}
            </div>
          </>
        )}
      </fieldset>

      <label className="field">Notes<textarea rows={2} value={draft.notes} onChange={(e) => set({ notes: e.target.value })} /></label>
      <ErrorBox error={error || lib.error} />
    </Modal>
  );
}
