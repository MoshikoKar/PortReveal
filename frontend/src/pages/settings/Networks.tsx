import { useEffect, useState } from 'react';
import { del, post, put } from '../../api';
import { Card, Empty, ErrorBox, Modal, SkeletonRows, confirmDiscard, useReportDirty } from '../../components/ui';
import { useApp } from '../../context';
import {
  NETWORK_NAME_HINT,
  NETWORK_NAME_LEGACY_HINT,
  isLegacyNetworkName,
  networkNameError,
  trimNetworkName,
} from '../../networkName';
import type { ArpSnmp, Network } from '../../types';
import { NETWORK_ZONES, fmtTime, useApi, useInFlight } from '../../util';

function NetworkNameCharsetHint() {
  return (
    <>
      Use English letters, numbers, spaces and{' '}
      <code>-</code> <code>_</code> <code>.</code> <code>(</code> <code>)</code> only
    </>
  );
}

/** Secrets are blank unless being changed; the *_set flags say whether a stored one exists. */
type ArpDraft = {
  host: string; port: string; version: '2c' | '3'; community: string; user: string;
  auth_protocol: string; auth_key: string; priv_protocol: string; priv_key: string;
  community_set: boolean; auth_key_set: boolean; priv_key_set: boolean;
};
type Draft = { id?: number; name: string; cidr: string; description: string; enabled: boolean; zone: string; vpn_s2s: boolean; expected_countries: string[]; arp: ArpDraft | null };

const VPN_S2S_TIP = 'Mark networks reached over a site-to-site VPN. Scans use the same remote discovery speed as '
  + 'before (so a /16 still finishes in about an hour), force the routed profile even if a NIC looks local, '
  + 'and block "fast" timing so the tunnel never sees a 2000 probes/s burst. Scanning is not slowed or disabled.';
const ARP_TIP = 'ARP does not cross a router or VPN, so the scanner cannot see MAC addresses of this site. Enter the '
  + "site's router, firewall or L3 switch: each scan reads its ARP table over SNMP (read-only) and fills in MACs for "
  + 'hosts that have none. SNMP must be enabled on that device and reachable from this server (UDP 161 through the tunnel).';
const AUTH_PROTOCOLS = ['SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'MD5'];
const PRIV_PROTOCOLS: [string, string][] = [
  ['AES', 'AES-128'], ['AES256', 'AES-256 (net-snmp)'], ['AES256C', 'AES-256 (Cisco)'],
  ['AES192', 'AES-192 (net-snmp)'], ['AES192C', 'AES-192 (Cisco)'], ['3DES', '3DES'], ['DES', 'DES'],
];
const NEW_ARP: ArpDraft = {
  host: '', port: '161', version: '2c', community: '', user: '', auth_protocol: 'SHA', auth_key: '',
  priv_protocol: 'AES', priv_key: '', community_set: false, auth_key_set: false, priv_key_set: false,
};
const SECRET_KEPT = '•••••• (unchanged)';

function arpDraft(a: ArpSnmp | null): ArpDraft | null {
  if (!a) return null;
  return {
    ...NEW_ARP, host: a.host, port: String(a.port), version: a.version, user: a.user ?? '',
    auth_protocol: a.auth_protocol ?? '', priv_protocol: a.priv_protocol ?? '',
    community_set: a.community_set, auth_key_set: a.auth_key_set, priv_key_set: a.priv_key_set,
  };
}

/** API body: a blank secret is sent as null, which keeps the stored one. */
function arpBody(a: ArpDraft | null) {
  if (!a) return null;
  const secret = (v: string) => v || null;
  const base = { host: a.host.trim(), port: Number(a.port) || 161, version: a.version };
  if (a.version === '2c') return { ...base, community: secret(a.community) };
  return {
    ...base, user: a.user.trim(), auth_protocol: a.auth_protocol || null, auth_key: secret(a.auth_key),
    priv_protocol: (a.auth_protocol && a.priv_protocol) || null, priv_key: secret(a.priv_key),
  };
}

type ProbeResult = { ok: true; entries: number; in_network: number } | { ok: false; error: string };

function ArpSnmpFields({ arp, onChange, networkId, saved }: {
  arp: ArpDraft; onChange: (a: ArpDraft) => void; networkId?: number; saved: boolean;
}) {
  const [probing, setProbing] = useState(false);
  const [result, setResult] = useState<ProbeResult | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);
  const set = (patch: Partial<ArpDraft>) => { onChange({ ...arp, ...patch }); setResult(null); };
  const probe = async () => {
    if (!networkId || probing) return;
    setProbing(true); setResult(null); setProbeError(null);
    try {
      setResult(await post<ProbeResult>(`/networks/${networkId}/arp-snmp/test`));
    } catch (e: any) {
      setProbeError(e.message);
    } finally {
      setProbing(false);
    }
  };
  return (
    <div className="stack" style={{ paddingLeft: 24, gap: 10 }}>
      <div className="form-grid">
        <label className="field">Router address<input type="text" value={arp.host} onChange={(e) => set({ host: e.target.value })} placeholder="10.20.0.1 or gw.branch.local" /></label>
        <label className="field">SNMP version
          <select value={arp.version} onChange={(e) => set({ version: e.target.value as ArpDraft['version'] })}>
            <option value="2c">v2c (community)</option>
            <option value="3">v3 (user / auth / privacy)</option>
          </select>
        </label>
        <label className="field">UDP port<input type="number" min={1} max={65535} value={arp.port} onChange={(e) => set({ port: e.target.value })} /></label>
      </div>
      {arp.version === '2c' ? (
        <div className="form-grid">
          <label className="field">Read-only community
            <input type="password" value={arp.community} placeholder={arp.community_set ? SECRET_KEPT : ''} onChange={(e) => set({ community: e.target.value })} autoComplete="new-password" />
          </label>
        </div>
      ) : (
        <div className="form-grid">
          <label className="field">User<input type="text" value={arp.user} onChange={(e) => set({ user: e.target.value })} autoComplete="off" /></label>
          <label className="field">Auth protocol
            <select value={arp.auth_protocol} onChange={(e) => set({ auth_protocol: e.target.value })}>
              <option value="">None (noAuthNoPriv)</option>
              {AUTH_PROTOCOLS.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
          {arp.auth_protocol && (
            <label className="field">Auth passphrase
              <input type="password" value={arp.auth_key} placeholder={arp.auth_key_set ? SECRET_KEPT : 'at least 8 characters'} onChange={(e) => set({ auth_key: e.target.value })} autoComplete="new-password" />
            </label>
          )}
          {arp.auth_protocol && (
            <label className="field">Privacy protocol
              <select value={arp.priv_protocol} onChange={(e) => set({ priv_protocol: e.target.value })}>
                <option value="">None (authNoPriv)</option>
                {PRIV_PROTOCOLS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
              </select>
            </label>
          )}
          {arp.auth_protocol && arp.priv_protocol && (
            <label className="field">Privacy passphrase
              <input type="password" value={arp.priv_key} placeholder={arp.priv_key_set ? SECRET_KEPT : 'at least 8 characters'} onChange={(e) => set({ priv_key: e.target.value })} autoComplete="new-password" />
            </label>
          )}
        </div>
      )}
      {networkId && (
        <div className="row wrap" style={{ gap: 10 }}>
          <button type="button" className="btn sm" onClick={probe} disabled={!saved || probing}
            title={saved ? 'Read the saved router once and count its ARP entries' : 'Save first: the test uses the saved settings'}>
            {probing ? 'Testing…' : 'Test connection'}
          </button>
          {!saved && <span className="muted small">Save to test these settings.</span>}
          {result?.ok && (
            <span className="small" role="status">Read {result.entries} ARP entr{result.entries === 1 ? 'y' : 'ies'}; {result.in_network} inside this network.</span>
          )}
        </div>
      )}
      <ErrorBox error={probeError || (result && !result.ok ? `SNMP test failed: ${result.error}` : null)} />
    </div>
  );
}

const GEO_TIP = 'ISO country codes this network is expected to live in. After each scan, published DNS names and public IPs are geolocated; a country outside this list is flagged. Leave empty to skip geo checks.';

function countryLabel(code: string): string {
  try {
    const name = new Intl.DisplayNames(['en'], { type: 'region' }).of(code);
    return name && name !== code ? `${code} (${name})` : code;
  } catch {
    return code;
  }
}

function CountryChips({ codes, onChange }: { codes: string[]; onChange: (c: string[]) => void }) {
  const [typed, setTyped] = useState('');
  const add = (raw: string) => {
    const code = raw.trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(code)) return;
    if (codes.includes(code)) { setTyped(''); return; }
    onChange([...codes, code]);
    setTyped('');
  };
  return (
    <label className="field" title={GEO_TIP}>Expected countries
      <div className="row wrap" style={{ gap: 6 }}>
        {codes.map((c) => (
          <span key={c} className="badge outline" style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
            {countryLabel(c)}
            <button type="button" className="btn ghost sm" aria-label={`Remove ${c}`} onClick={() => onChange(codes.filter((x) => x !== c))}>×</button>
          </span>
        ))}
        <input type="text" value={typed} maxLength={2} placeholder="AA" aria-label="Add country code"
          style={{ width: 72 }} title={GEO_TIP}
          onChange={(e) => setTyped(e.target.value.toUpperCase())}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ',' || e.key === ' ') { e.preventDefault(); add(typed); } }}
          onBlur={() => add(typed)} />
      </div>
    </label>
  );
}

/** `onCount`: told how many networks exist whenever the list loads (the setup wizard gates on it).
 *  `onDirtyChange`: told when the add/edit dialog holds unsaved edits (Settings / setup leave guards). */
export function NetworksSettings({ compact, onCount, onDirtyChange }: {
  compact?: boolean; onCount?: (n: number) => void; onDirtyChange?: (dirty: boolean) => void;
}) {
  const { isAdmin } = useApp();
  const [showArchived, setShowArchived] = useState(false);
  const { data, error, loading, reload } = useApi<Network[]>('/networks', { include_archived: showArchived ? 'true' : undefined });
  useEffect(() => {
    if (data) onCount?.(data.filter((n) => !n.archived_at).length);
  }, [data, onCount]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [initial, setInitial] = useState<Draft | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [nameTouched, setNameTouched] = useState(false);
  const { pending, track } = useInFlight();
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  // Legacy names with other characters stay editable for other fields; only validate when the name is new or changed.
  const nameUnchanged = !!draft?.id && trimNetworkName(draft.name) === trimNetworkName(initial?.name ?? '');
  const nameErr = draft && !nameUnchanged
    ? networkNameError(draft.name, { requireNonEmpty: nameTouched })
    : null;
  const legacyName = !!draft?.id && nameUnchanged && isLegacyNetworkName(draft.name);
  const nameDescId = nameErr ? 'network-name-error' : legacyName ? 'network-name-legacy' : undefined;
  const canSave = !!draft && !!trimNetworkName(draft.name) && !nameErr && !!draft.cidr.trim()
    && (!draft.arp || !!draft.arp.host.trim());
  useReportDirty(!!draft && dirty, onDirtyChange);

  const openDraft = (d: Draft) => { setDraft(d); setInitial(d); setSaveError(null); setNameTouched(false); };
  const draftOf = (n: Network): Draft => ({
    id: n.id, name: n.name, cidr: n.cidr, description: n.description ?? '', enabled: n.enabled, zone: n.zone ?? '',
    vpn_s2s: n.vpn_s2s, expected_countries: n.expected_countries ?? [], arp: arpDraft(n.arp_snmp),
  });
  const closeDraft = () => confirmDiscard(dirty) && setDraft(null);

  const save = async () => {
    if (!draft || saving || !canSave) return;
    setSaveError(null);
    setSaving(true);
    try {
      const body = { name: draft.name, cidr: draft.cidr, description: draft.description || null, enabled: draft.enabled, zone: draft.zone || null, vpn_s2s: draft.vpn_s2s, expected_countries: draft.expected_countries, arp_snmp: arpBody(draft.arp) };
      if (draft.id) {
        // Stay open after saving an ARP source so it can be tested right away.
        const saved = await put<Network>(`/networks/${draft.id}`, body);
        if (draft.arp) openDraft(draftOf(saved));
        else setDraft(null);
      } else {
        await post('/networks', body);
        setDraft(null);
      }
      reload();
    } catch (e: any) {
      setSaveError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const remove = async (n: Network) => {
    if (pending(`net-${n.id}`)) return;
    if (!confirm(`Archive network "${n.name}"? It stops being scanned. Its devices, events and history are kept `
      + 'but hidden from default views (Devices > "Show archived networks" reveals them). You can restore it later.')) return;
    setActionError(null);
    await track(`net-${n.id}`, async () => {
      try {
        await del(`/networks/${n.id}`);
      } catch (e: any) {
        setActionError(`Could not archive "${n.name}": ${e.message}`);
        return;
      }
      reload();
    });
  };

  const restore = async (n: Network) => {
    if (pending(`net-${n.id}`)) return;
    setActionError(null);
    await track(`net-${n.id}`, async () => {
      try {
        await post(`/networks/${n.id}/restore`);
      } catch (e: any) {
        setActionError(`Could not restore "${n.name}": ${e.message}`);
        return;
      }
      reload();
    });
  };

  const resetBaseline = async (n: Network) => {
    if (pending(`net-${n.id}`)) return;
    if (!confirm(`Reset the baseline of "${n.name}"? The next complete standard scan becomes the new baseline (no alerts).`)) return;
    setActionError(null);
    await track(`net-${n.id}`, async () => {
      try {
        await post(`/networks/${n.id}/reset-baseline`);
      } catch (e: any) {
        setActionError(`Could not reset the baseline of "${n.name}": ${e.message}`);
        return;
      }
      reload();
    });
  };

  return (
    <Card
      title="Network scopes"
      flush
      actions={isAdmin && <button className="btn primary sm" onClick={() => openDraft({ name: '', cidr: '', description: '', enabled: true, zone: '', vpn_s2s: false, expected_countries: [], arp: null })}>Add network</button>}
    >
      {!compact && (
        <div className="card-body muted small" style={{ borderBottom: '1px solid var(--border)' }}>
          Reusable scan scopes (up to /16 each). Enabled networks are scanned by the daily schedule. The first complete standard
          scan of a network is its baseline and never alerts. Archiving a network keeps its findings but hides them.
          <label className="check small" style={{ marginTop: 6 }}>
            <input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} />Show archived networks
          </label>
        </div>
      )}
      <ErrorBox error={error || actionError} />
      {loading && !data ? <SkeletonRows cols={isAdmin ? 7 : 6} /> : !data?.length ? <Empty>No networks yet.</Empty> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>CIDR</th><th>Zone</th><th>Devices</th><th>Baseline</th><th>Schedule</th>{isAdmin && <th />}</tr></thead>
            <tbody>
              {data.map((n) => (
                <tr key={n.id} className={n.archived_at ? 'dim' : undefined}>
                  <td><strong>{n.name}</strong>{n.vpn_s2s && <> <span className="badge outline" title={VPN_S2S_TIP}>VPN</span></>}{n.arp_snmp && <> <span className="badge outline" title={`MACs from the ARP table of ${n.arp_snmp.host} (SNMPv${n.arp_snmp.version})`}>ARP via SNMP</span></>}{(n.expected_countries ?? []).length > 0 && <> <span className="badge outline" title="Expected countries for geo mismatch checks">{n.expected_countries.map(countryLabel).join(', ')}</span></>}{n.description && <div className="muted small">{n.description}</div>}</td>
                  <td className="mono">{n.cidr}</td>
                  <td>{n.zone ?? <span className="muted">-</span>}</td>
                  <td>{n.active_count ?? 0} active / {n.device_count ?? 0}</td>
                  <td>{n.archived_at ? <span className="muted">-</span> : n.baseline_at ? fmtTime(n.baseline_at) : <span className="badge medium">pending</span>}</td>
                  <td>{n.archived_at
                    ? <span className="badge outline" title={`Archived ${fmtTime(n.archived_at)}`}>archived</span>
                    : n.enabled ? <span className="badge ok">enabled</span> : <span className="badge outline">disabled</span>}</td>
                  {isAdmin && (
                    <td className="right nowrap">
                      {n.archived_at ? (
                        <button className="btn sm" disabled={pending(`net-${n.id}`)} onClick={() => restore(n)}>Restore</button>
                      ) : (
                        <>
                          <button className="btn ghost sm" onClick={() => openDraft(draftOf(n))}>Edit</button>
                          {n.baseline_at && <button className="btn danger sm" disabled={pending(`net-${n.id}`)} onClick={() => resetBaseline(n)}>Reset baseline</button>}
                          <button className="btn danger sm" disabled={pending(`net-${n.id}`)} onClick={() => remove(n)}>Archive</button>
                        </>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {draft && (
        <Modal
          title={draft.id ? 'Edit network' : 'Add network'}
          onClose={() => setDraft(null)}
          dirty={dirty}
          footer={<>
            <button className="btn ghost" onClick={closeDraft}>Cancel</button>
            <button className="btn primary" onClick={save} disabled={saving || !canSave}
              title={canSave ? undefined : (nameErr || 'Enter a name and a CIDR')}>{saving ? 'Saving…' : 'Save'}</button>
          </>}
        >
          <label className="field">Name
            <input type="text" value={draft.name} aria-invalid={!!nameErr} aria-describedby={nameDescId}
              onChange={(e) => { setNameTouched(true); setDraft({ ...draft, name: e.target.value }); }}
              onBlur={() => setNameTouched(true)} placeholder="Office LAN" />
            {nameErr && (
              <span id="network-name-error" className="hint" style={{ color: 'var(--high)' }} role="alert">
                {nameErr === NETWORK_NAME_HINT ? <NetworkNameCharsetHint /> : nameErr}
              </span>
            )}
            {legacyName && !nameErr && (
              <span id="network-name-legacy" className="hint">{NETWORK_NAME_LEGACY_HINT}</span>
            )}
          </label>
          <label className="field" title="IPv4, maximum size /16 (65,536 addresses). Changing it resets the baseline.">
            CIDR
            <input type="text" value={draft.cidr} onChange={(e) => setDraft({ ...draft, cidr: e.target.value })} placeholder="10.0.0.0/24"
              title="IPv4, maximum size /16 (65,536 addresses). Changing it resets the baseline." />
          </label>
          <label className="field">Description<input type="text" value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} /></label>
          <label className="field" title="Admin services and databases score higher in users, iot and guest zones. Changing it re-scores this network's devices.">
            Zone
            <select value={draft.zone} onChange={(e) => setDraft({ ...draft, zone: e.target.value })}
              title="Admin services and databases score higher in users, iot and guest zones. Changing it re-scores this network's devices.">
              <option value="">None</option>
              {NETWORK_ZONES.map((z) => <option key={z} value={z}>{z}</option>)}
            </select>
          </label>
          <label className="check"><input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />Include in the scheduled daily scan</label>
          <label className="check" title={VPN_S2S_TIP}><input type="checkbox" checked={draft.vpn_s2s} onChange={(e) => setDraft({ ...draft, vpn_s2s: e.target.checked })} />Reached over VPN (site-to-site)</label>
          <CountryChips codes={draft.expected_countries} onChange={(expected_countries) => setDraft({ ...draft, expected_countries })} />
          <label className="check" title={ARP_TIP}><input type="checkbox" checked={!!draft.arp} onChange={(e) => setDraft({ ...draft, arp: e.target.checked ? (draft.arp ?? initial?.arp ?? NEW_ARP) : null })} />Get MAC addresses from the site's router (SNMP)</label>
          {draft.arp && (
            <ArpSnmpFields arp={draft.arp} onChange={(arp) => setDraft({ ...draft, arp })} networkId={draft.id}
              saved={!!initial?.arp && JSON.stringify(draft.arp) === JSON.stringify(initial.arp)} />
          )}
          <ErrorBox error={saveError} />
        </Modal>
      )}
    </Card>
  );
}
