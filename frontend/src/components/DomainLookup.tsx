import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { post } from '../api';
import {
  EXPOSURE_BADGE, EXPOSURE_LABELS, EXPOSURE_TIPS, FLAG_BADGE, FLAG_LABELS, FLAG_TIPS, type LookupState,
  checkLookupInput, hostingLabel, lookupView,
} from '../domains';
import type { DnsView, LookupResult } from '../types';
import { Card } from './ui';

function Records({ label, v }: { label: string; v: DnsView }) {
  const rows = [
    ...v.a.map((x) => ['A', x]), ...v.aaaa.map((x) => ['AAAA', x]), ...v.cname.map((x) => ['CNAME', x]),
  ];
  return (
    <div className="stack" style={{ gap: 2, minWidth: 0 }}>
      <div className="small muted">{label}{v.status && v.status !== 'ok' ? ` · ${v.status}` : ''}</div>
      {rows.length ? rows.map(([t, x]) => (
        <div key={`${t}-${x}`} className="mono small cell-ellipsis" title={x}><span className="muted">{t}</span> {x}</div>
      )) : <div className="muted small">no answer</div>}
    </div>
  );
}

/** Resolve one host name inside a configured domain now (admin): records, exposure, hosting, actions. */
export function DomainLookup({ domains, onChanged }: { domains: string[]; onChanged?: () => void }) {
  const [input, setInput] = useState('');
  const [state, setState] = useState<LookupState>({ status: 'idle' });
  const [actionMsg, setActionMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [acting, setActing] = useState(false);
  const view = lookupView(state);

  const run = async (e?: FormEvent) => {
    e?.preventDefault();
    setActionMsg(null);
    const invalid = checkLookupInput(input, domains);
    if (invalid) {
      setState({ status: 'invalid', message: invalid });
      return;
    }
    setState({ status: 'loading' });
    try {
      setState({ status: 'done', result: await post<LookupResult>('/domains/lookup', { hostname: input.trim() }) });
    } catch (err: any) {
      setState({ status: 'error', message: err.message });
    }
  };

  const act = async (kind: 'add' | 'scan') => {
    if (state.status !== 'done' || acting) return;
    setActing(true);
    setActionMsg(null);
    try {
      if (kind === 'add') {
        await post('/domains/lookup/add', { hostname: state.result.hostname });
        setState({ status: 'done', result: { ...state.result, in_inventory: true } });
        setActionMsg({ ok: true, text: `${state.result.hostname} added to the ${state.result.domain} inventory.` });
        onChanged?.();
      } else {
        const r = await post<{ scan_id: number; targets: string[] }>('/domains/lookup/port-scan', { hostname: state.result.hostname });
        setActionMsg({ ok: true, text: `Port scan #${r.scan_id} queued for ${r.targets.join(', ')}.` });
      }
    } catch (err: any) {
      setActionMsg({ ok: false, text: err.message });
    } finally {
      setActing(false);
    }
  };

  const r = state.status === 'done' ? state.result : null;
  return (
    <Card title="Lookup">
      <form className="row wrap" onSubmit={run} style={{ gap: 8 }}>
        <input type="search" value={input} onChange={(e) => setInput(e.target.value)} placeholder="test.example.com"
          aria-label="Host name to look up" spellCheck={false} style={{ flex: 1, minWidth: 220 }} data-testid="lookup-input" />
        <button className="btn primary" type="submit" disabled={view.busy}>{view.busy ? 'Resolving…' : 'Look up'}</button>
      </form>
      <div className="muted small" style={{ marginTop: 6 }}>
        Resolves the name now against the domain's internal and public resolvers. Works for hosts outside your networks too.
      </div>
      {view.message && <div className={`alert ${view.error ? 'error' : 'warn'}`} role={view.error ? 'alert' : 'status'} style={{ marginTop: 10 }}>{view.message}</div>}
      {r && (
        <div className="stack" style={{ marginTop: 12, gap: 10 }} data-testid="lookup-result">
          <div className="row wrap" style={{ gap: 6 }}>
            <strong className="mono">{r.hostname}</strong>
            <span className={`badge ${EXPOSURE_BADGE[r.exposure]}`} title={EXPOSURE_TIPS[r.exposure]}>{EXPOSURE_LABELS[r.exposure]}</span>
            {r.wildcard && <span className="badge medium" title="Matches the wildcard answer of the last scan">Wildcard</span>}
            {r.flags.map((f) => <span key={f} className={`badge ${FLAG_BADGE[f]}`} title={FLAG_TIPS[f]}>{FLAG_LABELS[f]}</span>)}
            <span className="muted small">in <Link to={`/domains/${r.domain_id}`}>{r.domain}</Link></span>
          </div>
          <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
            <Records label="Internal resolvers" v={r.internal} />
            <Records label="Public resolvers" v={r.public} />
            <div className="stack" style={{ gap: 2, minWidth: 0 }}>
              <div className="small muted">Hosting</div>
              {r.hosting.length ? r.hosting.map((h) => (
                <div key={h.ip} className="small cell-ellipsis" title={`${h.ip} · ${hostingLabel(h)}`}>
                  <span className="mono">{h.ip}</span>{' '}
                  {h.device_uuid ? <Link to={`/devices/${h.device_uuid}`}>{hostingLabel(h)}</Link> : <span className="muted">{hostingLabel(h)}</span>}
                </div>
              )) : <div className="muted small">-</div>}
            </div>
          </div>
          <div className="row wrap" style={{ gap: 8 }}>
            <button className="btn sm" disabled={!view.canAdd || acting} onClick={() => act('add')}
              title={r.in_inventory ? 'Already in the inventory' : undefined}>{r.in_inventory ? 'In inventory' : 'Add to inventory'}</button>
            <button className="btn sm" disabled={!view.canPortScan || acting} onClick={() => act('scan')}
              title="Queue a port scan of these addresses (scan profiles and exclusions apply)">Port scan now</button>
          </div>
        </div>
      )}
      {actionMsg && <div className={`alert ${actionMsg.ok ? 'ok' : 'error'}`} style={{ marginTop: 10 }}>{actionMsg.text}</div>}
    </Card>
  );
}
