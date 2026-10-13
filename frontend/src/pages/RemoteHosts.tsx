import { useState, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { post } from '../api';
import { HttpBadge, endpointUrl, isDesktopPage, isUsefulShot, shotNote, shotUrl } from '../components/WebShots';
import { Card, ErrorBox, Loading } from '../components/ui';
import { useApp } from '../context';
import type { WebCapture, WebHost, WebService } from '../types';
import { relTime, useApi } from '../util';

type ViewFilter = 'all' | 'shots' | 'open';

type RemoteCard = { h: WebHost; s: WebService; index: number };

/** One card per RDP/VNC endpoint from the latest web capture. */
function DesktopCard({ h, s, index }: RemoteCard) {
  const p = s.page;
  const total = h.services.length;
  const scheme = (p.scheme || s.scheme || '').toLowerCase();
  return (
    <Link to={`/devices/${h.device_uuid}/web`} className="host-card">
      {isUsefulShot(p) ? (
        <div className="shot-img"><img src={shotUrl(p)} alt="" loading="lazy" /></div>
      ) : (
        <div className="shot-img shot-ph"><span>{p.screenshot_status === 'captured' ? 'No screenshot' : shotNote(p)}</span></div>
      )}
      <div className="shot-meta">
        <div className="spread">
          <strong className="shot-title">{h.hostname ?? h.ip}</strong>
          <HttpBadge status={null} desktop={isDesktopPage(p) ? scheme : scheme || 'remote'} />
        </div>
        <div className="mono small muted shot-title" title={endpointUrl(p)}>
          {h.hostname && p.host_used !== h.ip ? `${h.ip} · ` : ''}{endpointUrl(p)}
        </div>
        <div className="small shot-title" title={p.title ?? undefined}>{p.title ?? <span className="muted">Untitled</span>}</div>
        <div>{s.ports.map((port) => <span className="chip" key={port}>{port}</span>)}</div>
        <div className="muted small">
          {total > 1 && <>service {index + 1} of {total} · </>}
          {relTime(p.captured_at)}
        </div>
      </div>
    </Link>
  );
}

function Section({ title, count, children }: { title: string; count: number; children: ReactNode }) {
  if (!count) return null;
  return (
    <section style={{ marginTop: 20 }}>
      <h2 className="section-title" style={{ fontSize: '1.05rem', margin: '0 0 10px', fontWeight: 600 }}>
        {title} <span className="muted" style={{ fontWeight: 500 }}>({count})</span>
      </h2>
      {children}
    </section>
  );
}

export default function RemoteHosts() {
  const { isAdmin } = useApp();
  const { data, error, reload } = useApi<{ hosts: WebHost[] }>('/web-hosts', { kind: 'remote' }, 15000);
  const active = useApi<{ running: WebCapture[]; queued: WebCapture[] }>('/web-captures/active', undefined, 4000);
  const [sp, setSp] = useSearchParams();
  const q = sp.get('q') ?? '';
  const view = (sp.get('view') as ViewFilter) || 'all';
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const update = (patch: Record<string, string | null>, replace = false) => {
    const next = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setSp(next, { replace });
  };

  const needle = q.trim().toLowerCase();
  const matches = (...values: unknown[]) =>
    !needle || values.some((v) => v != null && String(v).toLowerCase().includes(needle));

  const cards: RemoteCard[] = (data?.hosts ?? []).flatMap((h) =>
    h.services
      .map((s, index) => ({ h, s, index }))
      .filter(({ s }) => matches(h.hostname, h.ip, s.page.title, s.scheme, s.ports.join(' '), endpointUrl(s.page), shotNote(s.page))));

  const withShot = cards.filter(({ s }) => isUsefulShot(s.page));
  const openOnly = cards.filter(({ s }) => !isUsefulShot(s.page));
  const shown = view === 'shots' ? withShot : view === 'open' ? openOnly : cards;

  const remoteJobs = [...(active.data?.running ?? []), ...(active.data?.queued ?? [])]
    .filter((c) => (c.scope || 'all') === 'remote');
  const capturing = remoteJobs.length > 0;

  const recaptureAll = async () => {
    if (busy || capturing) return;
    setBusy(true);
    setActionError(null);
    try {
      await post('/web-captures', { inventory: true, scope: 'remote' });
      await active.reload();
      await reload();
    } catch (e: any) {
      setActionError(e.message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Remote desktops</h1>
          <p>
            RDP and VNC from inventory Web Capture. HTTP and RTSP stay on <Link to="/web">Web</Link>.
            Empty credentials only — NLA / password hosts stay listed without a frame.
          </p>
        </div>
        <div className="row wrap" style={{ gap: 10, alignItems: 'center' }}>
          {isAdmin && (
            <button
              type="button"
              className="btn primary"
              disabled={busy || capturing}
              onClick={recaptureAll}
              title={capturing ? 'A remote capture is already running' : 'Queue RDP/VNC stills for every open remote port in inventory'}
            >
              {capturing ? 'Capturing remotes…' : busy ? 'Starting…' : 'Recapture remotes'}
            </button>
          )}
          <input
            type="search"
            placeholder="Filter by host, IP, RDP/VNC…"
            value={q}
            onChange={(e) => update({ q: e.target.value || null }, true)}
            style={{ width: 240 }}
          />
        </div>
      </div>

      <div className="tabs" style={{ marginBottom: 14 }}>
        <button type="button" className={view === 'all' ? 'active' : ''} onClick={() => update({ view: null })}>
          All ({cards.length})
        </button>
        <button type="button" className={view === 'shots' ? 'active' : ''} onClick={() => update({ view: 'shots' })}>
          With screenshot ({withShot.length})
        </button>
        <button type="button" className={view === 'open' ? 'active' : ''} onClick={() => update({ view: 'open' })}>
          Open · no screenshot ({openOnly.length})
        </button>
      </div>

      <ErrorBox error={error || actionError} />
      {capturing && (
        <Card>
          <span className="muted small">
            Remote capture in progress
            {remoteJobs[0]?.stage ? ` — ${remoteJobs[0].stage}` : ''}
            {remoteJobs[0] != null ? ` (${Math.round((remoteJobs[0].progress || 0) * 100)}%)` : ''}.
            {' '}<Link to="/scans?tab=web-captures">View job</Link>
          </span>
        </Card>
      )}

      {!data ? <Loading /> : !data.hosts.length ? (
        <Card>
          <span className="muted">
            No RDP or VNC captures yet.
            {isAdmin
              ? ' Use Recapture remotes to still every open RDP/VNC port in inventory, or start a Web Capture from '
              : ' Start a Web Capture from '}
            <Link to="/scans?tab=web-captures">Scans → Web captures</Link>.
          </span>
        </Card>
      ) : shown.length === 0 ? (
        <Card>
          <span className="muted">
            {q
              ? 'No remote desktop matches the filter.'
              : view === 'shots'
                ? 'No RDP/VNC endpoints have a screenshot yet.'
                : view === 'open'
                  ? 'Every listed remote already has a screenshot.'
                  : 'No RDP or VNC endpoints in the latest captures.'}
          </span>
        </Card>
      ) : view === 'all' ? (
        <>
          <Section title="With screenshot" count={withShot.length}>
            <div className="host-grid">
              {withShot.map((c) => (
                <DesktopCard key={`${c.h.device_uuid}:${c.s.scheme}:${c.s.port}`} {...c} />
              ))}
            </div>
          </Section>
          <Section title="Open · no screenshot" count={openOnly.length}>
            <div className="host-grid">
              {openOnly.map((c) => (
                <DesktopCard key={`${c.h.device_uuid}:${c.s.scheme}:${c.s.port}`} {...c} />
              ))}
            </div>
          </Section>
        </>
      ) : (
        <div className="host-grid">
          {shown.map((c) => (
            <DesktopCard key={`${c.h.device_uuid}:${c.s.scheme}:${c.s.port}`} {...c} />
          ))}
        </div>
      )}
    </>
  );
}
