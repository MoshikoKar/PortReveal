import { Link, useSearchParams } from 'react-router-dom';
import { HttpBadge, endpointUrl, isDesktopPage, isUsefulShot, shotNote, shotUrl } from '../components/WebShots';
import { Card, ErrorBox, Loading } from '../components/ui';
import type { WebHost, WebService } from '../types';
import { relTime, useApi } from '../util';

/** One card per RDP/VNC endpoint from the latest web capture. */
function DesktopCard({ h, s, index }: { h: WebHost; s: WebService; index: number }) {
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

export default function RemoteHosts() {
  const { data, error } = useApi<{ hosts: WebHost[] }>('/web-hosts', { kind: 'remote' }, 15000);
  const [sp, setSp] = useSearchParams();
  const q = sp.get('q') ?? '';
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

  const cards = (data?.hosts ?? []).flatMap((h) =>
    h.services
      .map((s, index) => ({ h, s, index }))
      .filter(({ s }) => matches(h.hostname, h.ip, s.page.title, s.scheme, s.ports.join(' '), endpointUrl(s.page))));

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Remote desktops</h1>
          <p>RDP and VNC stills from the latest Web Capture. HTTP and RTSP interfaces stay on <Link to="/web">Web</Link>. Empty credentials only — hosts that require auth are listed without a frame.</p>
        </div>
        <input type="search" placeholder="Filter by host, IP, RDP/VNC…" value={q} onChange={(e) => update({ q: e.target.value || null }, true)} style={{ width: 260 }} />
      </div>
      <ErrorBox error={error} />
      {!data ? <Loading /> : !data.hosts.length ? (
        <Card>
          <span className="muted">No RDP or VNC captures yet. Start a Web Capture from <Link to="/scans?tab=web-captures">Scans → Web captures</Link> or a device page after a scan finds those ports.</span>
        </Card>
      ) : cards.length > 0 ? (
        <div className="host-grid">
          {cards.map(({ h, s, index }) => (
            <DesktopCard key={`${h.device_uuid}:${s.scheme}:${s.port}`} h={h} s={s} index={index} />
          ))}
        </div>
      ) : (
        <Card><span className="muted">{q ? 'No remote desktop matches the filter.' : 'No RDP or VNC endpoints in the latest captures.'}</span></Card>
      )}
    </>
  );
}
