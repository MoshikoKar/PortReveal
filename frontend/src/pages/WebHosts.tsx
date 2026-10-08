import { useState } from 'react';
import { Link } from 'react-router-dom';
import { HttpBadge, endpointUrl, isRtspPage, isUsefulShot, shotNote, shotUrl } from '../components/WebShots';
import { Card, ErrorBox, Loading } from '../components/ui';
import type { WebHost, WebService } from '../types';
import { relTime, useApi } from '../util';

/** A host is a real "web app" if its latest capture produced at least one usable web service. */
const isApp = (h: WebHost) => h.services.length > 0;

/** One card per web service, so every app on a host is visible without opening the host. */
function ServiceCard({ h, s, index }: { h: WebHost; s: WebService; index: number }) {
  const p = s.page;
  const total = h.services.length;
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
          <HttpBadge status={p.http_status} rtsp={isRtspPage(p)} />
        </div>
        <div className="mono small muted shot-title" title={endpointUrl(p)}>
          {h.hostname && p.host_used !== h.ip ? `${h.ip} · ` : ''}{endpointUrl(p)}
        </div>
        <div className="small shot-title" title={p.title ?? undefined}>{p.title ?? <span className="muted">Untitled</span>}</div>
        <div>{s.ports.map((port) => <span className="chip" key={port}>{port}</span>)}</div>
        <div className="row wrap" style={{ gap: 6 }}>
          {s.has_login && <span className="badge low">login page</span>}
          {p.tls_verified === false && <span className="badge outline">TLS unverified</span>}
        </div>
        <div className="muted small">
          {total > 1 && <>service {index + 1} of {total} · </>}
          {s.page_count} live page{s.page_count === 1 ? '' : 's'} · {relTime(p.captured_at)}
        </div>
      </div>
    </Link>
  );
}

export default function WebHosts() {
  const { data, error } = useApi<{ hosts: WebHost[] }>('/web-hosts', undefined, 15000);
  const [q, setQ] = useState('');
  const [showNoApp, setShowNoApp] = useState(false);

  const needle = q.trim().toLowerCase();
  const matches = (...values: unknown[]) =>
    !needle || values.some((v) => v != null && String(v).toLowerCase().includes(needle));

  // Services of the same host stay next to each other (hosts keep the API's order)
  const cards = (data?.hosts ?? []).filter(isApp).flatMap((h) =>
    h.services
      .map((s, index) => ({ h, s, index }))
      .filter(({ s }) => matches(h.hostname, h.ip, s.page.title, s.page.server_header, s.ports.join(' '), endpointUrl(s.page))));
  const noApp = (data?.hosts ?? []).filter((h) =>
    !isApp(h) && matches(h.hostname, h.ip, h.hero.title, h.hero.server_header, h.ports.join(' ')));

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Web interfaces</h1>
          <p>Every web service serving a real application, from the latest Web Capture — one card per service, so a host with several apps shows each. Default server pages, errors, blank pages and redirects are set aside.</p>
        </div>
        <input type="search" placeholder="Filter by host, IP, title, port…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 260 }} />
      </div>
      <ErrorBox error={error} />
      {!data ? <Loading /> : !data.hosts.length ? (
        <Card>
          <span className="muted">No captures yet. Start one from <Link to="/scans?tab=web-captures">Scans → Web captures</Link> or from a device page.</span>
        </Card>
      ) : (
        <>
          {cards.length > 0 ? (
            <div className="host-grid">
              {cards.map(({ h, s, index }) => <ServiceCard key={`${h.device_uuid}:${s.scheme}:${s.port}`} h={h} s={s} index={index} />)}
            </div>
          ) : (
            <Card><span className="muted">{q ? 'No web application matches the filter.' : 'No host is serving a web application in the latest captures.'}</span></Card>
          )}

          {noApp.length > 0 && (
            <Card
              title={`No web application — ${noApp.length} host${noApp.length === 1 ? '' : 's'}`}
              flush
              actions={<button className="btn sm ghost" onClick={() => setShowNoApp((v) => !v)}>{showNoApp ? 'Hide' : 'Show'}</button>}
            >
              {showNoApp && (
                <table>
                  <thead><tr><th>Host</th><th>Ports</th><th>Answered with</th><th /></tr></thead>
                  <tbody>
                    {noApp.map((h) => (
                      <tr key={h.device_uuid} className="clickable" onClick={() => { window.location.href = `/devices/${h.device_uuid}/web`; }}>
                        <td>
                          <Link to={`/devices/${h.device_uuid}/web`} onClick={(e) => e.stopPropagation()}>{h.hostname ?? h.ip}</Link>
                          {h.hostname && <div className="mono small muted">{h.ip}</div>}
                        </td>
                        <td>{h.ports.map((p) => <span className="chip" key={p}>{p}</span>)}</td>
                        <td><HttpBadge status={h.hero.http_status} /> <span className="small muted">{h.hero.title ?? shotNote(h.hero)}</span></td>
                        <td className="right"><span className="muted small">{relTime(h.captured_at)}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
          )}
        </>
      )}
    </>
  );
}
