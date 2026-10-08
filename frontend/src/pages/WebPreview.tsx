import { useMemo, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { WebCaptureDialog } from '../components/WebCaptureDialog';
import { RtspLivePlayer, liveStreamUrl } from '../components/RtspLivePlayer';
import { HttpBadge, KIND_LABELS, Lightbox, PageFlags, ShotTile, endpointUrl, isRtspPage, isUsefulShot, pathOf, shotNote } from '../components/WebShots';
import { Card, DeviceStatusBadge, ErrorBox, Kpi, Loading } from '../components/ui';
import { useApp } from '../context';
import type { DeviceDetail, DeviceWebInterfaces, WebPage } from '../types';
import { fmtTime, relTime, useApi } from '../util';

interface Endpoint {
  key: string;
  port: number;
  base: string;
  pages: WebPage[];   // real pages, shown as tiles
  errors: WebPage[];  // error responses, listed compactly
  server: string | null;
  tlsUnverified: boolean;
}

function groupEndpoints(pages: WebPage[]): Endpoint[] {
  const map = new Map<string, Endpoint>();
  for (const p of pages) {
    const key = `${p.scheme}:${p.port}`;
    let ep = map.get(key);
    if (!ep) {
      ep = { key, port: p.port, base: endpointUrl(p), pages: [], errors: [], server: null, tlsUnverified: false };
      map.set(key, ep);
    }
    (p.error_reason ? ep.errors : ep.pages).push(p);
    ep.server ??= p.server_header;
    ep.tlsUnverified ||= p.tls_verified === false;
  }
  const kindOrder = { home: 0, login: 1, register: 2, stream: 0, other: 3 } as const;
  const eps = [...map.values()];
  for (const ep of eps) ep.pages.sort((a, b) => kindOrder[a.kind] - kindOrder[b.kind]);
  // Endpoints with screenshots first, then ones with real pages, then error-only endpoints
  const score = (ep: Endpoint) => (ep.pages.some(isUsefulShot) ? 0 : ep.pages.length ? 1 : 2);
  return eps.sort((a, b) => score(a) - score(b) || a.port - b.port);
}

export default function WebPreview() {
  const { uuid } = useParams();
  const { isAdmin } = useApp();
  const [searchParams, setSearchParams] = useSearchParams();
  const captureParam = searchParams.get('capture');
  const [recapture, setRecapture] = useState(false);
  const [lightbox, setLightbox] = useState<number | null>(null);

  const dev = useApi<DeviceDetail>(`/devices/${uuid}`);
  const web = useApi<DeviceWebInterfaces>(`/devices/${uuid}/web-interfaces`, { capture_id: captureParam ?? undefined }, 8000);

  const pages = useMemo(() => web.data?.pages ?? [], [web.data]);
  const endpoints = useMemo(() => groupEndpoints(pages), [pages]);
  // Lightbox order follows the on-screen order
  const shots = useMemo(() => endpoints.flatMap((ep) => ep.pages.filter(isUsefulShot)), [endpoints]);

  const d = dev.data;
  const run = web.data?.captures.find((c) => c.id === web.data?.capture_id);
  const name = d ? d.hostname ?? d.current_ip : '…';
  const realPages = endpoints.reduce((n, ep) => n + ep.pages.length, 0);
  // Only count errors on ports that have no usable page (failed probes next to a live app are hidden).
  const errorCount = endpoints.reduce((n, ep) => n + (ep.pages.length ? 0 : ep.errors.length), 0);
  const hasLogin = pages.some((p) => p.kind === 'login' && !p.error_reason);
  const authRequired = pages.some((p) => p.http_status === 401 || p.http_status === 403);
  const tlsUnverified = pages.some((p) => p.tls_verified === false);
  const extRedirect = pages.some((p) => p.external_redirect);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="muted small">
            <Link to="/web">Web</Link> / {d ? <Link to={`/devices/${d.uuid}`}>{name}</Link> : name} /
          </div>
          <h1 className="row" style={{ gap: 12 }}>
            {name}
            {d && <DeviceStatusBadge status={d.status} />}
          </h1>
          <p className="mono">{d?.current_ip}{d?.hostname && d.dns_name && d.dns_name !== d.hostname && ` · ${d.dns_name}`}</p>
        </div>
        <div className="row wrap">
          {web.data && web.data.captures.length > 0 && (
            <select
              value={web.data.capture_id ?? ''}
              onChange={(e) => setSearchParams(e.target.value === String(web.data?.captures[0].id) ? {} : { capture: e.target.value })}
              aria-label="Capture"
            >
              {web.data.captures.map((c, i) => (
                <option key={c.id} value={c.id}>
                  {i === 0 ? 'Latest' : `Capture #${c.id}`} · {fmtTime(c.captured_at)} · {c.screenshot_count} shot{c.screenshot_count === 1 ? '' : 's'}{c.status === 'running' ? ' · running' : ''}
                </option>
              ))}
            </select>
          )}
          {isAdmin && d && <button className="btn primary" onClick={() => setRecapture(true)}>Capture again</button>}
        </div>
      </div>

      <ErrorBox error={dev.error ?? web.error} />
      {!web.data ? <Loading /> : !pages.length ? (
        <Card>
          <div className="stack" style={{ alignItems: 'flex-start' }}>
            <strong>No web capture for this host yet.</strong>
            <span className="muted">Web Capture probes HTTP(S) and RTSP ports found by a port scan. Run a Standard scan first if this host has no open ports in inventory.</span>
            {isAdmin && d && <button className="btn primary" onClick={() => setRecapture(true)}>Capture web interfaces</button>}
          </div>
        </Card>
      ) : (
        <>
          {run?.status === 'running' && (
            <div className="alert"><span className="spinner" style={{ verticalAlign: 'middle', marginRight: 8 }} />Capture #{run.id} is still running. New pages appear here as they are captured.</div>
          )}

          <div className="grid kpis">
            <Kpi label="Web endpoints" value={endpoints.length} sub={endpoints.map((e) => e.port).join(', ')} />
            <Kpi label="Live pages" value={realPages} sub={errorCount ? `${errorCount} error response${errorCount === 1 ? '' : 's'}` : 'no errors'} color="var(--ok)" />
            <Kpi label="Screenshots" value={shots.length} sub={run ? `captured ${relTime(run.captured_at)}` : undefined} color="var(--accent)" />
            <div className="kpi">
              <div className="label">Findings</div>
              <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
                {hasLogin && <span className="badge low">login page</span>}
                {authRequired && <span className="badge medium">auth required</span>}
                {tlsUnverified && <span className="badge outline">TLS unverified</span>}
                {extRedirect && <span className="badge medium">external redirect</span>}
                {!hasLogin && !authRequired && !tlsUnverified && !extRedirect && <span className="muted small">nothing notable</span>}
              </div>
            </div>
          </div>

          {endpoints.map((ep) => {
            const rtspPage = ep.pages.find(isRtspPage) ?? ep.errors.find(isRtspPage);
            const isRtsp = !!rtspPage;
            const livePage = ep.pages[0];
            const openLive = livePage ? (livePage.final_url || livePage.url) : ep.base;
            return (
              <Card
                key={ep.key}
                flush
                title={
                  <div className="row wrap" style={{ gap: 8 }}>
                    <h2 className="mono">{ep.base.replace(/\/$/, '')}</h2>
                    {isRtsp && <span className="badge accent">RTSP</span>}
                    {ep.server && <span className="badge outline" title="Server header">{ep.server}</span>}
                    {ep.tlsUnverified && <span className="badge outline">TLS unverified</span>}
                  </div>
                }
                actions={isRtsp ? undefined : <a className="btn sm" href={openLive} target="_blank" rel="noreferrer">Open live ↗</a>}
              >
                {isRtsp && rtspPage && (
                  <div className="card-body">
                    <RtspLivePlayer
                      src={liveStreamUrl(rtspPage.id)}
                      label={rtspPage.title ?? `RTSP :${ep.port}`}
                      posterUrl={rtspPage.has_screenshot ? `/api/web-pages/${rtspPage.id}/screenshot` : null}
                    />
                  </div>
                )}
                {ep.pages.length > 0 && (
                  <div className="shot-grid">
                    {ep.pages.map((p) => (
                      <ShotTile key={p.id} p={p} onOpen={() => setLightbox(shots.indexOf(p))} />
                    ))}
                  </div>
                )}
                {/* Hide failed home/discovery probes when a real page is already shown for this port. */}
                {ep.errors.length > 0 && ep.pages.length === 0 && (
                  <div className="error-list only">
                    <div className="muted small" style={{ marginBottom: 6 }}>No usable page on this port. It answered with:</div>
                    {ep.errors.map((p) => (
                      <div key={p.id} className="error-row">
                        <HttpBadge status={p.http_status} rtsp={isRtspPage(p)} />
                        <span className="mono small">{isRtspPage(p) ? p.url : pathOf(p.url)}</span>
                        <span className="small">{p.title ?? shotNote(p)}</span>
                        <span className="muted small">{KIND_LABELS[p.kind]} probe</span>
                        <PageFlags p={p} />
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            );
          })}
        </>
      )}

      {lightbox != null && lightbox >= 0 && shots.length > 0 && (
        <Lightbox pages={shots} index={Math.min(lightbox, shots.length - 1)} onIndex={setLightbox} onClose={() => setLightbox(null)} />
      )}
      {recapture && d && (
        <WebCaptureDialog
          preset={{ device_uuids: [d.uuid], deviceLabel: `${name} (${d.current_ip})`, lockTargets: true }}
          onClose={() => setRecapture(false)}
          onStarted={() => { setSearchParams({}); web.reload(); }}
        />
      )}
    </>
  );
}
