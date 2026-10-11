import { useEffect, useState, type MouseEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { del, get, post } from '../api';
import { EventFeed } from '../components/EventFeed';
import { ScanDialog } from '../components/ScanDialog';
import { WebCaptureDialog } from '../components/WebCaptureDialog';
import { HttpBadge, KIND_LABELS, isUsefulShot, shotNote, shotUrl } from '../components/WebShots';
import { Card, Empty, ErrorBox, Loading, MockBadge, Modal, Pager, Progress, ScanStatusBadge, SkeletonRows } from '../components/ui';
import { useApp } from '../context';
import type { Paged, Scan, SnapshotInfo, WebCapture } from '../types';
import { SCAN_TYPE_LABELS, duration, fmtTime, relTime, scanStageFraction, useApi, useInFlight } from '../util';

interface MockState { mock_active: boolean; last_step: number; steps: string[]; networks: { id: number; name: string; step: number }[] }

function IconRefresh({ spinning }: { spinning?: boolean }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
      style={spinning ? { animation: 'nf-spin 0.8s linear infinite' } : undefined} aria-hidden>
      <path d="M21 12a9 9 0 1 1-2.6-6.4" />
      <polyline points="21 3 21 9 15 9" />
    </svg>
  );
}

function IconStop() {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <rect x="6" y="6" width="12" height="12" rx="1.5" />
    </svg>
  );
}

function ScanScope({ s }: { s: Scan }) {
  const scope = s.network_name
    ? <span>{s.network_name}</span>
    : (() => {
        const t = s.targets ?? '';
        return <span className="mono small" title={t}>{t.length > 40 ? `${t.slice(0, 40)}…` : t || '—'}</span>;
      })();
  return (
    <>
      {scope}
      {s.criteria && <div className="muted small" title={s.criteria}>{s.criteria}</div>}
    </>
  );
}

function CaptureTargets({ c }: { c: WebCapture }) {
  const t = c.targets ?? '';
  return (
    <>
      <span className="mono small" title={t}>{t.length > 40 ? `${t.slice(0, 40)}…` : t || '—'}</span>
      {c.target_count > 1 && <div className="muted small">{c.target_count.toLocaleString()} addresses</div>}
    </>
  );
}

export default function Scans() {
  const { isAdmin, system, refreshSystem } = useApp();
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = searchParams.get('tab') === 'web-captures' ? 'web-captures' : 'scans';
  const [dialog, setDialog] = useState(false);
  const [wcDialog, setWcDialog] = useState(false);
  const [wcPage, setWcPage] = useState(1);
  const [wcDetail, setWcDetail] = useState<WebCapture | null>(null);
  // History page and the open scan's id live in the URL, so reload/Back/shared links keep them.
  const page = Math.max(1, Number.parseInt(searchParams.get('page') ?? '', 10) || 1);
  const detailId = Number.parseInt(searchParams.get('scan') ?? '', 10) || null;
  const setParam = (key: string, value: string | null, replace = false) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value == null) next.delete(key);
      else next.set(key, value);
      return next;
    }, { replace });
  };
  const setPage = (p: number) => setParam('page', p > 1 ? String(p) : null);
  const [detail, setDetail] = useState<Scan | null>(null);
  const [snapPage, setSnapPage] = useState(1);
  // Poll fast only while something is running or queued (here or per the app-wide status poll, which
  // also catches scheduled scans); idle pages refresh slowly. Web-capture endpoints load only on their tab.
  const [scansBusy, setScansBusy] = useState(false);
  const scanPoll = scansBusy || !!system?.scans.current || !!system?.scans.queued;
  const active = useApi<{ running: Scan[]; queued: Scan[] }>('/scans/active', undefined, scanPoll ? 2500 : 15000);
  const history = useApi<Paged<Scan>>('/scans', { page, page_size: 25 }, scanPoll ? 5000 : 30000);
  const snaps = useApi<Paged<SnapshotInfo>>('/snapshots', { page: snapPage, page_size: 10 }, 30000);
  const mock = useApi<MockState>(system?.scanner.mock_active ? '/dev/mock' : null, undefined, 5000);
  const onWcTab = tab === 'web-captures';
  const wcHistory = useApi<Paged<WebCapture>>(onWcTab ? '/web-captures' : null, { page: wcPage, page_size: 20 }, 5000);
  const wcActive = useApi<{ running: WebCapture[]; queued: WebCapture[] }>(onWcTab ? '/web-captures/active' : null, undefined, 4000);
  useEffect(() => {
    if (active.data) setScansBusy(active.data.running.length + active.data.queued.length > 0);
  }, [active.data]);
  const [err, setErr] = useState<string | null>(null);

  const [rerunBusy, setRerunBusy] = useState<number | null>(null);
  // Stop/cancel/delete buttons stay disabled while their request is in flight.
  const { pending, track } = useInFlight();
  const onStarted = () => { active.reload(); history.reload(); refreshSystem(); };

  const stopScan = async (id: number, e?: MouseEvent) => {
    e?.stopPropagation();
    if (pending(`stop-${id}`)) return;
    if (!confirm(`Stop scan #${id}? Its results so far are discarded and no inventory changes are applied.`)) return;
    setErr(null);
    await track(`stop-${id}`, async () => {
      try {
        await post(`/scans/${id}/cancel`);
        active.reload();
        history.reload();
        refreshSystem();
      } catch (err: any) {
        setErr(err.message);
      }
    });
  };

  const runAgain = async (s: Scan, e?: MouseEvent) => {
    e?.stopPropagation();
    if (system?.scanner.mode === 'unavailable') {
      setErr('Scanner unavailable');
      return;
    }
    const scope = s.network_name ?? s.targets ?? 'the same targets';
    const deep = s.scan_type === 'full' ? '\n\nThis is a deep scan of every port and can take a long time on large networks.' : '';
    if (!confirm(`Run a ${SCAN_TYPE_LABELS[s.scan_type]} scan of ${scope} again?${deep}`)) return;
    setErr(null);
    setRerunBusy(s.id);
    try {
      const body: Record<string, unknown> = { scan_type: s.scan_type };
      if (s.network_id != null) body.network_ids = [s.network_id];
      else if (s.targets) body.targets = s.targets;
      else throw new Error('This scan has no targets to repeat');
      if (s.criteria) body.criteria = s.criteria;
      await post<{ scans: Scan[] }>('/scans', body);
      onStarted();
    } catch (err: any) {
      setErr(err.message);
    } finally {
      setRerunBusy(null);
    }
  };

  const isActiveStatus = (status: Scan['status']) => status === 'queued' || status === 'running';

  const openDetail = (id: number) => setParam('scan', String(id));
  const closeDetail = () => setParam('scan', null, true);
  useEffect(() => {
    if (!detailId) {
      setDetail(null);
      return;
    }
    let live = true;
    setErr(null);
    get<Scan>(`/scans/${detailId}`).then(
      (d) => live && setDetail(d),
      (e: any) => {
        if (!live) return;
        setErr(`Could not open scan #${detailId}: ${e.message}`);
        setParam('scan', null, true);
      },
    );
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- refetch only when the URL's scan id changes
  }, [detailId]);
  const onWcStarted = () => { wcHistory.reload(); wcActive.reload(); };
  const running = active.data?.running ?? [];
  const queued = active.data?.queued ?? [];

  const wcCancel = async (id: number) => {
    if (pending(`wc-cancel-${id}`)) return;
    if (!confirm(`Cancel Web Capture job #${id}? Pages captured so far are kept.`)) return;
    setErr(null);
    await track(`wc-cancel-${id}`, async () => {
      try {
        await post(`/web-captures/${id}/cancel`);
        wcActive.reload();
        wcHistory.reload();
      } catch (e: any) {
        setErr(e.message);
      }
    });
  };
  const wcDelete = async (id: number) => {
    if (pending(`wc-delete-${id}`)) return;
    if (!confirm('Delete this Web Capture job and all its screenshots?')) return;
    setErr(null);
    await track(`wc-delete-${id}`, async () => {
      try {
        await del(`/web-captures/${id}`);
        wcHistory.reload();
        setWcDetail(null);
      } catch (e: any) {
        setErr(e.message);
      }
    });
  };
  const resetMock = async () => {
    if (pending('mock-reset')) return;
    if (!confirm('Reset the mock scanner scenario to its first step?')) return;
    setErr(null);
    await track('mock-reset', async () => {
      try {
        await post('/dev/mock/reset');
        mock.reload();
      } catch (e: any) {
        setErr(`Could not reset the mock scenario: ${e.message}`);
      }
    });
  };
  const openWcDetail = async (id: number) => {
    setErr(null);
    try {
      setWcDetail(await get<WebCapture>(`/web-captures/${id}`));
    } catch (e: any) {
      setErr(`Could not open Web Capture job #${id}: ${e.message}`);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Scans & jobs</h1>
          <p>Network scans and on-demand Web Capture jobs (inventory enrichment for known HTTP services).</p>
        </div>
        {isAdmin && tab === 'scans' && (
          <button
            className="btn primary"
            onClick={() => setDialog(true)}
            disabled={system?.scanner.mode === 'unavailable'}
            title={system?.scanner.mode === 'unavailable' ? `Scanner unavailable: ${system.scanner.message}` : undefined}
          >
            Scan now
          </button>
        )}
        {isAdmin && tab === 'web-captures' && (
          <button className="btn primary" onClick={() => setWcDialog(true)}>Web capture</button>
        )}
      </div>
      <nav className="tabs">
        <button className={tab === 'scans' ? 'active' : ''} onClick={() => setSearchParams({})}>Network scans</button>
        <button className={tab === 'web-captures' ? 'active' : ''} onClick={() => setSearchParams({ tab: 'web-captures' })}>Web captures</button>
      </nav>
      <ErrorBox error={err} />

      {tab === 'web-captures' && (
        <>
          <Card title="Active Web Capture jobs" flush>
            {wcActive.error && (
              <div className="card-body stack">
                <ErrorBox error={wcActive.error} />
                <div><button type="button" className="btn sm" onClick={() => wcActive.reload()}>Retry</button></div>
              </div>
            )}
            {!wcActive.data ? (
              wcActive.error ? null : <SkeletonRows cols={isAdmin ? 6 : 5} rows={3} />
            ) : !wcActive.data.running.length && !wcActive.data.queued.length ? (
              wcActive.error ? null : <Empty>No Web Capture running or queued.</Empty>
            ) : (
              <div className="table-wrap">
              <table>
                <thead><tr><th>#</th><th>Targets</th><th>Status</th><th>Progress</th><th>Started</th>{isAdmin && <th />}</tr></thead>
                <tbody>
                  {[...wcActive.data.running, ...wcActive.data.queued].map((c) => (
                    <tr key={c.id}>
                      <td>{c.id}</td>
                      <td><CaptureTargets c={c} /></td>
                      <td><ScanStatusBadge status={c.status as any} /></td>
                      <td>{c.status === 'running' ? <Progress value={c.progress} /> : <span className="muted small">queued</span>}</td>
                      <td className="small">{fmtTime(c.started_at ?? c.created_at)}</td>
                      {isAdmin && (
                        <td className="right">
                          <button className="btn danger sm" disabled={pending(`wc-cancel-${c.id}`)} onClick={() => wcCancel(c.id)}>
                            {pending(`wc-cancel-${c.id}`) ? 'Cancelling…' : 'Cancel'}
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}
          </Card>
          <Card title="Web Capture history" flush>
            {wcHistory.data ? (!wcHistory.data.items.length ? <Empty>No Web Capture jobs yet.</Empty> : (
              <>
                <div className="table-wrap">
                <table>
                  <thead><tr><th>#</th><th>Targets</th><th>Status</th><th>Pages</th><th>Shots</th><th>Finished</th><th /></tr></thead>
                  <tbody>
                    {wcHistory.data.items.map((c) => (
                      <tr key={c.id}>
                        <td>{c.id}{c.mock_mode && <MockBadge mode="mock" />}</td>
                        <td><CaptureTargets c={c} /></td>
                        <td><ScanStatusBadge status={c.status as any} /></td>
                        <td>{c.pages_captured}</td>
                        <td>{c.screenshots_captured}</td>
                        <td className="small">{fmtTime(c.finished_at)}</td>
                        <td className="right">
                          <button className="btn sm" onClick={() => openWcDetail(c.id)}>Details</button>
                          {isAdmin && c.status !== 'running' && c.status !== 'queued' && (
                            <button className="btn danger sm" style={{ marginLeft: 6 }} disabled={pending(`wc-delete-${c.id}`)} onClick={() => wcDelete(c.id)}>
                              {pending(`wc-delete-${c.id}`) ? 'Deleting…' : 'Delete'}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                </div>
                <Pager page={wcPage} pageSize={20} total={wcHistory.data.total} onPage={setWcPage} />
              </>
            )) : <Loading />}
          </Card>
          {wcDialog && <WebCaptureDialog onClose={() => setWcDialog(false)} onStarted={onWcStarted} />}
          {wcDetail && (
            <Modal title={`Web Capture #${wcDetail.id}`} onClose={() => setWcDetail(null)}>
              <dl className="dl">
                <dt>Status</dt><dd><ScanStatusBadge status={wcDetail.status as any} /></dd>
                <dt>Targets</dt><dd className="mono">{wcDetail.targets}</dd>
                <dt>Endpoints</dt><dd>{wcDetail.endpoints_found}</dd>
                <dt>Pages</dt><dd>{wcDetail.pages_captured} · {wcDetail.screenshots_captured} screenshots</dd>
                <dt>Requested by</dt><dd>{wcDetail.requested_by ?? '—'}</dd>
              </dl>
              {wcDetail.notes && <div className="alert" style={{ whiteSpace: 'pre-wrap' }}>{wcDetail.notes}</div>}
              {wcDetail.pages && wcDetail.pages.length > 0 && (
                <div className="table-wrap">
                <table>
                  <thead><tr><th>IP:port</th><th>Kind</th><th>Title</th><th>Preview</th></tr></thead>
                  <tbody>
                    {wcDetail.pages.map((p) => {
                      const preview = p.device_uuid ? `/devices/${p.device_uuid}/web?capture=${wcDetail.id}` : null;
                      return (
                        <tr key={p.id} className={p.error_reason ? 'dim' : ''}>
                          <td className="mono nowrap">{preview ? <Link to={preview}>{p.ip}:{p.port}</Link> : `${p.ip}:${p.port}`}</td>
                          <td>{KIND_LABELS[p.kind] ?? p.kind}</td>
                          <td>{p.title ?? '—'} <HttpBadge status={p.http_status} /></td>
                          <td>
                            {isUsefulShot(p) && preview ? (
                              <Link to={preview}><img src={shotUrl(p)} alt="" loading="lazy" className="thumb" /></Link>
                            ) : <span className="muted small">{shotNote(p)}</span>}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                </div>
              )}
            </Modal>
          )}
        </>
      )}

      {tab === 'scans' && (
        <>

      <Card title="Active scans" flush>
        {active.error && (
          <div className="card-body stack">
            <ErrorBox error={active.error} />
            <div><button type="button" className="btn sm" onClick={() => active.reload()}>Retry</button></div>
          </div>
        )}
        {!active.data ? (
          active.error ? null : <SkeletonRows cols={isAdmin ? 8 : 7} rows={3} />
        ) : !running.length && !queued.length ? (
          active.error ? null : <Empty>No scan running or queued.</Empty>
        ) : (
          <div className="table-wrap">
          <table>
            <thead><tr><th>#</th><th>Type</th><th>Scope</th><th>Status</th><th style={{ width: '28%' }}>Progress</th><th>Hosts</th><th>Started</th>{isAdmin && <th />}</tr></thead>
            <tbody>
              {[...running, ...queued].map((s) => (
                <tr key={s.id}>
                  <td>{s.id}</td>
                  <td>{SCAN_TYPE_LABELS[s.scan_type]} {s.scan_type === 'full' && <span className="badge medium">deep</span>} <MockBadge mode={s.scanner_mode} /></td>
                  <td><ScanScope s={s} /><div className="muted small">{s.target_count.toLocaleString()} addresses · {s.trigger}</div></td>
                  <td><ScanStatusBadge status={s.status} /></td>
                  <td>{s.status === 'running' ? <><Progress value={s.progress} /><div className="muted small" style={{ marginTop: 4 }}>{s.stage} · {Math.round(scanStageFraction(s) * 100)}% of stage</div></> : <span className="muted small">waiting for the current scan</span>}</td>
                  <td className="small">{s.hosts_discovered} found · {s.hosts_scanned} scanned</td>
                  <td className="small">{s.started_at ? `${fmtTime(s.started_at)} (${duration(s.started_at, null)})` : fmtTime(s.created_at)}</td>
                  {isAdmin && (
                    <td className="right">
                      <button className="btn danger icon sm" title="Stop scan" aria-label="Stop scan" disabled={pending(`stop-${s.id}`)} onClick={() => stopScan(s.id)}>
                        <IconStop />
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </Card>

      {mock.data?.mock_active && (
        <Card title="Mock scanner scenario (development)" actions={isAdmin && (
          <button className="btn danger sm" disabled={pending('mock-reset')} onClick={resetMock}>
            {pending('mock-reset') ? 'Resetting…' : 'Reset scenario'}
          </button>
        )}>
          <div className="stack" style={{ gap: 6 }}>
            <div className="muted small">Each completed network scan advances the simulated network one step. Results pass through the same comparison engine as real nmap data.</div>
            {mock.data.networks.map((n) => (
              <div key={n.id}><strong>{n.name}</strong>: next scan is step {n.step}/{mock.data!.last_step} — <span className="muted">{mock.data!.steps[n.step]}</span></div>
            ))}
          </div>
        </Card>
      )}

      <Card title="Scan history" flush>
        <ErrorBox error={history.error} />
        {!history.data ? <SkeletonRows cols={isAdmin ? 10 : 9} /> : !history.data.items.length ? <Empty>No scans yet.</Empty> : (
          <>
            <div className="table-wrap">
              <table>
                <thead><tr><th>#</th><th>Type</th><th>Scope</th><th>Status</th><th>Started</th><th>Duration</th><th>Hosts</th><th>Changes</th><th>By</th>{isAdmin && <th />}</tr></thead>
                <tbody>
                  {history.data.items.map((s) => (
                    <tr key={s.id} className="clickable" onClick={() => openDetail(s.id)}>
                      <td>{s.id}</td>
                      <td className="nowrap">{SCAN_TYPE_LABELS[s.scan_type]} <MockBadge mode={s.scanner_mode} /></td>
                      <td><ScanScope s={s} /></td>
                      <td className="nowrap"><ScanStatusBadge status={s.status} />{s.is_baseline && <span className="badge accent" style={{ marginLeft: 4 }}>baseline</span>}</td>
                      <td className="nowrap small" title={fmtTime(s.started_at, true)}>{s.started_at ? relTime(s.started_at) : '—'}</td>
                      <td className="small">{duration(s.started_at, s.finished_at)}</td>
                      <td className="small">{s.hosts_discovered}{s.hosts_failed > 0 && <span style={{ color: 'var(--medium)' }}> ({s.hosts_failed} failed)</span>}</td>
                      <td>{s.events_count}</td>
                      <td className="small muted">{s.trigger === 'scheduled' ? 'schedule' : s.trigger === 'presence' ? 'presence' : s.requested_by}</td>
                      {isAdmin && (
                        <td className="right nowrap" onClick={(e) => e.stopPropagation()}>
                          {isActiveStatus(s.status) ? (
                            <button className="btn danger icon sm" title="Stop scan" aria-label="Stop scan" disabled={pending(`stop-${s.id}`)} onClick={(e) => stopScan(s.id, e)}>
                              <IconStop />
                            </button>
                          ) : (
                            <button
                              className="btn icon sm"
                              title="Run again"
                              aria-label="Run again"
                              disabled={rerunBusy === s.id || system?.scanner.mode === 'unavailable'}
                              onClick={(e) => runAgain(s, e)}
                            >
                              <IconRefresh spinning={rerunBusy === s.id} />
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={page} pageSize={25} total={history.data.total} onPage={setPage} />
          </>
        )}
      </Card>

      <Card title="Daily snapshots" flush>
        <div className="card-body muted small" style={{ borderBottom: '1px solid var(--border)' }}>
          One compact copy of the normalized network state per network per day, kept for the retention period.
        </div>
        {!snaps.data ? <Loading /> : !snaps.data.items.length ? <Empty>No snapshots yet (created after each successful standard network scan).</Empty> : (
          <>
            <div className="table-wrap">
            <table>
              <thead><tr><th>Date</th><th>Network</th><th>Active / total</th><th>Open ports</th><th>Size</th><th /></tr></thead>
              <tbody>
                {snaps.data.items.map((s) => (
                  <tr key={s.id}>
                    <td>{s.snapshot_date}</td>
                    <td>{s.network_name}</td>
                    <td>{s.hosts_active} / {s.hosts_total}</td>
                    <td>{s.open_ports}</td>
                    <td className="small muted">{(s.size_bytes / 1024).toFixed(1)} KB</td>
                    <td className="right"><a href={`/api/snapshots/${s.id}`} target="_blank" rel="noreferrer" className="small">JSON</a></td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
            <Pager page={snapPage} pageSize={10} total={snaps.data.total} onPage={setSnapPage} />
          </>
        )}
      </Card>

      {dialog && <ScanDialog onClose={() => setDialog(false)} onStarted={onStarted} />}
        </>
      )}
      {tab === 'scans' && detail && (
        <Modal title={`Scan #${detail.id}`} onClose={closeDetail}>
          <dl className="dl">
            <dt>Type</dt><dd>{SCAN_TYPE_LABELS[detail.scan_type]} · {detail.trigger} {detail.is_baseline && <span className="badge accent">baseline</span>}</dd>
            <dt>Status</dt><dd><ScanStatusBadge status={detail.status} /></dd>
            <dt>Scanner</dt><dd>{detail.scanner_mode ?? '—'} <MockBadge mode={detail.scanner_mode} /></dd>
            <dt>Scope</dt><dd><ScanScope s={detail} /> · {detail.target_count.toLocaleString()} addresses (after exclusions)</dd>
            <dt>Started</dt><dd>{fmtTime(detail.started_at, true)}</dd>
            <dt>Finished</dt><dd>{fmtTime(detail.finished_at, true)} ({duration(detail.started_at, detail.finished_at)})</dd>
            <dt>Hosts</dt><dd>{detail.hosts_discovered} discovered · {detail.hosts_scanned} port-scanned · {detail.hosts_failed} failed</dd>
            <dt>Requested by</dt><dd>{detail.requested_by ?? '—'}</dd>
          </dl>
          {detail.error && <div className="alert error">{detail.error}</div>}
          {detail.notes && <div className="alert" style={{ whiteSpace: 'pre-wrap' }}>{detail.notes}</div>}
          {isAdmin && (
            <div className="row" style={{ marginBottom: 12, gap: 8 }}>
              {isActiveStatus(detail.status) ? (
                <button className="btn danger icon" title="Stop scan" aria-label="Stop scan" disabled={pending(`stop-${detail.id}`)} onClick={() => stopScan(detail.id)}>
                  <IconStop />
                </button>
              ) : (
                <button
                  className="btn icon primary"
                  title="Run again"
                  aria-label="Run again"
                  disabled={rerunBusy === detail.id || system?.scanner.mode === 'unavailable'}
                  onClick={() => runAgain(detail)}
                >
                  <IconRefresh spinning={rerunBusy === detail.id} />
                </button>
              )}
            </div>
          )}
          <h3>Changes ({detail.events_count})</h3>
          <div className="card"><EventFeed events={detail.events ?? []} empty="No changes in this scan." /></div>
          {detail.events_count > 0 && <Link to={`/changes?range=all`} onClick={() => setDetail(null)}>Open Changes →</Link>}
        </Modal>
      )}
    </>
  );
}
