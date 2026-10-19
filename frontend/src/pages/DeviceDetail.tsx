import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { del, post } from '../api';
import { ExposureCard, ProfileCard, RiskCard, RttCard, TagEditor, Timeline, TypeEvidenceCard, VulnPanel } from '../components/DeviceIntel';
import { EventFeed } from '../components/EventFeed';
import { ScanDialog } from '../components/ScanDialog';
import { WebCaptureDialog } from '../components/WebCaptureDialog';
import { ShotTile } from '../components/WebShots';
import { Card, DeviceStatusBadge, Empty, ErrorBox, IpAssignmentBadge, Loading, MacSourceBadge, MockBadge, NO_NAME_TIP, NO_NAME_VPN_TIP, Pager, RiskBadge, ScanStatusBadge, ScoreBadge, VulnJobBadge } from '../components/ui';
import { useApp } from '../context';
import type { ChangeEvent, DeviceDetail as Detail, DeviceWebInterfaces, Paged } from '../types';
import { SCAN_TYPE_LABELS, fmtTime, httpTitleDisplay, relTime, useApi } from '../util';

const PREVIEW_ROWS = 10;

interface ScanRow {
  scan_id: number; scan_type: 'discovery' | 'standard' | 'full'; scan_status: any; scanner_mode: string | null;
  created_at: string; ip: string; status: string; open_ports: number | null;
}

function previewRows<T>(items: T[], open: boolean): T[] {
  return open ? items : items.slice(0, PREVIEW_ROWS);
}

/** How the service label was established. nmap reports bare protocol soft matches as
 *  probed/10 too, so "fingerprinted" needs a product or version behind it. */
function IdentityBadge({ method, product, version }: { method: string | null; product: string | null; version: string | null }) {
  if (method === 'verified') {
    return <span className="badge ok" title="PortReveal confirmed the protocol with its own request">verified</span>;
  }
  if (method === 'probed' && (product || version)) {
    return <span className="badge ok" title="nmap matched a product signature">fingerprinted</span>;
  }
  if (method === 'probed') {
    return <span className="badge medium" title="nmap matched only a protocol pattern in the response; no product identified">protocol match only</span>;
  }
  if (!method && !product && !version) {
    return <span className="badge outline" title="No service identification">not identified</span>;
  }
  return <span className="badge outline" title="Guessed from the port number">port guess</span>;
}

/** Bottom bar; omitted when the list already fits in the preview. */
function SeeAllBar({ total, open, onToggle }: { total: number; open: boolean; onToggle: () => void }) {
  if (total <= PREVIEW_ROWS) return null;
  return (
    <button type="button" className="btn see-all" aria-expanded={open} onClick={onToggle}>
      {open ? 'Show less' : `See all ${total} →`}
    </button>
  );
}

export default function DeviceDetail() {
  const { uuid } = useParams();
  const { isAdmin } = useApp();
  const nav = useNavigate();
  const [scanType, setScanType] = useState<'standard' | 'full' | null>(null);
  const [webCapture, setWebCapture] = useState(false);
  const [showClosed, setShowClosed] = useState(false);
  const [portsOpen, setPortsOpen] = useState(false);
  const [scansOpen, setScansOpen] = useState(false);
  const [eventsOpen, setEventsOpen] = useState(false);
  const [evPage, setEvPage] = useState(1);
  const [scPage, setScPage] = useState(1);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  const [vulnChecking, setVulnChecking] = useState(false);
  const [vulnError, setVulnError] = useState<string | null>(null);
  const { data: d, error, reload } = useApi<Detail>(`/devices/${uuid}`, undefined, 15000);
  const events = useApi<Paged<ChangeEvent>>(`/devices/${uuid}/events`, { page: evPage, page_size: 15 }, 15000);
  const scans = useApi<Paged<ScanRow>>(`/devices/${uuid}/scans`, { page: scPage, page_size: 15 });
  const webIf = useApi<DeviceWebInterfaces>(`/devices/${uuid}/web-interfaces`, undefined, 15000);

  if (!d) return <>{error ? <ErrorBox error={error} /> : <Loading />}</>;
  const open = d.ports.filter((p) => p.is_open);
  const closed = d.ports.filter((p) => !p.is_open);
  const portRows = [...open, ...(showClosed ? closed : [])];

  const remove = async () => {
    if (removing || !confirm('Delete this device and its history? If it is still on the network it will be re-discovered as a new device.')) return;
    setRemoveError(null);
    setRemoving(true);
    try {
      await del(`/devices/${d.uuid}`);
    } catch (e: any) {
      setRemoveError(`Delete failed: ${e.message}`);
      setRemoving(false);
      return;
    }
    nav('/devices');
  };

  const checkVulnerabilities = async () => {
    if (vulnChecking) return;
    setVulnChecking(true);
    setVulnError(null);
    try {
      await post('/vuln-jobs', { device_uuids: [d.uuid] });
      await reload();
    } catch (e: any) {
      setVulnError(e.message);
    } finally {
      setVulnChecking(false);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <div className="muted small"><Link to="/devices">Devices</Link> /</div>
          <h1 className="row" style={{ gap: 12 }}>
            {d.hostname ?? d.discovery_name ?? d.current_ip}
            <DeviceStatusBadge status={d.status} failed={d.port_scan_failed} scannerHost={d.scanner_host} supersededBy={d.superseded_by} />
            <span title="Exposure score"><ScoreBadge score={d.score} /></span>
            {d.risk_scored_at && <span title="Risk score"><RiskBadge score={d.risk_score} kind="risk" /></span>}
            {d.risk_scored_at && <span title="Combined score"><RiskBadge score={d.combined_score} kind="combined" /></span>}
            {d.vuln_job && (
              <Link to="/reports#vuln-jobs" style={{ display: 'inline-flex', alignItems: 'center', lineHeight: 1 }}>
                <VulnJobBadge status={d.vuln_job.status} />
              </Link>
            )}
            {d.type && (
              <Link className={`badge ${d.type === 'unknown' ? 'outline' : 'accent'}`}
                to={`/search?q=${encodeURIComponent(`type:${d.type}`)}`}
                title={d.type_confidence != null ? `${d.type_confidence}% confidence` : undefined}>
                {d.type}
              </Link>
            )}
          </h1>
          <p className="mono">{d.current_ip}{d.mac && ` · ${d.mac}`}</p>
        </div>
        {isAdmin && (
          <div className="row">
            <button className="btn" onClick={() => setScanType('standard')}>Standard scan</button>
            <button className="btn warn" onClick={() => setScanType('full')}>Full port scan</button>
            <button className="btn" onClick={() => setWebCapture(true)}>Capture web interfaces</button>
            <button className="btn" onClick={checkVulnerabilities} disabled={vulnChecking}>
              {vulnChecking ? 'Checking…' : 'Check vulnerabilities'}
            </button>
            <button className="btn danger" onClick={remove} disabled={removing}>{removing ? 'Deleting…' : 'Delete'}</button>
          </div>
        )}
      </div>
      <ErrorBox error={removeError} />
      {d.superseded_by && (
        <div className="alert" role="status">
          Stale record: <Link to={`/devices/${d.superseded_by.uuid}`}>{d.superseded_by.label}</Link> is now active at {d.current_ip} and was seen more recently.
          This entry is probably an old identity for the same address{isAdmin ? ' and can be deleted' : ''}.
        </div>
      )}
      {d.scanner_host && (
        <div className="alert" role="status">
          {d.current_ip} is an address of the machine PortReveal scans from. A host often cannot probe itself
          (no ARP, raw packets do not loop back), so scans that miss it are not counted as missed; see the scan's notes.
        </div>
      )}
      <ErrorBox error={vulnError} />

      <div className="grid two">
        <Card title={`Network exposure - ${open.length} open port${open.length === 1 ? '' : 's'}`} flush
          actions={closed.length > 0 && <label className="check small"><input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} />show {closed.length} closed</label>}>
          {!d.last_port_scan_at && <div className="card-body muted small">This device has not been port-scanned yet (discovery only).</div>}
          {open.length === 0 && !showClosed ? <Empty>No open ports detected.</Empty> : (
            <>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Port</th><th>Service</th><th>Product / version</th><th>HTTP</th><th>Confidence</th><th>Open since</th><th>Last seen</th></tr></thead>
                  <tbody>
                    {previewRows(portRows, portsOpen).map((p) => (
                      <tr key={`${p.protocol}${p.port}`} className={p.is_open ? '' : 'dim'}>
                        <td className="mono nowrap"><strong>{p.protocol.toUpperCase()}/{p.port}</strong>{!p.is_open && <span className="badge outline" style={{ marginLeft: 6 }}>closed {fmtTime(p.closed_at)}</span>}</td>
                        <td>{p.service ?? '-'}{p.tunnel && <span className="badge outline" style={{ marginLeft: 6 }}>{p.tunnel}</span>}</td>
                        <td>
                          {[p.product, p.version].filter(Boolean).join(' ') || <span className="muted">-</span>}
                          {p.extra_info && <div className="muted small">{p.extra_info}</div>}
                          {p.cpe?.map((c) => <div key={c} className="mono muted small">{c}</div>)}
                        </td>
                        <td className="small">
                          {p.http ? (
                            <>
                              {p.http.status != null && <span className="badge outline">{p.http.status}</span>} {httpTitleDisplay(p.http.status, p.http.title) ?? <span className="muted">no title</span>}
                              {p.http.login && <span className="badge medium" style={{ marginLeft: 6 }}>login</span>}
                              {p.http.default_page && <span className="badge outline" style={{ marginLeft: 6 }}>default page</span>}
                              {p.http.server && <div className="muted">{p.http.server}</div>}
                            </>
                          ) : <span className="muted">-</span>}
                        </td>
                        <td className="small"><IdentityBadge method={p.method} product={p.product} version={p.version} />{p.confidence != null && <span className="muted"> {p.confidence}/10</span>}</td>
                        <td className="nowrap small">{fmtTime(p.opened_at)}</td>
                        <td className="nowrap small">{relTime(p.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <SeeAllBar total={portRows.length} open={portsOpen} onToggle={() => setPortsOpen((v) => !v)} />
            </>
          )}
        </Card>

        <Card title="Device">
          <dl className="dl">
            <dt>Hostname</dt><dd>{d.hostname ?? <span className="muted" title={d.vpn_s2s ? NO_NAME_VPN_TIP : NO_NAME_TIP}>-</span>}</dd>
            <dt>DNS name</dt><dd>{d.dns_name ?? '-'}</dd>
            <dt>Current IP</dt><dd className="mono">{d.current_ip} <IpAssignmentBadge value={d.ip_assignment} /></dd>
            <dt>Previous IPs</dt><dd className="mono">{d.previous_ips.length ? d.previous_ips.join(', ') : '-'}</dd>
            {d.mac && <><dt>MAC</dt><dd><span className="mono">{d.mac}</span><MacSourceBadge source={d.mac_source} /></dd></>}
            {d.vendor && <><dt>Vendor</dt><dd>{d.vendor}</dd></>}
            <dt>OS guess</dt>
            <dd>
              {d.os_name ?? '-'}
              {d.os_name && d.os_accuracy != null && d.os_accuracy < 85 && <span className="badge outline" style={{ marginLeft: 6 }}>uncertain</span>}
              {d.os_name && d.os_accuracy != null && <span className="muted small"> ({d.os_accuracy}% confidence)</span>}
              {d.os_name && d.os_source && <span className="badge outline" style={{ marginLeft: 6 }}>{d.os_source}</span>}
              {d.os_name && d.os_detected_at && (
                <span className="muted small"> · detected {relTime(d.os_detected_at)}</span>
              )}
            </dd>
            <dt>Network</dt><dd>{d.network_name ?? '-'}{d.vpn_s2s && <span className="badge outline" style={{ marginLeft: 6 }} title="Reached over a site-to-site VPN: ARP and local discovery names do not cross the routed path. To get MACs, set the site's router as the ARP source in Settings > Networks.">VPN</span>}{d.zone && <span className="badge outline" style={{ marginLeft: 6 }}>zone: {d.zone}</span>}</dd>
            <dt>Device type</dt>
            <dd>
              {d.type === 'unknown' ? <span className="muted">Unknown (low confidence)</span> : d.type ?? '-'}
              {d.type && d.type_confidence != null && <span className="muted small"> ({d.type_confidence}% confidence)</span>}
              {d.classified_at && <span className="muted small"> · classified {relTime(d.classified_at)}</span>}
            </dd>
            <dt>Local discovery name</dt>
            <dd>
              {d.discovery_name ?? <span className="muted">-</span>}
              {d.discovery_name && d.discovery_source && <span className="badge outline" style={{ marginLeft: 6 }}>{d.discovery_source}</span>}
            </dd>
            <dt>First seen</dt><dd>{fmtTime(d.first_seen)}</dd>
            <dt>Last seen</dt><dd>{fmtTime(d.last_seen)} <span className="muted">({relTime(d.last_seen)})</span></dd>
            <dt>Last port scan</dt><dd>{fmtTime(d.last_port_scan_at)}</dd>
            <dt>Last full scan</dt><dd>{d.full_scanned_at ? fmtTime(d.full_scanned_at) : 'never'}</dd>
            {d.missed_scans > 0 && <><dt>Missed scans</dt><dd>{d.missed_scans} consecutive</dd></>}
            <dt>Device ID</dt><dd className="mono small">{d.uuid}</dd>
          </dl>
        </Card>
      </div>

      <div className="grid three">
        <Card title="Tags"><TagEditor d={d} isAdmin={isAdmin} onChange={reload} /></Card>
        <ExposureCard d={d} />
        <ProfileCard d={d} isAdmin={isAdmin} onChange={reload} />
      </div>

      <div className="grid three">
        <RiskCard d={d} />
        <TypeEvidenceCard d={d} />
        <RttCard d={d} />
      </div>

      <VulnPanel d={d} isAdmin={isAdmin} onReload={reload} />

      <Card title="Web interfaces" flush
        actions={webIf.data?.pages.length ? <Link className="btn sm" to={`/devices/${d.uuid}/web`}>Open web preview →</Link> : undefined}>
        {webIf.error && <div className="card-body"><ErrorBox error={webIf.error} /></div>}
        {!webIf.data ? <Loading /> : !webIf.data.pages.length ? (
          <div className="card-body muted small">No web capture yet. Run <strong>Capture web interfaces</strong> after a port scan has found HTTP services.</div>
        ) : (() => {
          const live = webIf.data.pages.filter((p) => !p.error_reason);
          const errors = webIf.data.pages.length - live.length;
          const ports = [...new Set(webIf.data.pages.map((p) => p.port))].sort((a, b) => a - b);
          return (
            <>
              <div className="card-body muted small">
                {ports.length} web port{ports.length === 1 ? '' : 's'} ({ports.join(', ')}) · {live.length} live page{live.length === 1 ? '' : 's'}
                {errors > 0 && ` · ${errors} error response${errors === 1 ? '' : 's'}`} · captured {relTime(webIf.data.pages[0].captured_at)}
              </div>
              {live.length > 0 && (
                <div className="shot-grid" style={{ paddingTop: 0 }}>
                  {live.slice(0, 5).map((p) => (
                    <ShotTile key={p.id} p={p} onOpen={() => nav(`/devices/${d.uuid}/web`)} />
                  ))}
                </div>
              )}
            </>
          );
        })()}
      </Card>

      <div className="grid halves">
        <Card title="Change history" flush>
          <ErrorBox error={events.error} />
          {events.data ? (
            <>
              <EventFeed events={previewRows(events.data.items, eventsOpen)} empty="No changes recorded for this device." />
              <SeeAllBar total={events.data.items.length} open={eventsOpen} onToggle={() => setEventsOpen((v) => !v)} />
              <Pager page={evPage} pageSize={15} total={events.data.total} onPage={setEvPage} />
            </>
          ) : <Loading />}
        </Card>
        <div className="stack" style={{ gap: 16 }}>
          <Card title="Scan history" flush>
            {scans.data ? (!scans.data.items.length ? <Empty>No scans yet.</Empty> : (
              <>
                <table>
                  <thead><tr><th>Scan</th><th>Type</th><th>Time</th><th>IP</th><th>Result</th></tr></thead>
                  <tbody>
                    {previewRows(scans.data.items, scansOpen).map((s) => (
                      <tr key={s.scan_id}>
                        <td>#{s.scan_id} <MockBadge mode={s.scanner_mode} /></td>
                        <td>{SCAN_TYPE_LABELS[s.scan_type]}</td>
                        <td className="nowrap small">{fmtTime(s.created_at)}</td>
                        <td className="mono">{s.ip}</td>
                        <td>{s.status === 'up' ? (s.open_ports != null ? `${s.open_ports} open` : 'up') : <span className="badge medium">port scan failed</span>} <ScanStatusBadge status={s.scan_status} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <SeeAllBar total={scans.data.items.length} open={scansOpen} onToggle={() => setScansOpen((v) => !v)} />
                <Pager page={scPage} pageSize={15} total={scans.data.total} onPage={setScPage} />
              </>
            )) : <Loading />}
          </Card>
          {d.ips.length > 1 && (
            <Card title="IP address history" flush>
              <table>
                <thead><tr><th>IP</th><th>First seen</th><th>Last seen</th></tr></thead>
                <tbody>{d.ips.map((i) => <tr key={i.ip}><td className="mono">{i.ip}</td><td className="small">{fmtTime(i.first_seen)}</td><td className="small">{fmtTime(i.last_seen)}</td></tr>)}</tbody>
              </table>
            </Card>
          )}
        </div>
      </div>
      <Timeline uuid={d.uuid} />
      {scanType && (
        <ScanDialog
          preset={{ scan_type: scanType, device_uuids: [d.uuid], deviceLabel: `${d.hostname ?? d.current_ip} (${d.current_ip})`, lockTargets: true }}
          onClose={() => setScanType(null)}
          onStarted={() => nav('/scans')}
        />
      )}
      {webCapture && (
        <WebCaptureDialog
          preset={{ device_uuids: [d.uuid], deviceLabel: `${d.hostname ?? d.current_ip} (${d.current_ip})`, lockTargets: true }}
          onClose={() => setWebCapture(false)}
          onStarted={() => nav(`/devices/${d.uuid}/web`)}
        />
      )}
    </>
  );
}
