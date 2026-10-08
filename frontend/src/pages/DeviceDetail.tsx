import { Fragment, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { del, patch } from '../api';
import { EventFeed } from '../components/EventFeed';
import { ScanDialog } from '../components/ScanDialog';
import { WebCaptureDialog } from '../components/WebCaptureDialog';
import { ShotTile } from '../components/WebShots';
import { Card, DeviceStatusBadge, Empty, ErrorBox, FlagChips, Loading, MockBadge, Pager, ScanStatusBadge, vendorLabel } from '../components/ui';
import { useApp } from '../context';
import type { ChangeEvent, DeviceDetail as Detail, DeviceWebInterfaces, Paged } from '../types';
import { SCAN_TYPE_LABELS, fmtTime, relTime, useApi } from '../util';

interface ScanRow {
  scan_id: number; scan_type: 'discovery' | 'standard' | 'full'; scan_status: any; scanner_mode: string | null;
  created_at: string; ip: string; status: string; open_ports: number | null;
}

export default function DeviceDetail() {
  const { uuid } = useParams();
  const { isAdmin } = useApp();
  const nav = useNavigate();
  const [scanType, setScanType] = useState<'standard' | 'full' | null>(null);
  const [webCapture, setWebCapture] = useState(false);
  const [showClosed, setShowClosed] = useState(false);
  const [evPage, setEvPage] = useState(1);
  const [scPage, setScPage] = useState(1);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  const { data: d, error, reload } = useApi<Detail>(`/devices/${uuid}`, undefined, 15000);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [rawPort, setRawPort] = useState<string | null>(null);
  const [rawHost, setRawHost] = useState(false);
  const events = useApi<Paged<ChangeEvent>>(`/devices/${uuid}/events`, { page: evPage, page_size: 25 }, 15000);
  const scans = useApi<Paged<ScanRow>>(`/devices/${uuid}/scans`, { page: scPage, page_size: 15 });
  const webIf = useApi<DeviceWebInterfaces>(`/devices/${uuid}/web-interfaces`, undefined, 15000);

  if (!d) return <>{error ? <ErrorBox error={error} /> : <Loading />}</>;
  const open = d.ports.filter((p) => p.is_open);
  const id = d.identity;
  const flags = [...new Set([...d.flags, ...open.flatMap((p) => p.flags)])];
  const reported = (r?: { value: string; source: string }) => r ? <span title={`Reported by the device via ${r.source}`}>{r.value}</span> : '—';
  const modelLine = [id.manufacturer?.value, id.model?.value].filter(Boolean).join(' ') + (id.firmware ? ` · fw ${id.firmware.value}` : '');
  const modelSources = [...new Set([id.manufacturer, id.model, id.firmware].filter(Boolean).map((r) => r!.source))].join(', ');
  const closed = d.ports.filter((p) => !p.is_open);

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

  const setProfile = async (value: string) => {
    setProfileError(null);
    try {
      await patch(`/devices/${d.uuid}`, { port_profile: value || null });
      reload();
    } catch (e: any) {
      setProfileError(`Update failed: ${e.message}`);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <div className="muted small"><Link to="/devices">Devices</Link> /</div>
          <h1 className="row" style={{ gap: 12 }}>
            {d.hostname ?? id.name?.value ?? d.current_ip}
            <DeviceStatusBadge status={d.status} failed={d.port_scan_failed} reason={d.scan_failure} />
            <FlagChips flags={flags} />
          </h1>
          <p className="mono">{d.current_ip}{d.mac && ` · ${d.mac}`}</p>
          {modelLine.trim() && <p title={`Reported by the device via ${modelSources}`}>{modelLine}</p>}
        </div>
        {isAdmin && (
          <div className="row">
            <button className="btn" onClick={() => setScanType('standard')}>Standard scan</button>
            <button className="btn warn" onClick={() => setScanType('full')}>Full port scan</button>
            <button className="btn" onClick={() => setWebCapture(true)}>Capture web interfaces</button>
            <button className="btn danger" onClick={remove} disabled={removing}>{removing ? 'Deleting…' : 'Delete'}</button>
          </div>
        )}
      </div>
      <ErrorBox error={removeError} />

      <div className="grid two">
        <Card title={`Network exposure — ${open.length} open port${open.length === 1 ? '' : 's'}`} flush
          actions={closed.length > 0 && <label className="check small"><input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} />show {closed.length} closed</label>}>
          {!d.last_port_scan_at && <div className="card-body muted small">This device has not been port-scanned yet (discovery only).</div>}
          {open.length === 0 && !showClosed ? <Empty>No open ports detected.</Empty> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Port</th><th>Service</th><th>Product / version</th><th>Verified details</th><th>Confidence</th><th>Open since</th><th>Last seen</th></tr></thead>
                <tbody>
                  {[...open, ...(showClosed ? closed : [])].map((p) => {
                    const key = `${p.protocol}${p.port}`;
                    const scripts = Object.entries(p.details?.scripts ?? {});
                    return (<Fragment key={key}>
                    <tr className={p.is_open ? '' : 'dim'}>
                      <td className="mono nowrap"><strong>{p.protocol.toUpperCase()}/{p.port}</strong>{!p.is_open && <span className="badge outline" style={{ marginLeft: 6 }}>closed {fmtTime(p.closed_at)}</span>}</td>
                      <td>{p.service === 'unknown' ? <span className="muted">unknown</span> : p.service}</td>
                      <td>{[p.product, p.version].filter(Boolean).join(' ') || <span className="muted">—</span>}{p.extra_info && <div className="muted small">{p.extra_info}</div>}</td>
                      <td className="small">
                        {p.summary ?? <span className="muted">—</span>}
                        {scripts.length > 0 && <> <button className="btn sm" onClick={() => setRawPort(rawPort === key ? null : key)}>{rawPort === key ? 'hide' : 'raw'}</button></>}
                      </td>
                      <td className="small">{p.method === 'probed' ? <span className="badge ok">fingerprinted</span> : <span className="badge outline" title="nmap did not identify this service; a name looked up from the port number is not shown">not identified</span>}{p.confidence != null && <span className="muted"> {p.confidence}/10</span>}</td>
                      <td className="nowrap small">{fmtTime(p.opened_at)}</td>
                      <td className="nowrap small">{relTime(p.last_seen)}</td>
                    </tr>
                    {rawPort === key && (
                      <tr><td colSpan={7}>
                        {scripts.map(([sid, s]) => <div key={sid}><div className="muted small">{sid}</div><pre className="mono small" style={{ whiteSpace: 'pre-wrap', margin: '2px 0 8px' }}>{s.output}</pre></div>)}
                      </td></tr>
                    )}
                    </Fragment>);
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="Device">
          <dl className="dl">
            <dt>Hostname</dt><dd>{d.hostname ?? '—'}</dd>
            <dt>DNS name</dt><dd>{d.dns_name ?? '—'}</dd>
            <dt>Current IP</dt><dd className="mono">{d.current_ip}</dd>
            <dt>Previous IPs</dt><dd className="mono">{d.previous_ips.length ? d.previous_ips.join(', ') : '—'}</dd>
            <dt>MAC</dt><dd className="mono">{d.mac ?? '— (not on scanner L2 segment)'}</dd>
            <dt>Vendor</dt><dd title={d.mac_private ? 'Locally administered (randomized) MAC: the prefix identifies no manufacturer' : undefined}>{vendorLabel(d) ?? '—'}</dd>
            <dt>Announced name</dt><dd>{reported(id.name)}</dd>
            <dt>Model</dt><dd>{reported(id.model)}</dd>
            <dt>Manufacturer</dt><dd>{reported(id.manufacturer)}</dd>
            <dt>Firmware</dt><dd>{reported(id.firmware)}</dd>
            <dt>OS (reported)</dt><dd>{reported(id.os)}</dd>
            {d.host_scripts && Object.keys(d.host_scripts).length > 0 && <>
              <dt>Host checks</dt>
              <dd>
                <button className="btn sm" onClick={() => setRawHost(!rawHost)}>{rawHost ? 'hide raw' : 'raw'}</button>
                {rawHost && Object.entries(d.host_scripts).map(([sid, s]) => <div key={sid}><div className="muted small">{sid}</div><pre className="mono small" style={{ whiteSpace: 'pre-wrap', margin: '2px 0 8px' }}>{s.output}</pre></div>)}
              </dd>
            </>}
            <dt>OS guess</dt><dd>{d.os_name ?? '—'}</dd>
            <dt>Network</dt><dd>{d.network_name ?? '—'}</dd>
            <dt>First seen</dt><dd>{fmtTime(d.first_seen)}</dd>
            <dt>Last seen</dt><dd>{fmtTime(d.last_seen)} <span className="muted">({relTime(d.last_seen)})</span></dd>
            <dt>Last port scan</dt><dd>{fmtTime(d.last_port_scan_at)}</dd>
            {d.port_scan_failed && <><dt>Port scan failed</dt><dd>{d.scan_failure ?? 'reason not recorded'}{d.scan_failure_scan_id != null && <span className="muted"> (scan #{d.scan_failure_scan_id})</span>}</dd></>}
            <dt>Extra ports</dt>
            <dd>
              {isAdmin ? (
                <select value={d.port_profile ?? ''} onChange={(e) => setProfile(e.target.value)} aria-label="Extra port profile">
                  <option value="">Automatic{d.port_profile == null ? ' (none detected)' : ''}</option>
                  {d.port_profiles.map((p) => <option key={p} value={p}>{p === 'truenas' ? 'TrueNAS apps' : p}</option>)}
                  <option value="none">Off</option>
                </select>
              ) : (d.port_profile && d.port_profile !== 'none' ? d.port_profile : '—')}
              {d.port_profile && d.port_profile !== 'none' && d.port_profile_source && <span className="muted small"> verified by {d.port_profile_source}</span>}
              <ErrorBox error={profileError} />
            </dd>
            <dt>Last full scan</dt><dd>{d.full_scanned_at ? fmtTime(d.full_scanned_at) : 'never'}</dd>
            {d.missed_scans > 0 && <><dt>Missed scans</dt><dd>{d.missed_scans} consecutive</dd></>}
            <dt>Device ID</dt><dd className="mono small">{d.uuid}</dd>
          </dl>
        </Card>
      </div>

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
                  {live.slice(0, 4).map((p) => (
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
              <EventFeed events={events.data.items} empty="No changes recorded for this device." />
              <Pager page={evPage} pageSize={25} total={events.data.total} onPage={setEvPage} />
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
                    {scans.data.items.map((s) => (
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
