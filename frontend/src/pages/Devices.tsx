import { Fragment, useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { get, post } from '../api';
import { ScanDialog } from '../components/ScanDialog';
import { WebCaptureDialog } from '../components/WebCaptureDialog';
import { Card, DeviceStatusBadge, Empty, ErrorBox, IpAssignmentBadge, macSourceTitle, NO_NAME_TIP, NO_NAME_VPN_TIP, NoMac, Pager, PortChips, RiskBadge, ScoreBadge, SkeletonRows, SortTh } from '../components/ui';
import { useApp } from '../context';
import type { DeviceSummary, Network, Paged } from '../types';
import { fmtTime, relTime, useApi } from '../util';

const PAGE = 50;

export default function Devices() {
  const { isAdmin } = useApp();
  const nav = useNavigate();
  const [sp, setSp] = useSearchParams();
  const [qInput, setQInput] = useState(sp.get('q') ?? '');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [selectionScope, setSelectionScope] = useState<'page' | 'all'>('page');
  const [selectAllBusy, setSelectAllBusy] = useState(false);
  const [selectAllError, setSelectAllError] = useState<string | null>(null);
  const [selectionCleared, setSelectionCleared] = useState(false);
  const [scanPreset, setScanPreset] = useState<'standard' | 'full' | null>(null);
  const [webCaptureOpen, setWebCaptureOpen] = useState(false);
  const [showOs, setShowOs] = useState(false);
  const [showRtt, setShowRtt] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [vulnBusy, setVulnBusy] = useState(false);
  // Vuln-check queue result: success is a confirmation (alert ok), failure stays in the ErrorBox.
  const [vulnOk, setVulnOk] = useState<string | null>(null);
  const [vulnError, setVulnError] = useState<string | null>(null);
  const clearVulnMsgs = () => { setVulnOk(null); setVulnError(null); };
  const page = Number(sp.get('page') || 1);
  const filterKey = [
    sp.get('q') || '',
    sp.get('status') || '',
    sp.get('network_id') || '',
    sp.get('port') || '',
    sp.get('service') || '',
    sp.get('archived') || '',
  ].join('|');
  const showArchived = sp.get('archived') === '1';
  const params = {
    q: sp.get('q') || undefined,
    status: sp.get('status') || undefined,
    network_id: sp.get('network_id') || undefined,
    port: sp.get('port') || undefined,
    service: sp.get('service') || undefined,
    include_archived: showArchived ? 'true' : undefined,
    sort: sp.get('sort') || 'ip',
    order: sp.get('order') || 'asc',
    page,
    page_size: PAGE,
  };
  const filterParams = {
    q: params.q,
    status: params.status,
    network_id: params.network_id,
    port: params.port,
    service: params.service,
    include_archived: params.include_archived,
    sort: params.sort,
    order: params.order,
  };
  const { data, error, loading } = useApi<Paged<DeviceSummary>>('/devices', params, 15000);
  const networks = useApi<Network[]>('/networks', { include_archived: showArchived ? 'true' : undefined });
  const vpnNetworks = new Set(networks.data?.filter((n) => n.vpn_s2s).map((n) => n.id));

  const update = (patch: Record<string, string | undefined>, { replace = false }: { replace?: boolean } = {}) => {
    const next = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!('page' in patch)) next.delete('page');
    setSp(next, { replace });
  };

  useEffect(() => {
    const t = window.setTimeout(() => {
      if ((sp.get('q') ?? '') !== qInput) update({ q: qInput || undefined }, { replace: true });
    }, 300);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qInput]);

  // A filter change drops the selection (it may hold devices outside the new results); paging keeps it.
  // A brief notice says so, since the checkboxes just silently empty otherwise.
  useEffect(() => {
    if (selected.size) setSelectionCleared(true);
    clearVulnMsgs();
    setSelected(new Set());
    setSelectionScope('page');
    setSelectAllError(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset only when the filters change
  }, [filterKey]);

  useEffect(() => {
    if (!selectionCleared) return;
    const t = window.setTimeout(() => setSelectionCleared(false), 6000);
    return () => window.clearTimeout(t);
  }, [selectionCleared]);

  const sortBy = (col: string) => {
    const same = params.sort === col;
    update({ sort: col, order: same && params.order === 'asc' ? 'desc' : 'asc' });
  };
  const sortTh = (col: string, label: string) => (
    <SortTh active={params.sort === col} desc={params.order === 'desc'} onSort={() => sortBy(col)}>{label}</SortTh>
  );
  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const allSelected = items.length > 0 && items.every((d) => selected.has(d.uuid));
  const moreThanPage = total > items.length;
  const showSelectAllBanner = isAdmin && allSelected && moreThanPage && selectionScope === 'page';
  const toggle = (uuid: string) => {
    const s = new Set(selected);
    if (s.has(uuid)) s.delete(uuid);
    else s.add(uuid);
    setSelected(s);
    setSelectionScope('page');
    setSelectionCleared(false);
  };

  const selectPage = (on: boolean) => {
    const s = new Set(selected);
    items.forEach((d) => (on ? s.add(d.uuid) : s.delete(d.uuid)));
    setSelected(s);
    setSelectionScope('page');
    setSelectAllError(null);
    setSelectionCleared(false);
  };

  const selectAllMatching = async () => {
    setSelectAllBusy(true);
    setSelectAllError(null);
    try {
      const res = await get<{ uuids: string[]; total: number }>('/devices/uuids', filterParams);
      setSelected(new Set(res.uuids));
      setSelectionScope('all');
    } catch (e: any) {
      setSelectAllError(e.message);
    } finally {
      setSelectAllBusy(false);
    }
  };

  const activeFilters = ['port', 'service'].filter((k) => sp.get(k));
  const STATUS_LABELS: Record<string, string> = {
    active: 'Active', unknown: 'Unconfirmed', not_detected: 'Not detected',
  };
  const filterCriteria = (() => {
    const parts: string[] = [];
    if (params.q) parts.push(`search: ${params.q}`);
    if (params.status) parts.push(`status: ${STATUS_LABELS[params.status] ?? params.status}`);
    if (params.network_id) {
      const net = networks.data?.find((n) => String(n.id) === params.network_id);
      parts.push(`network: ${net?.name ?? `#${params.network_id}`}`);
    }
    if (params.port) parts.push(`port: ${params.port}`);
    if (params.service) parts.push(`service: ${params.service}`);
    if (!parts.length) return undefined;
    const scope = selectionScope === 'all' ? 'all matching' : `${selected.size} selected`;
    return `${parts.join(' · ')} (${scope})`;
  })();

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Devices</h1>
          <p>Inventory of every device ever detected, identified by MAC, hostname and history - not by IP alone.</p>
        </div>
      </div>

      <Card flush title={
        <div className="row wrap" style={{ flex: 1 }}>
          <input type="search" placeholder="Search IP, hostname, MAC, vendor… or a query like port:22 tag:camera" title="Accepts free text or the search query language (field:value). See the Search page for the field reference." value={qInput} onChange={(e) => setQInput(e.target.value)} style={{ minWidth: 320, flex: 1 }} />
          <select value={params.status ?? ''} onChange={(e) => update({ status: e.target.value || undefined })}>
            <option value="">All statuses</option><option value="active">Active</option><option value="unknown">Unconfirmed</option><option value="not_detected">Not detected</option>
          </select>
          <select value={params.network_id ?? ''} onChange={(e) => update({ network_id: e.target.value || undefined })}>
            <option value="">All networks</option>
            {networks.data?.map((n) => <option key={n.id} value={n.id}>{n.name}{n.archived_at ? ' (archived)' : ''}</option>)}
          </select>
          {activeFilters.map((k) => (
            <button key={k} className="btn sm toggle on" aria-pressed="true" title="Remove this filter"
              onClick={() => update({ [k]: undefined })}>{k}: {sp.get(k)} <span aria-hidden>✕</span></button>
          ))}
        </div>
      } actions={isAdmin && selected.size > 0 && (
        <>
          <span className="muted small">
            {selected.size} selected{selectionScope === 'all' ? ' (all matching)' : ''}
          </span>
          <button className="btn sm" onClick={() => { clearVulnMsgs(); setScanPreset('standard'); }}>Standard scan</button>
          <button className="btn warn sm" onClick={() => { clearVulnMsgs(); setScanPreset('full'); }}>Full port scan</button>
          <button className="btn sm" onClick={() => { clearVulnMsgs(); setWebCaptureOpen(true); }}>Web capture</button>
          <button className="btn sm" disabled={vulnBusy} onClick={async () => {
            setVulnBusy(true); clearVulnMsgs();
            try {
              await post('/vuln-jobs', { device_uuids: [...selected] });
              setVulnOk(`Vulnerability check queued for ${selected.size} device(s).`);
            } catch (e: any) {
              setVulnError(e.message);
            } finally {
              setVulnBusy(false);
            }
          }}>{vulnBusy ? 'Queuing…' : 'Check vulnerabilities'}</button>
        </>
      )}>
        <ErrorBox error={error || selectAllError || vulnError} />
        {vulnOk && <div className="alert ok" role="status" style={{ margin: '0.75rem 1rem 0' }}>{vulnOk}</div>}
        <div className="row wrap" style={{ gap: 12, padding: '0.5rem 1rem' }}>
          <label className="check small"><input type="checkbox" checked={showOs} onChange={(e) => setShowOs(e.target.checked)} />Show OS column</label>
          <label className="check small"><input type="checkbox" checked={showRtt} onChange={(e) => setShowRtt(e.target.checked)} />Show RTT column</label>
          <label className="check small" title="Devices of networks removed in Settings > Networks are kept but hidden by default">
            <input type="checkbox" checked={showArchived} onChange={(e) => update({ archived: e.target.checked ? '1' : undefined, network_id: undefined })} />Show archived networks
          </label>
        </div>
        {isAdmin && selectionCleared && (
          <div className="alert" role="status" style={{ margin: '0.75rem 1rem 0' }}>
            <span className="small">Selection cleared because the filters changed.</span>
            {' '}
            <button className="btn sm ghost" onClick={() => setSelectionCleared(false)}>Dismiss</button>
          </div>
        )}
        {showSelectAllBanner && (
          <div className="alert" style={{ margin: '0.75rem 1rem 0' }}>
            <span className="small">
              All <strong>{items.length}</strong> devices on this page are selected.
            </span>
            {' '}
            <button className="btn sm" disabled={selectAllBusy} onClick={selectAllMatching}>
              {selectAllBusy ? 'Selecting…' : `Select all ${total} matching filter`}
            </button>
          </div>
        )}
        {selectionScope === 'all' && selected.size > 0 && (
          <div className="alert" style={{ margin: '0.75rem 1rem 0' }}>
            <span className="small">
              All <strong>{selected.size}</strong> devices matching the current filter are selected.
            </span>
            {' '}
            <button className="btn sm ghost" onClick={() => { setSelected(new Set()); setSelectionScope('page'); }}>
              Clear selection
            </button>
          </div>
        )}
        {loading && !data ? <SkeletonRows cols={isAdmin ? 13 : 12} /> : !items.length ? <Empty>No devices match.</Empty> : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {isAdmin && (
                    <th style={{ width: 30 }}>
                      <input type="checkbox" checked={allSelected} onChange={() => selectPage(!allSelected)} />
                    </th>
                  )}
                  {sortTh('status', 'Status')}
                  {sortTh('ip', 'IP address')}
                  {sortTh('hostname', 'Hostname')}
                  <th>Services</th>
                  <th>MAC / vendor</th>
                  {sortTh('open_ports', 'Open ports')}
                  {showOs && sortTh('os', 'OS')}
                  {showRtt && <th title="Last measured round-trip time">RTT</th>}
                  <th>Network</th>
                  <th title="Exposure score">Exposure</th>
                  <th title="Vulnerability-based risk score">Risk</th>
                  <th title="Risk boosted by exposure">Combined</th>
                  {sortTh('last_seen', 'Last seen')}
                  {sortTh('first_seen', 'First seen')}
                </tr>
              </thead>
              <tbody>
                {items.map((d) => {
                  const vpn = d.network_id != null && vpnNetworks.has(d.network_id);
                  return (
                  <Fragment key={d.uuid}>
                  <tr className={`clickable ${selected.has(d.uuid) ? 'selected' : ''} ${d.status === 'not_detected' ? 'dim' : ''}`} onClick={() => nav(`/devices/${d.uuid}`)}>
                    {isAdmin && <td onClick={(e) => e.stopPropagation()}><input type="checkbox" checked={selected.has(d.uuid)} onChange={() => toggle(d.uuid)} /></td>}
                    <td><DeviceStatusBadge status={d.status} failed={d.port_scan_failed} /></td>
                    <td className="mono">{d.current_ip} <IpAssignmentBadge value={d.ip_assignment} /></td>
                    <td>
                      {d.hostname ?? d.discovery_name ?? <span className="muted" title={vpn ? NO_NAME_VPN_TIP : NO_NAME_TIP}>-</span>}
                      {!d.hostname && d.discovery_name && <span className="badge outline" style={{ marginLeft: 6 }}>{d.discovery_source}</span>}
                    </td>
                    <td className="nowrap">
                      {d.open_ports.length > 0 && (
                        <button type="button" className={`btn sm toggle${expanded.has(d.uuid) ? ' on' : ''}`}
                          onClick={(e) => { e.stopPropagation(); setExpanded((prev) => { const n = new Set(prev); if (n.has(d.uuid)) n.delete(d.uuid); else n.add(d.uuid); return n; }); }}
                          aria-expanded={expanded.has(d.uuid)}>
                          {expanded.has(d.uuid) ? 'Hide services' : 'Services'}
                        </button>
                      )}
                    </td>
                    <td>{d.mac ? <span className="mono" title={macSourceTitle(d.mac_source)}>{d.mac}</span> : <NoMac vpn={vpn} className="small" />}{d.vendor && <div className="muted small">{d.vendor}</div>}</td>
                    <td><PortChips ports={d.open_ports} /></td>
                    {showOs && (
                      <td className="small" title={d.os_accuracy != null ? `${d.os_accuracy}% confidence` : undefined}>
                        {d.os_name ?? <span className="muted">-</span>}
                        {d.os_name && d.os_accuracy != null && d.os_accuracy < 85 && <span className="badge outline" style={{ marginLeft: 4 }}>uncertain</span>}
                      </td>
                    )}
                    {showRtt && (
                      <td className="mono small">{d.last_rtt_ms != null ? `${d.last_rtt_ms.toFixed(1)} ms` : <span className="muted">-</span>}</td>
                    )}
                    <td className="small">{d.network_name ?? <span className="muted">-</span>}</td>
                    <td>{d.score != null ? <ScoreBadge score={d.score} /> : <span className="muted">-</span>}</td>
                    <td>{d.risk_scored_at != null ? <RiskBadge score={d.risk_score} kind="risk" /> : <span className="muted">-</span>}</td>
                    <td>{d.risk_scored_at != null ? <RiskBadge score={d.combined_score} kind="combined" /> : <span className="muted">-</span>}</td>
                    <td className="nowrap" title={fmtTime(d.last_seen)}>{relTime(d.last_seen)}</td>
                    <td className="nowrap muted small">{fmtTime(d.first_seen)}</td>
                  </tr>
                  {expanded.has(d.uuid) && (
                    <tr className="dim">
                      <td colSpan={99} style={{ paddingLeft: isAdmin ? 48 : 16 }}>
                        <div className="stack" style={{ gap: 4 }}>
                          {d.open_ports.map((p) => (
                            <div key={`${p.protocol}-${p.port}`} className="small">
                              <span className="mono">{p.protocol.toUpperCase()}/{p.port}</span>
                              {' '}{p.service ?? 'not identified'}
                              {(p.product || p.version) && <span className="muted"> - {[p.product, p.version].filter(Boolean).join(' ')}</span>}
                              {!p.product && !p.version && p.service && <span className="badge outline" style={{ marginLeft: 6 }}>protocol match only</span>}
                            </div>
                          ))}
                        </div>
                      </td>
                    </tr>
                  )}
                  </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {data && <Pager page={page} pageSize={PAGE} total={data.total} onPage={(p) => update({ page: String(p) })} />}
      </Card>
      {scanPreset && (
        <ScanDialog
          preset={{
            scan_type: scanPreset,
            device_uuids: [...selected],
            deviceLabel: `${selected.size} selected device(s)`,
            criteria: filterCriteria,
          }}
          onClose={() => setScanPreset(null)}
          onStarted={() => { setSelected(new Set()); setSelectionScope('page'); nav('/scans'); }}
        />
      )}
      {webCaptureOpen && (
        <WebCaptureDialog
          preset={{ device_uuids: [...selected], deviceLabel: `${selected.size} selected device(s)` }}
          onClose={() => setWebCaptureOpen(false)}
          onStarted={() => { setSelected(new Set()); setSelectionScope('page'); nav('/scans?tab=web-captures'); }}
        />
      )}
    </>
  );
}
