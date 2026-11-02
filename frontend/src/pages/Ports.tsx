import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { Card, Empty, ErrorBox, SkeletonRows, SortTh } from '../components/ui';
import { serviceName } from '../serviceNames';
import type { ExposedPort, Network } from '../types';
import { useApi } from '../util';

type SortKey = 'count' | 'port' | 'service';
const SORT_KEYS: SortKey[] = ['count', 'port', 'service'];
// Host count reads best largest-first; port number and service name read best ascending.
const defaultDesc = (key: SortKey) => key === 'count';
const RISK_TEXT = { admin: 'Remote admin', database: 'Database' } as const;
const HOSTS_TIP = 'Every known host with this port open, including hosts not detected in the latest scan.';

export default function Ports() {
  const [sp, setSp] = useSearchParams();
  const networkId = sp.get('network_id') ?? undefined;
  const { data, error } = useApi<{ ports: ExposedPort[]; total: number; truncated: boolean }>('/exposed-ports', { network_id: networkId }, 30000);
  const networks = useApi<Network[]>('/networks');
  const nav = useNavigate();
  // The detail page's breadcrumb returns to this exact view (sort, filters, network).
  const linkState = { from: useLocation().search };
  const q = sp.get('q') ?? '';
  const onlyNew = sp.get('new') === '1';
  const onlyRisky = sp.get('risky') === '1';
  const sortKey = SORT_KEYS.find((k) => k === sp.get('sort')) ?? 'count';
  const dir = sp.get('dir');
  const sort = { key: sortKey, desc: dir === 'asc' ? false : dir === 'desc' ? true : defaultDesc(sortKey) };

  /** Update query params, dropping empty values so default views keep a clean URL. Discrete filters push; typing uses replace. */
  const set = (patch: Record<string, string | undefined>, { replace = false }: { replace?: boolean } = {}) => {
    const next = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setSp(next, { replace });
  };

  const needle = q.trim().toLowerCase();
  // A bare number is a port number (22 should not also match 1022); "tcp", "tcp/44" match by prefix.
  const matches = (p: ExposedPort) => !needle
    || (/^\d+$/.test(needle) ? String(p.port) === needle : `${p.protocol}/${p.port}`.startsWith(needle))
    || p.services.some((s) => s.service.toLowerCase().includes(needle))
    || !!serviceName(p.service)?.toLowerCase().includes(needle);
  const all = data?.ports ?? [];
  const newCount = all.filter((p) => p.new > 0).length;
  const riskyCount = all.filter((p) => p.risk).length;
  const rows = all
    .filter((p) => matches(p) && (!onlyNew || p.new > 0) && (!onlyRisky || p.risk))
    .sort((a, b) => {
      const cmp = sort.key === 'count' ? a.count - b.count
        : sort.key === 'port' ? a.port - b.port || a.protocol.localeCompare(b.protocol)
        : a.service.localeCompare(b.service);
      return sort.desc ? -cmp : cmp;
    });
  const totalHosts = rows.reduce((n, p) => n + p.count, 0);
  const filtered = !!needle || onlyNew || onlyRisky;

  const sortBy = (key: SortKey) => {
    const desc = sort.key === key ? !sort.desc : defaultDesc(key);
    set({ sort: key === 'count' ? undefined : key, dir: desc === defaultDesc(key) ? undefined : desc ? 'desc' : 'asc' });
  };
  const networkName = networks.data?.find((n) => String(n.id) === networkId)?.name;
  const portLink = (p: ExposedPort) =>
    `/ports/${p.protocol}/${p.port}${networkName ? `?network=${encodeURIComponent(networkName)}` : ''}`;
  const changesLink = (p: ExposedPort) => `/changes?type=port_opened&range=7d&port=${p.port}&proto=${p.protocol}`;

  return (
    <>
      <div className="page-head">
        <div className="page-head-main">
          <h1>Exposed ports</h1>
          <p>Every open port known on the network, by number of hosts exposing it. Open a port for its products, versions, web titles and hosts.</p>
        </div>
        <div className="row wrap gap-2 page-head-actions">
          <select aria-label="Network" value={networkId ?? ''} onChange={(e) => set({ network_id: e.target.value })}>
            <option value="">All networks</option>
            {(networks.data ?? []).map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
          </select>
          <input type="search" className="ports-filter" aria-label="Filter ports" placeholder="Port, service or tcp/udp…" value={q}
            onChange={(e) => set({ q: e.target.value }, { replace: true })} />
        </div>
      </div>
      <ErrorBox error={error} />
      {data?.truncated && (
        <div className="alert warn">
          Showing the {data.ports.length.toLocaleString()} most-exposed of {data.total.toLocaleString()} ports. Filtering and sorting apply to these only.
        </div>
      )}
      {!data ? (!error && <Card flush title="Ports"><SkeletonRows cols={3} /></Card>) : (
        <Card flush
          title={`${rows.length} port${rows.length === 1 ? '' : 's'}${networkName ? ` in ${networkName}` : ''} · open ${totalHosts} time${totalHosts === 1 ? '' : 's'} across known hosts`}
          actions={<>
            <button className={`btn sm toggle ${onlyNew ? 'on' : ''}`} aria-pressed={onlyNew} onClick={() => set({ new: onlyNew ? undefined : '1' })}
              title="Ports that a host opened in the last 7 days and still has open">
              New in 7 days <span className="muted">{newCount}</span>
            </button>
            <button className={`btn sm toggle ${onlyRisky ? 'on' : ''}`} aria-pressed={onlyRisky} onClick={() => set({ risky: onlyRisky ? undefined : '1' })}
              title="Services that raise a host's exposure score (remote admin, databases, file sharing, FTP)">
              Risky services <span className="muted">{riskyCount}</span>
            </button>
          </>}>
          <p className="sr-only" aria-live="polite">{rows.length} port{rows.length === 1 ? '' : 's'} shown</p>
          {rows.length === 0 ? (
            filtered ? (
              <Empty>
                No ports match {needle ? <>“{q.trim()}”</> : 'these filters'}{needle && (onlyNew || onlyRisky) ? ' with these filters' : ''}.{' '}
                <button className="btn sm" onClick={() => set({ q: undefined, new: undefined, risky: undefined })}>Clear filters</button>
              </Empty>
            ) : (
              <Empty>No open ports known{networkName ? ` in ${networkName}` : ''} yet. <Link to="/scans">Run a standard or full scan</Link> to fill this list.</Empty>
            )
          ) : (
            <div className="table-wrap">
            <table className="ports-table">
              <thead>
                <tr>
                  <SortTh className="port-col" active={sort.key === 'port'} desc={sort.desc} onSort={() => sortBy('port')}>Port</SortTh>
                  <SortTh active={sort.key === 'service'} desc={sort.desc} onSort={() => sortBy('service')}>Service</SortTh>
                  <SortTh className="right hosts-col" title={HOSTS_TIP} active={sort.key === 'count'} desc={sort.desc} onSort={() => sortBy('count')}>Known hosts</SortTh>
                </tr>
              </thead>
              <tbody>
                {rows.map((p) => {
                  const plain = serviceName(p.service);
                  const others = p.services.filter((s) => s.service !== p.service);
                  return (
                    <tr key={`${p.protocol}${p.port}`} className="clickable" onClick={() => nav(portLink(p), { state: linkState })}>
                      <td className="mono port-col">
                        <Link className="row-link" to={portLink(p)} state={linkState} onClick={(e) => e.stopPropagation()}>{p.protocol.toUpperCase()}/{p.port}</Link>
                      </td>
                      <td>
                        <div className="port-svc">
                          <span>{p.service}</span>
                          {plain && <span className="muted">{plain}</span>}
                          {p.risk && (
                            <span className="badge medium" title={`Raises the exposure score of every host running it (${p.risk.label})`}>
                              {p.risk.kind ? RISK_TEXT[p.risk.kind] : 'Risky service'}
                            </span>
                          )}
                          {p.new > 0 && (
                            <Link className="badge accent" to={changesLink(p)} onClick={(e) => e.stopPropagation()}
                              title={`${p.new} host${p.new === 1 ? '' : 's'} opened this port in the last 7 days. Open in Changes.`}>
                              +{p.new} new
                            </Link>
                          )}
                        </div>
                        {others.length > 0 && (
                          <div className="muted small">Also reported as {others.map((s) => `${s.service} (${s.count})`).join(', ')}</div>
                        )}
                      </td>
                      <td className="right hosts-col">{p.count}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            </div>
          )}
        </Card>
      )}
    </>
  );
}
