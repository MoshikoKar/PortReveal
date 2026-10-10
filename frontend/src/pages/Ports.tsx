import { useNavigate, useSearchParams } from 'react-router-dom';
import { Card, Empty, ErrorBox, Loading, SortTh } from '../components/ui';
import type { ExposedPort, Network } from '../types';
import { useApi } from '../util';

type SortKey = 'count' | 'port' | 'service';
const SORT_KEYS: SortKey[] = ['count', 'port', 'service'];
// Host count reads best largest-first; port number and service name read best ascending.
const defaultDesc = (key: SortKey) => key === 'count';

export default function Ports() {
  const [sp, setSp] = useSearchParams();
  const networkId = sp.get('network_id') ?? undefined;
  const { data, error } = useApi<{ ports: ExposedPort[]; total: number; truncated: boolean }>('/exposed-ports', { network_id: networkId }, 30000);
  const networks = useApi<Network[]>('/networks');
  const nav = useNavigate();
  const q = sp.get('q') ?? '';
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
  const rows = (data?.ports ?? [])
    .filter((p) => !needle || `${p.protocol}/${p.port}`.includes(needle) || String(p.port) === needle
      || p.services.some((s) => s.service.toLowerCase().includes(needle)))
    .sort((a, b) => {
      const cmp = sort.key === 'count' ? a.count - b.count
        : sort.key === 'port' ? a.port - b.port || a.protocol.localeCompare(b.protocol)
        : a.service.localeCompare(b.service);
      return sort.desc ? -cmp : cmp;
    });
  const totalHosts = rows.reduce((n, p) => n + p.count, 0);

  const sortBy = (key: SortKey) => {
    const desc = sort.key === key ? !sort.desc : defaultDesc(key);
    set({ sort: key === 'count' ? undefined : key, dir: desc === defaultDesc(key) ? undefined : desc ? 'desc' : 'asc' });
  };
  const networkName = networks.data?.find((n) => String(n.id) === networkId)?.name;
  const portLink = (p: ExposedPort) =>
    `/ports/${p.protocol}/${p.port}${networkName ? `?network=${encodeURIComponent(networkName)}` : ''}`;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Exposed ports</h1>
          <p>Every open port known on the network, by number of hosts exposing it. Click a port for its products, versions, web titles and hosts.</p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <select value={networkId ?? ''} onChange={(e) => set({ network_id: e.target.value })}>
            <option value="">All networks</option>
            {(networks.data ?? []).map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}
          </select>
          <input type="search" placeholder="Filter by port or service…" value={q} onChange={(e) => set({ q: e.target.value }, { replace: true })} style={{ width: 220 }} />
        </div>
      </div>
      <ErrorBox error={error} />
      {data?.truncated && (
        <div className="alert warn">
          Showing the {data.ports.length.toLocaleString()} most-exposed of {data.total.toLocaleString()} ports. Filtering and sorting apply to these only.
        </div>
      )}
      {!data ? <Loading /> : (
        <Card flush title={`${rows.length} port${rows.length === 1 ? '' : 's'} · ${totalHosts} open-port instances`}>
          {rows.length === 0 ? <Empty>No open ports match.</Empty> : (
            <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <SortTh active={sort.key === 'port'} desc={sort.desc} onSort={() => sortBy('port')}>Port</SortTh>
                  <SortTh active={sort.key === 'service'} desc={sort.desc} onSort={() => sortBy('service')}>Service</SortTh>
                  <th>Also reported as</th>
                  <SortTh className="right" active={sort.key === 'count'} desc={sort.desc} onSort={() => sortBy('count')}>Hosts</SortTh>
                </tr>
              </thead>
              <tbody>
                {rows.map((p) => (
                  <tr key={`${p.protocol}${p.port}`} className="clickable" onClick={() => nav(portLink(p))}>
                    <td className="mono">{p.protocol.toUpperCase()}/{p.port}</td>
                    <td>{p.service}</td>
                    <td className="muted small">
                      {p.services.filter((s) => s.service !== p.service).map((s) => `${s.service} (${s.count})`).join(', ')}
                    </td>
                    <td className="right">{p.count} host{p.count === 1 ? '' : 's'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          )}
        </Card>
      )}
    </>
  );
}
