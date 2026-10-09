import { useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { FacetList, HostResult } from '../components/SearchParts';
import { Card, Empty, ErrorBox, Loading, Pager } from '../components/ui';
import type { Facets, Paged, SearchHost } from '../types';
import { addTerm, quoteValue, useApi } from '../util';

const PAGE_SIZE = 25;
const PORT_FACETS = 'product,version,http.title,http.server,tag';
const PROTOCOLS = ['tcp', 'udp'];
const MAX_PORT = 65535;

export default function PortDetail() {
  const { proto = '', port = '' } = useParams();
  const [sp] = useSearchParams();
  const nav = useNavigate();
  const network = sp.get('network');
  const [page, setPage] = useState(1);
  const n = Number(port);
  const valid = PROTOCOLS.includes(proto) && /^\d+$/.test(port) && n >= 1 && n <= MAX_PORT;
  const base = `port:${n}${proto === 'tcp' ? '' : ` proto:${proto}`}`;
  const q = network ? addTerm(base, `network:=${quoteValue(network)}`) : base;
  const facets = useApi<Facets>(valid ? '/search/facets' : null, { q, facets: PORT_FACETS });
  const hosts = useApi<Paged<SearchHost>>(valid ? '/search' : null, { q, page, page_size: PAGE_SIZE });

  if (!valid) return <ErrorBox error={`Not a valid port: ${proto}/${port}`} />;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="muted small"><Link to="/ports">Exposed ports</Link> /</div>
          <h1 className="mono">{proto.toUpperCase()}/{n}</h1>
          <p>{network ? `In ${network}. ` : ''}{hosts.data ? `${hosts.data.total} host${hosts.data.total === 1 ? '' : 's'} with this port open.` : ' '}</p>
        </div>
        <Link className="btn" to={`/search?q=${encodeURIComponent(q)}`}>Open in search →</Link>
      </div>
      <div className="search-layout">
        <aside className="card card-body">
          {facets.data ? (
            <FacetList facets={facets.data} onPick={(f) => nav(`/search?q=${encodeURIComponent(addTerm(q, f.term))}`)} />
          ) : facets.error ? <ErrorBox error={facets.error} /> : <Loading />}
        </aside>
        <div className="stack" style={{ minWidth: 0 }}>
          <ErrorBox error={hosts.error} />
          {!hosts.data ? <Loading /> : !hosts.data.items.length ? <Card><Empty>No host has this port open.</Empty></Card> : (
            <Card flush>
              {hosts.data.items.map((h) => <HostResult key={h.uuid} h={h} />)}
              <Pager page={page} pageSize={PAGE_SIZE} total={hosts.data.total} onPage={setPage} />
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
