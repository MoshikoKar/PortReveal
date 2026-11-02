import { useState } from 'react';
import { Link, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { FacetList, HostResult, SaveWatchDialog } from '../components/SearchParts';
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
  // Set by the Ports list so the breadcrumb returns to the same sort/filter/network view.
  const from = (useLocation().state as { from?: string } | null)?.from ?? '';
  const network = sp.get('network');
  const [page, setPage] = useState(1);
  const [watching, setWatching] = useState(false);
  const [watched, setWatched] = useState<string | null>(null);
  const n = Number(port);
  const valid = PROTOCOLS.includes(proto) && /^\d+$/.test(port) && n >= 1 && n <= MAX_PORT;
  const base = `port:${n}${proto === 'tcp' ? '' : ` proto:${proto}`}`;
  const q = network ? addTerm(base, `network:=${quoteValue(network)}`) : base;
  const facets = useApi<Facets>(valid ? '/search/facets' : null, { q, facets: PORT_FACETS });
  const hosts = useApi<Paged<SearchHost>>(valid ? '/search' : null, { q, page, page_size: PAGE_SIZE });

  if (!valid) return <ErrorBox error={`Not a valid port: ${proto}/${port}`} />;

  const total = hosts.data?.total;
  return (
    <>
      <div className="page-head">
        <div className="page-head-main">
          <div className="muted small"><Link to={`/ports${from}`}>Exposed ports</Link> /</div>
          <h1><span className="mono">{proto.toUpperCase()}/{n}</span></h1>
          <p>
            {network ? `In ${network}. ` : ''}
            {total != null ? `${total} known host${total === 1 ? '' : 's'} with this port open, including any not detected in the latest scan.` : ' '}
          </p>
        </div>
        <div className="row wrap gap-2 page-head-actions">
          <Link className="btn" to={`/changes?type=port_opened,port_closed&range=30d&port=${n}&proto=${proto}`}>Changes on this port</Link>
          <button className="btn" onClick={() => setWatching(true)}>Watch this port</button>
          <Link className="btn" to={`/search?q=${encodeURIComponent(q)}`}>Open in search →</Link>
        </div>
      </div>
      {watched && <div className="alert ok">Saved watch “{watched}”. <Link to="/watches">Open watches →</Link></div>}
      <div className="search-layout">
        <aside className="card card-body">
          <h2 className="sr-only">Breakdown of these hosts</h2>
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
      {watching && (
        <SaveWatchDialog query={q} onClose={() => setWatching(false)} onSaved={(s) => { setWatching(false); setWatched(s.name); }} />
      )}
    </>
  );
}
