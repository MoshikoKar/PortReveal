import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { EventTable } from '../components/EventTable';
import { Card, Empty, ErrorBox, Pager, SkeletonRows } from '../components/ui';
import type { ChangeEvent, EventType, Paged } from '../types';
import { EVENT_LABELS, useApi } from '../util';

const RANGES: Record<string, number | null> = { '24h': 1, '7d': 7, '30d': 30, all: null };
const PAGE = 50;

export default function Changes() {
  const [sp, setSp] = useSearchParams();
  const types = (sp.get('type') ?? '').split(',').filter(Boolean) as EventType[];
  const range = sp.get('range') ?? '7d';
  const page = Number(sp.get('page') || 1);
  const [qInput, setQInput] = useState(sp.get('q') ?? '');

  const since = useMemo(() => {
    const days = RANGES[range];
    return days ? new Date(Date.now() - days * 86400_000).toISOString() : undefined;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range, sp.get('page')]);

  const set = (patch: Record<string, string | undefined>, { replace = false }: { replace?: boolean } = {}) => {
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
      if ((sp.get('q') ?? '') !== qInput) set({ q: qInput || undefined }, { replace: true });
    }, 300);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qInput]);

  const { data, error, loading } = useApi<Paged<ChangeEvent>>('/events', {
    type: types.join(',') || undefined, severity: sp.get('severity') || undefined, q: sp.get('q') || undefined,
    since, page, page_size: PAGE,
  }, 15000);

  const toggleType = (t: EventType) => {
    const next = types.includes(t) ? types.filter((x) => x !== t) : [...types, t];
    set({ type: next.join(',') || undefined });
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Changes</h1>
          <p>Every state transition detected between scans. Unchanged state never creates duplicate entries.</p>
        </div>
      </div>
      <Card flush title={
        <div className="stack" style={{ gap: 10, flex: 1 }}>
          <div className="row wrap">
            <input type="search" placeholder="Search device, IP, MAC, message…" value={qInput} onChange={(e) => setQInput(e.target.value)} style={{ minWidth: 280, flex: 1 }} />
            <select value={sp.get('severity') ?? ''} onChange={(e) => set({ severity: e.target.value || undefined })}>
              <option value="">All severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option>
            </select>
            <div className="row" style={{ gap: 4 }}>
              {Object.keys(RANGES).map((r) => (
                <button key={r} className={`btn sm toggle ${range === r ? 'on' : ''}`} aria-pressed={range === r} onClick={() => set({ range: r })}>{r === 'all' ? 'All time' : `Last ${r}`}</button>
              ))}
            </div>
          </div>
          <div className="row wrap" style={{ gap: 6 }}>
            {(Object.keys(EVENT_LABELS) as EventType[]).map((t) => (
              <button key={t} className={`btn sm toggle ${types.includes(t) ? 'on' : ''}`} aria-pressed={types.includes(t)} onClick={() => toggleType(t)}>{EVENT_LABELS[t]}</button>
            ))}
            {types.length > 0 && <button className="btn sm ghost" onClick={() => set({ type: undefined })}>Clear</button>}
          </div>
        </div>
      }>
        <ErrorBox error={error} />
        {loading && !data ? <SkeletonRows cols={6} /> : !data?.items.length ? <Empty>No changes match these filters.</Empty> : (
          <div className="table-wrap">
            <EventTable events={data.items} />
          </div>
        )}
        {data && <Pager page={page} pageSize={PAGE} total={data.total} onPage={(p) => set({ page: String(p) })} />}
      </Card>
    </>
  );
}
