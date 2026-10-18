import { useState, type ReactNode } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Card, Empty, ErrorBox, Kpi, Loading, RiskBadge, ScoreBadge, VulnJobBadge } from '../components/ui';
import type { Paged, ReportHost, VulnJob } from '../types';
import { fmtTime, quoteValue, relTime, useApi } from '../util';

interface Exposure {
  levels: { high: number; medium: number; low: number };
  thresholds: { high: number; medium: number };
  distribution: { from: number; to: number; count: number }[];
  top: ReportHost[];
}
interface RareService {
  network: string | null; port: number; protocol: string; service: string | null;
  product: string | null; version: string | null; host: ReportHost;
}
interface Skew { product: string; hosts: number; versions: { version: string; hosts: number }[] }
interface Subnet { subnet: string; hosts: number; active: number; max_score: number; avg_score: number; query: string }
interface VulnReport {
  top_devices: (ReportHost & { risk: number; combined: number })[];
  top_cves: { cve_id: string; cvss_base: number | null; kev: boolean; epss: number | null; device_count: number }[];
}

const PREVIEW_ROWS = 5;
const searchLink = (q: string) => `/search?q=${encodeURIComponent(q)}`;

function SeeAll({ total, open, onToggle }: { total: number; open: boolean; onToggle: () => void }) {
  if (total <= PREVIEW_ROWS) return null;
  return (
    <button type="button" className="small" onClick={onToggle}
      style={{ background: 'none', border: 0, padding: 0, color: 'var(--accent)', cursor: 'pointer' }}>
      {open ? 'Show less' : `See all ${total} →`}
    </button>
  );
}

function preview<T>(items: T[], open: boolean): T[] {
  return open ? items : items.slice(0, PREVIEW_ROWS);
}

function HostTable({ hosts, empty }: { hosts: ReportHost[]; empty: string }) {
  const nav = useNavigate();
  if (!hosts.length) return <Empty>{empty}</Empty>;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Host</th><th>Type</th><th>Network</th><th className="right">Score</th></tr></thead>
        <tbody>
          {hosts.map((h) => (
            <tr key={h.uuid} className="clickable" onClick={() => nav(`/devices/${h.uuid}`)}>
              <td><span className="mono">{h.ip}</span>{h.hostname && <div className="muted small">{h.hostname}</div>}</td>
              <td>{h.type ?? '—'}</td>
              <td>{h.network ?? '—'}</td>
              <td className="right"><ScoreBadge score={h.score} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ReportBlurb({ children }: { children: ReactNode }) {
  return (
    <div className="card-body muted small" style={{ borderBottom: '1px solid var(--border)' }}>
      {children}
    </div>
  );
}

export default function Reports() {
  const nav = useNavigate();
  const exposure = useApi<Exposure>('/reports/exposure');
  const rare = useApi<{ min_hosts: number; items: RareService[] }>('/reports/rare-services');
  const skew = useApi<{ items: Skew[] }>('/reports/version-skew');
  const subnets = useApi<{ items: Subnet[] }>('/reports/subnets');
  const vuln = useApi<VulnReport>('/reports/vulnerabilities');
  const [rareOpen, setRareOpen] = useState(false);
  const [skewOpen, setSkewOpen] = useState(false);
  const [subnetsOpen, setSubnetsOpen] = useState(false);
  const [riskOpen, setRiskOpen] = useState(false);
  const [cveOpen, setCveOpen] = useState(false);
  const e = exposure.data;
  const maxBucket = Math.max(1, ...(e?.distribution.map((b) => b.count) ?? []));
  const rareItems = rare.data?.items ?? [];
  const skewItems = skew.data?.items ?? [];
  const subnetItems = subnets.data?.items ?? [];
  const topDevices = vuln.data?.top_devices ?? [];
  const topCves = vuln.data?.top_cves ?? [];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Reports</h1>
          <p>Inventory analysis from stored scan and web capture data. Exposure scores weigh risky services, logins and newness; they are not vulnerability findings.</p>
        </div>
      </div>

      <ErrorBox error={exposure.error} />
      {!e ? (!exposure.error && <Loading />) : (
        <>
          <div className="grid kpis">
            <Kpi label="High exposure" value={e.levels.high} sub={`score ≥ ${e.thresholds.high}`} color="var(--high)" onClick={() => nav(searchLink(`score:>=${e.thresholds.high}`))} />
            <Kpi label="Medium exposure" value={e.levels.medium} sub={`score ${e.thresholds.medium}–${e.thresholds.high - 1}`} color="var(--medium)" onClick={() => nav(searchLink(`score:${e.thresholds.medium}-${e.thresholds.high - 1}`))} />
            <Kpi label="Low exposure" value={e.levels.low} sub={`score < ${e.thresholds.medium}`} color="var(--ok)" onClick={() => nav(searchLink(`score:<${e.thresholds.medium}`))} />
          </div>
          <div className="grid halves">
            <Card title="Score distribution">
              <div className="bars">
                {e.distribution.map((b) => (
                  <Link key={b.from} to={searchLink(`score:${b.from}-${b.to}`)} className="bar-row" style={{ color: 'var(--text-2)' }}>
                    <span className="mono">{b.from}–{b.to}</span>
                    <span className="bar-track"><span className="bar-fill" style={{ display: 'block', width: `${(b.count / maxBucket) * 100}%`, ['--bar-color' as any]: b.from >= e.thresholds.high ? 'var(--high)' : b.from >= e.thresholds.medium ? 'var(--medium)' : 'var(--ok)' }} /></span>
                    <span className="right">{b.count}</span>
                  </Link>
                ))}
              </div>
            </Card>
            <Card title="Most exposed hosts" flush actions={<Link to={searchLink('score:>0')} className="small">All in search →</Link>}>
              <HostTable hosts={preview(e.top, false)} empty="No host has a non-zero exposure score." />
            </Card>
          </div>
        </>
      )}

      <div className="grid halves">
        <Card title="Rare services" flush actions={
          <SeeAll total={rareItems.length} open={rareOpen} onToggle={() => setRareOpen((v) => !v)} />
        }>
          <ReportBlurb>
            Ports open on exactly one host of a network with at least {rare.data?.min_hosts ?? '…'} hosts. Often forgotten or unexpected services.
          </ReportBlurb>
          <ErrorBox error={rare.error} />
          {!rare.data ? (!rare.error && <Loading />) : !rareItems.length ? <Empty>No rare services found.</Empty> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Port</th><th>Service</th><th>Host</th><th>Network</th></tr></thead>
                <tbody>
                  {preview(rareItems, rareOpen).map((r) => (
                    <tr key={`${r.network}-${r.protocol}${r.port}`} className="clickable" onClick={() => nav(`/devices/${r.host.uuid}`)}>
                      <td className="mono nowrap">{r.port}/{r.protocol}</td>
                      <td>{[r.product, r.version].filter(Boolean).join(' ') || r.service || '—'}</td>
                      <td><span className="mono">{r.host.ip}</span>{r.host.hostname && <div className="muted small">{r.host.hostname}</div>}</td>
                      <td>{r.network ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Version skew" flush actions={
          <SeeAll total={skewItems.length} open={skewOpen} onToggle={() => setSkewOpen((v) => !v)} />
        }>
          <ReportBlurb>
            Products running two or more versions. Click a version to see its hosts.
          </ReportBlurb>
          <ErrorBox error={skew.error} />
          {!skew.data ? (!skew.error && <Loading />) : !skewItems.length ? <Empty>Every product runs a single version.</Empty> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Product</th><th>Versions (hosts)</th></tr></thead>
                <tbody>
                  {preview(skewItems, skewOpen).map((s) => (
                    <tr key={s.product}>
                      <td><Link to={searchLink(`product:=${quoteValue(s.product)}`)}>{s.product}</Link><div className="muted small">{s.hosts} hosts</div></td>
                      <td>
                        {s.versions.map((v) => (
                          <Link key={v.version} className="chip" to={searchLink(`product:=${quoteValue(s.product)} version:=${quoteValue(v.version)}`)}>
                            {v.version} ({v.hosts})
                          </Link>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <div className="grid halves">
        <Card title="At-risk devices" flush actions={
          <div className="row" style={{ gap: 12 }}>
            <Link className="small" to="/vulnerabilities">Open vulnerabilities dashboard →</Link>
            <SeeAll total={topDevices.length} open={riskOpen} onToggle={() => setRiskOpen((v) => !v)} />
          </div>
        }>
          <ReportBlurb>
            Devices ranked by combined score (risk from matched CVEs, boosted by exposure) — same numbers as
            the <Link to="/vulnerabilities">vulnerabilities dashboard</Link>. Requires the vulnerability feed
            to be enabled in Settings.
          </ReportBlurb>
          <ErrorBox error={vuln.error} />
          {!vuln.data ? (!vuln.error && <Loading />) : !topDevices.length ? (
            <Empty>No device has a non-zero risk score yet.</Empty>
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Host</th><th>Network</th><th className="right">Risk</th><th className="right">Combined</th></tr></thead>
                <tbody>
                  {preview(topDevices, riskOpen).map((h) => (
                    <tr key={h.uuid} className="clickable" onClick={() => nav(`/devices/${h.uuid}`)}>
                      <td><span className="mono">{h.ip}</span>{h.hostname && <div className="muted small">{h.hostname}</div>}</td>
                      <td>{h.network ?? '—'}</td>
                      <td className="right"><RiskBadge score={h.risk} kind="risk" /></td>
                      <td className="right"><RiskBadge score={h.combined} kind="combined" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card title="Top vulnerabilities" flush actions={
          <div className="row" style={{ gap: 12 }}>
            <Link className="small" to="/vulnerabilities">Open vulnerabilities dashboard →</Link>
            <SeeAll total={topCves.length} open={cveOpen} onToggle={() => setCveOpen((v) => !v)} />
          </div>
        }>
          <ReportBlurb>
            CVEs matched on the most devices (confirmed or potential, not dismissed) — same computation as the{' '}
            <Link to="/vulnerabilities">vulnerabilities dashboard</Link>.
          </ReportBlurb>
          <ErrorBox error={vuln.error} />
          {!vuln.data ? (!vuln.error && <Loading />) : !topCves.length ? (
            <Empty>No vulnerability matched yet.</Empty>
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>CVE</th><th className="right">CVSS</th><th>KEV</th><th className="right">Devices</th></tr></thead>
                <tbody>
                  {preview(topCves, cveOpen).map((c) => (
                    <tr key={c.cve_id} className="clickable" onClick={() => nav(searchLink(`cve:${c.cve_id}`))}>
                      <td className="mono">{c.cve_id}</td>
                      <td className="right mono">{c.cvss_base != null ? c.cvss_base.toFixed(1) : '—'}</td>
                      <td>{c.kev && <span className="badge high">KEV</span>}</td>
                      <td className="right">{c.device_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <Card title="Subnets (/24)" flush actions={
        <SeeAll total={subnetItems.length} open={subnetsOpen} onToggle={() => setSubnetsOpen((v) => !v)} />
      }>
        <ErrorBox error={subnets.error} />
        {!subnets.data ? (!subnets.error && <Loading />) : !subnetItems.length ? <Empty>No IPv4 hosts known yet.</Empty> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Subnet</th><th className="right">Hosts</th><th className="right">Active</th><th className="right">Max score</th><th className="right">Average score</th></tr></thead>
              <tbody>
                {preview(subnetItems, subnetsOpen).map((s) => (
                  <tr key={s.subnet} className="clickable" onClick={() => nav(searchLink(s.query))}>
                    <td className="mono">{s.subnet}</td>
                    <td className="right">{s.hosts}</td>
                    <td className="right">{s.active}</td>
                    <td className="right"><ScoreBadge score={s.max_score} /></td>
                    <td className="right">{s.avg_score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <HeatmapCard />
      <VulnJobsCard />
    </>
  );
}

function VulnJobsCard() {
  const jobs = useApi<Paged<VulnJob>>('/vuln-jobs', { page_size: 10 }, 10000);
  const items = jobs.data?.items ?? [];
  return (
    <Card id="vuln-jobs" title="Vulnerability check jobs" flush>
      <ReportBlurb>
        Background local-CPE match + allow-listed script runs queued after a scan or manually (spec section 8).
        Each one recomputes risk/combined scores for the devices it covers when it finishes.
      </ReportBlurb>
      <ErrorBox error={jobs.error} />
      {!jobs.data ? (!jobs.error && <Loading />) : !items.length ? <Empty>No vulnerability check has run yet.</Empty> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Status</th><th>Trigger</th><th className="right">Devices</th><th>Stage</th><th>Finished</th><th>Findings</th></tr></thead>
            <tbody>
              {items.map((j) => (
                <tr key={j.id}>
                  <td><VulnJobBadge status={j.status} /></td>
                  <td className="small">{j.trigger === 'manual' ? 'Manual' : 'After scan'}</td>
                  <td className="right">{j.device_count}</td>
                  <td className="small">{j.stage ?? '—'}</td>
                  <td className="nowrap small" title={j.finished_at ? fmtTime(j.finished_at) : undefined}>
                    {j.finished_at ? relTime(j.finished_at) : '—'}
                  </td>
                  <td className="small">
                    {j.stats ? `${j.stats.matched ?? 0} matched, ${j.stats.cves_found ?? 0} from scripts` : '—'}
                    {j.error && <div className="muted small" title={j.error}>{j.error.slice(0, 60)}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

interface HeatCell {
  host: number; ip: string; present: boolean; score: number;
  uuid: string | null; hostname: string | null; status: string | null;
}
interface HeatGrid { subnet: string; hosts: number; query: string; cells: HeatCell[] }

const HEAT_COLUMNS = 16;
const HEAT_TILE_WIDTH = 170;

function HeatTile({ grid, maxScore }: { grid: HeatGrid; maxScore: number }) {
  const nav = useNavigate();
  return (
    <div style={{ width: HEAT_TILE_WIDTH }}>
      <Link to={searchLink(grid.query)} className="small mono">{grid.subnet}</Link>
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${HEAT_COLUMNS}, 1fr)`, gap: 1, marginTop: 4 }}>
        {grid.cells.map((c) => (
          <button
            key={c.host}
            type="button"
            title={c.present ? `${c.ip}${c.hostname ? ` (${c.hostname})` : ''} · score ${c.score}` : c.ip}
            disabled={!c.uuid}
            onClick={() => c.uuid && nav(`/devices/${c.uuid}`)}
            style={{
              aspectRatio: '1', border: 0, borderRadius: 1, padding: 0, cursor: c.uuid ? 'pointer' : 'default',
              background: c.present
                ? `color-mix(in srgb, var(--high) ${(c.score / maxScore) * 100}%, var(--ok))`
                : 'var(--bg-2, #eee)',
              opacity: c.present ? 1 : 0.35,
            }}
          />
        ))}
      </div>
      <div className="muted small" style={{ marginTop: 4 }}>{grid.hosts} hosts</div>
    </div>
  );
}

function HeatmapCard() {
  const heat = useApi<{ items: HeatGrid[] }>('/reports/heatmap');
  const grids = heat.data?.items ?? [];
  const maxScore = Math.max(1, ...grids.flatMap((g) => g.cells.map((c) => c.score)));
  return (
    <Card title="Subnet heatmaps" flush>
      <ReportBlurb>
        One /24 grid per subnet with known hosts, coloured by exposure score on a shared scale. Empty cells have no known host.
      </ReportBlurb>
      <ErrorBox error={heat.error} />
      {!heat.data ? (!heat.error && <Loading />) : !grids.length ? <Empty>No IPv4 hosts for a heatmap yet.</Empty> : (
        <div style={{ padding: '0.75rem 1rem 1rem', display: 'flex', flexWrap: 'wrap', gap: '1rem' }}>
          {grids.map((g) => <HeatTile key={g.subnet} grid={g} maxScore={maxScore} />)}
        </div>
      )}
    </Card>
  );
}
