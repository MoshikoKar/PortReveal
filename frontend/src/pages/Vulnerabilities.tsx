import { useSearchParams } from 'react-router-dom';
import { VulnFacets } from '../components/VulnFacets';
import { VulnFindingsTable } from '../components/VulnFindingsTable';
import { VulnHeatmap } from '../components/VulnHeatmap';
import { VulnTopLists } from '../components/VulnTopLists';
import { VulnRiskTrend, VulnSeverityTrend, VulnTrend } from '../components/VulnTrend';
import { Card, ErrorBox, Kpi, Loading } from '../components/ui';
import type { VulnSummary } from '../types';
import { fmtTime, relTime, useApi } from '../util';
import { clearVulnFilters, parseVulnFilters, setVulnFilter, toggleVulnFilter, type VulnFilterKey } from '../vulnFilters';

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'var(--high)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--ok)',
};

const FILTER_LABELS: Record<VulnFilterKey, string> = {
  severity: 'severity', kev: 'KEV', epss_min: 'EPSS ≥', network_id: 'network', service: 'service',
  port: 'port', os_name: 'OS', device_type: 'device type', state: 'state', cve_age: 'CVE age',
  exposure_duration: 'exposure duration',
};

export default function Vulnerabilities() {
  const [sp, setSp] = useSearchParams();
  const filters = parseVulnFilters(sp);
  const page = Number(sp.get('page') || 1);
  const { data, error, reload } = useApi<VulnSummary>('/vulns/summary', undefined, 30000);

  const toggle = (key: VulnFilterKey, value: string) => setSp(toggleVulnFilter(sp, key, value));
  const set = (key: VulnFilterKey, value: string | undefined) => setSp(setVulnFilter(sp, key, value));
  const setPage = (p: number) => {
    const next = new URLSearchParams(sp);
    if (p <= 1) next.delete('page');
    else next.set('page', String(p));
    setSp(next);
  };
  const activeFilters = Object.entries(filters) as [VulnFilterKey, string][];

  const severity = data?.severity_counts ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const risk = data?.risk_device_levels ?? { high: 0, medium: 0, low: 0 };
  const epssPct = data ? Math.round(data.epss_threshold * 100) : 0;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Vulnerabilities</h1>
          <p>Matched CVEs across the network. Severity bands come from CVSS score, not NVD&apos;s own severity label — the two can disagree.</p>
        </div>
      </div>
      <ErrorBox error={error} />
      {!data ? (!error && <Loading />) : (
        <>
          {activeFilters.length > 0 && (
            <div className="row wrap" style={{ gap: 8, marginBottom: 12 }}>
              <span className="muted small">Filters:</span>
              {activeFilters.map(([key, value]) => (
                <button key={key} type="button" className="badge outline" style={{ cursor: 'pointer', border: 0 }}
                  onClick={() => set(key, undefined)} title="Remove this filter">
                  {FILTER_LABELS[key]}: {value} ✕
                </button>
              ))}
              <button type="button" className="btn sm ghost" onClick={() => setSp(clearVulnFilters(sp))}>Clear all</button>
            </div>
          )}

          <Card className={data.kev_count > 0 ? 'kev-card active' : 'kev-card'}>
            <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
              onClick={() => toggle('kev', 'true')}>
              <div>
                <div className="label" style={{ fontSize: 13, fontWeight: 600, color: data.kev_count > 0 ? 'var(--high)' : 'var(--muted)' }}>
                  Actively exploited (CISA KEV)
                </div>
                <div className="muted small">Known to be exploited in the wild — the most urgent findings on this network.</div>
              </div>
              <div style={{ fontSize: 40, fontWeight: 700, color: data.kev_count > 0 ? 'var(--high)' : undefined }}>
                {data.kev_count}
              </div>
            </div>
          </Card>

          <div className="grid kpis">
            <Kpi label="Critical" value={severity.critical} color={SEVERITY_COLOR.critical} onClick={() => toggle('severity', 'critical')} />
            <Kpi label="High" value={severity.high} color={SEVERITY_COLOR.high} onClick={() => toggle('severity', 'high')} />
            <Kpi label="Medium" value={severity.medium} color={SEVERITY_COLOR.medium} onClick={() => toggle('severity', 'medium')} />
            <Kpi label="Low" value={severity.low} color={SEVERITY_COLOR.low} onClick={() => toggle('severity', 'low')} />
            <Kpi label={`High exploit probability (EPSS ≥ ${epssPct}%)`} value={data.epss_high_count}
              sub="FIRST.org exploitation-probability score" onClick={() => set('epss_min', String(data.epss_threshold))} />
            <Kpi label="High-risk devices" value={risk.high} sub={`${risk.medium} medium · ${risk.low} low`}
              color={risk.high ? 'var(--high)' : undefined} />
            <Kpi label="Confirmed findings" value={data.confirmed_count} onClick={() => toggle('state', 'confirmed')} />
            <Kpi label="Potential findings" value={data.potential_count} onClick={() => toggle('state', 'potential')} />
          </div>

          <Card title="Vulnerability feed">
            {data.feed.stale && (
              <div className="badge high" style={{ marginBottom: 10 }}>
                Stale — oldest enabled source hasn&apos;t synced in over {data.feed.stale_threshold_hours}h
              </div>
            )}
            <dl className="dl">
              <dt>Oldest enabled-source sync</dt>
              <dd>
                {data.feed.oldest_synced_at
                  ? <>{fmtTime(data.feed.oldest_synced_at)} <span className="muted">({relTime(data.feed.oldest_synced_at)})</span></>
                  : <span className="muted">never synced</span>}
              </dd>
              <dt>Most recent enabled-source sync</dt>
              <dd>
                {data.feed.newest_synced_at
                  ? <>{fmtTime(data.feed.newest_synced_at)} <span className="muted">({relTime(data.feed.newest_synced_at)})</span></>
                  : <span className="muted">never synced</span>}
              </dd>
            </dl>
          </Card>

          <div className="grid three">
            <Card title="New vs. resolved vs. dismissed (weekly)">
              <VulnTrend points={data.weekly} />
            </Card>
            <Card title="Open vulnerabilities over time (by severity)">
              <VulnSeverityTrend points={data.snapshot_trend} />
            </Card>
            <Card title="Average network risk score over time">
              <VulnRiskTrend points={data.snapshot_trend} />
            </Card>
          </div>

          <Card title="Severity by network" actions={<span className="muted small">Severity is derived from CVSS, not NVD&apos;s label</span>}>
            <VulnHeatmap rows={data.severity_by_network} filters={filters}
              onCellClick={(networkId, severity) => {
                let next = toggleVulnFilter(sp, 'severity', severity);
                next = setVulnFilter(next, 'network_id', networkId != null ? String(networkId) : undefined);
                setSp(next);
              }} />
          </Card>

          <VulnFacets summary={data} filters={filters} onToggle={toggle} />
          <VulnTopLists summary={data} />
          <VulnFindingsTable
            filters={filters}
            page={page}
            onPage={setPage}
            onToggleDismissed={(show) => set('state', show ? 'dismissed' : undefined)}
            onChanged={() => { void reload(); }}
          />
        </>
      )}
    </>
  );
}
