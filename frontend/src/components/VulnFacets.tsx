import { Card } from './ui';
import type { AgeBucket, FacetBucket, VulnSummary } from '../types';
import { barWidthPct, maxOf } from '../vulnChartMath';
import type { VulnFilterKey, VulnFilters } from '../vulnFilters';

const AGE_BUCKETS: AgeBucket[] = ['under_30d', '30_90d', '90_365d', 'over_365d', 'unknown'];
const AGE_LABELS: Record<AgeBucket, string> = {
  under_30d: '< 30 days', '30_90d': '30-90 days', '90_365d': '90 days - 1 year', over_365d: '> 1 year', unknown: 'unknown',
};

function ageBuckets(counts: Record<AgeBucket, number>): FacetBucket[] {
  return AGE_BUCKETS.map((key) => ({ key, count: counts[key], label: AGE_LABELS[key] }));
}

function FacetBars({ title, buckets, filterKey, filters, onToggle, clickable = true }: {
  title: string;
  buckets: FacetBucket[];
  filterKey?: VulnFilterKey;
  filters: VulnFilters;
  onToggle: (key: VulnFilterKey, value: string) => void;
  /** False for facets with no matching GET /api/vulns filter (e.g. vendor/product) — display only. */
  clickable?: boolean;
}) {
  const max = maxOf(buckets.map((b) => b.count));
  const selected = filterKey ? filters[filterKey] : undefined;
  return (
    <Card title={title}>
      {buckets.length === 0 ? <div className="muted small">No data yet.</div> : (
        <div className="bars">
          {buckets.map((b) => {
            const value = String(b.key);
            const rowClickable = clickable && !!filterKey && value !== 'unassigned';
            const active = selected === value;
            const row = (
              <>
                <span style={active ? { fontWeight: 600, color: 'var(--accent)' } : undefined}>{b.label ?? value}</span>
                <span className="bar-track"><span className="bar-fill" style={{ width: `${barWidthPct(b.count, max)}%` }} /></span>
                <span className="right">{b.count}</span>
              </>
            );
            if (!rowClickable) {
              return <div key={value} className="bar-row" style={{ color: 'var(--text-2)' }}>{row}</div>;
            }
            return (
              <button key={value} type="button" className="bar-row"
                style={{ color: 'var(--text-2)', background: 'none', border: 0, padding: 0, width: '100%', cursor: 'pointer', font: 'inherit', textAlign: 'left' }}
                onClick={() => filterKey && onToggle(filterKey, value)}>
                {row}
              </button>
            );
          })}
        </div>
      )}
    </Card>
  );
}

export function VulnFacets({ summary, filters, onToggle }: {
  summary: VulnSummary;
  filters: VulnFilters;
  onToggle: (key: VulnFilterKey, value: string) => void;
}) {
  return (
    <div className="grid halves">
      <FacetBars title="By OS" buckets={summary.facets.os} filterKey="os_name" filters={filters} onToggle={onToggle} />
      <FacetBars title="By service" buckets={summary.facets.service} filterKey="service" filters={filters} onToggle={onToggle} />
      <FacetBars title="By port" buckets={summary.facets.port} filterKey="port" filters={filters} onToggle={onToggle} />
      <FacetBars title="By network" buckets={summary.facets.network} filterKey="network_id" filters={filters} onToggle={onToggle} />
      <FacetBars title="By device type" buckets={summary.facets.device_type} filterKey="device_type" filters={filters} onToggle={onToggle} />
      <FacetBars title="By vendor / product" buckets={summary.facets.vendor_product}
        filters={filters} onToggle={onToggle} clickable={false} />
      <FacetBars title="By CVE age (published)" buckets={ageBuckets(summary.facets.cve_age)} filterKey="cve_age"
        filters={filters} onToggle={onToggle} />
      <FacetBars title="By exposure duration" buckets={ageBuckets(summary.facets.exposure_duration)}
        filterKey="exposure_duration" filters={filters} onToggle={onToggle} />
    </div>
  );
}
