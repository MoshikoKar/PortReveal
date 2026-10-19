import { Card, useRowLimit } from './ui';
import type { AgeBucket, FacetBucket, VulnSummary } from '../types';
import { barFillStyle, maxOf } from '../vulnChartMath';
import {
  type VulnFilterKey, type VulnFilters, vendorProductFacetActive,
} from '../vulnFilters';

const AGE_BUCKETS: AgeBucket[] = ['under_30d', '30_90d', '90_365d', 'over_365d', 'unknown'];
const AGE_LABELS: Record<AgeBucket, string> = {
  under_30d: '< 30 days', '30_90d': '30-90 days', '90_365d': '90 days - 1 year', over_365d: '> 1 year', unknown: 'unknown',
};

function ageBuckets(counts: Record<AgeBucket, number>): FacetBucket[] {
  return AGE_BUCKETS.map((key) => ({ key, count: counts[key], label: AGE_LABELS[key] }));
}

/** One facet card: at most 10 bars, then "See all" pages through the rest. Bars scale to the
 * largest bucket overall, so they stay comparable across pages. */
function BarsCard({ title, buckets, isActive, onClick }: {
  title: string;
  buckets: FacetBucket[];
  isActive: (value: string) => boolean;
  onClick: (value: string) => void;
}) {
  const max = maxOf(buckets.map((b) => b.count));
  const { rows, actions } = useRowLimit(buckets);
  return (
    <Card title={title} actions={actions}>
      {buckets.length === 0 ? <div className="muted small">No data yet.</div> : (
        <div className="bars">
          {rows.map((b) => {
            const value = String(b.key);
            const active = isActive(value);
            return (
              <button key={value} type="button" className={`bar-row ${active ? 'active' : ''}`} aria-pressed={active}
                title={`${b.label ?? value}: ${b.count}`} onClick={() => onClick(value)}>
                <span>{b.label ?? value}</span>
                <span className="bar-track"><span className="bar-fill" style={barFillStyle(b.count, max)} /></span>
                <span className="right">{b.count}</span>
              </button>
            );
          })}
        </div>
      )}
    </Card>
  );
}

export function VulnFacets({ summary, filters, onToggle, onToggleVendorProduct }: {
  summary: VulnSummary;
  filters: VulnFilters;
  onToggle: (key: VulnFilterKey, value: string) => void;
  onToggleVendorProduct: (facetKey: string) => void;
}) {
  const facet = (title: string, buckets: FacetBucket[], key: VulnFilterKey) => (
    <BarsCard title={title} buckets={buckets}
      isActive={(value) => filters[key] === value} onClick={(value) => onToggle(key, value)} />
  );
  return (
    <>
      {/* Text-heavy facets stay at two columns. */}
      <div className="grid halves">
        {facet('By OS', summary.facets.os, 'os_name')}
        {/* One click sets both URL params (`vendor` + `product`), matching the summary bucket key
            `vendor:product` (or `vendor=unknown` with no product). */}
        <BarsCard title="By vendor / product" buckets={summary.facets.vendor_product}
          isActive={(value) => vendorProductFacetActive(filters, value)} onClick={onToggleVendorProduct} />
      </div>
      {/* Grouped by length so cards sharing a row are about the same height: the open-ended
          facets (up to 10 rows each), then the short ones (a few networks, 5 age buckets). */}
      <div className="grid three">
        {facet('By service', summary.facets.service, 'service')}
        {facet('By port', summary.facets.port, 'port')}
        {facet('By device type', summary.facets.device_type, 'device_type')}
      </div>
      <div className="grid three">
        {facet('By network', summary.facets.network, 'network_id')}
        {facet('By CVE age (published)', ageBuckets(summary.facets.cve_age), 'cve_age')}
        {facet('By exposure duration', ageBuckets(summary.facets.exposure_duration), 'exposure_duration')}
      </div>
    </>
  );
}
