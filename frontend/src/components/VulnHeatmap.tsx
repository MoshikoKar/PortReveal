import type { VulnSummary } from '../types';
import { cellFillStyle, maxOf } from '../vulnChartMath';
import type { VulnFilters } from '../vulnFilters';
import { Card, useClientSort, useRowLimit } from './ui';

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

/** "Severity by network" matrix -- distinct from the existing IP-grid exposure heatmap on the
 * Reports page, which colors by exposure score, not CVSS severity. Severity here is derived from
 * CVSS, not NVD's own severity label (the UI note repeats this near the dashboard header). */
export function VulnHeatmap({ rows, filters, onCellClick, onNetworkClick }: {
  rows: VulnSummary['severity_by_network'];
  filters: VulnFilters;
  onCellClick: (networkId: number | null, severity: string) => void;
  /** Click the network name to scope the whole page to that network (same as the By network facet). */
  onNetworkClick: (networkId: number | null) => void;
}) {
  type Row = (typeof rows)[number];
  const { rows: sorted, th } = useClientSort<Row, 'network' | (typeof SEVERITIES)[number]>(rows, {
    network: (r) => r.network,
    critical: (r) => r.critical, high: (r) => r.high, medium: (r) => r.medium, low: (r) => r.low,
  }, SEVERITIES);
  const { rows: visible, actions } = useRowLimit(sorted);
  const max = maxOf(rows.flatMap((r) => SEVERITIES.map((s) => r[s])));
  return (
    <Card title="Severity by network"
      actions={<><span className="muted small">Severity is derived from CVSS, not NVD&apos;s label</span>{actions}</>}>
      {rows.length === 0 ? <div className="muted small">No networks with matched findings yet.</div> : (
        <div className="table-wrap">
          {/* Fixed layout: a capped network column, then four equal severity columns. */}
          <table className="compact heatmap">
            <colgroup>
              <col className="heatmap-label" />
              {SEVERITIES.map((s) => <col key={s} />)}
            </colgroup>
            <thead>
              <tr>
                {th('network', 'Network')}
                {SEVERITIES.map((s) => th(s, s[0].toUpperCase() + s.slice(1)))}
              </tr>
            </thead>
            <tbody>
              {visible.map((row) => {
                const netKey = row.network_id != null ? String(row.network_id) : 'unassigned';
                const networkActive = filters.network_id === netKey && !filters.severity;
                return (
                  <tr key={row.network_id ?? 'unassigned'}>
                    <td className="heatmap-name" title={row.network}>
                      <button
                        type="button"
                        className={`heatmap-network-btn ${networkActive ? 'active' : ''}`}
                        aria-pressed={networkActive}
                        title={`Filter by network: ${row.network}`}
                        onClick={() => onNetworkClick(row.network_id)}
                      >
                        {row.network}
                      </button>
                    </td>
                    {SEVERITIES.map((s) => {
                      const count = row[s];
                      const active = filters.network_id === netKey && filters.severity === s;
                      const fill = cellFillStyle(s, count, max);
                      return (
                        <td key={s} className="heatmap-cell">
                          <button
                            type="button"
                            className={active ? 'active' : undefined}
                            disabled={count === 0}
                            aria-pressed={active}
                            title={`${row.network}: ${count} ${s}`}
                            onClick={() => onCellClick(row.network_id, s)}
                            style={{ background: fill.background, color: fill.color }}
                          >
                            {count || ''}
                          </button>
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
