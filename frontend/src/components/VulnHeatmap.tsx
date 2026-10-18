import type { VulnSummary } from '../types';
import { cellIntensity, maxOf } from '../vulnChartMath';
import type { VulnFilters } from '../vulnFilters';

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

/** "Severity by network" matrix -- distinct from the existing IP-grid exposure heatmap on the
 * Reports page, which colors by exposure score, not CVSS severity. Severity here is derived from
 * CVSS, not NVD's own severity label (the UI note repeats this near the dashboard header). */
export function VulnHeatmap({ rows, filters, onCellClick }: {
  rows: VulnSummary['severity_by_network'];
  filters: VulnFilters;
  onCellClick: (networkId: number | null, severity: string) => void;
}) {
  if (rows.length === 0) return <div className="muted small">No networks with matched findings yet.</div>;
  const max = maxOf(rows.flatMap((r) => SEVERITIES.map((s) => r[s])));
  return (
    <div className="table-wrap">
      <table className="compact">
        <thead>
          <tr>
            <th>Network</th>
            {SEVERITIES.map((s) => <th key={s} style={{ textTransform: 'capitalize' }}>{s}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.network_id ?? 'unassigned'}>
              <td>{row.network}</td>
              {SEVERITIES.map((s) => {
                const count = row[s];
                const active = filters.network_id === String(row.network_id) && filters.severity === s;
                return (
                  <td key={s} style={{ padding: 2 }}>
                    <button
                      type="button"
                      disabled={count === 0}
                      title={`${row.network}: ${count} ${s}`}
                      onClick={() => onCellClick(row.network_id, s)}
                      style={{
                        width: '100%', height: 28, border: active ? '2px solid var(--accent)' : 0, borderRadius: 3,
                        padding: 0, cursor: count ? 'pointer' : 'default', color: 'var(--text-1)', fontSize: 12,
                        background: count
                          ? `color-mix(in srgb, var(--high) ${Math.round(cellIntensity(count, max) * 100)}%, var(--panel-3))`
                          : 'var(--panel-3)',
                      }}
                    >
                      {count || ''}
                    </button>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
