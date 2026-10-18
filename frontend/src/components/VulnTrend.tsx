import type { VulnSnapshotPoint, VulnWeeklyPoint } from '../types';
import { linePath, maxOf, trendHasData } from '../vulnChartMath';
import { Empty } from './ui';

const SERIES: { key: keyof Pick<VulnWeeklyPoint, 'new' | 'resolved' | 'dismissed'>; color: string; label: string }[] = [
  { key: 'new', color: 'var(--high)', label: 'new' },
  { key: 'resolved', color: 'var(--ok)', label: 'resolved' },
  { key: 'dismissed', color: 'var(--muted)', label: 'dismissed' },
];

const SEVERITY_SERIES: { key: keyof Pick<VulnSnapshotPoint, 'critical' | 'high' | 'medium' | 'low'>; color: string; label: string }[] = [
  { key: 'critical', color: 'var(--high)', label: 'critical' },
  { key: 'high', color: '#fb923c', label: 'high' },
  { key: 'medium', color: 'var(--medium)', label: 'medium' },
  { key: 'low', color: 'var(--low)', label: 'low' },
];

export function VulnTrend({ points }: { points: VulnWeeklyPoint[] }) {
  const totals = points.flatMap((p) => [p.new, p.resolved, p.dismissed]);
  if (!trendHasData(totals)) {
    return <Empty>No new, resolved or dismissed findings in this window yet.</Empty>;
  }
  const W = 560, H = 150, L = 34, R = 10, T = 10, B = 22;
  const max = maxOf(totals);
  const opts = { width: W, height: H, left: L, right: R, top: T, bottom: B, max };
  return (
    <svg className="trend" viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Weekly new, resolved and dismissed findings">
      {[0, 0.5, 1].map((f) => (
        <line key={f} x1={L} x2={W - R} y1={T + (H - T - B) * f} y2={T + (H - T - B) * f} stroke="var(--border)" />
      ))}
      {SERIES.map((s) => (
        <path key={s.key} d={linePath(points.map((p) => p[s.key]), opts)} fill="none" stroke={s.color} strokeWidth="2" />
      ))}
      <text x={L - 6} y={T + 4} textAnchor="end">{max}</text>
      <text x={L - 6} y={H - B} textAnchor="end">0</text>
      <text x={L} y={H - 6}>{points[0].week_start.slice(5)}</text>
      <text x={W - R} y={H - 6} textAnchor="end">{points[points.length - 1].week_start.slice(5)}</text>
      <g transform={`translate(${L + 8}, ${T + 8})`}>
        {SERIES.map((s, i) => (
          <g key={s.key} transform={`translate(${i * 70}, 0)`}>
            <rect width="10" height="3" y="3" fill={s.color} /><text x="14" y="8">{s.label}</text>
          </g>
        ))}
      </g>
    </svg>
  );
}

/** Guard shared by the two snapshot-trend charts below: at least two daily/weekly points. */
function needsMorePoints(points: VulnSnapshotPoint[]) {
  return points.length < 2;
}

export function VulnSeverityTrend({ points }: { points: VulnSnapshotPoint[] }) {
  if (needsMorePoints(points)) {
    return <Empty>Trend appears after two daily snapshots.</Empty>;
  }
  const W = 560, H = 150, L = 34, R = 10, T = 10, B = 22;
  const max = maxOf(points.flatMap((p) => [p.critical, p.high, p.medium, p.low]));
  const opts = { width: W, height: H, left: L, right: R, top: T, bottom: B, max };
  return (
    <svg className="trend" viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Open vulnerability count over time, by severity">
      {[0, 0.5, 1].map((f) => (
        <line key={f} x1={L} x2={W - R} y1={T + (H - T - B) * f} y2={T + (H - T - B) * f} stroke="var(--border)" />
      ))}
      {SEVERITY_SERIES.map((s) => (
        <path key={s.key} d={linePath(points.map((p) => p[s.key]), opts)} fill="none" stroke={s.color} strokeWidth="2" />
      ))}
      <text x={L - 6} y={T + 4} textAnchor="end">{max}</text>
      <text x={L - 6} y={H - B} textAnchor="end">0</text>
      <text x={L} y={H - 6}>{points[0].date.slice(5)}</text>
      <text x={W - R} y={H - 6} textAnchor="end">{points[points.length - 1].date.slice(5)}</text>
      <g transform={`translate(${L + 8}, ${T + 8})`}>
        {SEVERITY_SERIES.map((s, i) => (
          <g key={s.key} transform={`translate(${i * 60}, 0)`}>
            <rect width="10" height="3" y="3" fill={s.color} /><text x="14" y="8">{s.label}</text>
          </g>
        ))}
      </g>
    </svg>
  );
}

export function VulnRiskTrend({ points }: { points: VulnSnapshotPoint[] }) {
  const withRisk = points.filter((p) => p.avg_risk_score != null || p.avg_combined_score != null);
  if (needsMorePoints(withRisk)) {
    return <Empty>Trend appears after two daily snapshots with a scored device.</Empty>;
  }
  const W = 560, H = 150, L = 34, R = 10, T = 10, B = 22;
  const max = maxOf(withRisk.flatMap((p) => [p.avg_risk_score ?? 0, p.avg_combined_score ?? 0]));
  const opts = { width: W, height: H, left: L, right: R, top: T, bottom: B, max };
  return (
    <svg className="trend" viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Average network risk and combined score over time">
      {[0, 0.5, 1].map((f) => (
        <line key={f} x1={L} x2={W - R} y1={T + (H - T - B) * f} y2={T + (H - T - B) * f} stroke="var(--border)" />
      ))}
      <path d={linePath(withRisk.map((p) => p.avg_combined_score ?? 0), opts)} fill="none" stroke="var(--medium)" strokeWidth="1.6" />
      <path d={linePath(withRisk.map((p) => p.avg_risk_score ?? 0), opts)} fill="none" stroke="var(--accent)" strokeWidth="2" />
      <text x={L - 6} y={T + 4} textAnchor="end">{max}</text>
      <text x={L - 6} y={H - B} textAnchor="end">0</text>
      <text x={L} y={H - 6}>{withRisk[0].date.slice(5)}</text>
      <text x={W - R} y={H - 6} textAnchor="end">{withRisk[withRisk.length - 1].date.slice(5)}</text>
      <g transform={`translate(${L + 8}, ${T + 8})`}>
        <rect width="10" height="3" y="3" fill="var(--accent)" /><text x="14" y="8">risk (vuln-based)</text>
        <rect x="110" width="10" height="3" y="3" fill="var(--medium)" /><text x="124" y="8">combined (+ exposure)</text>
      </g>
    </svg>
  );
}
