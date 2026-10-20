import type { ReactNode } from 'react';
import { fmtTick, niceMax } from '../chartAxis';
import type { VulnSnapshotPoint, VulnWeeklyPoint } from '../types';
import { linePath, maxOf, trendHasData } from '../vulnChartMath';
import { Empty } from './ui';

interface LegendItem { color: string; label: string }

const SERIES: (LegendItem & { key: keyof Pick<VulnWeeklyPoint, 'new' | 'resolved' | 'dismissed'> })[] = [
  { key: 'new', color: 'var(--high)', label: 'new' },
  { key: 'resolved', color: 'var(--ok)', label: 'resolved' },
  { key: 'dismissed', color: 'var(--muted)', label: 'dismissed' },
];

const SEVERITY_SERIES: (LegendItem & { key: keyof Pick<VulnSnapshotPoint, 'critical' | 'high' | 'medium' | 'low'> })[] = [
  { key: 'critical', color: 'var(--high)', label: 'critical' },
  { key: 'high', color: '#fb923c', label: 'high' },
  { key: 'medium', color: 'var(--medium)', label: 'medium' },
  { key: 'low', color: 'var(--low)', label: 'low' },
];

const RISK_LEGEND: LegendItem[] = [
  { color: 'var(--accent)', label: 'risk (vuln-based)' },
  { color: 'var(--medium)', label: 'combined (+ exposure)' },
];

// Same box as the Dashboard's Trend: T leaves a band above the plot for the legend, L fits "12.5k".
// No right axis here, so R only needs room for the last x label.
const W = 560, H = 150, L = 40, R = 12, T = 22, B = 20;
const PLOT_H = H - T - B;
// Rough 11px glyph width, used to space legend entries by label length instead of a fixed step.
const LEGEND_CHAR_W = 6.2;

const scale = (max: number) => ({ width: W, height: H, left: L, right: R, top: T, bottom: B, max });

/** Grid, 0 / half / max y ticks, first/last x labels and a legend above the plot band. */
function TrendFrame({ label, max, from, to, legend, children }: {
  label: string; max: number; from: string; to: string; legend: LegendItem[]; children: ReactNode;
}) {
  let offset = 0;
  const placed = legend.map((s) => {
    const x = offset;
    offset += 16 + s.label.length * LEGEND_CHAR_W + 14;
    return { ...s, x };
  });
  return (
    <svg className="trend" viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={label}>
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={L} x2={W - R} y1={T + PLOT_H * f} y2={T + PLOT_H * f} stroke="var(--border)" />
          <text x={L - 6} y={T + PLOT_H * f + 3} textAnchor="end">{fmtTick(max * (1 - f))}</text>
        </g>
      ))}
      <text x={L} y={H - 5}>{from}</text>
      <text x={W - R} y={H - 5} textAnchor="end">{to}</text>
      {children}
      <g transform={`translate(${L}, 4)`}>
        {placed.map((s) => (
          <g key={s.label} transform={`translate(${s.x}, 0)`}>
            <rect width="12" height="2.5" y="4" fill={s.color} /><text x="16" y="8">{s.label}</text>
          </g>
        ))}
      </g>
    </svg>
  );
}

export function VulnTrend({ points }: { points: VulnWeeklyPoint[] }) {
  const totals = points.flatMap((p) => [p.new, p.resolved, p.dismissed]);
  if (!trendHasData(totals)) {
    return <Empty>No new, resolved or dismissed findings in this window yet.</Empty>;
  }
  const max = niceMax(maxOf(totals));
  return (
    <TrendFrame label="Weekly new, resolved and dismissed findings" max={max} legend={SERIES}
      from={points[0].week_start.slice(5)} to={points[points.length - 1].week_start.slice(5)}>
      {SERIES.map((s) => (
        <path key={s.key} d={linePath(points.map((p) => p[s.key]), scale(max))} fill="none" stroke={s.color} strokeWidth="2" />
      ))}
    </TrendFrame>
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
  const max = niceMax(maxOf(points.flatMap((p) => [p.critical, p.high, p.medium, p.low])));
  return (
    <TrendFrame label="Open vulnerability count over time, by severity" max={max} legend={SEVERITY_SERIES}
      from={points[0].date.slice(5)} to={points[points.length - 1].date.slice(5)}>
      {SEVERITY_SERIES.map((s) => (
        <path key={s.key} d={linePath(points.map((p) => p[s.key]), scale(max))} fill="none" stroke={s.color} strokeWidth="2" />
      ))}
    </TrendFrame>
  );
}

export function VulnRiskTrend({ points }: { points: VulnSnapshotPoint[] }) {
  const withRisk = points.filter((p) => p.avg_risk_score != null || p.avg_combined_score != null);
  if (needsMorePoints(withRisk)) {
    return <Empty>Trend appears after two daily snapshots with a scored device.</Empty>;
  }
  const max = niceMax(maxOf(withRisk.flatMap((p) => [p.avg_risk_score ?? 0, p.avg_combined_score ?? 0])));
  return (
    <TrendFrame label="Average network risk and combined score over time" max={max} legend={RISK_LEGEND}
      from={withRisk[0].date.slice(5)} to={withRisk[withRisk.length - 1].date.slice(5)}>
      <path d={linePath(withRisk.map((p) => p.avg_combined_score ?? 0), scale(max))} fill="none" stroke="var(--medium)" strokeWidth="1.6" />
      <path d={linePath(withRisk.map((p) => p.avg_risk_score ?? 0), scale(max))} fill="none" stroke="var(--accent)" strokeWidth="2" />
    </TrendFrame>
  );
}
