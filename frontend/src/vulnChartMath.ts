/** Pure scaling/bucketing math for the vulnerabilities dashboard's facet bars, trend chart and
 * severity-by-network matrix -- no SVG/DOM here, just numbers, so it's unit-testable without a
 * component-rendering harness (none exists in this repo).
 */

export function maxOf(values: number[]): number {
  return Math.max(1, ...values);
}

/** 0-100 bar width for a horizontal facet bar, relative to the largest bucket in its facet. */
export function barWidthPct(count: number, max: number): number {
  if (max <= 0) return 0;
  return Math.min(100, Math.max(0, (count / max) * 100));
}

/** Inline style for a facet `.bar-fill`: width is count/max of that card (0 → empty).
 * Fill color comes from CSS (`--bar-color` or `--accent`); callers may set `--bar-color`
 * for severity-tinted bars. */
export function barFillStyle(count: number, max: number): { width: string } {
  return { width: `${barWidthPct(count, max)}%` };
}

/** Evenly spaced X position for point `index` of `count` across [left, width - right]. */
export function xScale(index: number, count: number, left: number, right: number, width: number): number {
  if (count <= 1) return left;
  return left + (index * (width - left - right)) / (count - 1);
}

/** Y position for `value` (0 at `max`) within [top, height - bottom], inverted (SVG y grows down). */
export function yScale(value: number, max: number, top: number, bottom: number, height: number): number {
  if (max <= 0) return height - bottom;
  const frac = Math.min(1, Math.max(0, value / max));
  return top + (height - top - bottom) * (1 - frac);
}

export interface LinePathOpts {
  width: number;
  height: number;
  left: number;
  right: number;
  top: number;
  bottom: number;
  max: number;
}

/** SVG path `d` for a polyline through `values`, one per evenly spaced X position. */
export function linePath(values: number[], opts: LinePathOpts): string {
  return values
    .map((v, i) => {
      const x = xScale(i, values.length, opts.left, opts.right, opts.width);
      const y = yScale(v, opts.max, opts.top, opts.bottom, opts.height);
      return `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
}

/** False when every point is zero -- the weekly series is always a fixed 12-week window, so an
 * empty state means "no activity yet", not "too few points" (unlike the 30-day snapshot trend). */
export function trendHasData(totals: number[]): boolean {
  return totals.some((v) => v > 0);
}

/** 0-1 color-mix intensity for a severity-by-network matrix cell, relative to the matrix's max count. */
export function cellIntensity(count: number, max: number): number {
  if (max <= 0 || count <= 0) return 0;
  return Math.min(1, count / max);
}

/** CSS color variables aligned with the rest of the app (KPI / badge severity tones). */
export const SEVERITY_COLOR_VAR: Record<'critical' | 'high' | 'medium' | 'low', string> = {
  critical: 'var(--high)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--ok)',
};

/** Per-severity mix floors/spans so Low < Medium < High < Critical stays obvious even when a
 * Low cell has a higher count than a High cell (count only modulates within the severity band). */
const SEVERITY_MIX: Record<'critical' | 'high' | 'medium' | 'low', { floor: number; span: number }> = {
  low: { floor: 28, span: 18 },
  medium: { floor: 48, span: 18 },
  high: { floor: 68, span: 16 },
  critical: { floor: 86, span: 14 },
};

/** Background + readable text for a severity-by-network heatmap cell. */
export function cellFillStyle(
  severity: 'critical' | 'high' | 'medium' | 'low',
  count: number,
  max: number,
): { background: string; color: string } {
  if (count <= 0) return { background: 'var(--panel-3)', color: 'var(--muted)' };
  const intensity = cellIntensity(count, max);
  const { floor, span } = SEVERITY_MIX[severity];
  const pct = floor + Math.round(intensity * span);
  return {
    background: `color-mix(in srgb, ${SEVERITY_COLOR_VAR[severity]} ${pct}%, var(--panel-3))`,
    color: 'var(--text)',
  };
}
