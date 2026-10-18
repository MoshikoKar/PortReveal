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

/** 0-1 intensity for count relative to the matrix max (used only within a severity band). */
export function cellIntensity(count: number, max: number): number {
  if (max <= 0 || count <= 0) return 0;
  return Math.min(1, count / max);
}

export type SeverityKey = 'critical' | 'high' | 'medium' | 'low';

/**
 * Warm single-hue-family ramp (pale yellow → orange → red → deep crimson).
 * Lightness bands are disjoint so count modulation never lets a Low cell look darker than Medium
 * (or Medium darker than High, etc.). Higher severity = lower lightness = darker/more intense.
 */
const SEVERITY_HSL: Record<SeverityKey, { h: number; s: number; lMax: number; lMin: number }> = {
  low: { h: 48, s: 88, lMax: 78, lMin: 68 },
  medium: { h: 32, s: 90, lMax: 58, lMin: 50 },
  high: { h: 10, s: 82, lMax: 46, lMin: 38 },
  critical: { h: 0, s: 78, lMax: 32, lMin: 24 },
};

/** Resolved HSL lightness (0-100) for a cell -- exported for ramp unit tests. */
export function cellFillLightness(severity: SeverityKey, count: number, max: number): number {
  const { lMax, lMin } = SEVERITY_HSL[severity];
  const t = cellIntensity(count, max);
  return lMax - t * (lMax - lMin);
}

function hslToRgb(h: number, s: number, l: number): [number, number, number] {
  // s,l in [0,1]; h in degrees
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const hp = ((h % 360) + 360) % 360 / 60;
  const x = c * (1 - Math.abs((hp % 2) - 1));
  let r1 = 0, g1 = 0, b1 = 0;
  if (hp < 1) [r1, g1, b1] = [c, x, 0];
  else if (hp < 2) [r1, g1, b1] = [x, c, 0];
  else if (hp < 3) [r1, g1, b1] = [0, c, x];
  else if (hp < 4) [r1, g1, b1] = [0, x, c];
  else if (hp < 5) [r1, g1, b1] = [x, 0, c];
  else [r1, g1, b1] = [c, 0, x];
  const m = l - c / 2;
  return [Math.round((r1 + m) * 255), Math.round((g1 + m) * 255), Math.round((b1 + m) * 255)];
}

function srgbChannelToLinear(c: number): number {
  const v = c / 255;
  return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
}

/** Relative luminance (WCAG 2.x), 0 = black, 1 = white. */
export function relativeLuminance(r: number, g: number, b: number): number {
  return 0.2126 * srgbChannelToLinear(r) + 0.7152 * srgbChannelToLinear(g) + 0.0722 * srgbChannelToLinear(b);
}

export function contrastRatio(l1: number, l2: number): number {
  const a = Math.max(l1, l2);
  const b = Math.min(l1, l2);
  return (a + 0.05) / (b + 0.05);
}

const TEXT_LIGHT = '#ffffff';
const TEXT_DARK = '#141210';

/** Pick white or near-black text for WCAG AA (≥4.5:1) against the fill. */
export function readableTextColor(r: number, g: number, b: number): string {
  const bg = relativeLuminance(r, g, b);
  const white = contrastRatio(bg, 1);
  const black = contrastRatio(bg, relativeLuminance(0x14, 0x12, 0x10));
  if (white >= 4.5 && white >= black) return TEXT_LIGHT;
  if (black >= 4.5) return TEXT_DARK;
  return white >= black ? TEXT_LIGHT : TEXT_DARK;
}

/** Background + readable text for a severity-by-network heatmap cell. */
export function cellFillStyle(
  severity: SeverityKey,
  count: number,
  max: number,
): { background: string; color: string } {
  if (count <= 0) return { background: 'var(--panel-3)', color: 'var(--muted)' };
  const { h, s } = SEVERITY_HSL[severity];
  const l = cellFillLightness(severity, count, max);
  const [r, g, b] = hslToRgb(h, s / 100, l / 100);
  return {
    background: `hsl(${h} ${s}% ${l.toFixed(1)}%)`,
    color: readableTextColor(r, g, b),
  };
}
