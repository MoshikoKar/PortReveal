/** Y-axis helpers shared by the hand-rolled SVG trend charts (Dashboard exposure trend, vuln trends). */

/** Smallest "round" value >= v so the 0 / half / max ticks read cleanly (568 → 600, 4891 → 5000). */
export function niceMax(v: number): number {
  if (v <= 2) return 2;
  const mag = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * mag >= v) return m * mag;
  return 10 * mag;
}

/** Compact tick label: 12500 → "12.5k", 1250 → "1.25k" (niceMax half ticks), 600 → "600", 2.5 → "2.5". */
export const fmtTick = (v: number): string =>
  v >= 1000 ? `${+(v / 1000).toFixed(2)}k` : `${+v.toFixed(1)}`;
