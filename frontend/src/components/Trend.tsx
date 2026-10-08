// Minimal dependency-free line chart for the 30-day snapshot trend.
interface Point { date: string; hosts_active: number; open_ports: number }

export function Trend({ points }: { points: Point[] }) {
  if (points.length < 2) {
    return <div className="empty">Trend appears after two daily snapshots.</div>;
  }
  const W = 560, H = 150, L = 34, R = 34, T = 10, B = 22;
  const xs = (i: number) => L + (i * (W - L - R)) / (points.length - 1);
  const maxH = Math.max(1, ...points.map((p) => p.hosts_active));
  const maxP = Math.max(1, ...points.map((p) => p.open_ports));
  const yH = (v: number) => T + (H - T - B) * (1 - v / maxH);
  const yP = (v: number) => T + (H - T - B) * (1 - v / maxP);
  const path = (f: (p: Point) => number) => points.map((p, i) => `${i ? 'L' : 'M'}${xs(i).toFixed(1)},${f(p).toFixed(1)}`).join(' ');
  return (
    <svg className="trend" viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="30 day trend">
      {[0, 0.5, 1].map((f) => (
        <line key={f} x1={L} x2={W - R} y1={T + (H - T - B) * f} y2={T + (H - T - B) * f} stroke="var(--border)" />
      ))}
      <path d={path((p) => yP(p.open_ports))} fill="none" stroke="var(--medium)" strokeWidth="1.6" />
      <path d={path((p) => yH(p.hosts_active))} fill="none" stroke="var(--accent)" strokeWidth="2" />
      <text x={L - 6} y={T + 4} textAnchor="end">{maxH}</text>
      <text x={L - 6} y={H - B} textAnchor="end">0</text>
      <text x={W - R + 6} y={T + 4}>{maxP}</text>
      <text x={L} y={H - 6}>{points[0].date.slice(5)}</text>
      <text x={W - R} y={H - 6} textAnchor="end">{points[points.length - 1].date.slice(5)}</text>
      <g transform={`translate(${L + 8}, ${T + 8})`}>
        <rect width="10" height="3" y="3" fill="var(--accent)" /><text x="14" y="8">active hosts</text>
        <rect x="90" width="10" height="3" y="3" fill="var(--medium)" /><text x="104" y="8">open ports</text>
      </g>
    </svg>
  );
}
