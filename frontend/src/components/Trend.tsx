// Minimal dependency-free dual-axis line chart for the 30-day snapshot trend.
// Left axis = active hosts, right axis = open ports; hover (or arrow keys) shows a day's values.
import { useState, type KeyboardEvent, type PointerEvent } from 'react';
import { fmtTick, niceMax } from '../chartAxis';
import { Empty } from './ui';

interface Point { date: string; hosts_active: number; open_ports: number }

export function Trend({ points }: { points: Point[] }) {
  const [hover, setHover] = useState<number | null>(null);
  if (points.length < 2) {
    return <Empty>Trend appears after two daily snapshots.</Empty>;
  }
  const W = 560, H = 150, L = 36, R = 36, T = 22, B = 20;
  const plotW = W - L - R, plotH = H - T - B;
  const n = points.length;
  // Snapshots aren't guaranteed daily, so place each point by its real date rather than its index.
  const DAY = 86_400_000;
  const t = points.map((p) => Date.parse(p.date));
  const span = Math.max(DAY, t[n - 1] - t[0]);
  const xAt = (ms: number) => L + ((ms - t[0]) / span) * plotW;
  const xs = (i: number) => xAt(t[i]);
  const maxH = niceMax(Math.max(...points.map((p) => p.hosts_active)));
  const maxP = niceMax(Math.max(...points.map((p) => p.open_ports)));
  const yH = (v: number) => T + plotH * (1 - v / maxH);
  const yP = (v: number) => T + plotH * (1 - v / maxP);
  const line = (f: (p: Point) => number) => points.map((p, i) => `${i ? 'L' : 'M'}${xs(i).toFixed(1)},${f(p).toFixed(1)}`).join(' ');
  const portsLine = line((p) => yP(p.open_ports));
  const portsArea = `${portsLine} L${xs(n - 1).toFixed(1)},${T + plotH} L${L},${T + plotH} Z`;

  // Up to 5 evenly spaced day labels across the range, first and last day included.
  const days = Math.round(span / DAY);
  const tickCount = Math.min(4, days);
  const xTicks = [...new Set(Array.from({ length: tickCount + 1 }, (_, k) => Math.round((k * days) / tickCount)))]
    .map((d) => t[0] + d * DAY);

  const onMove = (e: PointerEvent<SVGSVGElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const vx = ((e.clientX - r.left) / r.width) * W;
    let best = 0;
    for (let i = 1; i < n; i++) if (Math.abs(xs(i) - vx) < Math.abs(xs(best) - vx)) best = i;
    setHover(best);
  };
  const onKey = (e: KeyboardEvent<SVGSVGElement>) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    e.preventDefault();
    const d = e.key === 'ArrowLeft' ? -1 : 1;
    setHover((h) => Math.min(n - 1, Math.max(0, (h ?? (d > 0 ? -1 : n)) + d)));
  };

  const hp = hover != null ? points[hover] : null;
  const leftSide = hover != null && xs(hover) > L + plotW / 2;

  return (
    <div className="trend-wrap">
      <svg
        className="trend" viewBox={`0 0 ${W} ${H}`} width="100%" role="img" tabIndex={0}
        aria-label={`30 day trend: ${points[n - 1].hosts_active} active hosts and ${points[n - 1].open_ports} open ports on ${points[n - 1].date}. Use arrow keys to inspect days.`}
        onPointerMove={onMove} onPointerLeave={() => setHover(null)} onKeyDown={onKey} onBlur={() => setHover(null)}
      >
        {[0, 0.5, 1].map((f) => (
          <g key={f}>
            <line x1={L} x2={W - R} y1={T + plotH * f} y2={T + plotH * f} stroke="var(--border)" />
            <text className="ax-h" x={L - 6} y={T + plotH * f + 3} textAnchor="end">{fmtTick(maxH * (1 - f))}</text>
            <text className="ax-p" x={W - R + 6} y={T + plotH * f + 3}>{fmtTick(maxP * (1 - f))}</text>
          </g>
        ))}
        {xTicks.map((ms, k) => (
          <text key={ms} x={xAt(ms)} y={H - 5} textAnchor={k === 0 ? 'start' : k === xTicks.length - 1 ? 'end' : 'middle'}>
            {new Date(ms).toISOString().slice(5, 10)}
          </text>
        ))}

        <defs>
          <linearGradient id="trend-ports-fill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stopColor="var(--medium)" stopOpacity="0.16" />
            <stop offset="1" stopColor="var(--medium)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={portsArea} fill="url(#trend-ports-fill)" />
        <path d={portsLine} fill="none" stroke="var(--medium)" strokeWidth="1.5" strokeDasharray="4 3" />
        <path d={line((p) => yH(p.hosts_active))} fill="none" stroke="var(--accent)" strokeWidth="2" />

        <g transform={`translate(${L}, 4)`}>
          <rect width="12" height="2.5" y="4" fill="var(--accent)" /><text x="16" y="8">active hosts (left)</text>
          <line x1="132" x2="144" y1="5.25" y2="5.25" stroke="var(--medium)" strokeWidth="2" strokeDasharray="4 2" />
          <text x="148" y="8">open ports (right)</text>
        </g>

        {hp && hover != null && (
          <g pointerEvents="none">
            <line x1={xs(hover)} x2={xs(hover)} y1={T} y2={T + plotH} stroke="var(--muted)" strokeDasharray="2 2" />
            <circle cx={xs(hover)} cy={yP(hp.open_ports)} r="3.5" fill="var(--panel)" stroke="var(--medium)" strokeWidth="2" />
            <circle cx={xs(hover)} cy={yH(hp.hosts_active)} r="3.5" fill="var(--panel)" stroke="var(--accent)" strokeWidth="2" />
          </g>
        )}
      </svg>

      {hp && hover != null && (
        <div
          className={`trend-tip${leftSide ? ' flip' : ''}`}
          style={{ left: `${(xs(hover) / W) * 100}%` }}
          role="status"
        >
          <div className="trend-tip-date">{hp.date}</div>
          <div><span className="sw" style={{ background: 'var(--accent)' }} />Active hosts <b>{hp.hosts_active.toLocaleString()}</b></div>
          <div><span className="sw" style={{ background: 'var(--medium)' }} />Open ports <b>{hp.open_ports.toLocaleString()}</b></div>
        </div>
      )}
    </div>
  );
}
