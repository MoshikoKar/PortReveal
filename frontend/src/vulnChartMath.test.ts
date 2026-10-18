import { describe, expect, it } from 'vitest';
import {
  barFillStyle, barWidthPct, cellIntensity, linePath, maxOf, trendHasData, xScale, yScale,
} from './vulnChartMath';

describe('maxOf', () => {
  it('is at least 1 to avoid division by zero', () => {
    expect(maxOf([])).toBe(1);
    expect(maxOf([0, 0])).toBe(1);
  });

  it('returns the largest value', () => {
    expect(maxOf([3, 7, 2])).toBe(7);
  });
});

describe('barWidthPct', () => {
  it('scales proportionally to max', () => {
    expect(barWidthPct(5, 10)).toBe(50);
    expect(barWidthPct(10, 10)).toBe(100);
    expect(barWidthPct(0, 10)).toBe(0);
  });

  it('is 0 when max is 0', () => {
    expect(barWidthPct(5, 0)).toBe(0);
  });

  it('clamps to [0, 100]', () => {
    expect(barWidthPct(-1, 10)).toBe(0);
    expect(barWidthPct(20, 10)).toBe(100);
  });
});

describe('barFillStyle', () => {
  it('sets fill width proportional to count / max in the card (0 → empty)', () => {
    // Mirrors the vuln dashboard bug report: unknown 463 vs nas 109, and <30d 572 vs 30-90d 0.
    const max = maxOf([463, 109]);
    expect(barFillStyle(463, max)).toEqual({ width: '100%' });
    expect(barFillStyle(109, max).width).toBe(`${(109 / 463) * 100}%`);
    expect(barFillStyle(0, max)).toEqual({ width: '0%' });
    expect(barFillStyle(572, 572)).toEqual({ width: '100%' });
  });
});

describe('xScale', () => {
  it('spaces points evenly across the plot width', () => {
    expect(xScale(0, 3, 10, 10, 100)).toBe(10);
    expect(xScale(2, 3, 10, 10, 100)).toBe(90);
    expect(xScale(1, 3, 10, 10, 100)).toBe(50);
  });

  it('pins a single point to the left edge', () => {
    expect(xScale(0, 1, 10, 10, 100)).toBe(10);
  });
});

describe('yScale', () => {
  it('maps 0 to the bottom and max to the top', () => {
    expect(yScale(0, 10, 0, 0, 100)).toBe(100);
    expect(yScale(10, 10, 0, 0, 100)).toBe(0);
  });

  it('is pinned to the bottom when max is 0', () => {
    expect(yScale(5, 0, 0, 10, 100)).toBe(90);
  });

  it('clamps values above max', () => {
    expect(yScale(20, 10, 0, 0, 100)).toBe(0);
  });
});

describe('linePath', () => {
  it('builds an SVG path with one M and the rest L', () => {
    const d = linePath([0, 5, 10], { width: 100, height: 100, left: 0, right: 0, top: 0, bottom: 0, max: 10 });
    const commands = d.split(' ').map((s) => s[0]);
    expect(commands).toEqual(['M', 'L', 'L']);
  });
});

describe('trendHasData', () => {
  it('is false when every point is zero', () => {
    expect(trendHasData([0, 0, 0])).toBe(false);
  });

  it('is true when any point is non-zero', () => {
    expect(trendHasData([0, 0, 3])).toBe(true);
  });
});

describe('cellIntensity', () => {
  it('scales 0-1 relative to the matrix max', () => {
    expect(cellIntensity(5, 10)).toBe(0.5);
    expect(cellIntensity(10, 10)).toBe(1);
  });

  it('is 0 for an empty cell or an empty matrix', () => {
    expect(cellIntensity(0, 10)).toBe(0);
    expect(cellIntensity(5, 0)).toBe(0);
  });
});
