import { describe, expect, it } from 'vitest';
import { fmtTick, niceMax } from './chartAxis';

describe('niceMax', () => {
  it('has a floor of 2 so tiny series still get a half tick', () => {
    expect(niceMax(0)).toBe(2);
    expect(niceMax(1)).toBe(2);
  });

  it('rounds up to the next round step', () => {
    expect(niceMax(568)).toBe(600);
    expect(niceMax(4891)).toBe(5000);
    expect(niceMax(16735)).toBe(20000);
    expect(niceMax(18303)).toBe(20000);
  });

  it('keeps values that are already round', () => {
    expect(niceMax(1000)).toBe(1000);
    expect(niceMax(25)).toBe(25);
  });
});

describe('fmtTick', () => {
  it('abbreviates thousands', () => {
    expect(fmtTick(20000)).toBe('20k');
    expect(fmtTick(12500)).toBe('12.5k');
    expect(fmtTick(1250)).toBe('1.25k');
  });

  it('drops trailing zeros below 1000', () => {
    expect(fmtTick(600)).toBe('600');
    expect(fmtTick(2.5)).toBe('2.5');
    expect(fmtTick(0)).toBe('0');
  });
});
