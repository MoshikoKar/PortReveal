import { useLayoutEffect, useState, type RefObject } from 'react';

/**
 * How many row elements matching `rowSelector` fit completely in the scroll parent of `ref`.
 * Rows are measured where they actually sit, so headers, content above the rows and the body's
 * bottom padding are accounted for and the last shown row is never cut. Rows not rendered yet
 * are estimated from the tallest rendered one.
 * Returns null until measured (or when the body has no fixed height yet), and while `disabled`
 * so "Fit height" can measure the widget's full, untruncated content.
 */
export function useFittingRows(
  ref: RefObject<HTMLElement | null>,
  count: number,
  rowSelector = '.bar-row, tr, .event-row',
  disabled = false,
): number | null {
  const [fit, setFit] = useState<number | null>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    const body = el?.closest('.card-body') as HTMLElement | null ?? el?.parentElement;
    if (!el || !body) return;
    const measure = () => {
      const rows = el.querySelectorAll(rowSelector);
      if (!rows.length) { setFit(null); return; }
      // Bottom edge of the body's content box, relative to the top of its scrolled content.
      const limit = body.clientHeight - parseFloat(getComputedStyle(body).paddingBottom);
      if (limit <= 0) { setFit(null); return; }
      const top = body.getBoundingClientRect().top + body.clientTop - body.scrollTop;
      let n = 0;
      let bottom = 0;
      let tallest = 0;
      for (const row of rows) {
        const r = row.getBoundingClientRect();
        if (r.bottom - top > limit + 0.5) break;
        n += 1;
        bottom = r.bottom - top;
        tallest = Math.max(tallest, r.height);
      }
      if (n === rows.length && tallest > 0) {
        const gap = parseFloat(getComputedStyle(rows[0].parentElement ?? el).rowGap) || 0;
        n += Math.floor((limit - bottom) / (tallest + gap));
      }
      setFit(Math.max(1, n));
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(body);
    return () => ro.disconnect();
  }, [ref, count, rowSelector, disabled]);
  return disabled ? null : fit;
}

/** Track width/height of an element for charts that must fill the card. */
export function useContainerSize(ref: RefObject<HTMLElement | null>): { width: number; height: number } {
  const [size, setSize] = useState({ width: 0, height: 0 });
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const measure = () => {
      setSize({ width: el.clientWidth, height: el.clientHeight });
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref]);
  return size;
}

/** Estimate grid row units needed for content height (for fit-height-to-content). */
export function rowsForContentHeight(contentPx: number, rowHeight: number, marginY: number): number {
  if (contentPx <= 0) return 1;
  return Math.max(1, Math.ceil((contentPx + marginY) / (rowHeight + marginY)));
}
