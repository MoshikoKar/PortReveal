import { useLayoutEffect, useState, type RefObject } from 'react';

/**
 * How many row elements matching `rowSelector` fit in the scroll parent of `ref`.
 * Returns null until measured (or when the body has no fixed height yet).
 */
export function useFittingRows(
  ref: RefObject<HTMLElement | null>,
  count: number,
  rowSelector = '.bar-row, tr, .event-row',
): number | null {
  const [fit, setFit] = useState<number | null>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    const body = el?.closest('.card-body') as HTMLElement | null ?? el?.parentElement;
    if (!el || !body) return;
    const measure = () => {
      const row = el.querySelector(rowSelector);
      if (!row) { setFit(null); return; }
      const pad = getComputedStyle(body);
      const room = body.clientHeight - parseFloat(pad.paddingTop) - parseFloat(pad.paddingBottom);
      if (room <= 0) { setFit(null); return; }
      const gap = parseFloat(getComputedStyle(el).rowGap || getComputedStyle(el).gap) || 0;
      const rh = row.getBoundingClientRect().height + gap;
      if (rh <= 0) { setFit(null); return; }
      setFit(Math.max(1, Math.floor((room + gap) / rh)));
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(body);
    return () => ro.disconnect();
  }, [ref, count, rowSelector]);
  return fit;
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
