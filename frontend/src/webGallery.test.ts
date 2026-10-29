import { describe, expect, it, vi } from 'vitest';
import { filtersFromParams, observeWhenVisible, previewQuery, withFilters } from './webGallery';

/** Fake IntersectionObserver: tests decide which observed elements are on screen. */
class FakeObserver {
  static all: FakeObserver[] = [];
  targets: Element[] = [];
  disconnected = false;
  constructor(public cb: IntersectionObserverCallback, public opts?: IntersectionObserverInit) {
    FakeObserver.all.push(this);
  }
  observe(el: Element) { this.targets.push(el); }
  disconnect() { this.disconnected = true; }
  /** Report `el` as entering (true) or outside (false) the viewport. */
  fire(el: Element, isIntersecting: boolean) {
    if (this.disconnected) return;
    this.cb([{ target: el, isIntersecting } as IntersectionObserverEntry], this as unknown as IntersectionObserver);
  }
}

const card = (name: string) => ({ name }) as unknown as Element;

describe('observeWhenVisible', () => {
  it('loads only the cards that become visible, once each', () => {
    FakeObserver.all = [];
    const loaded: string[] = [];
    const cards = ['a', 'b', 'c'].map(card);
    cards.forEach((el, i) => observeWhenVisible(el, () => loaded.push(['a', 'b', 'c'][i]), '200px', FakeObserver));

    const [a, b, c] = FakeObserver.all;
    expect(a.opts?.rootMargin).toBe('200px');
    a.fire(cards[0], true);
    b.fire(cards[1], false); // below the fold: nothing loads
    expect(loaded).toEqual(['a']);
    a.fire(cards[0], true); // scrolling past again does not reload
    expect(loaded).toEqual(['a']);
    expect(a.disconnected).toBe(true);
    c.fire(cards[2], true);
    expect(loaded).toEqual(['a', 'c']);
    expect(b.disconnected).toBe(false);
  });

  it('cleanup stops a card that unmounts before it is seen', () => {
    FakeObserver.all = [];
    const onVisible = vi.fn();
    const el = card('x');
    const stop = observeWhenVisible(el, onVisible, '200px', FakeObserver);
    stop();
    FakeObserver.all[0].fire(el, true);
    expect(onVisible).not.toHaveBeenCalled();
  });

  it('loads right away without IntersectionObserver', () => {
    const onVisible = vi.fn();
    observeWhenVisible(card('x'), onVisible, '200px', undefined);
    expect(onVisible).toHaveBeenCalledTimes(1);
  });
});

describe('gallery filters in the URL', () => {
  it('reads every filter back from the URL', () => {
    const f = filtersFromParams(new URLSearchParams('q=host-a&network=3&port=443&scheme=https&status=no_preview&archived=1'));
    expect(f).toEqual({ q: 'host-a', network: 3, port: 443, scheme: 'https', status: 'no_preview', archived: true });
  });

  it('ignores malformed values', () => {
    const f = filtersFromParams(new URLSearchParams('network=abc&port=70000&scheme=ftp&status=bogus&archived=yes'));
    expect(f).toEqual({ q: '', network: null, port: null, scheme: null, status: 'ok', archived: false });
  });

  it('opens on "With preview"; status=all lists every card', () => {
    expect(filtersFromParams(new URLSearchParams()).status).toBe('ok');
    expect(filtersFromParams(new URLSearchParams('status=all')).status).toBeNull();
    const sp = new URLSearchParams();
    expect(withFilters(sp, { status: null }).toString()).toBe('status=all');
    expect(withFilters(new URLSearchParams('status=error'), { status: 'ok' }).toString()).toBe('');
  });

  it('round-trips through the URL and keeps unrelated params', () => {
    const sp = withFilters(new URLSearchParams('tab=x'), { q: '10.0.0.10', port: 8080, scheme: 'http', status: 'error', archived: true });
    expect(sp.get('tab')).toBe('x');
    expect(filtersFromParams(sp)).toMatchObject({ q: '10.0.0.10', port: 8080, scheme: 'http', status: 'error', archived: true });
    const cleared = withFilters(sp, { q: '', port: null, scheme: null, status: 'ok', archived: false });
    expect(cleared.toString()).toBe('tab=x');
  });

  it('builds the API query from the filters', () => {
    const f = filtersFromParams(new URLSearchParams('q=%20host-a%20&network=2&scheme=https&status=ok&archived=1'));
    expect(previewQuery(f, 2)).toEqual({
      page: 2, page_size: 36, q: 'host-a', network_id: 2, scheme: 'https', status: 'ok', include_archived: 'true',
    });
    expect(previewQuery(filtersFromParams(new URLSearchParams()), 1)).toEqual({ page: 1, page_size: 36, status: 'ok' });
    expect(previewQuery(filtersFromParams(new URLSearchParams('status=all')), 1)).toEqual({ page: 1, page_size: 36 });
  });
});
