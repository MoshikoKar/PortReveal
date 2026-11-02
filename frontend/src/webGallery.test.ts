import { describe, expect, it, vi } from 'vitest';
import {
  ageDays, captureAgeText, filterUpdater, filtersFromParams, hasFilters, observeWhenVisible, pageTitle, previewQuery, withFilters,
} from './webGallery';

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
    const f = filtersFromParams(new URLSearchParams(
      'q=host-a&network=3&port=443&scheme=https&status=no_preview&attention=1&new=1&sort=oldest&archived=1'));
    expect(f).toEqual({
      q: 'host-a', network: 3, port: 443, scheme: 'https', status: 'no_preview', attention: true, fresh: true,
      sort: 'oldest', archived: true,
    });
  });

  it('ignores malformed values', () => {
    const f = filtersFromParams(new URLSearchParams('network=abc&port=70000&scheme=ftp&status=bogus&sort=x&archived=yes'));
    expect(f).toEqual({
      q: '', network: null, port: null, scheme: null, status: null, attention: false, fresh: false, sort: 'risk',
      archived: false,
    });
  });

  it('lists every card by default; older status=all links still work', () => {
    expect(filtersFromParams(new URLSearchParams()).status).toBeNull();
    expect(filtersFromParams(new URLSearchParams('status=all')).status).toBeNull();
    expect(withFilters(new URLSearchParams('status=error'), { status: null }).toString()).toBe('');
    expect(withFilters(new URLSearchParams('sort=name'), { sort: 'risk' }).toString()).toBe('');
  });

  it('round-trips through the URL and keeps unrelated params', () => {
    const sp = withFilters(new URLSearchParams('tab=x'),
      { q: '10.99.0.10', port: 8080, scheme: 'http', status: 'error', fresh: true, archived: true });
    expect(sp.get('tab')).toBe('x');
    expect(sp.get('new')).toBe('1');
    expect(filtersFromParams(sp)).toMatchObject({ q: '10.99.0.10', port: 8080, scheme: 'http', status: 'error', fresh: true, archived: true });
    const cleared = withFilters(sp, { q: '', port: null, scheme: null, status: null, fresh: false, archived: false });
    expect(cleared.toString()).toBe('tab=x');
  });

  it('builds the API query from the filters', () => {
    const f = filtersFromParams(new URLSearchParams('q=%20host-a%20&network=2&scheme=https&status=ok&attention=1&sort=name&archived=1'));
    expect(previewQuery(f, 2)).toEqual({
      page: 2, page_size: 36, q: 'host-a', network_id: 2, scheme: 'https', status: 'ok', attention: 'true', sort: 'name',
      include_archived: 'true',
    });
    expect(previewQuery(filtersFromParams(new URLSearchParams()), 1)).toEqual({ page: 1, page_size: 36 });
    expect(previewQuery(filtersFromParams(new URLSearchParams('new=1')), 1)).toEqual({ page: 1, page_size: 36, new: 'true' });
  });

  it('knows when anything narrows the gallery', () => {
    expect(hasFilters(filtersFromParams(new URLSearchParams('sort=name')))).toBe(false);
    expect(hasFilters(filtersFromParams(new URLSearchParams('attention=1')))).toBe(true);
  });
});

describe('page titles and capture age', () => {
  it('decodes entities and collapses whitespace', () => {
    expect(pageTitle('&nbsp;&nbsp;Router &amp; Switch&#39;s &#x2014; admin ')).toBe("Router & Switch's — admin");
    expect(pageTitle('&nbsp; ')).toBeNull();
    expect(pageTitle(null)).toBeNull();
    expect(pageTitle('&bogus; ok')).toBe('&bogus; ok');
  });

  it('words the age range of the listed captures', () => {
    const now = Date.parse('2026-01-30T12:00:00Z');
    expect(captureAgeText(['2026-01-30T08:00:00Z', '2026-01-30T09:00:00Z'], now)).toBe('Captured today');
    expect(captureAgeText(['2026-01-29T08:00:00Z', '2026-01-29T09:00:00Z'], now)).toBe('Captured 1 day ago');
    expect(captureAgeText(['2026-01-03T08:00:00Z', '2026-01-26T09:00:00Z'], now)).toBe('Captures 4–27 days old');
    expect(ageDays('2026-01-20T12:00:00Z', now)).toBe(10);
  });
});

describe('filterUpdater (debounced search)', () => {
  it('commits q onto the params current at commit time, never reverting a filter clicked meanwhile', () => {
    vi.useFakeTimers();
    try {
      let url = new URLSearchParams('status=error');
      const ref = { current: url };
      const set = (next: URLSearchParams) => { url = next; ref.current = next; };
      const update = filterUpdater(() => ref.current, set);
      // The user types: the search commit is debounced (as WebHosts does)...
      setTimeout(() => update({ q: 'camera' }, true), 300);
      // ...and clicks "All" before it fires.
      update({ status: null });
      expect(url.toString()).toBe('');
      vi.advanceTimersByTime(300);
      expect(url.get('status')).toBeNull();
      expect(url.get('q')).toBe('camera');
    } finally {
      vi.useRealTimers();
    }
  });

  it('only touches the patched keys', () => {
    let url = new URLSearchParams('network=2&port=443&scheme=https&status=all&archived=1');
    filterUpdater(() => url, (next) => { url = next; })({ q: 'nas' });
    expect(filtersFromParams(url)).toMatchObject({ q: 'nas', network: 2, port: 443, scheme: 'https', status: null, archived: true });
  });
});
