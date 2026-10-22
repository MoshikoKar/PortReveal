import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  applyVulnSearchQ, clearVulnFilters, displayHiddenReasons, liveSearchParams,
  shouldResyncVulnQInput, withPendingVulnSearchQ,
} from './vulnFilters';

describe('applyVulnSearchQ', () => {
  it('returns null when URL q already matches the trimmed input', () => {
    const prev = new URLSearchParams('q=openssh&severity=high');
    expect(applyVulnSearchQ(prev, 'openssh')).toBeNull();
    expect(applyVulnSearchQ(prev, '  openssh  ')).toBeNull();
  });

  it('preserves other params from the live prev at fire time', () => {
    const prev = new URLSearchParams('severity=critical&page=2');
    const next = applyVulnSearchQ(prev, 'openssh');
    expect(next).not.toBeNull();
    expect(next!.get('q')).toBe('openssh');
    expect(next!.get('severity')).toBe('critical');
    expect(next!.get('page')).toBeNull();
  });

  it('trims q; whitespace-only clears search (no chip / no badge source)', () => {
    const prev = new URLSearchParams('q=x&severity=high&only_hidden=1');
    expect(applyVulnSearchQ(prev, '  openssh  ')!.get('q')).toBe('openssh');
    const cleared = applyVulnSearchQ(prev, '   \t  ');
    expect(cleared!.get('q')).toBeNull();
    expect(cleared!.get('only_hidden')).toBeNull();
    expect(cleared!.get('severity')).toBe('high');
  });

  it('stale-prev scenario: Clear all then debounce must use live empty params, not a snapshot', () => {
    // After Clear all the address bar is empty; RR functional prev may still be the old URL.
    const staleSnapshot = new URLSearchParams('severity=high&q=openssh&only_hidden=1');
    const liveAfterClear = new URLSearchParams('');

    // Bug if debounce used staleSnapshot with emptied input: severity would reappear.
    const wrong = applyVulnSearchQ(staleSnapshot, '');
    expect(wrong!.get('severity')).toBe('high');

    // Correct: apply onto live cleared params — nothing to restore.
    expect(applyVulnSearchQ(liveAfterClear, '')).toBeNull();

    // Typing after clear must not resurrect severity from a stale snapshot either.
    const resurrected = applyVulnSearchQ(staleSnapshot, 'nginx');
    expect(resurrected!.get('severity')).toBe('high'); // what a stale prev would do
    const correct = applyVulnSearchQ(liveAfterClear, 'nginx');
    expect(correct!.get('q')).toBe('nginx');
    expect(correct!.get('severity')).toBeNull();
  });

  it('stale-prev scenario: facet click during debounce must merge onto live URL with the facet', () => {
    const staleAtKeystroke = new URLSearchParams('q=ope');
    const liveAfterFacet = new URLSearchParams('severity=high&q=ope');
    // Debounce fires with full term; must keep severity from live, not drop it via stale.
    const next = applyVulnSearchQ(liveAfterFacet, 'openssh');
    expect(next!.get('q')).toBe('openssh');
    expect(next!.get('severity')).toBe('high');
    const lost = applyVulnSearchQ(staleAtKeystroke, 'openssh');
    expect(lost!.get('severity')).toBeNull();
  });
});

describe('liveSearchParams', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('reads window.location.search (not a closed-over snapshot)', () => {
    vi.stubGlobal('window', {
      location: { search: '?severity=high&q=openssh' },
    });
    const live = liveSearchParams();
    expect(live.get('severity')).toBe('high');
    expect(live.get('q')).toBe('openssh');
  });
});

describe('withPendingVulnSearchQ', () => {
  it('commits trimmed in-progress search onto a facet URL update', () => {
    const next = withPendingVulnSearchQ(new URLSearchParams('severity=high'), '  nginx  ');
    expect(next.get('severity')).toBe('high');
    expect(next.get('q')).toBe('nginx');
  });
});

describe('shouldResyncVulnQInput', () => {
  it('does not resync when URL q equals what the box last wrote', () => {
    expect(shouldResyncVulnQInput('op', 'op')).toBe(false);
  });

  it('resyncs when URL q changes externally (back/forward/shared link)', () => {
    expect(shouldResyncVulnQInput('nginx', 'openssh')).toBe(true);
    expect(shouldResyncVulnQInput('', 'openssh')).toBe(true);
  });
});

describe('clearVulnFilters clears q', () => {
  it('drops q and only_hidden along with facet filters', () => {
    const sp = new URLSearchParams('severity=critical&q=openssh&only_hidden=1&sort=cvss&page=2');
    const next = clearVulnFilters(sp);
    expect(next.get('severity')).toBeNull();
    expect(next.get('q')).toBeNull();
    expect(next.get('only_hidden')).toBeNull();
    expect(next.get('sort')).toBe('cvss');
    expect(next.get('page')).toBeNull();
  });
});

describe('displayHiddenReasons', () => {
  it('omits Dismissed / Potential (hidden) when the state pill already says so', () => {
    expect(displayHiddenReasons('dismissed', ['Dismissed', 'Below CVSS floor']))
      .toEqual(['Below CVSS floor']);
    expect(displayHiddenReasons('potential', ['Potential (hidden)', 'Below CVSS floor']))
      .toEqual(['Below CVSS floor']);
    expect(displayHiddenReasons('confirmed', ['Below CVSS floor'])).toEqual(['Below CVSS floor']);
  });
});
