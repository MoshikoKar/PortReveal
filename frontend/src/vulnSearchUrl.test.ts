import { describe, expect, it } from 'vitest';
import {
  applyVulnSearchQ, clearVulnFilters, displayHiddenReasons, shouldResyncVulnQInput,
} from './vulnFilters';

describe('applyVulnSearchQ', () => {
  it('returns null when URL q already matches the input (no overwrite navigation)', () => {
    const prev = new URLSearchParams('q=openssh&severity=high');
    expect(applyVulnSearchQ(prev, 'openssh')).toBeNull();
  });

  it('preserves other params from prev at fire time (avoids stale-closure facet loss)', () => {
    // Debounce started with empty filters; a facet click added severity before the timer fired.
    const prev = new URLSearchParams('severity=critical&page=2');
    const next = applyVulnSearchQ(prev, 'openssh');
    expect(next).not.toBeNull();
    expect(next!.get('q')).toBe('openssh');
    expect(next!.get('severity')).toBe('critical');
    expect(next!.get('page')).toBeNull();
  });

  it('clears q and only_hidden when the input is emptied', () => {
    const prev = new URLSearchParams('q=openssh&only_hidden=1&kev=true');
    const next = applyVulnSearchQ(prev, '');
    expect(next!.get('q')).toBeNull();
    expect(next!.get('only_hidden')).toBeNull();
    expect(next!.get('kev')).toBe('true');
  });
});

describe('shouldResyncVulnQInput', () => {
  it('does not resync when URL q equals what the box last wrote (avoids mid-typing overwrite)', () => {
    // User typed "op" → debounce wrote "op"; local input already advanced to "ope".
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
