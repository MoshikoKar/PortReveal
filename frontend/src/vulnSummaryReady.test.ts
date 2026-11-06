import { describe, expect, it } from 'vitest';
import { isVulnSummaryReady, nextLoadedSummaryKey } from './vulnSummaryReady';

const ALL = '';
const NET_A = '?network_id=1';
const NET_B = '?network_id=2';
const summary = { total: 1 };

describe('isVulnSummaryReady', () => {
  it('requires data, not-loading, and exact payload-key match', () => {
    expect(isVulnSummaryReady(summary, false, ALL, ALL)).toBe(true);
    expect(isVulnSummaryReady(null, false, ALL, ALL)).toBe(false);
    expect(isVulnSummaryReady(summary, true, ALL, ALL)).toBe(false);
    expect(isVulnSummaryReady(summary, false, ALL, NET_A)).toBe(false);
    expect(isVulnSummaryReady(summary, false, null, ALL)).toBe(false);
  });
});

describe('nextLoadedSummaryKey / payload-key binding', () => {
  it('does not stamp while loading (stale data must stay bound to previous key)', () => {
    expect(nextLoadedSummaryKey({
      loading: true,
      data: summary,
      wantedKey: NET_A,
      prevLoadedKey: ALL,
    })).toBe(ALL);
  });

  it('stamps wantedKey only when a fetch completes with data', () => {
    expect(nextLoadedSummaryKey({
      loading: false,
      data: summary,
      wantedKey: NET_A,
      prevLoadedKey: ALL,
    })).toBe(NET_A);
  });

  it('leaves prev when data is missing', () => {
    expect(nextLoadedSummaryKey({
      loading: false,
      data: null,
      wantedKey: NET_A,
      prevLoadedKey: ALL,
    })).toBe(ALL);
  });

  it('simulates filter transition: ready only after matching response, not on wanted-key alone', () => {
    let loaded: string | null = null;
    // Cold start fetch completes for all-networks.
    loaded = nextLoadedSummaryKey({
      loading: false, data: summary, wantedKey: ALL, prevLoadedKey: loaded,
    });
    expect(loaded).toBe(ALL);
    expect(isVulnSummaryReady(summary, false, loaded, ALL)).toBe(true);

    // User selects network A. Effect deps are [loading, data] only — wanted alone does not
    // re-stamp. Stale all-networks data remains under loaded=ALL while wanted=NET_A.
    const wanted = NET_A;
    expect(isVulnSummaryReady(summary, false, loaded, wanted)).toBe(false);

    // Fetch in flight: still not ready.
    expect(isVulnSummaryReady(summary, true, loaded, wanted)).toBe(false);
    loaded = nextLoadedSummaryKey({
      loading: true, data: summary, wantedKey: wanted, prevLoadedKey: loaded,
    });
    expect(loaded).toBe(ALL);
    expect(isVulnSummaryReady(summary, true, loaded, wanted)).toBe(false);

    // Matching network-A response arrives.
    loaded = nextLoadedSummaryKey({
      loading: false, data: { total: 2 }, wantedKey: wanted, prevLoadedKey: loaded,
    });
    expect(loaded).toBe(NET_A);
    expect(isVulnSummaryReady({ total: 2 }, false, loaded, wanted)).toBe(true);
  });

  it('out-of-order: stale payload stays unbound until the matching fetch completes', () => {
    // Started for NET_A, then user switched to NET_B before NET_A returned.
    // useApi ignores the NET_A response (seq); data stays previous until NET_B completes.
    let loaded: string | null = ALL;
    loaded = nextLoadedSummaryKey({
      loading: true, data: summary, wantedKey: NET_B, prevLoadedKey: loaded,
    });
    expect(loaded).toBe(ALL);
    expect(isVulnSummaryReady(summary, true, loaded, NET_B)).toBe(false);

    // Race we prevent in the page effect: stamping wantedKey while still showing stale data
    // would make isVulnSummaryReady true for the wrong payload. Omitting wantedKey from the
    // effect deps means nextLoadedSummaryKey is not invoked on key-only changes, so loaded
    // stays ALL until B's completion:
    expect(isVulnSummaryReady(summary, false, ALL, NET_B)).toBe(false);

    loaded = nextLoadedSummaryKey({
      loading: false, data: { network: 'B' }, wantedKey: NET_B, prevLoadedKey: ALL,
    });
    expect(loaded).toBe(NET_B);
    expect(isVulnSummaryReady({ network: 'B' }, false, loaded, NET_B)).toBe(true);
  });
});

