/**
 * Summary payload ↔ filter-key binding for Export/Print.
 *
 * useApi keeps the previous payload while a new filter fetch is in flight. Print must wait
 * until the loaded payload's key matches the wanted filters — never treat a wanted-key-only
 * change as proof that `data` belongs to the new filter (that raced ahead of setLoading(true)).
 */

/** Whether print/export may use the current summary payload for the wanted filters. */
export function isVulnSummaryReady(
  data: unknown | null | undefined,
  loading: boolean,
  loadedKey: string | null,
  wantedKey: string,
): boolean {
  return !!data && !loading && loadedKey === wantedKey;
}

/**
 * Next loadedSummaryKey after a useApi (loading, data) transition.
 *
 * Call only when `loading` or `data` changes — not when `wantedKey` alone changes. Stamping on
 * wanted-key-only would bind a stale all-networks (or prior-network) payload to the new filter
 * before the matching response arrives. Out-of-order: useApi drops stale responses via seq, so
 * when an older fetch completes after a newer one started, `data` does not update and this
 * helper is not re-invoked with the obsolete key.
 */
export function nextLoadedSummaryKey(args: {
  loading: boolean;
  data: unknown | null | undefined;
  wantedKey: string;
  prevLoadedKey: string | null;
}): string | null {
  if (args.loading || !args.data) return args.prevLoadedKey;
  return args.wantedKey;
}
