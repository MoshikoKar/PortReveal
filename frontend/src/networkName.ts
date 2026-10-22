// Network name rules shared by Settings / setup forms (keep in sync with backend netutils.validate_network_name).

export const NETWORK_NAME_MAX = 25;
export const NETWORK_NAME_EMPTY_MSG = 'Name must not be empty';
export const NETWORK_NAME_MAX_MSG = `At most ${NETWORK_NAME_MAX} characters`;
/** Plain-text charset hint (titles, equality checks). UI renders the punctuation as <code> chips. */
export const NETWORK_NAME_HINT = 'Use English letters, numbers, spaces and - _ . ( ) only';
export const NETWORK_NAME_LEGACY_HINT =
  `Legacy name — renaming requires ≤${NETWORK_NAME_MAX} English characters`;

const NETWORK_NAME_RE = /^[A-Za-z0-9 ._()-]+$/;

/** Match backend trim_network_name / JS String.trim (BOM + whitespace). */
export function trimNetworkName(raw: string): string {
  return raw.trim();
}

/**
 * Cap typed/pasted input so the trimmed name is at most `max` characters.
 * Preserves leading/trailing spaces while under the limit (so multi-word names
 * stay editable); when over, returns the trimmed+clipped core.
 */
export function limitNetworkNameInput(raw: string, max = NETWORK_NAME_MAX): string {
  if (trimNetworkName(raw).length <= max) return raw;
  return trimNetworkName(raw).slice(0, max);
}

/** True when a stored name would fail create/rename (charset or length). */
export function isLegacyNetworkName(raw: string): boolean {
  const name = trimNetworkName(raw);
  return !!name && (!NETWORK_NAME_RE.test(name) || name.length > NETWORK_NAME_MAX);
}

/**
 * Error for a new or changed network name, or null when valid.
 * Empty/whitespace-only: returns NETWORK_NAME_EMPTY_MSG when requireNonEmpty is true (field touched).
 */
export function networkNameError(raw: string, opts?: { requireNonEmpty?: boolean }): string | null {
  const name = trimNetworkName(raw);
  if (!name) return opts?.requireNonEmpty ? NETWORK_NAME_EMPTY_MSG : null;
  if (name.length > NETWORK_NAME_MAX) return NETWORK_NAME_MAX_MSG;
  if (!NETWORK_NAME_RE.test(name)) return NETWORK_NAME_HINT;
  return null;
}
