// Network name rules shared by Settings / setup forms (keep in sync with backend netutils.validate_network_name).

export const NETWORK_NAME_MAX = 120;
export const NETWORK_NAME_EMPTY_MSG = 'Name must not be empty';
export const NETWORK_NAME_MAX_MSG = `At most ${NETWORK_NAME_MAX} characters`;
/** Plain-text charset hint (titles, equality checks). UI renders the punctuation as <code> chips. */
export const NETWORK_NAME_HINT = 'Use English letters, numbers, spaces and - _ . ( ) only';
export const NETWORK_NAME_LEGACY_HINT = 'Legacy name — renaming requires English characters';

const NETWORK_NAME_RE = /^[A-Za-z0-9 ._()-]+$/;

/** Match backend trim_network_name / JS String.trim (BOM + whitespace). */
export function trimNetworkName(raw: string): string {
  return raw.trim();
}

/** True when a stored name would fail the create/rename charset rule. */
export function isLegacyNetworkName(raw: string): boolean {
  const name = trimNetworkName(raw);
  return !!name && !NETWORK_NAME_RE.test(name);
}

/** Error for a new or changed network name, or null when valid / still empty. */
export function networkNameError(raw: string): string | null {
  const name = trimNetworkName(raw);
  if (!name) return null;
  if (name.length > NETWORK_NAME_MAX) return NETWORK_NAME_MAX_MSG;
  if (!NETWORK_NAME_RE.test(name)) return NETWORK_NAME_HINT;
  return null;
}
