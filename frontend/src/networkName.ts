// Network name rules shared by Settings / setup forms (keep in sync with backend netutils.validate_network_name).

export const NETWORK_NAME_MAX = 120;
export const NETWORK_NAME_HINT = 'Use English letters, numbers, spaces and - _ . ( ) only';

const NETWORK_NAME_RE = /^[A-Za-z0-9 ._()-]+$/;

/** Error for a new or changed network name, or null when valid. Empty input returns null (Save stays disabled separately). */
export function networkNameError(raw: string): string | null {
  const name = raw.trim();
  if (!name) return null;
  if (name.length > NETWORK_NAME_MAX) return `At most ${NETWORK_NAME_MAX} characters`;
  if (!NETWORK_NAME_RE.test(name)) return NETWORK_NAME_HINT;
  return null;
}
