// Wordlist library UI rules: client-side prechecks (the server re-validates everything) and status text.
import type { Wordlist, WordlistImportResult, WordlistImportSummary, WordlistLibrary, WordlistLimits } from './types';

export const NAME_MAX = 64;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,63}$/;
const TEXT_EXTS = ['.txt', '.lst', '.list', '.dic'];

/** Upload / import progress shown under the library toolbar. */
export type ImportState =
  | { status: 'idle' }
  | { status: 'busy'; text: string }
  | { status: 'done'; text: string; samples: string[]; reasons: [string, number][] }
  | { status: 'error'; text: string };

export function nameError(name: string): string | null {
  const n = name.trim().replace(/\s+/g, ' ');
  if (!n) return null; // optional on create: derived from the file name
  if (n.length > NAME_MAX) return `Name must be at most ${NAME_MAX} characters.`;
  if (!NAME_RE.test(n)) return "Use letters, digits, space, '.', '_', '-', '(' and ')'; start with a letter or digit.";
  return null;
}

export function acceptedExtensions(limits?: Pick<WordlistLimits, 'extensions'> | null): string {
  return (limits?.extensions ?? [...TEXT_EXTS, ...TEXT_EXTS.map((e) => `${e}.gz`)]).join(',');
}

/** Extension and size precheck before upload. Content (binary, UTF-8, gzip bombs) is checked server-side. */
export function fileError(file: { name: string; size: number } | null, limits?: WordlistLimits | null): string | null {
  if (!file) return 'Choose a file.';
  const n = file.name.toLowerCase();
  const base = n.endsWith('.gz') ? n.slice(0, -3) : n;
  if (!TEXT_EXTS.some((e) => base.endsWith(e))) return 'Unsupported file type: use .txt, .lst, .list or .dic (optionally .gz).';
  if (file.size === 0) return 'The file is empty.';
  if (limits && file.size > limits.max_upload_bytes) return `File is larger than ${formatBytes(limits.max_upload_bytes)}.`;
  return null;
}

export function urlError(url: string, allowHttp = false): string | null {
  const u = url.trim();
  if (!u) return 'Enter a URL.';
  let parsed: URL;
  try {
    parsed = new URL(u);
  } catch {
    return 'Enter a valid URL.';
  }
  const okScheme = parsed.protocol === 'https:' || (allowHttp && parsed.protocol === 'http:');
  if (!okScheme) return allowHttp ? 'Only http:// or https:// URLs are allowed.' : 'Only https:// URLs are allowed.';
  if (parsed.username || parsed.password) return 'Credentials in the URL are not allowed.';
  return null;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export const shortSha = (sha: string) => sha.slice(0, 12);

/** "Accepted 120 / skipped 3 (duplicate 2, path traversal 1)". */
export function summaryText(s: WordlistImportSummary): string {
  return `Accepted ${s.accepted.toLocaleString('en-US')} / skipped ${s.skipped.toLocaleString('en-US')}`;
}

/** Every skip reason with its count, most frequent first (the counts add up to `skipped`). */
export function skipReasons(s: WordlistImportSummary): [string, number][] {
  return Object.entries(s.reasons).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

export const skipReasonsText = (reasons: [string, number][]) =>
  reasons.map(([k, v]) => `${k}: ${v.toLocaleString('en-US')}`).join(', ');

/** Up to this many reasons are listed inline; more go into a collapsible list. */
export const INLINE_REASONS = 4;

export function doneState(verb: 'Uploaded' | 'Imported' | 'Re-imported', r: WordlistImportResult): ImportState {
  let text = `${verb} “${r.wordlist.name}”. ${summaryText(r.summary)}.`;
  if (r.previous_entries !== undefined) {
    const delta = r.wordlist.entries - r.previous_entries;
    text += r.changed === false
      ? ' Source unchanged.'
      : ` Entries ${r.previous_entries.toLocaleString('en-US')} → ${r.wordlist.entries.toLocaleString('en-US')} (${delta >= 0 ? '+' : ''}${delta.toLocaleString('en-US')}).`;
  }
  return { status: 'done', text, samples: r.summary.samples, reasons: skipReasons(r.summary) };
}

export const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function errorState(e: unknown): ImportState {
  return { status: 'error', text: errorText(e) };
}

/** Options for the "Discovery wordlist" select: built-in first, then stored paths lists. */
export function discoveryOptions(lib: WordlistLibrary | null): { value: string; label: string }[] {
  const builtin = { value: '', label: `Built-in (${lib?.builtin.entries ?? '…'} paths)` };
  const lists = (lib?.items ?? []).filter((w) => w.kind === 'paths')
    .map((w) => ({ value: String(w.id), label: `${w.name} (${w.entries.toLocaleString('en-US')} paths)` }));
  return [builtin, ...lists];
}

/** The id to show/save: a selection that no longer exists (deleted elsewhere) falls back to built-in. */
export function effectiveSelection(id: number | null, lib: WordlistLibrary | null): number | null {
  if (id == null || !lib) return id;
  return lib.items.some((w) => w.id === id && w.kind === 'paths') ? id : null;
}

export type DomainRef = { id: number; name: string };

/** Same wording as the API's 409: "In use by 2 domain(s): example.com, example.org". */
export function inUseByDomainsText(domains: DomainRef[]): string {
  const names = domains.slice(0, 5).map((d) => d.name).join(', ') + (domains.length > 5 ? ` +${domains.length - 5}` : '');
  return `In use by ${domains.length} domain(s): ${names}`;
}

/** Domains from a refused delete (409 wordlist_in_use), or null for any other error. */
export function domainsFromError(e: unknown): DomainRef[] | null {
  const err = e as { status?: number; code?: string; body?: { domains?: unknown } } | null;
  if (!err || err.status !== 409 || err.code !== 'wordlist_in_use' || !Array.isArray(err.body?.domains)) return null;
  return (err.body!.domains as DomainRef[]).filter((d) => d && typeof d.id === 'number' && typeof d.name === 'string');
}

export function deleteConfirmText(w: Pick<Wordlist, 'name' | 'in_use'>): string {
  return w.in_use
    ? `“${w.name}” is selected as the Web capture discovery wordlist. Delete it and fall back to the built-in list?`
    : `Delete the wordlist “${w.name}”?`;
}
