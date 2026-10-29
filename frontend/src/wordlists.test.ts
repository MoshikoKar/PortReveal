import { describe, expect, it } from 'vitest';
import type { Wordlist, WordlistImportResult, WordlistLibrary, WordlistLimits } from './types';
import {
  acceptedExtensions, deleteConfirmText, discoveryOptions, domainsFromError, doneState, effectiveSelection, errorState,
  fileError, formatBytes, inUseByDomainsText, nameError, shortSha, skipReasons, skipReasonsText, summaryText, urlError,
} from './wordlists';
import { ApiError } from './api';

const limits: WordlistLimits = {
  max_upload_bytes: 10 * 1024 * 1024,
  max_decompressed_bytes: 50 * 1024 * 1024,
  max_entries: 1_000_000,
  allow_http: false,
  extensions: ['.txt', '.lst', '.list', '.dic', '.txt.gz', '.lst.gz', '.list.gz', '.dic.gz'],
};

function wordlist(over: Partial<Wordlist> = {}): Wordlist {
  return {
    id: 1, name: 'Common paths', kind: 'paths', source: 'upload', source_url: null, original_filename: 'paths.txt',
    entries: 120, skipped: 3, size_bytes: 2048, sha256: 'a'.repeat(64), created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z', created_by: 'admin', in_use: false, domains: [], ...over,
  };
}

function library(items: Wordlist[]): WordlistLibrary {
  return { items, builtin: { name: 'Built-in', kind: 'paths', source: 'builtin', entries: 80, in_use: true }, limits, subdomain_discovery: false };
}

describe('upload prechecks', () => {
  it('accepts text extensions and their .gz', () => {
    for (const name of ['a.txt', 'a.lst', 'a.list', 'a.dic', 'A.TXT', 'a.txt.gz', 'a.dic.gz']) {
      expect(fileError({ name, size: 10 }, limits)).toBeNull();
    }
  });

  it('rejects archives, executables and bare .gz', () => {
    for (const name of ['a.zip', 'a.tar.gz', 'a.exe', 'a.gz', 'noext']) {
      expect(fileError({ name, size: 10 }, limits)).toMatch(/Unsupported file type/);
    }
  });

  it('rejects empty, oversized and missing files', () => {
    expect(fileError(null, limits)).toBe('Choose a file.');
    expect(fileError({ name: 'a.txt', size: 0 }, limits)).toBe('The file is empty.');
    expect(fileError({ name: 'a.txt', size: limits.max_upload_bytes + 1 }, limits)).toBe('File is larger than 10.0 MB.');
  });

  it('builds the accept attribute from the server limits', () => {
    expect(acceptedExtensions(limits)).toBe('.txt,.lst,.list,.dic,.txt.gz,.lst.gz,.list.gz,.dic.gz');
    expect(acceptedExtensions(null)).toContain('.dic.gz');
  });
});

describe('import URL precheck', () => {
  it('requires https unless http is enabled', () => {
    expect(urlError('https://lists.example.test/a.txt')).toBeNull();
    expect(urlError('http://lists.example.test/a.txt')).toBe('Only https:// URLs are allowed.');
    expect(urlError('http://lists.example.test/a.txt', true)).toBeNull();
    expect(urlError('file:///etc/passwd', true)).toBe('Only http:// or https:// URLs are allowed.');
    expect(urlError('javascript:alert(1)')).toBe('Only https:// URLs are allowed.');
  });

  it('rejects credentials, blanks and junk', () => {
    expect(urlError('https://user:pw@lists.example.test/a.txt')).toBe('Credentials in the URL are not allowed.');
    expect(urlError('   ')).toBe('Enter a URL.');
    expect(urlError('not a url')).toBe('Enter a valid URL.');
  });
});

describe('names', () => {
  it('allows the safe charset up to 64 characters', () => {
    expect(nameError('')).toBeNull(); // optional on create
    expect(nameError('Common paths (v2)')).toBeNull();
    expect(nameError('x'.repeat(64))).toBeNull();
    expect(nameError('x'.repeat(65))).toMatch(/at most 64/);
    expect(nameError('<img src=x onerror=alert(1)>')).toMatch(/letters, digits/);
    expect(nameError('../etc')).toMatch(/letters, digits/);
  });
});

describe('import states and summaries', () => {
  const result = (over: Partial<WordlistImportResult> = {}): WordlistImportResult => ({
    wordlist: wordlist(),
    summary: { accepted: 1200, skipped: 4, reasons: { duplicate: 2, 'path traversal': 1, 'URL scheme': 1, 'too long': 0 }, samples: ['line 7: path traversal'] },
    ...over,
  });

  it('summarizes accepted / skipped with the first reasons', () => {
    expect(summaryText(result().summary)).toBe('Accepted 1,200 / skipped 4');
    expect(summaryText({ accepted: 3, skipped: 0, reasons: {}, samples: [] })).toBe('Accepted 3 / skipped 0');
  });

  it('upload and import done states carry the summary and skipped samples', () => {
    const s = doneState('Uploaded', result());
    expect(s).toEqual({
      status: 'done',
      text: 'Uploaded “Common paths”. Accepted 1,200 / skipped 4.',
      samples: ['line 7: path traversal'],
      reasons: [['duplicate', 2], ['path traversal', 1], ['URL scheme', 1]],
    });
    expect(doneState('Imported', result()).status).toBe('done');
  });

  it('re-import shows the entry-count change, or that the source is unchanged', () => {
    const grown = doneState('Re-imported', result({ wordlist: wordlist({ entries: 1250 }), previous_entries: 1200, changed: true }));
    expect(grown.status === 'done' && grown.text).toContain('Entries 1,200 → 1,250 (+50).');
    const shrunk = doneState('Re-imported', result({ wordlist: wordlist({ entries: 1190 }), previous_entries: 1200, changed: true }));
    expect(shrunk.status === 'done' && shrunk.text).toContain('(-10)');
    const same = doneState('Re-imported', result({ previous_entries: 120, changed: false }));
    expect(same.status === 'done' && same.text).toContain('Source unchanged.');
  });

  it('error state keeps the server message', () => {
    expect(errorState(new Error('lists.example.test resolves to a blocked address (10.0.0.1)'))).toEqual({
      status: 'error', text: 'lists.example.test resolves to a blocked address (10.0.0.1)',
    });
    expect(errorState('boom')).toEqual({ status: 'error', text: 'boom' });
  });
});

describe('discovery select', () => {
  const lib = library([wordlist(), wordlist({ id: 2, name: 'Subs', kind: 'subdomains' })]);

  it('offers built-in first and only paths lists', () => {
    expect(discoveryOptions(lib)).toEqual([
      { value: '', label: 'Built-in (80 paths)' },
      { value: '1', label: 'Common paths (120 paths)' },
    ]);
    expect(discoveryOptions(null)).toEqual([{ value: '', label: 'Built-in (… paths)' }]);
  });

  it('falls back to built-in for a missing or non-paths selection', () => {
    expect(effectiveSelection(1, lib)).toBe(1);
    expect(effectiveSelection(2, lib)).toBeNull();
    expect(effectiveSelection(99, lib)).toBeNull();
    expect(effectiveSelection(null, lib)).toBeNull();
    expect(effectiveSelection(5, null)).toBe(5); // library not loaded yet: keep the saved value
  });
});

describe('table helpers', () => {
  it('formats sizes and short hashes', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
    expect(formatBytes(3 * 1024 * 1024)).toBe('3.0 MB');
    expect(shortSha('0123456789abcdef'.repeat(4))).toBe('0123456789ab');
  });

  it('warns about fallback when deleting the selected list', () => {
    expect(deleteConfirmText(wordlist({ in_use: true }))).toMatch(/fall back to the built-in list/);
    expect(deleteConfirmText(wordlist())).toBe('Delete the wordlist “Common paths”?');
  });
});

describe('wordlist used by domains', () => {
  const domains = [{ id: 1, name: 'example.com' }, { id: 2, name: 'example.org' }];

  it('words the block like the API', () => {
    expect(inUseByDomainsText(domains)).toBe('In use by 2 domain(s): example.com, example.org');
    const many = Array.from({ length: 7 }, (_, i) => ({ id: i, name: `d${i}.example.com` }));
    expect(inUseByDomainsText(many)).toBe('In use by 7 domain(s): d0.example.com, d1.example.com, d2.example.com, d3.example.com, d4.example.com +2');
  });

  it('reads the domains from a refused delete only', () => {
    const refused = new ApiError(409, 'In use by 2 domain(s): example.com, example.org.', undefined, 'r1', 'wordlist_in_use');
    refused.body = { code: 'wordlist_in_use', domains };
    expect(domainsFromError(refused)).toEqual(domains);
    const otherConflict = new ApiError(409, 'a wordlist named x already exists', undefined, 'r2', 'conflict');
    expect(domainsFromError(otherConflict)).toBeNull();
    expect(domainsFromError(new Error('network down'))).toBeNull();
  });
});

describe('skip reasons', () => {
  it('lists every reason grouped with its count, adding up to skipped', () => {
    const summary = {
      accepted: 10, skipped: 13, samples: [],
      reasons: { 'path traversal': 3, 'control character': 2, 'URL scheme': 3, duplicate: 4, 'line too long': 1 },
    };
    const reasons = skipReasons(summary);
    expect(reasons.map(([k]) => k)).toEqual(['duplicate', 'path traversal', 'URL scheme', 'control character', 'line too long']);
    expect(reasons.reduce((n, [, v]) => n + v, 0)).toBe(summary.skipped);
    expect(skipReasonsText(reasons.slice(1, 3))).toBe('path traversal: 3, URL scheme: 3');
    expect(skipReasons({ accepted: 1, skipped: 0, reasons: {}, samples: [] })).toEqual([]);
  });
});
