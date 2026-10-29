// Wordlist library (Settings > Web capture): upload, import from URL, re-import, rename, delete.
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { del, patch, post, postForm } from '../../api';
import { Card, Empty, ErrorBox, Modal, SkeletonRows, useReportDirty } from '../../components/ui';
import type { Wordlist, WordlistImportResult, WordlistKind, WordlistLibrary } from '../../types';
import { fmtTime, useApi, useInFlight } from '../../util';
import {
  acceptedExtensions, deleteConfirmText, domainsFromError, doneState, errorState, errorText, fileError, formatBytes,
  INLINE_REASONS, inUseByDomainsText, nameError, NAME_MAX, shortSha, skipReasonsText, urlError, type DomainRef,
  type ImportState,
} from '../../wordlists';

function DomainLinks({ domains }: { domains: DomainRef[] }) {
  return <>{domains.map((d, i) => <span key={d.id}>{i > 0 && ', '}<Link to={`/domains/${d.id}`}>{d.name}</Link></span>)}</>;
}
import { WebCaptureForm } from './Forms';

/** Web capture tab: settings form (with the discovery wordlist select) and the wordlist library. */
export function WebCaptureTab({ onDirtyChange }: { onDirtyChange?: (dirty: boolean) => void }) {
  const lib = useApi<WordlistLibrary>('/wordlists');
  const [formDirty, setFormDirty] = useState(false);
  const [libDirty, setLibDirty] = useState(false);
  useReportDirty(formDirty || libDirty, onDirtyChange);
  return (
    <>
      <WebCaptureForm onDirtyChange={setFormDirty} wordlists={lib.data} />
      <WordlistLibraryCard lib={lib.data} error={lib.error} loading={lib.loading} reload={lib.reload} onDirtyChange={setLibDirty} />
    </>
  );
}

type Draft =
  | { mode: 'upload'; kind: WordlistKind; name: string }
  | { mode: 'url'; kind: WordlistKind; name: string; url: string }
  | { mode: 'rename'; id: number; name: string };

const KIND_LABEL: Record<WordlistKind, string> = { paths: 'Paths', subdomains: 'Subdomains' };
const SOURCE_LABEL: Record<string, string> = { upload: 'Upload', url: 'URL', builtin: 'Built-in' };

function WordlistLibraryCard({ lib, error, loading, reload, onDirtyChange }: {
  lib: WordlistLibrary | null; error: string | null; loading: boolean; reload: () => void;
  onDirtyChange?: (dirty: boolean) => void;
}) {
  const [draft, setDraft] = useState<Draft | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [state, setState] = useState<ImportState>({ status: 'idle' });
  const [blocked, setBlocked] = useState<{ name: string; domains: DomainRef[] } | null>(null);
  const [modalError, setModalError] = useState<string | null>(null);
  const { pending, track } = useInFlight();
  const busy = state.status === 'busy';
  const dirty = !!draft && (draft.mode === 'rename' ? false : !!draft.name || !!file || (draft.mode === 'url' && !!draft.url));
  useReportDirty(dirty || busy, onDirtyChange);
  const limits = lib?.limits ?? null;

  const open = (d: Draft) => {
    setDraft(d);
    setFile(null);
    setModalError(null);
  };

  const precheck = (): string | null => {
    if (!draft) return null;
    if (draft.mode === 'rename') return draft.name.trim() ? nameError(draft.name) : 'Enter a name.';
    const err = nameError(draft.name);
    if (err) return err;
    if (draft.mode === 'upload') return fileError(file, limits);
    return urlError(draft.url, limits?.allow_http);
  };

  const submit = async () => {
    if (!draft || busy) return;
    const err = precheck();
    if (err) {
      setModalError(err);
      return;
    }
    setModalError(null);
    const d = draft;
    if (d.mode === 'rename') {
      try {
        await patch<Wordlist>(`/wordlists/${d.id}`, { name: d.name.trim() });
        setDraft(null);
        reload();
      } catch (e) {
        setModalError(errorText(e));
      }
      return;
    }
    setState({ status: 'busy', text: d.mode === 'upload' ? 'Uploading and validating…' : 'Downloading and validating…' });
    try {
      let r: WordlistImportResult;
      if (d.mode === 'upload') {
        const fd = new FormData();
        fd.append('file', file as File);
        fd.append('kind', d.kind);
        if (d.name.trim()) fd.append('name', d.name.trim());
        r = await postForm<WordlistImportResult>('/wordlists/upload', fd);
      } else {
        r = await post<WordlistImportResult>('/wordlists/import', { url: d.url.trim(), kind: d.kind, name: d.name.trim() || null });
      }
      setState(doneState(d.mode === 'upload' ? 'Uploaded' : 'Imported', r));
      setDraft(null);
      reload();
    } catch (e) {
      setState({ status: 'idle' });
      setModalError(errorText(e));
    }
  };

  const reimport = (w: Wordlist) => track(`wl-${w.id}`, async () => {
    setState({ status: 'busy', text: `Re-importing “${w.name}”…` });
    try {
      setState(doneState('Re-imported', await post<WordlistImportResult>(`/wordlists/${w.id}/reimport`)));
      reload();
    } catch (e) {
      setState(errorState(e));
    }
  });

  const remove = (w: Wordlist) => {
    // Used by a domain: never deleted (no silent fallback); say which domains to change first.
    if (w.domains?.length) {
      setBlocked({ name: w.name, domains: w.domains });
      return;
    }
    if (!confirm(deleteConfirmText(w))) return;
    setBlocked(null);
    void track(`wl-${w.id}`, async () => {
      try {
        await del(`/wordlists/${w.id}${w.in_use ? '?force=true' : ''}`);
        setState({ status: 'idle' });
        reload();
      } catch (e) {
        const domains = domainsFromError(e);
        if (domains) {
          setBlocked({ name: w.name, domains });
          reload();
        } else {
          setState(errorState(e));
        }
      }
    });
  };

  const actions = (
    <div className="row">
      <button className="btn sm" disabled={busy} onClick={() => open({ mode: 'url', kind: 'paths', name: '', url: '' })}>Import from URL</button>
      <button className="btn primary sm" disabled={busy} onClick={() => open({ mode: 'upload', kind: 'paths', name: '' })}>Upload wordlist</button>
    </div>
  );

  return (
    <Card title="Wordlists" flush actions={actions}>
      <div className="card-body muted small" style={{ borderBottom: '1px solid var(--border)' }}>
        Paths tried for app discovery (and subdomain lists, selectable per domain under Domains for wordlist brute force).
        Plain UTF-8 text, one entry per line, <code>#</code> comments ignored; {acceptedExtensions(limits).split(',').join(' ')}.
        {limits && <> Up to {formatBytes(limits.max_upload_bytes)} ({formatBytes(limits.max_decompressed_bytes)} uncompressed), {limits.max_entries.toLocaleString('en-US')} entries.</>}
        {' '}Invalid lines are skipped; URL imports run only when you click and refuse private or internal addresses.
      </div>
      <ErrorBox error={error} />
      {blocked && (
        <div className="card-body">
          <div className="alert error spread" role="alert" data-testid="wordlist-blocked">
            <span>
              “{blocked.name}” cannot be deleted. In use by {blocked.domains.length} domain(s): <DomainLinks domains={blocked.domains} />.
              {' '}Choose another wordlist for them first.
            </span>
            <button type="button" className="btn ghost sm" onClick={() => setBlocked(null)} aria-label="Dismiss" title="Dismiss">✕</button>
          </div>
        </div>
      )}
      {state.status === 'busy' && <div className="card-body"><div className="alert" role="status" data-testid="wordlist-status">{state.text}</div></div>}
      {state.status === 'error' && <div className="card-body"><div className="alert error" role="alert" data-testid="wordlist-status">{state.text}</div></div>}
      {state.status === 'done' && (
        <div className="card-body">
          <div className="alert ok spread" role="status" data-testid="wordlist-status">
            <div className="stack" style={{ gap: 4 }}>
              <span data-testid="wordlist-summary">{state.text}</span>
              {state.reasons.length > 0 && state.reasons.length <= INLINE_REASONS && (
                <span className="small" data-testid="wordlist-reasons">Skipped: {skipReasonsText(state.reasons)}</span>
              )}
              {state.reasons.length > INLINE_REASONS && (
                <details className="small" data-testid="wordlist-reasons">
                  <summary>Skipped by reason ({state.reasons.length} reasons)</summary>
                  <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
                    {state.reasons.map(([k, v]) => <li key={k}>{k}: {v.toLocaleString('en-US')}</li>)}
                  </ul>
                </details>
              )}
              {state.samples.length > 0 && <span className="small">First skipped: {state.samples.join('; ')}</span>}
            </div>
            <button type="button" className="btn ghost sm" onClick={() => setState({ status: 'idle' })} aria-label="Dismiss" title="Dismiss">✕</button>
          </div>
        </div>
      )}
      {loading && !lib ? <SkeletonRows cols={9} /> : !lib ? <Empty>Wordlists unavailable.</Empty> : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Name</th><th>Type</th><th>Source</th><th className="right">Entries</th><th className="right">Size</th><th>SHA-256</th><th>Created</th><th>Updated</th><th>By</th><th /></tr>
            </thead>
            <tbody>
              <tr className="dim">
                <td><strong>{lib.builtin.name}</strong> {lib.builtin.in_use && <span className="badge ok">in use</span>}</td>
                <td>{KIND_LABEL.paths}</td><td>{SOURCE_LABEL.builtin}</td>
                <td className="right">{lib.builtin.entries.toLocaleString('en-US')}</td>
                <td className="right">-</td><td>-</td><td>-</td><td>-</td><td>-</td><td />
              </tr>
              {lib.items.map((w) => (
                <tr key={w.id} data-testid={`wordlist-row-${w.id}`}>
                  <td>
                    <strong>{w.name}</strong> {w.in_use && <span className="badge ok">in use</span>}
                    {w.skipped > 0 && <div className="muted small">{w.skipped.toLocaleString('en-US')} lines skipped</div>}
                    {w.domains?.length > 0 && <div className="small muted" title={inUseByDomainsText(w.domains)}>Used by <DomainLinks domains={w.domains} /></div>}
                  </td>
                  <td>{KIND_LABEL[w.kind] ?? w.kind}</td>
                  <td className="small" title={w.source_url ?? w.original_filename ?? undefined}>{SOURCE_LABEL[w.source] ?? w.source}</td>
                  <td className="right">{w.entries.toLocaleString('en-US')}</td>
                  <td className="right nowrap">{formatBytes(w.size_bytes)}</td>
                  <td className="mono small" title={w.sha256}>{shortSha(w.sha256)}</td>
                  <td className="small nowrap">{fmtTime(w.created_at)}</td>
                  <td className="small nowrap">{fmtTime(w.updated_at)}</td>
                  <td className="small">{w.created_by ?? '-'}</td>
                  <td className="right nowrap">
                    <div className="row" style={{ justifyContent: 'flex-end' }}>
                      {w.source === 'url' && (
                        <button className="btn sm" disabled={busy || pending(`wl-${w.id}`)} onClick={() => void reimport(w)}>Re-import</button>
                      )}
                      <button className="btn ghost sm" disabled={pending(`wl-${w.id}`)} onClick={() => open({ mode: 'rename', id: w.id, name: w.name })}>Rename</button>
                      <button className="btn danger sm" disabled={busy || pending(`wl-${w.id}`)} onClick={() => remove(w)}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {draft && (
        <Modal
          title={draft.mode === 'upload' ? 'Upload wordlist' : draft.mode === 'url' ? 'Import wordlist from URL' : 'Rename wordlist'}
          onClose={() => !busy && setDraft(null)}
          dirty={dirty}
          footer={<>
            <button className="btn ghost" disabled={busy} onClick={() => setDraft(null)}>Cancel</button>
            <button className="btn primary" disabled={busy} onClick={submit}>
              {busy ? (draft.mode === 'upload' ? 'Uploading…' : 'Importing…') : draft.mode === 'upload' ? 'Upload' : draft.mode === 'url' ? 'Import' : 'Save'}
            </button>
          </>}
        >
          {draft.mode === 'upload' && (
            <label className="field">File
              <input type="file" accept={acceptedExtensions(limits)} disabled={busy}
                onChange={(e) => { setFile(e.target.files?.[0] ?? null); setModalError(null); }} />
            </label>
          )}
          {draft.mode === 'url' && (
            <label className="field">URL
              <input type="url" value={draft.url} disabled={busy} placeholder="https://lists.example.test/paths.txt"
                onChange={(e) => setDraft({ ...draft, url: e.target.value })} />
              <span className="hint">{limits?.allow_http ? 'http(s)' : 'https'} only; no credentials. Private, loopback and link-local addresses are refused.</span>
            </label>
          )}
          {draft.mode !== 'rename' && (
            <label className="field">Type
              <select value={draft.kind} disabled={busy} onChange={(e) => setDraft({ ...draft, kind: e.target.value as WordlistKind })}>
                <option value="paths">Paths (app discovery)</option>
                <option value="subdomains">Subdomains</option>
              </select>
            </label>
          )}
          <label className="field">Name
            <input type="text" value={draft.name} maxLength={NAME_MAX} disabled={busy}
              placeholder={draft.mode === 'rename' ? '' : 'from the file name'}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
          </label>
          {busy && <div className="muted small" role="status">{state.status === 'busy' ? state.text : ''}</div>}
          <ErrorBox error={modalError} />
        </Modal>
      )}
    </Card>
  );
}
