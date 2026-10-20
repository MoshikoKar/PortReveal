import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { put } from '../api';
import { useApp } from '../context';
import { DashboardGrid } from '../dashboard/DashboardGrid';
import { defaultDashboardPrefs } from '../dashboard/defaults';
import { loadDashboardPrefs, prefsForSave } from '../dashboard/mergeLayout';
import type { DashboardPrefs } from '../dashboard/types';
import { useEditHistory } from '../dashboard/useEditHistory';
import { ErrorBox, Loading } from '../components/ui';
import type { Dashboard as DashboardData, User } from '../types';
import { useApi } from '../util';

function SearchBox() {
  const nav = useNavigate();
  const [q, setQ] = useState('');
  const submit = (e: FormEvent) => {
    e.preventDefault();
    nav(q.trim() ? `/search?q=${encodeURIComponent(q.trim())}` : '/search');
  };
  return (
    <form className="search-bar" onSubmit={submit}>
      <input type="search" value={q} onChange={(e) => setQ(e.target.value)} maxLength={1000} aria-label="Search the inventory"
        placeholder='Search the inventory: port:3389 · tag:camera · product:openssh · http.title:"login"' />
      <button className="btn primary" type="submit">Search</button>
    </form>
  );
}

const prefsKey = (p: DashboardPrefs) => JSON.stringify(prefsForSave(p));

export default function Dashboard() {
  const { data, error, reload } = useApi<DashboardData>('/dashboard', undefined, 10000);
  const { user, setUser } = useApp();
  const [editing, setEditing] = useState(false);
  const [baseline, setBaseline] = useState<DashboardPrefs>(() => loadDashboardPrefs(user.preferences));
  const history = useEditHistory(baseline);
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [saveError, setSaveError] = useState<string | null>(null);

  const { prefs, commit, reset, undo, redo, canUndo, canRedo } = history;
  const dirty = useMemo(() => editing && prefsKey(prefs) !== prefsKey(baseline), [editing, prefs, baseline]);
  const isDefault = useMemo(() => prefsKey(prefs) === prefsKey(defaultDashboardPrefs()), [prefs]);

  // Re-sync when stored preferences change outside edit mode (e.g. re-login).
  useEffect(() => {
    if (editing) return;
    const loaded = loadDashboardPrefs(user.preferences);
    setBaseline(loaded);
    reset(loaded);
  }, [user.preferences, editing, reset]);

  const startEdit = () => {
    const snap = loadDashboardPrefs(user.preferences);
    setBaseline(snap);
    reset(snap);
    setSaveState('idle');
    setSaveError(null);
    setEditing(true);
  };

  const cancelEdit = useCallback(() => {
    reset(baseline);
    setEditing(false);
    setSaveState('idle');
    setSaveError(null);
  }, [baseline, reset]);

  const resetLayout = () => {
    commit(defaultDashboardPrefs());
  };

  const save = useCallback(async () => {
    if (!dirty) {
      setEditing(false);
      return;
    }
    setSaveState('saving');
    setSaveError(null);
    try {
      const body = prefsForSave(prefs);
      const res = await put<{ user: User }>('/auth/me/preferences', body);
      setUser(res.user);
      const loaded = loadDashboardPrefs(res.user.preferences);
      setBaseline(loaded);
      reset(loaded);
      setSaveState('saved');
      setEditing(false);
    } catch (ex: any) {
      // Keep the user's edits and stay in edit mode so they can retry.
      setSaveState('error');
      setSaveError(ex.message || 'Failed to save layout');
    }
  }, [dirty, prefs, reset, setUser]);

  // Ctrl/Cmd+Z undo, Ctrl+Shift+Z / Ctrl+Y redo, Escape leaves edit mode when nothing changed.
  useEffect(() => {
    if (!editing) return;
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (target?.closest('input, textarea, select, [contenteditable="true"]')) return;
      const mod = e.ctrlKey || e.metaKey;
      const key = e.key.toLowerCase();
      if (mod && key === 'z') {
        e.preventDefault();
        if (e.shiftKey) redo(); else undo();
      } else if (mod && key === 'y') {
        e.preventDefault();
        redo();
      } else if (key === 'escape' && !dirty && !document.querySelector('details[open]')) {
        cancelEdit();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [editing, dirty, undo, redo, cancelEdit]);

  // Warn before closing or reloading the tab with unsaved layout edits.
  useEffect(() => {
    if (!dirty) return;
    const onBeforeUnload = (e: BeforeUnloadEvent) => { e.preventDefault(); };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [dirty]);

  if (!data) return <>{error ? <ErrorBox error={error} /> : <Loading />}</>;

  const editActions = (
    <>
      <button type="button" className="btn sm" disabled={!canUndo} onClick={undo} title="Undo (Ctrl+Z)">Undo</button>
      <button type="button" className="btn sm" disabled={!canRedo} onClick={redo} title="Redo (Ctrl+Shift+Z)">Redo</button>
      <button type="button" className="btn sm" disabled={isDefault} onClick={resetLayout}
        title="Restore the default widgets, sizes, and KPIs (undoable)">Reset to default</button>
      <button type="button" className="btn sm" onClick={cancelEdit}>{dirty ? 'Discard' : 'Cancel'}</button>
      <button type="button" className="btn sm primary" disabled={saveState === 'saving'} onClick={save}>
        {saveState === 'saving' ? 'Saving…' : dirty ? 'Save layout' : 'Done'}
      </button>
    </>
  );

  return (
    <div className="dashboard">
      <div className="page-head">
        <div>
          <h1>Network overview</h1>
          <p>What exists on the network, what it exposes, and what changed.</p>
        </div>
        <div className="row wrap" style={{ gap: 8 }}>
          {saveState === 'saved' && !editing && <span className="muted small">Layout saved</span>}
          {saveState === 'error' && saveError && <span className="small" style={{ color: 'var(--high)' }}>{saveError}</span>}
          {!editing && <button type="button" className="btn" onClick={startEdit}>Customize layout</button>}
        </div>
      </div>
      <ErrorBox error={error} />
      <SearchBox />
      <DashboardGrid
        data={data}
        prefs={prefs}
        editing={editing}
        onPrefsCommit={commit}
        reload={reload}
        editActions={editActions}
      />
    </div>
  );
}
