import { useCallback, useEffect, useState, type FormEvent } from 'react';
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

export default function Dashboard() {
  const { data, error, reload } = useApi<DashboardData>('/dashboard', undefined, 10000);
  const { user, setUser } = useApp();
  const [editing, setEditing] = useState(false);
  const [baseline, setBaseline] = useState<DashboardPrefs>(() => loadDashboardPrefs(user.preferences));
  const history = useEditHistory(baseline);
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [saveError, setSaveError] = useState<string | null>(null);

  const { prefs, commit, reset, undo, redo, canUndo, canRedo } = history;

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

  const cancelEdit = () => {
    reset(baseline);
    setEditing(false);
    setSaveState('idle');
    setSaveError(null);
  };

  const resetLayout = () => {
    commit(defaultDashboardPrefs());
  };

  const save = useCallback(async () => {
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
      setSaveState('error');
      setSaveError(ex.message || 'Failed to save layout');
      reset(baseline);
    }
  }, [baseline, prefs, reset, setUser]);

  if (!data) return <>{error ? <ErrorBox error={error} /> : <Loading />}</>;

  return (
    <div className="dashboard">
      <div className="page-head">
        <div>
          <h1>Network overview</h1>
          <p>What exists on the network, what it exposes, and what changed.</p>
        </div>
        <div className="row wrap" style={{ gap: 8 }}>
          {!editing ? (
            <button type="button" className="btn" onClick={startEdit}>Customize layout</button>
          ) : (
            <>
              <button type="button" className="btn sm" disabled={!canUndo} onClick={undo}>Undo</button>
              <button type="button" className="btn sm" disabled={!canRedo} onClick={redo}>Redo</button>
              <button type="button" className="btn sm" onClick={resetLayout}>Reset layout</button>
              <button type="button" className="btn" onClick={cancelEdit}>Cancel changes</button>
              <button type="button" className="btn primary" disabled={saveState === 'saving'} onClick={save}>
                {saveState === 'saving' ? 'Saving…' : 'Save'}
              </button>
            </>
          )}
          {saveState === 'saved' && !editing && <span className="muted small">Saved</span>}
          {saveState === 'error' && saveError && <span className="small" style={{ color: 'var(--high)' }}>{saveError}</span>}
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
      />
    </div>
  );
}
