import { useCallback, useState } from 'react';
import type { DashboardPrefs } from './types';

const MAX_STACK = 50;

export function useEditHistory(initial: DashboardPrefs) {
  const [present, setPresent] = useState(initial);
  const [past, setPast] = useState<DashboardPrefs[]>([]);
  const [future, setFuture] = useState<DashboardPrefs[]>([]);

  const reset = useCallback((next: DashboardPrefs) => {
    setPresent(next);
    setPast([]);
    setFuture([]);
  }, []);

  const commit = useCallback((next: DashboardPrefs | ((prev: DashboardPrefs) => DashboardPrefs)) => {
    setPresent((prev) => {
      const value = typeof next === 'function' ? next(prev) : next;
      if (value === prev) return prev;
      setPast((p) => [...p.slice(-(MAX_STACK - 1)), prev]);
      setFuture([]);
      return value;
    });
  }, []);

  /** Replace present without pushing history (e.g. live drag preview — we commit on stop). */
  const replace = useCallback((next: DashboardPrefs) => {
    setPresent(next);
  }, []);

  const undo = useCallback(() => {
    setPast((p) => {
      if (!p.length) return p;
      const prev = p[p.length - 1];
      setPresent((cur) => {
        setFuture((f) => [cur, ...f].slice(0, MAX_STACK));
        return prev;
      });
      return p.slice(0, -1);
    });
  }, []);

  const redo = useCallback(() => {
    setFuture((f) => {
      if (!f.length) return f;
      const [next, ...rest] = f;
      setPresent((cur) => {
        setPast((p) => [...p, cur].slice(-MAX_STACK));
        return next;
      });
      return rest;
    });
  }, []);

  return {
    prefs: present,
    commit,
    replace,
    reset,
    undo,
    redo,
    canUndo: past.length > 0,
    canRedo: future.length > 0,
  };
}
