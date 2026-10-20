import { useCallback, useReducer } from 'react';
import type { DashboardPrefs } from './types';

const MAX_STACK = 50;

interface HistoryState {
  past: DashboardPrefs[];
  present: DashboardPrefs;
  future: DashboardPrefs[];
}

type Action =
  | { type: 'commit'; next: DashboardPrefs | ((prev: DashboardPrefs) => DashboardPrefs) }
  | { type: 'reset'; next: DashboardPrefs }
  | { type: 'undo' }
  | { type: 'redo' };

// One reducer keeps past/present/future in step; nested setState calls inside updaters double-push
// under StrictMode (updaters run twice), which made Undo need two clicks.
function reducer(state: HistoryState, action: Action): HistoryState {
  switch (action.type) {
    case 'commit': {
      const value = typeof action.next === 'function' ? action.next(state.present) : action.next;
      if (value === state.present) return state;
      return { past: [...state.past.slice(-(MAX_STACK - 1)), state.present], present: value, future: [] };
    }
    case 'reset':
      return { past: [], present: action.next, future: [] };
    case 'undo': {
      if (!state.past.length) return state;
      const prev = state.past[state.past.length - 1];
      return { past: state.past.slice(0, -1), present: prev, future: [state.present, ...state.future].slice(0, MAX_STACK) };
    }
    case 'redo': {
      if (!state.future.length) return state;
      const [next, ...rest] = state.future;
      return { past: [...state.past, state.present].slice(-MAX_STACK), present: next, future: rest };
    }
  }
}

export function useEditHistory(initial: DashboardPrefs) {
  const [state, dispatch] = useReducer(reducer, { past: [], present: initial, future: [] });

  const commit = useCallback(
    (next: DashboardPrefs | ((prev: DashboardPrefs) => DashboardPrefs)) => dispatch({ type: 'commit', next }),
    [],
  );
  const reset = useCallback((next: DashboardPrefs) => dispatch({ type: 'reset', next }), []);
  const undo = useCallback(() => dispatch({ type: 'undo' }), []);
  const redo = useCallback(() => dispatch({ type: 'redo' }), []);

  return {
    prefs: state.present,
    commit,
    reset,
    undo,
    redo,
    canUndo: state.past.length > 0,
    canRedo: state.future.length > 0,
  };
}
