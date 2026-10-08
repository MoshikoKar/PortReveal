import { createContext, useContext } from 'react';
import type { SystemStatus, User } from './types';

export interface AppCtx {
  user: User;
  isAdmin: boolean;
  system: SystemStatus | null;
  refreshSystem: () => void;
  logout: () => void;
}

export const AppContext = createContext<AppCtx | null>(null);

export function useApp(): AppCtx {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('AppContext missing');
  return ctx;
}
