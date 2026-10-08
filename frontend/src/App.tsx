import { useCallback, useEffect, useMemo, useState } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { get, post } from './api';
import { Layout } from './components/Layout';
import { Loading } from './components/ui';
import { AppContext } from './context';
import Changes from './pages/Changes';
import Dashboard from './pages/Dashboard';
import DeviceDetail from './pages/DeviceDetail';
import Devices from './pages/Devices';
import Login from './pages/Login';
import Scans from './pages/Scans';
import Settings from './pages/Settings';
import Setup from './pages/Setup';
import WebHosts from './pages/WebHosts';
import WebPreview from './pages/WebPreview';
import type { SetupStatus, SystemStatus, User } from './types';

export default function App() {
  const [setup, setSetup] = useState<SetupStatus | null>(null);
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [system, setSystem] = useState<SystemStatus | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);

  const boot = useCallback(async () => {
    try {
      const st = await get<SetupStatus>('/setup/status');
      setSetup(st);
      setBootError(null);
      if (st.needs_admin) {
        setUser(null); // nobody can be logged in before the first admin exists
        return;
      }
      try {
        const me = await get<{ user: User }>('/auth/me');
        setUser(me.user);
      } catch {
        setUser(null);
      }
    } catch (e: any) {
      setBootError(e.message);
    }
  }, []);

  useEffect(() => {
    boot();
    const onUnauthorized = () => setUser(null);
    window.addEventListener('nf:unauthorized', onUnauthorized);
    return () => window.removeEventListener('nf:unauthorized', onUnauthorized);
  }, [boot]);

  const refreshSystem = useCallback(() => {
    get<SystemStatus>('/system/status').then(setSystem).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (!user) return;
    refreshSystem();
    const t = window.setInterval(() => document.visibilityState === 'visible' && refreshSystem(), 5000);
    return () => window.clearInterval(t);
  }, [user, refreshSystem]);

  const logout = useCallback(async () => {
    try {
      await post('/auth/logout');
    } catch {
      /* session may already be gone */
    }
    setUser(null);
  }, []);

  const ctx = useMemo(
    () => (user ? { user, isAdmin: user.role === 'admin', system, refreshSystem, logout } : null),
    [user, system, refreshSystem, logout],
  );

  if (bootError) {
    return (
      <div className="login-wrap">
        <div className="card login"><div className="card-body stack">
          <h2>Backend unavailable</h2>
          <div className="alert error">{bootError}</div>
          <div className="muted small">In development start everything with <code>npm run dev</code>. The API must answer on /api/health.</div>
          <button className="btn primary" onClick={boot}>Retry</button>
        </div></div>
      </div>
    );
  }
  if (!setup || user === undefined) return <div className="login-wrap"><Loading /></div>;

  const onLoggedIn = (u: User) => {
    setUser(u);
    get<SetupStatus>('/setup/status').then(setSetup);
  };

  if (!user && !setup.needs_admin) return <Login status={setup} onLogin={onLoggedIn} />;

  // First-run wizard. Always rendered at the same tree position so its step survives the admin login.
  if (setup.needs_admin || (user?.role === 'admin' && !setup.setup_completed)) {
    return (
      <AppContext.Provider value={ctx}>
        <Setup status={setup} startAtAdmin={!user} onUser={onLoggedIn} onDone={boot} />
      </AppContext.Provider>
    );
  }
  if (!user) return null;

  return (
    <AppContext.Provider value={ctx}>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/devices" element={<Devices />} />
          <Route path="/devices/:uuid" element={<DeviceDetail />} />
          <Route path="/devices/:uuid/web" element={<WebPreview />} />
          <Route path="/web" element={<WebHosts />} />
          <Route path="/changes" element={<Changes />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/settings/:tab" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </AppContext.Provider>
  );
}
