import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, Route, Routes, matchPath, useLocation, useNavigate } from 'react-router-dom';
import { get, post } from './api';
import { Layout } from './components/Layout';
import { Card, Loading } from './components/ui';
import { AppContext } from './context';
// Login and Setup render before sign-in, so they stay in the entry bundle; app pages load on first visit.
import Login from './pages/Login';
import Setup from './pages/Setup';
import type { SetupStatus, SystemStatus, User } from './types';

const Changes = lazy(() => import('./pages/Changes'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const DeviceDetail = lazy(() => import('./pages/DeviceDetail'));
const Devices = lazy(() => import('./pages/Devices'));
const PortDetail = lazy(() => import('./pages/PortDetail'));
const Ports = lazy(() => import('./pages/Ports'));
const Reports = lazy(() => import('./pages/Reports'));
const Scans = lazy(() => import('./pages/Scans'));
const Search = lazy(() => import('./pages/Search'));
const Settings = lazy(() => import('./pages/Settings'));
const Watches = lazy(() => import('./pages/Watches'));
const RemoteHosts = lazy(() => import('./pages/RemoteHosts'));
const WebHosts = lazy(() => import('./pages/WebHosts'));
const WebPreview = lazy(() => import('./pages/WebPreview'));
const Vulnerabilities = lazy(() => import('./pages/Vulnerabilities'));
const CveDetail = lazy(() => import('./pages/CveDetail'));
const CveWatchlist = lazy(() => import('./pages/CveWatchlist'));

/** Paths that render real pages after login (must stay aligned with <Routes> below). */
const APP_ROUTE_PATTERNS = [
  '/',
  '/search',
  '/watches',
  '/reports',
  '/devices',
  '/devices/:uuid',
  '/devices/:uuid/web',
  '/web',
  '/remote',
  '/changes',
  '/ports',
  '/ports/:proto/:port',
  '/vulnerabilities',
  '/vulnerabilities/watchlist',
  '/vulnerabilities/:cve_id',
  '/scans',
  '/settings',
  '/settings/:tab',
] as const;

function isKnownAppPath(pathname: string): boolean {
  return APP_ROUTE_PATTERNS.some((pattern) => matchPath({ path: pattern, end: true }, pathname) != null);
}

export default function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const [setup, setSetup] = useState<SetupStatus | null>(null);
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [system, setSystem] = useState<SystemStatus | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  const [sessionExpired, setSessionExpired] = useState(false);
  const userRef = useRef(user);
  const locationRef = useRef(location);
  const returnToRef = useRef<string | null>(null);
  userRef.current = user;
  locationRef.current = location;

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
    const onUnauthorized = () => {
      // Only treat mid-session 401 as expiry (not cold-start /auth/me while user is still undefined).
      if (userRef.current) {
        const { pathname, search } = locationRef.current;
        returnToRef.current = `${pathname}${search}`;
        setSessionExpired(true);
      }
      setUser(null);
    };
    window.addEventListener('nf:unauthorized', onUnauthorized);
    return () => window.removeEventListener('nf:unauthorized', onUnauthorized);
  }, [boot]);

  const refreshSystem = useCallback(() => {
    get<SystemStatus>('/system/status').then(setSystem).catch(() => undefined);
  }, []);

  // 5s while a scan is running/queued (topbar progress), 30s when idle. Starting a scan from the UI
  // calls refreshSystem() right away, so the fast rate kicks in immediately; scheduled scans within 30s.
  const scanBusy = !!system?.scans.current || !!system?.scans.queued;
  useEffect(() => {
    if (!user) return;
    refreshSystem();
  }, [user, refreshSystem]);
  useEffect(() => {
    if (!user) return;
    const t = window.setInterval(() => document.visibilityState === 'visible' && refreshSystem(), scanBusy ? 5000 : 30000);
    return () => window.clearInterval(t);
  }, [user, refreshSystem, scanBusy]);

  const logout = useCallback(async () => {
    try {
      await post('/auth/logout');
    } catch {
      /* session may already be gone */
    }
    returnToRef.current = null;
    setSessionExpired(false);
    setUser(null);
  }, []);

  const ctx = useMemo(
    () => (user ? { user, isAdmin: user.role === 'admin', system, refreshSystem, setUser, logout } : null),
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
    setSessionExpired(false);
    get<SetupStatus>('/setup/status').then(setSetup);
    const back = returnToRef.current;
    returnToRef.current = null;
    if (back) {
      navigate(back, { replace: true });
    } else if (!isKnownAppPath(location.pathname)) {
      // Unauth gate keeps the URL (e.g. /login); without a returnTo that would hit NotFound.
      navigate('/', { replace: true });
    }
  };

  if (!user && !setup.needs_admin) {
    return <Login status={setup} onLogin={onLoggedIn} sessionExpired={sessionExpired} />;
  }

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
        <Suspense fallback={<Loading />}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/search" element={<Search />} />
            <Route path="/watches" element={<Watches />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/devices/:uuid" element={<DeviceDetail />} />
            <Route path="/devices/:uuid/web" element={<WebPreview />} />
            <Route path="/web" element={<WebHosts />} />
            <Route path="/remote" element={<RemoteHosts />} />
            <Route path="/changes" element={<Changes />} />
            <Route path="/ports" element={<Ports />} />
            <Route path="/ports/:proto/:port" element={<PortDetail />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/vulnerabilities/watchlist" element={<CveWatchlist />} />
            <Route path="/vulnerabilities/:cve_id" element={<CveDetail />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/settings/:tab" element={<Settings />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
      </Layout>
    </AppContext.Provider>
  );
}

function NotFound() {
  const { pathname } = useLocation();
  return (
    <Card title="Page not found">
      <div className="stack">
        <div>There is no page at <code>{pathname}</code>. The link may be outdated or mistyped.</div>
        <div><Link className="btn primary" to="/">Go to dashboard</Link></div>
      </div>
    </Card>
  );
}
