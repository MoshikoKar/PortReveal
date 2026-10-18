import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import logoLockup from '../assets/logo-lockup.png';
import logoMark from '../assets/logo-mark.png';
import { useApp } from '../context';
import type { SystemStatus } from '../types';
import { SCAN_TYPE_LABELS, scanStageFraction } from '../util';
import { Progress } from './ui';

const Icon = ({ d }: { d: string }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>
);
const ICONS = {
  dashboard: 'M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z',
  devices: 'M4 4h16v10H4zM8 20h8M12 14v6',
  ports: 'M5 4h14v11H5zM9 15v5M15 15v5M8 8h2M14 8h2M8 11h8',
  changes: 'M3 12h4l3 8 4-16 3 8h4',
  web: 'M3 5h18v14H3zM3 9h18M6.5 7h.01M9 7h.01',
  remote: 'M2 6h20v10H2zM8 20h8M12 16v4',
  scans: 'M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l7-7',
  vulnerabilities: 'M12 2 4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5zM12 8v4M12 16h.01',
  search: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM21 21l-5-5',
  watches: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  reports: 'M4 20V10M10 20V4M16 20v-7M22 20H2',
  menu: 'M4 6h16M4 12h16M4 18h16',
  close: 'M6 6l12 12M18 6L6 18',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
};

const NAV: { to: string; label: string; icon: keyof typeof ICONS; end?: boolean }[] = [
  { to: '/', label: 'Dashboard', icon: 'dashboard', end: true },
  { to: '/scans', label: 'Scans', icon: 'scans' },
  { to: '/devices', label: 'Devices', icon: 'devices' },
  { to: '/ports', label: 'Ports', icon: 'ports' },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: 'vulnerabilities' },
  { to: '/changes', label: 'Changes', icon: 'changes' },
  { to: '/watches', label: 'Watches', icon: 'watches' },
  { to: '/search', label: 'Search', icon: 'search' },
  { to: '/web', label: 'Web', icon: 'web' },
  { to: '/remote', label: 'Remote', icon: 'remote' },
  { to: '/reports', label: 'Reports', icon: 'reports' },
  { to: '/settings', label: 'Settings', icon: 'settings' },
];

export function Logo() {
  return <img className="brand-logo" src={logoMark} width={106} height={120} alt="" aria-hidden />;
}

/** Full mark + wordmark + tagline artwork (sidebar header, sign-in screen). */
export function LogoLockup({ className = 'brand-lockup-img' }: { className?: string }) {
  return <img className={className} src={logoLockup} width={720} height={289} alt="PortReveal — Network discovery" />;
}

export function BrandLockup({ subtitle = 'Network discovery' }: { subtitle?: string }) {
  return (
    <div>
      <div className="brand-name"><span className="brand-port">Port</span><span className="brand-reveal">Reveal</span></div>
      <div className="brand-sub">{subtitle}</div>
    </div>
  );
}

/** Secondary diagnostics folded behind one control; the dot shows the worst state at a glance. */
function SystemMenu({ system, readOnly }: { system: SystemStatus; readOnly: boolean }) {
  const ref = useRef<HTMLDetailsElement>(null);
  const { scanner, database, app } = system;
  const level = !database.ok || scanner.mode === 'unavailable' ? 'high' : scanner.mode === 'mock' || app.dev_mode ? 'medium' : 'ok';

  useEffect(() => {
    const close = (e: Event) => {
      const el = ref.current;
      if (!el?.open) return;
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !el.contains(e.target as Node)) el.open = false;
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', close);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('keydown', close);
    };
  }, []);

  return (
    <details className="sysmenu" ref={ref}>
      <summary className="btn sm ghost">
        <span className="dot" style={{ color: `var(--${level})` }} />System{readOnly && <span className="muted"> · read-only</span>}
      </summary>
      <div className="sysmenu-panel">
        <dl className="dl compact">
          {app.dev_mode && <><dt>Mode</dt><dd><span className="badge medium">DEV</span></dd></>}
          <dt>Database</dt>
          <dd>{database.type} · {database.ok ? 'OK' : 'error'}{database.location && <div className="mono small muted">{database.location}</div>}</dd>
          <dt>Scanner</dt>
          <dd>
            <span className={`badge ${scanner.mode === 'nmap' ? 'ok' : scanner.mode === 'mock' ? 'medium' : 'high'}`}><span className="dot" />{scanner.mode}</span>
            <div className="small muted">{scanner.message}</div>
          </dd>
          {app.dev_mode && <><dt>nmap</dt><dd>{scanner.nmap_detected ? scanner.nmap_version : <span style={{ color: 'var(--high)' }}>not detected</span>}</dd></>}
          <dt>Access</dt><dd>{readOnly ? 'Read-only (viewer)' : 'Administrator'}</dd>
        </dl>
      </div>
    </details>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const { user, isAdmin, system, logout } = useApp();
  const scanner = system?.scanner;
  const current = system?.scans.current;
  // Narrow viewports (<900px) collapse the sidebar into a top bar; the toggle opens the nav.
  const [navOpen, setNavOpen] = useState(false);
  const { pathname } = useLocation();
  // A device's web preview (/devices/:uuid/web) belongs to the Web section, not Devices.
  const navPath = /^\/devices\/[^/]+\/web$/.test(pathname) ? '/web' : pathname;
  const activeNav = NAV.find((n) => (n.end ? navPath === n.to : navPath === n.to || navPath.startsWith(`${n.to}/`)));
  useEffect(() => setNavOpen(false), [pathname]);
  useEffect(() => {
    if (!navOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setNavOpen(false);
    // The open nav overlays the page: lock its scroll, and close if the viewport widens past the breakpoint.
    const narrow = window.matchMedia('(max-width: 900px)');
    const onWiden = () => !narrow.matches && setNavOpen(false);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    document.addEventListener('keydown', onKey);
    narrow.addEventListener('change', onWiden);
    return () => {
      document.body.style.overflow = prevOverflow;
      document.removeEventListener('keydown', onKey);
      narrow.removeEventListener('change', onWiden);
    };
  }, [navOpen]);
  return (
    <div className="app">
      <aside className={`sidebar ${navOpen ? 'open' : ''}`}>
        <div className="brand">
          <Link className="brand-home" to="/">
            <LogoLockup className="sidebar-lockup" />
          </Link>
          {activeNav && <span className="nav-current"><Icon d={ICONS[activeNav.icon]} />{activeNav.label}</span>}
          <button className="btn ghost icon nav-toggle" onClick={() => setNavOpen((o) => !o)}
            aria-expanded={navOpen} aria-controls="main-nav" aria-label={navOpen ? 'Close menu' : 'Open menu'} title={navOpen ? 'Close menu' : 'Open menu'}>
            <Icon d={navOpen ? ICONS.close : ICONS.menu} />
          </button>
        </div>
        <div className="sidebar-drawer">
          <nav className="nav" id="main-nav">
            {NAV.map((n) => (
              <Link key={n.to} to={n.to} className={n === activeNav ? 'active' : undefined} aria-current={n === activeNav ? 'page' : undefined}>
                <Icon d={ICONS[n.icon]} />{n.label}
              </Link>
            ))}
          </nav>
          <div className="sidebar-foot">
            <div>
              <div style={{ color: 'var(--text-2)' }}>{user.display_name || user.username}</div>
              <div>{user.role === 'admin' ? 'Administrator' : 'Viewer (read-only)'} · {user.source}</div>
            </div>
            <button className="btn sm" onClick={logout}>Sign out</button>
            <div>v{system?.app.version}</div>
          </div>
        </div>
      </aside>
      {navOpen && <div className="nav-backdrop" onClick={() => setNavOpen(false)} aria-hidden />}
      <div className="main">
        {scanner?.mock_active && (
          <div className="banner">
            SIMULATED DATA — the mock scanner is active. Scan results are generated, not observed on a real network.
          </div>
        )}
        {scanner?.mode === 'unavailable' && (
          <div className="banner danger">Scanner unavailable: {scanner.message}</div>
        )}
        {system && !system.database.ok && <div className="banner danger">Database unavailable: {system.database.message}</div>}
        <header className="topbar">
          {current ? (
            <Link to="/scans" className="row title" style={{ color: 'var(--text)', gap: 10, minWidth: 260 }}>
              <span className="badge accent pulse"><span className="dot" />Scanning</span>
              <span className="small">{SCAN_TYPE_LABELS[current.scan_type]} · {current.network_name ?? 'targets'} · {current.stage}</span>
              <span style={{ width: 120 }}><Progress value={current.progress} /></span>
              <span className="small muted">{Math.round(scanStageFraction(current) * 100)}%</span>
            </Link>
          ) : (
            <span className="title muted small">{system?.scans.queued ? `${system.scans.queued} scan(s) queued` : 'No scan running'}</span>
          )}
          {system && <SystemMenu system={system} readOnly={!isAdmin} />}
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
