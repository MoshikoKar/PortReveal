import type { ReactNode } from 'react';
import { Link, NavLink } from 'react-router-dom';
import { useApp } from '../context';
import { SCAN_TYPE_LABELS } from '../util';
import { Progress } from './ui';

const Icon = ({ d }: { d: string }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>
);
const ICONS = {
  dashboard: 'M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z',
  devices: 'M4 4h16v10H4zM8 20h8M12 14v6',
  changes: 'M3 12h4l3 8 4-16 3 8h4',
  web: 'M3 5h18v14H3zM3 9h18M6.5 7h.01M9 7h.01',
  scans: 'M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l7-7',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
};

export function Logo() {
  return (
    <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden>
      <circle cx="16" cy="16" r="12" fill="none" stroke="var(--accent)" strokeWidth="2" />
      <circle cx="16" cy="16" r="6" fill="none" stroke="var(--accent)" strokeWidth="2" opacity=".55" />
      <circle cx="24" cy="9" r="3" fill="var(--medium)" />
    </svg>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const { user, isAdmin, system, logout } = useApp();
  const scanner = system?.scanner;
  const current = system?.scans.current;
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <Logo />
          <div>
            <div className="brand-name">NETWORK FINDER</div>
            <div className="brand-sub">Discovery · Change detection</div>
          </div>
        </div>
        <nav className="nav">
          <NavLink to="/" end><Icon d={ICONS.dashboard} />Dashboard</NavLink>
          <NavLink to="/devices"><Icon d={ICONS.devices} />Devices</NavLink>
          <NavLink to="/changes"><Icon d={ICONS.changes} />Changes</NavLink>
          <NavLink to="/web"><Icon d={ICONS.web} />Web</NavLink>
          <NavLink to="/scans"><Icon d={ICONS.scans} />Scans</NavLink>
          <NavLink to="/settings"><Icon d={ICONS.settings} />Settings</NavLink>
        </nav>
        <div className="sidebar-foot">
          <div>
            <div style={{ color: 'var(--text-2)' }}>{user.display_name || user.username}</div>
            <div>{user.role === 'admin' ? 'Administrator' : 'Viewer (read-only)'} · {user.source}</div>
          </div>
          <button className="btn sm" onClick={logout}>Sign out</button>
          <div>v{system?.app.version}</div>
        </div>
      </aside>
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
              <span className="small muted">{Math.round(current.progress * 100)}%</span>
            </Link>
          ) : (
            <span className="title muted small">{system?.scans.queued ? `${system.scans.queued} scan(s) queued` : 'No scan running'}</span>
          )}
          {system?.app.dev_mode && <span className="badge medium" title="Development mode">DEV</span>}
          {system && (
            <span className="badge outline" title={system.database.location ?? undefined}>
              DB: {system.database.type}
            </span>
          )}
          {scanner && (
            <span
              className={`badge ${scanner.mode === 'nmap' ? 'ok' : scanner.mode === 'mock' ? 'medium' : 'high'}`}
              title={scanner.message}
            >
              <span className="dot" />Scanner: {scanner.mode}
            </span>
          )}
          {scanner && system?.app.dev_mode && (
            <span className={`badge ${scanner.nmap_detected ? 'outline' : 'high'}`}>
              nmap {scanner.nmap_detected ? scanner.nmap_version : 'not detected'}
            </span>
          )}
          {!isAdmin && <span className="badge outline">read-only</span>}
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
