import { useEffect, useState, type MouseEvent } from 'react';
import { NavLink, Navigate, useLocation, useParams } from 'react-router-dom';
import { confirmDiscard } from '../components/ui';
import { useApp } from '../context';
import { AuditSettings, HealthPanel, UsersSettings } from './settings/Admin';
import { DataTransferPanel } from './settings/DataTransfer';
import { ExclusionsSettings } from './settings/Exclusions';
import { LdapForm, NotificationsForm, PresenceForm, RetentionForm, ScanProfileForm, ScheduleForm, WebCaptureForm } from './settings/Forms';
import { NetworksSettings } from './settings/Networks';
import { TokensSettings } from './settings/Tokens';

const TABS = [
  { id: 'networks', label: 'Networks', viewer: true },
  { id: 'exclusions', label: 'Exclusions', viewer: true },
  { id: 'schedule', label: 'Schedule', viewer: false },
  { id: 'scan-profiles', label: 'Scan profiles', viewer: false },
  { id: 'web-capture', label: 'Web capture', viewer: false },
  { id: 'notifications', label: 'Notifications', viewer: false },
  { id: 'authentication', label: 'Authentication', viewer: false },
  { id: 'users', label: 'Users', viewer: false },
  { id: 'retention', label: 'Retention', viewer: false },
  { id: 'data', label: 'Data', viewer: false },
  { id: 'audit', label: 'Audit log', viewer: false },
  { id: 'tokens', label: 'API tokens', viewer: true },
  { id: 'health', label: 'System health', viewer: true },
];

export default function Settings() {
  const { isAdmin } = useApp();
  const { tab } = useParams();
  const location = useLocation();
  const tabs = TABS.filter((t) => isAdmin || t.viewer);
  // Schedule hosts two forms; keep their dirty flags separate so one clear does not wipe the other.
  const [formDirty, setFormDirty] = useState(false);
  const [presenceDirty, setPresenceDirty] = useState(false);
  const dirty = formDirty || presenceDirty;
  const tabAllowed = !!tab && tabs.some((t) => t.id === tab);

  // Fresh tab mount = fresh forms; clear so a prior tab's dirty does not block the next.
  useEffect(() => {
    setFormDirty(false);
    setPresenceDirty(false);
  }, [tab]);

  // Sidebar (and other in-app links): leaving Settings would unmount a dirty form with no tab click.
  useEffect(() => {
    if (!dirty || !tabAllowed || !tab) return;
    const onClick = (e: globalThis.MouseEvent) => {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      const el = (e.target as Element | null)?.closest?.('a[href]');
      if (!el || el.getAttribute('target') === '_blank' || el.hasAttribute('download')) return;
      // Tab NavLinks use onTabClick; avoid a second confirm.
      if (el.closest('nav.tabs')) return;
      const href = el.getAttribute('href');
      if (!href || href.startsWith('#')) return;
      let url: URL;
      try {
        url = new URL(href, window.location.href);
      } catch {
        return;
      }
      if (url.origin !== window.location.origin) return;
      if (url.pathname === `/settings/${tab}`) return;
      if (url.pathname === '/settings' && tab === 'networks') return;
      if (!confirmDiscard(true)) {
        e.preventDefault();
        e.stopPropagation();
      }
    };
    document.addEventListener('click', onClick, true);
    return () => document.removeEventListener('click', onClick, true);
  }, [dirty, tab, tabAllowed]);

  useEffect(() => {
    if (!dirty || !tabAllowed) return;
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [dirty, tabAllowed]);

  // Bare /settings gets a real tab URL so the Networks tab shows as active.
  if (!tab) return <Navigate to="/settings/networks" replace />;
  if (!tabAllowed) {
    const forbidden = TABS.find((t) => t.id === tab);
    return <Navigate to="/settings/networks" replace state={forbidden ? { deniedTab: forbidden.label } : undefined} />;
  }

  const deniedTab = (location.state as { deniedTab?: string } | null)?.deniedTab;
  const onTabClick = (e: MouseEvent<HTMLAnchorElement>, id: string) => {
    if (id === tab) return;
    if (!confirmDiscard(dirty)) e.preventDefault();
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p>{isAdmin ? 'Central configuration. All changes apply immediately and are recorded in the audit log.' : 'Read-only view.'}</p>
        </div>
      </div>
      <nav className="tabs">
        {tabs.map((t) => (
          <NavLink key={t.id} to={`/settings/${t.id}`} onClick={(e) => onTabClick(e, t.id)}>{t.label}</NavLink>
        ))}
      </nav>
      {deniedTab && tab === 'networks' && (
        <div className="alert warn" role="status">“{deniedTab}” settings are admin only, so you were taken to Networks instead.</div>
      )}
      {tab === 'networks' && <NetworksSettings />}
      {tab === 'exclusions' && <ExclusionsSettings />}
      {tab === 'schedule' && <><ScheduleForm onDirtyChange={setFormDirty} /><PresenceForm onDirtyChange={setPresenceDirty} /></>}
      {tab === 'scan-profiles' && <ScanProfileForm onDirtyChange={setFormDirty} />}
      {tab === 'web-capture' && <WebCaptureForm onDirtyChange={setFormDirty} />}
      {tab === 'notifications' && <NotificationsForm onDirtyChange={setFormDirty} />}
      {tab === 'authentication' && <LdapForm onDirtyChange={setFormDirty} />}
      {tab === 'users' && <UsersSettings />}
      {tab === 'retention' && <RetentionForm onDirtyChange={setFormDirty} />}
      {tab === 'data' && <DataTransferPanel />}
      {tab === 'audit' && <AuditSettings />}
      {tab === 'tokens' && <TokensSettings />}
      {tab === 'health' && <HealthPanel />}
    </>
  );
}
