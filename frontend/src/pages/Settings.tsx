import { useEffect, useMemo, useState, type MouseEvent } from 'react';
import { Link, NavLink, Navigate, useLocation, useParams, useSearchParams } from 'react-router-dom';
import { confirmDiscard, useHistoryGuard } from '../components/ui';
import { useApp } from '../context';
import { AuditSettings, HealthPanel, UsersSettings } from './settings/Admin';
import { DataTransferPanel } from './settings/DataTransfer';
import { ExclusionsSettings } from './settings/Exclusions';
import { SettingsStatusRefresh } from './settings/formKit';
import { DiscoveryForm, DomainDiscoveryForm, GeoForm, LdapForm, PresenceForm, RetentionForm, ScanProfileForm, ScheduleForm, VulnForm } from './settings/Forms';
import { NetworksSettings } from './settings/Networks';
import { NOTIFICATION_SECTIONS, NotificationsSettings } from './settings/Notifications';
import { SettingsOverview, sectionStates, useSettingsStatus } from './settings/Overview';
import { TokensSettings } from './settings/Tokens';
import { WebCaptureTab, WordlistsTab } from './settings/Wordlists';

type Section = { id: string; label: string; viewer: boolean };

const OVERVIEW: Section = { id: 'overview', label: 'Overview', viewer: true };

// Ordered like the product's pipeline: scan, enrich, alert, then who has access and how the system keeps data.
const GROUPS: { label: string; sections: Section[] }[] = [
  {
    label: 'Scanning',
    sections: [
      { id: 'networks', label: 'Networks', viewer: true },
      { id: 'exclusions', label: 'Exclusions', viewer: true },
      { id: 'schedule', label: 'Schedule', viewer: false },
      { id: 'scan-profiles', label: 'Scanner tuning', viewer: false },
    ],
  },
  {
    label: 'Enrichment',
    sections: [
      { id: 'web-capture', label: 'Web capture', viewer: false },
      { id: 'wordlists', label: 'Wordlists', viewer: false },
      { id: 'discovery', label: 'Local discovery', viewer: false },
      { id: 'geo', label: 'Geo', viewer: false },
      { id: 'domain-discovery', label: 'Domain discovery', viewer: false },
      { id: 'vulnerabilities', label: 'Vulnerabilities', viewer: false },
    ],
  },
  { label: 'Alerts', sections: [{ id: 'notifications', label: 'Notifications', viewer: false }] },
  {
    label: 'Access',
    sections: [
      { id: 'authentication', label: 'LDAP sign-in', viewer: false },
      { id: 'users', label: 'Users', viewer: false },
      { id: 'tokens', label: 'API tokens', viewer: true },
    ],
  },
  {
    label: 'System',
    sections: [
      { id: 'retention', label: 'Retention', viewer: false },
      { id: 'data', label: 'Export / import', viewer: false },
      { id: 'audit', label: 'Audit log', viewer: false },
      { id: 'health', label: 'System health', viewer: true },
    ],
  },
];

const ALL: Section[] = [OVERVIEW, ...GROUPS.flatMap((g) => g.sections)];

function Chevron({ open }: { open: boolean }) {
  return (
    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden
      style={{ transform: open ? 'rotate(180deg)' : undefined }}>
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}

export default function Settings() {
  const { isAdmin, system } = useApp();
  const { tab, section } = useParams();
  const { pathname } = useLocation();
  const [sp, setSp] = useSearchParams();
  const groups = useMemo(
    () => GROUPS.map((g) => ({ ...g, sections: g.sections.filter((s) => isAdmin || s.viewer) })).filter((g) => g.sections.length),
    [isAdmin],
  );
  const visible = useMemo(() => [OVERVIEW, ...groups.flatMap((g) => g.sections)], [groups]);
  const status = useSettingsStatus(isAdmin);
  const states = useMemo(() => sectionStates(status.data, system), [status.data, system]);
  const [navOpen, setNavOpen] = useState(false);
  // Schedule hosts two forms; keep their dirty flags separate so one clear does not wipe the other.
  const [formDirty, setFormDirty] = useState(false);
  const [presenceDirty, setPresenceDirty] = useState(false);
  // List tabs (networks, exclusions, users, tokens): their add/edit dialog holds unsaved input.
  const [entityDirty, setEntityDirty] = useState(false);
  const dirty = formDirty || presenceDirty || entityDirty;
  const tabAllowed = !!tab && visible.some((t) => t.id === tab);

  // Fresh tab mount = fresh forms; clear so a prior tab's dirty does not block the next.
  useEffect(() => {
    setFormDirty(false);
    setPresenceDirty(false);
    setEntityDirty(false);
    setNavOpen(false);
  }, [tab, section]);

  // Sections changed elsewhere (networks added, users removed) show up when the overview is opened again.
  const { reload } = status;
  useEffect(() => {
    if (tab === 'overview') reload();
  }, [tab, reload]);

  // Browser Back/Forward would unmount the dirty form too; restore the URL if the user keeps editing.
  useHistoryGuard(dirty && tabAllowed);

  // Sidebar (and other in-app links): leaving Settings would unmount a dirty form with no rail click.
  useEffect(() => {
    if (!dirty || !tabAllowed || !tab) return;
    const onClick = (e: globalThis.MouseEvent) => {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      const el = (e.target as Element | null)?.closest?.('a[href]');
      if (!el || el.getAttribute('target') === '_blank' || el.hasAttribute('download')) return;
      // Rail links use onNavClick; avoid a second confirm.
      if (el.closest('nav.settings-rail')) return;
      const href = el.getAttribute('href');
      if (!href || href.startsWith('#')) return;
      let url: URL;
      try {
        url = new URL(href, window.location.href);
      } catch {
        return;
      }
      if (url.origin !== window.location.origin) return;
      if (url.pathname === window.location.pathname) return;
      if (url.pathname === '/settings' && tab === 'overview') return;
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

  // Bare /settings opens the overview.
  if (!tab) return <Navigate to="/settings/overview" replace />;
  if (!tabAllowed) {
    // The notice rides in the query (not history state) so it survives a refresh until dismissed.
    const forbidden = ALL.find((t) => t.id === tab);
    return <Navigate to={forbidden ? `/settings/overview?denied=${forbidden.id}` : '/settings/overview'} replace />;
  }

  const current = visible.find((t) => t.id === tab)!;
  const subLabel = tab === 'notifications' ? NOTIFICATION_SECTIONS.find((s) => s.id === section)?.label : undefined;
  const deniedTab = ALL.find((t) => t.id === sp.get('denied'))?.label;
  const dismissDenied = () => {
    const next = new URLSearchParams(sp);
    next.delete('denied');
    setSp(next, { replace: true });
  };
  const onNavClick = (e: MouseEvent<HTMLAnchorElement>, to: string) => {
    if (to === pathname) {
      setNavOpen(false);
      return;
    }
    if (!confirmDiscard(dirty)) e.preventDefault();
  };
  const marker = (id: string) => {
    const st = states[id];
    return st?.short ? <span className={`rail-state ${st.tone}`}>{st.short}</span> : null;
  };

  return (
    <SettingsStatusRefresh.Provider value={reload}>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p>{isAdmin ? 'Changes take effect when saved and are recorded in the audit log.' : 'Read-only view.'}</p>
        </div>
      </div>
      <div className="settings-layout">
        <div className="settings-nav">
          <button type="button" className="btn settings-nav-toggle" aria-expanded={navOpen} aria-controls="settings-rail"
            onClick={() => setNavOpen((o) => !o)}>
            <span className="muted">Section</span>
            <span className="settings-nav-current">{current.label}{subLabel && ` · ${subLabel}`}</span>
            <Chevron open={navOpen} />
          </button>
          <nav id="settings-rail" className={`settings-rail${navOpen ? ' open' : ''}`} aria-label="Settings sections">
            <NavLink to="/settings/overview" onClick={(e) => onNavClick(e, '/settings/overview')}>Overview</NavLink>
            {groups.map((g) => (
              <div key={g.label} className="rail-group">
                <span className="rail-heading" id={`rail-${g.label.toLowerCase()}`}>{g.label}</span>
                <ul aria-labelledby={`rail-${g.label.toLowerCase()}`}>
                  {g.sections.map((s) => (
                    <li key={s.id}>
                      {s.id === 'notifications' ? (
                        <>
                          <Link to={tab === 'notifications' ? pathname : '/settings/notifications'}
                            className={tab === 'notifications' ? 'parent-active' : undefined}
                            onClick={(e) => onNavClick(e, tab === 'notifications' ? pathname : '/settings/notifications')}>
                            {s.label}{marker(s.id)}
                          </Link>
                          {tab === 'notifications' && (
                            <ul className="rail-sub" aria-label="Notification settings">
                              {NOTIFICATION_SECTIONS.map((n) => (
                                <li key={n.id}>
                                  <NavLink to={`/settings/notifications/${n.id}`} onClick={(e) => onNavClick(e, `/settings/notifications/${n.id}`)}>{n.label}</NavLink>
                                </li>
                              ))}
                            </ul>
                          )}
                        </>
                      ) : (
                        <NavLink to={`/settings/${s.id}`} onClick={(e) => onNavClick(e, `/settings/${s.id}`)}>{s.label}{marker(s.id)}</NavLink>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>
        </div>
        <div className="settings-body stack">
          {deniedTab && tab === 'overview' && (
            <div className="alert warn spread" role="status">
              <span>“{deniedTab}” settings are admin only, so you were taken to the overview instead.</span>
              <button type="button" className="btn ghost sm" onClick={dismissDenied} aria-label="Dismiss" title="Dismiss">✕</button>
            </div>
          )}
          {tab === 'overview' && <SettingsOverview groups={groups} states={states} loaded={!!status.data} />}
          {tab === 'networks' && <NetworksSettings onDirtyChange={setEntityDirty} />}
          {tab === 'exclusions' && <ExclusionsSettings onDirtyChange={setEntityDirty} />}
          {tab === 'schedule' && <><ScheduleForm onDirtyChange={setFormDirty} /><PresenceForm onDirtyChange={setPresenceDirty} /></>}
          {tab === 'scan-profiles' && <ScanProfileForm onDirtyChange={setFormDirty} />}
          {tab === 'web-capture' && <WebCaptureTab onDirtyChange={setFormDirty} />}
          {tab === 'wordlists' && <WordlistsTab onDirtyChange={setEntityDirty} />}
          {tab === 'vulnerabilities' && <VulnForm onDirtyChange={setFormDirty} />}
          {tab === 'discovery' && <DiscoveryForm onDirtyChange={setFormDirty} />}
          {tab === 'geo' && <GeoForm onDirtyChange={setFormDirty} />}
          {tab === 'domain-discovery' && <DomainDiscoveryForm onDirtyChange={setFormDirty} />}
          {tab === 'notifications' && <NotificationsSettings onDirtyChange={setFormDirty} />}
          {tab === 'authentication' && <LdapForm onDirtyChange={setFormDirty} />}
          {tab === 'users' && <UsersSettings onDirtyChange={setEntityDirty} />}
          {tab === 'retention' && <RetentionForm onDirtyChange={setFormDirty} />}
          {tab === 'data' && <DataTransferPanel />}
          {tab === 'audit' && <AuditSettings />}
          {tab === 'tokens' && <TokensSettings onDirtyChange={setEntityDirty} />}
          {tab === 'health' && <HealthPanel />}
        </div>
      </div>
    </SettingsStatusRefresh.Provider>
  );
}
