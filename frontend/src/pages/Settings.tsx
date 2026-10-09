import { NavLink, Navigate, useParams } from 'react-router-dom';
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
  const { tab = 'networks' } = useParams();
  const tabs = TABS.filter((t) => isAdmin || t.viewer);
  if (!tabs.some((t) => t.id === tab)) return <Navigate to="/settings/networks" replace />;
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p>{isAdmin ? 'Central configuration. All changes apply immediately and are recorded in the audit log.' : 'Read-only view.'}</p>
        </div>
      </div>
      <nav className="tabs">
        {tabs.map((t) => <NavLink key={t.id} to={`/settings/${t.id}`}>{t.label}</NavLink>)}
      </nav>
      {tab === 'networks' && <NetworksSettings />}
      {tab === 'exclusions' && <ExclusionsSettings />}
      {tab === 'schedule' && <><ScheduleForm /><PresenceForm /></>}
      {tab === 'scan-profiles' && <ScanProfileForm />}
      {tab === 'web-capture' && <WebCaptureForm />}
      {tab === 'notifications' && <NotificationsForm />}
      {tab === 'authentication' && <LdapForm />}
      {tab === 'users' && <UsersSettings />}
      {tab === 'retention' && <RetentionForm />}
      {tab === 'data' && <DataTransferPanel />}
      {tab === 'audit' && <AuditSettings />}
      {tab === 'tokens' && <TokensSettings />}
      {tab === 'health' && <HealthPanel />}
    </>
  );
}
