// Users, audit log and system health.
import { useState } from 'react';
import { del, patch, post, put } from '../../api';
import { Card, Empty, ErrorBox, Loading, Modal, Pager, ScanStatusBadge, SkeletonRows, confirmDiscard } from '../../components/ui';
import { useApp } from '../../context';
import type { AuditEntry, Paged, User } from '../../types';
import { fmtTime, relTime, useApi, useInFlight } from '../../util';

export function UsersSettings() {
  const { user: me } = useApp();
  const { data, error, loading, reload } = useApi<User[]>('/users');
  const [draft, setDraft] = useState<{ username: string; password: string; role: 'admin' | 'viewer' } | null>(null);
  const [pw, setPw] = useState<{ user: User; password: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // Row actions are keyed per user; the Create/Set password dialogs share the `dialog` key.
  const { pending, track } = useInFlight();
  const saving = pending('dialog');

  const draftDirty = !!draft && (draft.username !== '' || draft.password !== '' || draft.role !== 'viewer');
  const canCreate = !!draft && !!draft.username.trim() && !!draft.password;
  const closeDraft = () => confirmDiscard(draftDirty) && setDraft(null);
  const closePw = () => confirmDiscard(!!pw?.password) && setPw(null);

  const changeRole = (u: User, role: 'admin' | 'viewer') => {
    const msg = role === 'viewer'
      ? `Change ${u.username} from Administrator to Viewer? They lose access to configuration and scans.`
      : `Make ${u.username} an Administrator? They gain full access to configuration, users and scans.`;
    if (confirm(msg)) track(`user-${u.id}`, () => act(() => patch(`/users/${u.id}`, { role })));
  };
  const toggleActive = (u: User) => {
    const msg = u.is_active
      ? `Disable ${u.username}? They are signed out and can no longer log in.`
      : `Enable ${u.username}? They can log in again.`;
    if (confirm(msg)) track(`user-${u.id}`, () => act(() => patch(`/users/${u.id}`, { is_active: !u.is_active })));
  };
  const remove = (u: User) => {
    if (confirm(`Delete user ${u.username}?`)) track(`user-${u.id}`, () => act(() => del(`/users/${u.id}`)));
  };
  /** Dialog submit: busy while in flight, closes only on success. */
  const submit = (fn: () => Promise<unknown>, close: () => void) =>
    track('dialog', async () => { if (await act(fn)) close(); });

  const act = async (fn: () => Promise<unknown>) => {
    setErr(null);
    try {
      await fn();
      reload();
      return true;
    } catch (e: any) {
      setErr(e.message);
      return false;
    }
  };

  return (
    <Card title="Users" flush actions={<button className="btn primary sm" onClick={() => setDraft({ username: '', password: '', role: 'viewer' })}>Add local user</button>}>
      <div className="card-body muted small" style={{ borderBottom: '1px solid var(--border)' }}>
        Two roles: <strong>Administrator</strong> (configuration and scans) and <strong>Viewer</strong> (read-only). LDAP users are created on
        first login; their role follows directory group membership. At least one active local administrator always remains.
      </div>
      <ErrorBox error={error || err} />
      {loading && !data ? <SkeletonRows cols={6} /> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>User</th><th>Source</th><th>Role</th><th>Status</th><th>Last login</th><th /></tr></thead>
            <tbody>
              {data?.map((u) => (
                <tr key={u.id} className={u.is_active ? '' : 'dim'}>
                  <td><strong>{u.username}</strong>{u.display_name && <div className="muted small">{u.display_name}</div>}</td>
                  <td>{u.source}</td>
                  <td>
                    <select value={u.role} disabled={u.id === me.id || pending(`user-${u.id}`)} onChange={(e) => changeRole(u, e.target.value as 'admin' | 'viewer')}>
                      <option value="admin">Administrator</option><option value="viewer">Viewer</option>
                    </select>
                  </td>
                  <td>{u.is_active ? <span className="badge ok">active</span> : <span className="badge outline">disabled</span>}</td>
                  <td>{u.last_login_at ? relTime(u.last_login_at) : 'never'}</td>
                  <td className="right nowrap">
                    {u.source === 'local' && <button className="btn ghost sm" onClick={() => setPw({ user: u, password: '' })}>Set password</button>}
                    {u.id !== me.id && (
                      <>
                        <button className={`btn sm ${u.is_active ? 'warn' : 'ghost'}`} disabled={pending(`user-${u.id}`)} onClick={() => toggleActive(u)}>{u.is_active ? 'Disable' : 'Enable'}</button>
                        <button className="btn danger sm" disabled={pending(`user-${u.id}`)} onClick={() => remove(u)}>Delete</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {draft && (
        <Modal title="Add local user" onClose={() => setDraft(null)} dirty={draftDirty}
          footer={<><button className="btn ghost" onClick={closeDraft}>Cancel</button>
            <button className="btn primary" disabled={saving || !canCreate} title={canCreate ? undefined : 'Enter a username and a password'}
              onClick={() => submit(() => post('/users', draft), () => setDraft(null))}>{saving ? 'Creating…' : 'Create'}</button></>}>
          <label className="field">Username<input type="text" value={draft.username} onChange={(e) => setDraft({ ...draft, username: e.target.value })} /></label>
          <label className="field">Password<input type="password" value={draft.password} onChange={(e) => setDraft({ ...draft, password: e.target.value })} autoComplete="new-password" /><span className="hint">Minimum 8 characters</span></label>
          <label className="field">Role
            <select value={draft.role} onChange={(e) => setDraft({ ...draft, role: e.target.value as 'admin' | 'viewer' })}>
              <option value="viewer">Viewer (read-only)</option><option value="admin">Administrator</option>
            </select>
          </label>
          <ErrorBox error={err} />
        </Modal>
      )}
      {pw && (
        <Modal title={`Set password for ${pw.user.username}`} onClose={() => setPw(null)} dirty={!!pw.password}
          footer={<><button className="btn ghost" onClick={closePw}>Cancel</button>
            <button className="btn primary" disabled={saving || !pw.password}
              onClick={() => submit(() => patch(`/users/${pw.user.id}`, { password: pw.password }), () => setPw(null))}>{saving ? 'Saving…' : 'Save'}</button></>}>
          <label className="field">New password<input type="password" value={pw.password} onChange={(e) => setPw({ ...pw, password: e.target.value })} autoComplete="new-password" /></label>
          <ErrorBox error={err} />
        </Modal>
      )}
    </Card>
  );
}

export function AuditSettings() {
  const [page, setPage] = useState(1);
  const [q, setQ] = useState('');
  const { data, error, loading } = useApi<Paged<AuditEntry>>('/audit', { page, page_size: 50, q }, 15000);
  return (
    <Card title="Audit log" flush actions={<input type="search" placeholder="Filter action / user / target" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />}>
      <ErrorBox error={error} />
      {loading && !data ? <SkeletonRows cols={6} /> : !data?.items.length ? <Empty>No entries.</Empty> : (
        <>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead>
              <tbody>
                {data.items.map((a) => (
                  <tr key={a.id}>
                    <td className="nowrap">{fmtTime(a.created_at, true)}</td>
                    <td>{a.username}</td>
                    <td><span className={`badge ${a.action.includes('failed') ? 'high' : 'outline'}`}>{a.action}</span></td>
                    <td>{a.target}</td>
                    <td className="mono small" style={{ maxWidth: 420, overflowWrap: 'anywhere' }}>{a.details}</td>
                    <td className="mono">{a.ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={page} pageSize={50} total={data.total} onPage={setPage} />
        </>
      )}
    </Card>
  );
}

function Health({ ok, label, children }: { ok: boolean | null; label: string; children: React.ReactNode }) {
  return (
    <div className="kpi" style={{ ['--kpi-color' as any]: ok === null ? 'var(--medium)' : ok ? 'var(--ok)' : 'var(--high)' }}>
      <div className="label">{label}</div>
      <div style={{ marginTop: 6 }}>{children}</div>
    </div>
  );
}

interface MockData { hidden: boolean; scans: number; devices: number; events: number }

function MockDataCard() {
  const { isAdmin, refreshSystem } = useApp();
  const { data, error, reload } = useApi<MockData>('/mock-data');
  const [err, setErr] = useState<string | null>(null);
  if (!data || (!data.hidden && !data.scans && !data.devices)) return error ? <ErrorBox error={error} /> : null;
  const toggle = async (hidden: boolean) => {
    setErr(null);
    try {
      await put('/mock-data', { hidden });
      reload();
      refreshSystem();
    } catch (e: any) {
      setErr(e.message);
    }
  };
  return (
    <Card title="Simulated data">
      <p className="muted small">
        The mock scanner left {data.scans} scan(s), {data.devices} device(s) and {data.events} change event(s) in the database.
        Hiding removes them from the dashboard, lists and counts without deleting anything. Devices that a real nmap scan has seen are never hidden.
      </p>
      {isAdmin
        ? <label className="check"><input type="checkbox" checked={data.hidden} onChange={(e) => toggle(e.target.checked)} />Hide simulated (mock) data</label>
        : <div>{data.hidden ? 'Hidden' : 'Shown'} <span className="muted small">(an administrator can change this)</span></div>}
      <ErrorBox error={err} />
    </Card>
  );
}

export function HealthPanel() {
  const { system } = useApp();
  if (!system) return <Loading />;
  const { app, database, scanner, scans } = system;
  return (
    <div className="stack">
      <div className="grid kpis">
        <Health ok={app.status === 'ok' && app.worker_running && app.scheduler_running} label="Application">
          <div>{app.status.toUpperCase()} · v{app.version}</div>
          <div className="muted small">worker {app.worker_running ? 'running' : 'stopped'} · scheduler {app.scheduler_running ? 'running' : 'stopped'}</div>
          <div className="muted small">uptime {Math.round(app.uptime_seconds / 60)} min</div>
        </Health>
        <Health ok={database.ok} label="Database">
          <div>{database.type} · {database.ok ? 'OK' : 'ERROR'}</div>
          {database.location && <div className="muted small mono" style={{ overflowWrap: 'anywhere' }}>{database.location}</div>}
        </Health>
        <Health ok={scanner.mode === 'nmap' ? true : scanner.mode === 'mock' ? null : false} label="Scanner">
          <div>{scanner.mode}{scanner.mock_active && ' (simulated)'}</div>
          <div className="muted small">{scanner.message}</div>
        </Health>
        <Health ok={!scans.last_failed || (scans.last_successful?.id ?? 0) > scans.last_failed.id} label="Scans">
          <div className="small">Last success: {scans.last_successful ? fmtTime(scans.last_successful.finished_at) : '—'}</div>
          <div className="small">Last failure: {scans.last_failed ? fmtTime(scans.last_failed.finished_at) : '—'}</div>
          <div className="small">Next: {scans.next_scheduled ? fmtTime(scans.next_scheduled) : 'not scheduled'}</div>
        </Health>
      </div>
      <MockDataCard />
      {app.dev_mode && (
        <Card title="Development diagnostics">
          <dl className="dl">
            <dt>Mode</dt><dd><span className="badge medium">DEV</span> APP_ENV={app.env}</dd>
            <dt>Database</dt><dd>{database.type}{database.location && <span className="mono"> · {database.location}</span>}</dd>
            <dt>Scanner mode</dt><dd>configured <code>{scanner.configured_mode}</code> → effective <code>{scanner.mode}</code></dd>
            <dt>nmap</dt><dd>{scanner.nmap_detected ? `detected (${scanner.nmap_version}) at ${scanner.nmap_path}` : `NOT detected (${scanner.nmap_path})`} · {scanner.privileged ? 'privileged' : 'unprivileged'}</dd>
            <dt>Mock scanner</dt><dd>{scanner.mock_active ? 'ACTIVE – results are simulated' : 'inactive'}</dd>
            <dt>Current scan</dt><dd>{scans.current ? <><ScanStatusBadge status={scans.current.status} /> #{scans.current.id}</> : 'none'} · {scans.queued} queued</dd>
          </dl>
        </Card>
      )}
    </div>
  );
}
