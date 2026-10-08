import { useState, type FormEvent } from 'react';
import { post } from '../api';
import { Logo } from '../components/Layout';
import { ErrorBox } from '../components/ui';
import type { SetupStatus, User } from '../types';

export default function Login({ status, onLogin }: { status: SetupStatus; onLogin: (u: User) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await post<{ user: User }>('/auth/login', { username, password });
      onLogin(res.user);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="card login" onSubmit={submit}>
        <div className="card-body stack" style={{ gap: 16, padding: 24 }}>
          <div className="row">
            <Logo />
            <div>
              <div className="brand-name">NETWORK FINDER</div>
              <div className="brand-sub">Network discovery & change detection</div>
            </div>
          </div>
          {status.dev_mode && (
            <div className="alert warn small">
              Development mode{status.scanner_mode === 'mock' ? ' · mock scanner (simulated data)' : ''}. Default dev login is set
              by DEV_ADMIN_USERNAME / DEV_ADMIN_PASSWORD (admin / admin).
            </div>
          )}
          <label className="field">
            Username
            <input type="text" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} required />
          </label>
          <label className="field">
            Password
            <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </label>
          <ErrorBox error={error} />
          <button className="btn primary" disabled={busy} type="submit">{busy ? 'Signing in…' : 'Sign in'}</button>
          <div className="muted small">Local accounts always work; directory (LDAP) accounts work when LDAP is enabled.</div>
        </div>
      </form>
    </div>
  );
}
