// First-run wizard: admin -> network -> exclusions -> schedule -> SMTP -> LDAP -> recipients -> baseline.
import { useState, type FormEvent } from 'react';
import { get, post } from '../api';
import { Logo } from '../components/Layout';
import { ErrorBox } from '../components/ui';
import type { Network, SetupStatus, User } from '../types';
import { ExclusionsSettings } from './settings/Exclusions';
import { LdapForm, NotificationsForm, ScheduleForm } from './settings/Forms';
import { NetworksSettings } from './settings/Networks';

const STEPS = ['Administrator', 'Network scope', 'Exclusions', 'Schedule', 'SMTP', 'LDAP (optional)', 'Recipients', 'Baseline scan'];

function AdminStep({ onUser }: { onUser: (u: User) => void }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (password !== confirm) return setError('Passwords do not match');
    try {
      const r = await post<{ user: User }>('/setup/admin', { username, password });
      onUser(r.user);
    } catch (err: any) {
      setError(err.message);
    }
  };
  return (
    <form className="stack" onSubmit={submit}>
      <p className="muted">Create the local administrator. Local accounts keep working even when LDAP is enabled (fallback access).</p>
      <label className="field">Username<input type="text" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus /></label>
      <label className="field">Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" /><span className="hint">At least 8 characters</span></label>
      <label className="field">Confirm password<input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" /></label>
      <ErrorBox error={error} />
      <div><button className="btn primary" type="submit">Create administrator</button></div>
    </form>
  );
}

function BaselineStep({ onFinish }: { onFinish: () => void }) {
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const start = async () => {
    setError(null);
    try {
      const nets = await get<Network[]>('/networks');
      if (!nets.length) return setError('Add at least one network first.');
      await post('/scans', { scan_type: 'standard', network_ids: nets.map((n) => n.id) });
      setMsg(`Baseline scan queued for ${nets.length} network(s). It runs in the background; nothing found by it will alert.`);
    } catch (e: any) {
      setError(e.message);
    }
  };
  return (
    <div className="stack">
      <p className="muted">
        The first complete standard scan of each network becomes its <strong>baseline</strong>: everything found is the known initial state and
        generates no alerts. Later scans are compared against it. For a /16 this can take a while.
      </p>
      {msg && <div className="alert ok">{msg}</div>}
      <ErrorBox error={error} />
      <div className="row">
        {!msg && <button className="btn primary" onClick={start}>Run baseline scan now</button>}
        <button className="btn" onClick={onFinish}>{msg ? 'Finish setup' : 'Skip – finish setup'}</button>
      </div>
    </div>
  );
}

export default function Setup({ status, startAtAdmin, onUser, onDone }: {
  status: SetupStatus; startAtAdmin: boolean; onUser: (u: User) => void; onDone: () => void;
}) {
  const [step, setStep] = useState(startAtAdmin ? 0 : 1);
  const next = () => setStep((s) => Math.min(STEPS.length - 1, s + 1));
  const finish = async () => {
    await post('/setup/complete');
    onDone();
  };
  return (
    <div className="login-wrap" style={{ alignItems: 'start', paddingTop: 40 }}>
      <div className="card wizard">
        <div className="card-head">
          <div className="row"><Logo /><div><div className="brand-name">NETWORK FINDER</div><div className="brand-sub">First-run setup</div></div></div>
          {status.dev_mode && <span className="badge medium">DEV</span>}
        </div>
        <div className="steps">
          {STEPS.map((s, i) => <span key={s} className={i === step ? 'current' : i < step ? 'done' : ''}>{i + 1}. {s}</span>)}
        </div>
        <div className="card-body stack" style={{ padding: 20 }}>
          <h2>{STEPS[step]}</h2>
          {step === 0 && <AdminStep onUser={(u) => { onUser(u); next(); }} />}
          {step === 1 && <NetworksSettings compact />}
          {step === 2 && <ExclusionsSettings />}
          {step === 3 && <ScheduleForm onSaved={next} />}
          {step === 4 && <NotificationsForm part="smtp" onSaved={next} />}
          {step === 5 && <LdapForm onSaved={next} />}
          {step === 6 && <NotificationsForm part="recipients" onSaved={next} />}
          {step === 7 && <BaselineStep onFinish={finish} />}
          {step > 0 && (
            <div className="spread" style={{ borderTop: '1px solid var(--border)', paddingTop: 14 }}>
              <button className="btn ghost" onClick={() => setStep(step - 1)} disabled={step <= 1}>Back</button>
              <div className="row">
                {step < STEPS.length - 1 && <button className="btn" onClick={next}>{[2, 4, 5, 6].includes(step) ? 'Skip / next' : 'Next'}</button>}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
