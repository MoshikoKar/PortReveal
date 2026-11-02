// Shared Settings form pieces: labelled fields with linked hints, and the save bar every settings form ends with.
import { createContext, useContext, useId, type FormEvent, type ReactNode } from 'react';

export type SaveMsg = { ok: boolean; text: string; at?: number } | null;

/** Lets a saved form refresh the Settings overview and the section rail's on/off markers. */
export const SettingsStatusRefresh = createContext<(() => void) | null>(null);
export const useRefreshSettingsStatus = () => useContext(SettingsStatusRefresh) ?? (() => {});

export const savedMsg = (): SaveMsg => ({ ok: true, text: 'Saved', at: Date.now() });

/** A label, its control and an optional hint. The hint sits outside the label and is linked with aria-describedby. */
export function Field({ label, hint, children }: {
  label: ReactNode; hint?: ReactNode; children: (p: { id: string; 'aria-describedby'?: string }) => ReactNode;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children({ id, 'aria-describedby': hint ? hintId : undefined })}
      {hint && <span className="hint" id={hintId}>{hint}</span>}
    </div>
  );
}

export function Num({ label, value, onChange, hint, min, max, disabled }: {
  label: string; value: number; onChange: (v: number) => void; hint?: ReactNode; min?: number; max?: number; disabled?: boolean;
}) {
  return (
    <Field label={label} hint={hint}>
      {(p) => <input {...p} type="number" value={value} min={min} max={max} disabled={disabled} onChange={(e) => onChange(Number(e.target.value))} />}
    </Field>
  );
}

/** Wraps a settings form so Enter in any field saves it. */
export function SettingsForm({ onSave, children }: { onSave: () => void; children: ReactNode }) {
  const submit = (e: FormEvent) => {
    e.preventDefault();
    onSave();
  };
  return <form className="stack" onSubmit={submit} noValidate>{children}</form>;
}

const clock = (at: number) => new Date(at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

/**
 * Save + Revert with one status line: "Unsaved changes" while the form differs from the server,
 * "Saved hh:mm" after a save, and save errors as an alert. Extra actions (sync, test) go in `children`.
 */
export function SaveBar({ dirty, saving, msg, onRevert, alwaysEnabled, children }: {
  dirty: boolean; saving: boolean; msg: SaveMsg; onRevert: () => void;
  /** Setup wizard steps save (and advance) even when the defaults are left unchanged. */
  alwaysEnabled?: boolean; children?: ReactNode;
}) {
  const state = dirty ? 'Unsaved changes' : msg?.ok && msg.at ? `${msg.text} ${clock(msg.at)}` : '';
  return (
    <div className="save-bar">
      {msg && !msg.ok && <div className="alert error" role="alert">{msg.text}</div>}
      <div className="save-bar-row">
        <button type="submit" className="btn primary" disabled={saving || (!dirty && !alwaysEnabled)}>{saving ? 'Saving…' : 'Save'}</button>
        <button type="button" className="btn ghost" disabled={saving || !dirty} onClick={onRevert}>Revert</button>
        <span className={`save-state${dirty ? ' dirty' : ''}`} role="status">{state}</span>
        {children && <span className="save-bar-extra">{children}</span>}
      </div>
    </div>
  );
}
