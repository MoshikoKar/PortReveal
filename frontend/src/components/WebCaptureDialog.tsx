import { useState } from 'react';
import { post } from '../api';
import { confirmDiscard, ErrorBox, Modal } from './ui';

export interface WebCapturePreset {
  device_uuids?: string[];
  deviceLabel?: string;
  lockTargets?: boolean;
  targets?: string;
}

export function WebCaptureDialog({ preset, onClose, onStarted }: {
  preset?: WebCapturePreset;
  onClose: () => void;
  onStarted?: () => void;
}) {
  const initialMode = preset?.device_uuids ? 'devices' : 'targets';
  const [mode, setMode] = useState<'devices' | 'targets'>(initialMode);
  const [targets, setTargets] = useState(preset?.targets ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {};
      if (mode === 'devices' && preset?.device_uuids?.length) {
        body.device_uuids = preset.device_uuids;
      } else {
        body.targets = targets;
      }
      await post('/web-captures', body);
      onStarted?.();
      onClose();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const ready = mode === 'devices' ? !!preset?.device_uuids?.length : targets.trim().length > 0;
  // Any departure from the preset counts, including a mode-only change.
  const dirty = mode !== initialMode || targets !== (preset?.targets ?? '');
  const startHint = !ready
    ? mode === 'targets' ? 'Enter targets' : 'Select at least one device'
    : busy ? 'Starting web capture…'
    : undefined;
  const requestClose = () => confirmDiscard(dirty) && onClose();

  return (
    <Modal
      title="Web Capture"
      onClose={onClose}
      dirty={dirty}
      footer={
        <>
          <button className="btn ghost" onClick={requestClose}>Cancel</button>
          <button className="btn primary" disabled={!ready || busy} onClick={submit} title={startHint}>
            {busy ? 'Starting…' : 'Capture web interfaces'}
          </button>
        </>
      }
    >
      <div className="alert">
        <div className="small">
          Inventory enrichment only: captures known HTTP(S) services from existing scan data for the selected targets.
          Does not run a new port scan.
        </div>
      </div>
      <ErrorBox error={error} />
      <div className="stack">
        <h3>Targets</h3>
        {preset?.lockTargets ? (
          <div>{preset.deviceLabel}</div>
        ) : (
          <>
            {preset?.device_uuids && (
              <div className="tabs">
                <button className={mode === 'devices' ? 'active' : ''} onClick={() => setMode('devices')}>
                  Selected devices ({preset.device_uuids.length})
                </button>
                <button className={mode === 'targets' ? 'active' : ''} onClick={() => setMode('targets')}>IP / range / CIDR</button>
              </div>
            )}
            {mode === 'devices' && preset?.device_uuids && (
              <div className="muted">{preset.deviceLabel ?? `${preset.device_uuids.length} device(s)`}</div>
            )}
            {mode === 'targets' && (
              <label className="field">
                <textarea rows={3} value={targets} onChange={(e) => setTargets(e.target.value)}
                  placeholder="10.0.0.10, 10.0.0.0/24, 10.0.1.10-50" />
                <span className="hint">IPs, CIDRs, or ranges. Exclusions apply. Not arbitrary URLs.</span>
              </label>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}
