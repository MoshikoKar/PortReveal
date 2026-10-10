import { useState } from 'react';
import { post } from '../api';
import { useApp } from '../context';
import type { Network, Scan, ScanType } from '../types';
import { useApi } from '../util';
import { confirmDiscard, ErrorBox, Loading, Modal } from './ui';

export interface ScanPreset {
  scan_type?: ScanType;
  device_uuids?: string[];
  deviceLabel?: string;
  criteria?: string;
  lockTargets?: boolean;
}

const TYPE_INFO: Record<ScanType, string> = {
  discovery: 'Lightweight host discovery (ARP/ICMP/TCP probes). Detects new, missing and moved devices. No port scan.',
  standard: 'Discovery, then the common TCP ports with safe service/version identification on live hosts. Same as the daily scan.',
  full: 'DEEP SCAN: discovery, then all 65,535 TCP ports with service identification on live hosts. Much slower and noisier - use for specific hosts or small ranges.',
};

export function ScanDialog({ preset, onClose, onStarted }: {
  preset?: ScanPreset; onClose: () => void; onStarted?: (scans: Scan[]) => void;
}) {
  const { system } = useApp();
  const networks = useApi<Network[]>('/networks');
  const [type, setType] = useState<ScanType>(preset?.scan_type ?? 'standard');
  const [mode, setMode] = useState<'networks' | 'targets' | 'devices'>(preset?.device_uuids ? 'devices' : 'networks');
  const [selected, setSelected] = useState<number[]>([]);
  const [targets, setTargets] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const unavailable = system?.scanner.mode === 'unavailable';

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = { scan_type: type };
      if (mode === 'devices') body.device_uuids = preset?.device_uuids;
      else if (mode === 'networks') body.network_ids = selected;
      else body.targets = targets;
      if (preset?.criteria) body.criteria = preset.criteria;
      const res = await post<{ scans: Scan[] }>('/scans', body);
      onStarted?.(res.scans);
      onClose();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const ready = mode === 'devices' ? !!preset?.device_uuids?.length : mode === 'networks' ? selected.length > 0 : targets.trim().length > 0;
  const dirty = selected.length > 0 || targets !== '';
  const startHint = !ready
    ? mode === 'networks' ? 'Select at least one network' : mode === 'targets' ? 'Enter targets' : 'Select at least one device'
    : unavailable ? system?.scanner.message ?? 'Scanner unavailable'
    : busy ? 'Starting scan…'
    : undefined;
  const requestClose = () => confirmDiscard(dirty) && onClose();

  return (
    <Modal
      title="Scan now"
      onClose={onClose}
      dirty={dirty}
      footer={
        <>
          <button className="btn ghost" onClick={requestClose}>Cancel</button>
          <button className={`btn ${type === 'full' ? 'warn' : 'primary'}`} disabled={!ready || busy || unavailable} onClick={submit} title={startHint}>
            {busy ? 'Starting…' : type === 'full' ? 'Start full port scan' : 'Start scan'}
          </button>
        </>
      }
    >
      {unavailable && <div className="alert error">{system?.scanner.message}</div>}
      {system?.scanner.mock_active && <div className="alert warn">Mock scanner active: this scan produces SIMULATED results.</div>}
      <div className="stack">
        <h3>Scan type</h3>
        {(['discovery', 'standard', 'full'] as ScanType[]).map((t) => (
          <label key={t} className="check" style={{ alignItems: 'flex-start' }}>
            <input type="radio" name="scan_type" checked={type === t} onChange={() => setType(t)} style={{ marginTop: 3 }} />
            <span>
              <strong>{t === 'full' ? 'Full port scan (1-65535)' : t[0].toUpperCase() + t.slice(1)}</strong>
              <div className={`small ${t === 'full' ? '' : 'muted'}`} style={t === 'full' ? { color: 'var(--medium)' } : undefined}>{TYPE_INFO[t]}</div>
            </span>
          </label>
        ))}
      </div>

      <div className="stack">
        <h3>Targets</h3>
        {preset?.lockTargets ? (
          <div>{preset.deviceLabel}</div>
        ) : (
          <>
            <div className="tabs">
              {preset?.device_uuids && (
                <button className={mode === 'devices' ? 'active' : ''} onClick={() => setMode('devices')}>
                  Selected devices ({preset.device_uuids.length})
                </button>
              )}
              <button className={mode === 'networks' ? 'active' : ''} onClick={() => setMode('networks')}>Networks</button>
              <button className={mode === 'targets' ? 'active' : ''} onClick={() => setMode('targets')}>IP / range / CIDR</button>
            </div>
            {mode === 'devices' && (
              <div className="stack" style={{ gap: 4 }}>
                <div className="muted">{preset?.deviceLabel ?? `${preset?.device_uuids?.length} selected device(s)`}</div>
                {preset?.criteria && <div className="muted small">Criteria: {preset.criteria}</div>}
              </div>
            )}
            {mode === 'networks' && (
              <div className="stack" style={{ gap: 6 }}>
                {networks.loading && !networks.data ? (
                  <Loading />
                ) : (
                  <>
                    <ErrorBox error={networks.error} />
                    {networks.data && networks.data.length === 0 && (
                      <div className="muted">No networks configured. Add one in Settings → Networks.</div>
                    )}
                    {networks.data?.map((n) => (
                      <label key={n.id} className="check">
                        <input
                          type="checkbox"
                          checked={selected.includes(n.id)}
                          onChange={(e) => setSelected(e.target.checked ? [...selected, n.id] : selected.filter((x) => x !== n.id))}
                        />
                        <span>{n.name} <span className="mono muted">{n.cidr}</span>{!n.enabled && <span className="muted small"> (schedule disabled)</span>}</span>
                      </label>
                    ))}
                  </>
                )}
              </div>
            )}
            {mode === 'targets' && (
              <label className="field">
                <textarea rows={3} value={targets} onChange={(e) => setTargets(e.target.value)} placeholder="10.20.15.22, 10.20.16.0/24, 10.20.17.10-50, server01.corp.local" />
                <span className="hint">IPs, CIDRs, ranges or hostnames, separated by commas or new lines. Exclusions always apply.</span>
              </label>
            )}
          </>
        )}
      </div>
      <ErrorBox error={error} />
    </Modal>
  );
}
