// Scan dialog rules, kept free of React so they can be unit-tested.
import type { ScanType } from '../types';

export type ScanTargetMode = 'networks' | 'targets' | 'devices';

export interface ScanForm {
  type: ScanType;
  mode: ScanTargetMode;
  selected: number[];
  targets: string;
  deviceUuids?: string[];
  criteria?: string;
}

/** True when the chosen target mode has something to scan. */
export function scanReady(f: ScanForm): boolean {
  if (f.mode === 'devices') return !!f.deviceUuids?.length;
  if (f.mode === 'networks') return f.selected.length > 0;
  return f.targets.trim().length > 0;
}

/** Why Start is disabled, or undefined when it is enabled. */
export function scanStartHint(f: ScanForm, opts: { unavailable: boolean; unavailableMessage?: string; busy: boolean }): string | undefined {
  if (!scanReady(f)) {
    return f.mode === 'networks' ? 'Select at least one network' : f.mode === 'targets' ? 'Enter targets' : 'Select at least one device';
  }
  if (opts.unavailable) return opts.unavailableMessage ?? 'Scanner unavailable';
  if (opts.busy) return 'Starting scan…';
  return undefined;
}

/** POST /scans body: exactly one of network_ids, targets or device_uuids (the API rejects anything else). */
export function scanRequestBody(f: ScanForm): Record<string, unknown> {
  const body: Record<string, unknown> = { scan_type: f.type };
  if (f.mode === 'devices') body.device_uuids = f.deviceUuids;
  else if (f.mode === 'networks') body.network_ids = f.selected;
  else body.targets = f.targets;
  if (f.criteria) body.criteria = f.criteria;
  return body;
}
