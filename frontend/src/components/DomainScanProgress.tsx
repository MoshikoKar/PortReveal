import { currentPhase, formatEta, formatPercent, formatRate, phaseCounter, progressWidth, stepperItems } from '../domains';
import type { DomainScanJob } from '../types';
import { Card } from './ui';

/** Running domain scan: phase stepper, overall percent and the current phase's counters. */
export function DomainScanProgress({ scan, onCancel, cancelling }: {
  scan: DomainScanJob; onCancel?: () => void; cancelling?: boolean;
}) {
  const cur = currentPhase(scan.phases);
  const counters = cur ? [phaseCounter(cur), cur.found ? `${cur.found.toLocaleString('en-US')} found` : '', formatRate(cur.rate), formatEta(cur.eta_s)]
    .filter((x, i, all) => x && all.indexOf(x) === i) : [];
  return (
    <Card
      title={`Domain scan #${scan.id} · ${scan.status === 'queued' ? 'queued' : cur?.label ?? scan.stage ?? 'starting'}`}
      actions={onCancel && <button className="btn warn sm" disabled={cancelling} onClick={onCancel}>{cancelling ? 'Cancelling…' : 'Cancel scan'}</button>}
    >
      <div className="stack domain-scan-progress" style={{ gap: 10 }} data-testid="domain-scan-progress">
        {scan.status === 'queued' && <div className="muted small">Waiting for a free slot (network scans go first).</div>}
        <ol className="phase-steps" aria-label="Scan phases">
          {stepperItems(scan.phases).map((s) => (
            <li key={s.key} className={`phase-step ${s.status}`} title={s.title} data-testid={`phase-${s.key}`}>
              <span className={`badge ${s.badge}`} aria-hidden>{s.mark}</span>
              <span className="phase-label">{s.label}</span>
            </li>
          ))}
        </ol>
        <div className="row" style={{ gap: 10, alignItems: 'center' }}>
          <div className="progress" style={{ flex: 1 }}><div style={{ width: progressWidth(scan.progress) }} /></div>
          <strong className="small" style={{ minWidth: 44, textAlign: 'right' }}>{formatPercent(scan.progress)}</strong>
        </div>
        {cur && counters.length > 0 && <div className="small muted" data-testid="phase-counters">{counters.join(' · ')}</div>}
      </div>
    </Card>
  );
}
