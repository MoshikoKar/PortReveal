import { Link } from 'react-router-dom';
import { useApp } from '../context';
import type { VulnSummary } from '../types';
import { fmtTime, relTime } from '../util';
import type { VulnFilterKey, VulnFilters } from '../vulnFilters';
import { Kpi } from './ui';

const BANDS = [
  { key: 'critical', label: 'Critical', range: 'CVSS 9.0 and up' },
  { key: 'high', label: 'High', range: 'CVSS 7.0 to 8.9' },
  { key: 'medium', label: 'Medium', range: 'CVSS 4.0 to 6.9' },
  { key: 'low', label: 'Low', range: 'CVSS below 4.0' },
  { key: 'unknown', label: 'Unscored', range: 'No CVSS score in the local cache' },
] as const;

function count(n: number, one: string, many = `${one}s`) {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

/** One sentence a generalist (or a wall display) can read first: how much, how urgent, what's new. */
function Headline({ s, filtered }: { s: VulnSummary; filtered: boolean }) {
  if (s.findings_total === 0) {
    return (
      <p className="vuln-headline">
        No vulnerability findings{filtered ? ' match these filters' : ''}.
        {s.new_since_last_scan_count === 0 && !filtered && ' Nothing new since the last scan.'}
      </p>
    );
  }
  return (
    <p className="vuln-headline">
      <strong>{count(s.findings_total, 'finding')}</strong> on <strong>{count(s.device_count, 'device')}</strong>.{' '}
      {s.kev_count > 0
        ? <><strong className="sev-text sev-critical">{s.kev_count.toLocaleString()} {s.kev_count === 1 ? 'is' : 'are'} actively exploited</strong>: start there.</>
        : 'None is on the CISA list of actively exploited vulnerabilities.'}{' '}
      {s.new_since_last_scan_count > 0
        ? <><strong>{s.new_since_last_scan_count.toLocaleString()} new</strong> since the last scan.</>
        : 'Nothing new since the last scan.'}
    </p>
  );
}

/** Feed freshness in plain words; exact timestamps stay in the hover title. */
function FeedStatus({ feed }: { feed: VulnSummary['feed'] }) {
  const { newest_synced_at: newest, oldest_synced_at: oldest } = feed;
  return (
    <p className="vuln-feed small muted">
      {newest && (
        <span title={fmtTime(newest)}>Vulnerability data updated {relTime(newest)}</span>
      )}
      {oldest && oldest !== newest && (
        <span title={fmtTime(oldest)}> · oldest source {relTime(oldest)}</span>
      )}
      {feed.stale && (
        <span className="badge sev-high" style={{ marginLeft: 8 }}
          title={`Each enabled source should sync at least every ${feed.stale_threshold_hours} hours`}>
          {oldest
            ? `Stale: a source has not synced in over ${feed.stale_threshold_hours}h`
            : 'Stale: a source has never synced'}
        </span>
      )}
    </p>
  );
}

/** Top of the page: headline sentence, the three numbers to act on, and the severity mix. */
export function VulnGlance({ summary: s, filters, filtered, onToggle }: {
  summary: VulnSummary;
  filters: VulnFilters;
  filtered: boolean;
  onToggle: (key: VulnFilterKey, value: string) => void;
}) {
  const { isAdmin } = useApp();
  if (!s.feed.newest_synced_at) {
    return (
      <div className="alert warn vuln-never-synced" role="status">
        <strong>Vulnerability data has never been downloaded.</strong> No CVE can be matched until it is,
        so an empty list here does not mean the network is clean.{' '}
        {isAdmin
          ? <Link to="/settings/vulnerabilities">Open vulnerability settings</Link>
          : 'Ask an admin to sync the vulnerability feed.'}
      </div>
    );
  }
  const sev = s.severity_counts;
  const total = BANDS.reduce((n, b) => n + (sev[b.key] ?? 0), 0);
  const risk = s.risk_device_levels;
  return (
    <section className="vuln-glance" aria-label="Summary">
      <Headline s={s} filtered={filtered} />
      <div className="vuln-glance-grid">
        <Kpi className={s.kev_count > 0 ? 'kpi-kev' : undefined}
          label="Actively exploited (CISA KEV)"
          value={s.kev_count}
          sub={s.kev_count > 0 ? 'Findings attackers are known to use. Fix these first.' : 'No finding is on the CISA KEV list.'}
          active={filters.kev === 'true'} onClick={() => onToggle('kev', 'true')} />
        <Kpi label="New since last scan" value={s.new_since_last_scan_count}
          sub={`${count(s.new_since_last_db_update_count, 'finding')} new since the last data update`}
          color={s.new_since_last_scan_count > 0 ? 'var(--accent)' : undefined}
          active={filters.new_since === 'scan'} onClick={() => onToggle('new_since', 'scan')} />
        <Kpi label="High-risk devices" value={risk.high}
          sub={`of ${count(s.device_count, 'affected device')} · ${risk.medium} medium risk`}
          color={risk.high ? 'var(--sev-high)' : undefined}
          active={filters.risk_band === 'high'} onClick={() => onToggle('risk_band', 'high')} />
        <div className="kpi vuln-sev-strip">
          <div className="label" id="vuln-sev-label">Findings by severity (CVSS)</div>
          <div className="vuln-sev-bar" aria-hidden>
            {BANDS.map((b) => (sev[b.key] ?? 0) > 0 && (
              <span key={b.key} className={`sev-fill sev-${b.key === 'unknown' ? 'unscored' : b.key}`}
                style={{ flexGrow: sev[b.key] }} />
            ))}
            {total === 0 && <span className="sev-fill" style={{ flexGrow: 1 }} />}
          </div>
          <div className="vuln-sev-legend" role="group" aria-labelledby="vuln-sev-label">
            {BANDS.map((b) => {
              const n = sev[b.key] ?? 0;
              if (b.key === 'unknown' && n === 0) return null;
              const on = filters.severity === b.key;
              return (
                <button key={b.key} type="button" aria-pressed={on} title={`${b.label}: ${b.range}`}
                  className={`vuln-sev-item sev-${b.key === 'unknown' ? 'unscored' : b.key} ${on ? 'active' : ''}`}
                  onClick={() => onToggle('severity', b.key)}>
                  <span className="vuln-sev-swatch" aria-hidden />
                  <span className="vuln-sev-count">{n.toLocaleString()}</span>
                  <span className="vuln-sev-name">{b.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>
      <FeedStatus feed={s.feed} />
    </section>
  );
}
