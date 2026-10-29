import { useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { SEVERITY_BADGE, SEVERITY_ORDER, openPortsText, vulnsHref, webPreviewHref } from '../domains';
import type { Subdomain, SubdomainDetail, WebPage } from '../types';
import { fmtTime, relTime } from '../util';
import { Card, Empty, RiskBadge, ScoreBadge } from './ui';
import { ShotTile, isUsefulShot } from './WebShots';

const UNSCORED_TIP = 'Not scored: no inventory device on this name\'s addresses yet (or not risk-scored)';

/** One score cell like the Devices list; "-" when no linked device / not scored. */
export function ScoreCell({ score, kind }: { score: number | null | undefined; kind: 'exposure' | 'risk' | 'combined' }) {
  if (score == null) return <span className="muted" title={UNSCORED_TIP}>-</span>;
  return kind === 'exposure' ? <ScoreBadge score={score} /> : <RiskBadge score={score} kind={kind} />;
}

/** Inventory "Ports" cell: open-port count plus a web link when a page was captured. */
export function PortsCell({ s }: { s: Subdomain }) {
  const href = webPreviewHref(s);
  return (
    <span className="sd-ports-cell">
      <span className={s.open_ports_count ? undefined : 'muted'} title={s.open_ports_count == null ? UNSCORED_TIP : undefined}>
        {openPortsText(s.open_ports_count)}
      </span>
      {href && <Link className="badge outline" to={href} title="Open web preview" data-testid="subdomain-web-link">web</Link>}
    </span>
  );
}

/** Header score badges + counts (same components as DeviceDetail). */
export function SubdomainScoreBadges({ s }: { s: Subdomain }) {
  return (
    <>
      <span title="Exposure score (highest linked device)" data-testid="subdomain-score-exposure"><ScoreCell score={s.exposure_score} kind="exposure" /></span>
      <span title="Risk score (highest linked device)"><ScoreCell score={s.risk_score} kind="risk" /></span>
      <span title="Combined score (highest linked device)" data-testid="subdomain-score-combined"><ScoreCell score={s.combined_score} kind="combined" /></span>
      {s.open_ports_count != null && <span className="badge outline">{openPortsText(s.open_ports_count)}</span>}
      {!!s.vulns_count && (
        <span className={`badge ${s.worst_severity ? SEVERITY_BADGE[s.worst_severity] : 'outline'}`}
          title={s.worst_severity ? `Worst severity: ${s.worst_severity}` : undefined}>
          {s.vulns_count} vuln{s.vulns_count === 1 ? '' : 's'}
        </span>
      )}
    </>
  );
}

/** "Not scanned yet" note with the "Port scan now" action (admins, names that resolve). */
function NotScanned({ action }: { action?: ReactNode }) {
  return (
    <div className="card-body muted small row wrap" style={{ gap: 8 }} data-testid="subdomain-not-scanned">
      <span>Not scanned yet: no inventory device on this name&apos;s addresses.</span>{action}
    </div>
  );
}

/** Small "Devices" list, shown when the name points at several inventory devices. */
export function SubdomainDevicesCard({ devices }: { devices: SubdomainDetail['devices'] }) {
  return (
    <Card title={`Devices - ${devices.length}`} flush>
      <div className="table-wrap">
        <table className="domain-table fit-table">
          <thead><tr><th className="domain-col-fluid">Device</th><th>IP</th><th title="Exposure score">Exposure</th><th>Risk</th><th>Combined</th><th>Ports</th><th>Vulns</th></tr></thead>
          <tbody>
            {devices.map((dv) => (
              <tr key={dv.uuid}>
                <td className="domain-col-fluid"><Link className="cell-ellipsis" title={dv.label} to={`/devices/${dv.uuid}`}>{dv.label}</Link></td>
                <td className="mono small">{dv.ip}</td>
                <td><ScoreBadge score={dv.exposure_score} /></td>
                <td>{dv.risk_scored_at ? <RiskBadge score={dv.risk_score} kind="risk" /> : <span className="muted">-</span>}</td>
                <td>{dv.risk_scored_at ? <RiskBadge score={dv.combined_score} kind="combined" /> : <span className="muted">-</span>}</td>
                <td className="small">{openPortsText(dv.open_ports_count)}</td>
                <td className="small">{dv.vulnerabilities ? <Link to={vulnsHref(dv.uuid)}>{dv.vulnerabilities}</Link> : <span className="muted">0</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

/** Ports of every linked device, like DeviceDetail's "Network exposure" card, with the device per row
 *  and an "Open" column (web preview / the URL under this name). */
export function SubdomainPortsCard({ s, scanAction }: { s: SubdomainDetail; scanAction?: ReactNode }) {
  const [showClosed, setShowClosed] = useState(false);
  const open = s.ports.filter((p) => p.is_open);
  const closed = s.ports.filter((p) => !p.is_open);
  const rows = [...open, ...(showClosed ? closed : [])];
  return (
    <Card title={`Network exposure - ${open.length} open port${open.length === 1 ? '' : 's'}`} flush
      actions={closed.length > 0 && <label className="check small"><input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} />show {closed.length} closed</label>}>
      {!s.devices.length ? <NotScanned action={scanAction} /> : !rows.length ? (
        <Empty>{s.devices.some((dv) => dv.last_port_scan_at) ? 'No open ports detected.' : 'Linked device not port-scanned yet (discovery only).'}</Empty>
      ) : (
        <div className="table-wrap">
          <table className="domain-table fit-table sd-ports-table" data-testid="subdomain-ports">
            <thead>
              <tr>
                <th>Port</th><th>Proto</th><th>State</th><th className="domain-col-fluid">Service</th><th className="domain-col-fluid">Product</th>
                <th className="domain-col-fluid">Version</th><th className="domain-col-fluid">Banner</th><th className="domain-col-fluid">IP / device</th><th>Open</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <tr key={`${p.device_uuid}-${p.protocol}-${p.port}`} className={p.is_open ? undefined : 'dim'}>
                  <td className="mono"><strong>{p.port}</strong></td>
                  <td className="small">{p.protocol.toUpperCase()}</td>
                  <td className="small" title={p.is_open ? undefined : `closed ${fmtTime(p.closed_at)}`}>{p.is_open ? 'open' : 'closed'}</td>
                  <td className="domain-col-fluid small"><span className="cell-ellipsis" title={p.service ?? undefined}>{p.service ?? '-'}</span></td>
                  <td className="domain-col-fluid small"><span className="cell-ellipsis" title={p.product ?? undefined}>{p.product ?? '-'}</span></td>
                  <td className="domain-col-fluid small"><span className="cell-ellipsis" title={p.version ?? undefined}>{p.version ?? '-'}</span></td>
                  <td className="domain-col-fluid small mono"><span className="cell-ellipsis" title={p.banner ?? undefined}>{p.banner ?? '-'}</span></td>
                  <td className="domain-col-fluid small">
                    <span className="cell-ellipsis" title={`${p.ip} · ${p.device_label}`}>
                      <Link to={`/devices/${p.device_uuid}`}>{p.ip}</Link>{s.devices.length > 1 && <span className="muted"> {p.device_label}</span>}
                    </span>
                  </td>
                  <td className="small" data-testid="port-open">
                    {p.has_preview && <Link to={`/devices/${p.device_uuid}/web`} title="Open the captured web preview">Preview</Link>}
                    {p.has_preview && p.url && ' · '}
                    {p.url && <a href={p.url} target="_blank" rel="noopener noreferrer" title={p.url}>URL ↗</a>}
                    {!p.has_preview && !p.url && <span className="muted">-</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

/** Captured pages under this name and on the linked devices: thumbnails, then every page in one line each. */
export function SubdomainWebCard({ pages, onOpen, captureAction }: {
  pages: WebPage[]; onOpen: (p: WebPage) => void; captureAction?: ReactNode;
}) {
  const shots = pages.filter(isUsefulShot).slice(0, 8);
  return (
    <Card id="web" title="Web" flush>
      {!pages.length ? (
        <div className="card-body muted small row wrap" style={{ gap: 8 }} data-testid="subdomain-web-empty">
          <span>No web capture yet.</span>{captureAction}
        </div>
      ) : (
        <>
          {shots.length > 0 && (
            <div className="shot-grid" data-testid="subdomain-web-grid">
              {shots.map((p) => <ShotTile key={p.id} p={p} onOpen={() => onOpen(p)} />)}
            </div>
          )}
          <div className="table-wrap">
            <table className="domain-table fit-table sd-web-table">
              <thead><tr><th className="sd-web-url">URL</th><th className="domain-col-fluid">Title</th><th>Status</th><th>Captured</th></tr></thead>
              <tbody>
                {pages.map((p) => (
                  <tr key={p.id}>
                    <td className="sd-web-url mono small">
                      <span className="cell-ellipsis" title={p.url}>{p.device_uuid ? <Link to={`/devices/${p.device_uuid}/web`}>{p.url}</Link> : p.url}</span>
                    </td>
                    <td className="domain-col-fluid small"><span className="cell-ellipsis" title={p.title ?? undefined}>{p.title ?? '-'}</span></td>
                    <td className="small">{p.http_status ?? '-'}</td>
                    <td className="small" title={fmtTime(p.captured_at)}>{relTime(p.captured_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Card>
  );
}

/** Severity summary + top findings of the linked devices (dismissed findings excluded). */
export function SubdomainVulnsCard({ s }: { s: SubdomainDetail }) {
  const v = s.vulns;
  return (
    <Card title={`Vulnerabilities - ${v.total}`} flush
      actions={s.devices.map((dv) => (
        <Link key={dv.uuid} className="btn sm" to={vulnsHref(dv.uuid)} title={`Vulnerabilities of ${dv.label}`}>
          {s.devices.length > 1 ? dv.ip : 'All findings'} →
        </Link>
      ))}>
      {!s.devices.length ? <NotScanned /> : !v.total ? <Empty>No vulnerabilities matched on the linked devices.</Empty> : (
        <>
          <div className="card-body row wrap" style={{ gap: 6 }} data-testid="subdomain-vuln-summary">
            {SEVERITY_ORDER.map((sev) => (
              <span key={sev} className={`badge ${v.by_severity[sev] ? SEVERITY_BADGE[sev] : 'outline'}`}>{sev} {v.by_severity[sev]}</span>
            ))}
            {v.by_severity.unknown > 0 && <span className="badge outline">unrated {v.by_severity.unknown}</span>}
          </div>
          <div className="table-wrap">
            <table className="domain-table fit-table">
              <thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Port</th><th className="domain-col-fluid">Product</th></tr></thead>
              <tbody>
                {v.top.map((f) => (
                  <tr key={`${f.device_uuid}-${f.port}-${f.cve_id}`}>
                    <td className="mono small"><Link to={`/vulnerabilities/${f.cve_id}`}>{f.cve_id}</Link>{f.kev && <span className="badge high" style={{ marginLeft: 6 }} title="CISA Known Exploited Vulnerability">KEV</span>}</td>
                    <td>{f.severity ? <span className={`badge ${SEVERITY_BADGE[f.severity]}`}>{f.severity}</span> : <span className="muted">-</span>}</td>
                    <td className="small">{f.cvss_base ?? '-'}</td>
                    <td className="mono small">{f.protocol}/{f.port}</td>
                    <td className="domain-col-fluid small"><span className="cell-ellipsis" title={[f.product, f.version].filter(Boolean).join(' ') || undefined}>{[f.product, f.version].filter(Boolean).join(' ') || '-'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Card>
  );
}
