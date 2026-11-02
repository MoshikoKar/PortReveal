/** Pure row-formatting helpers for the vulnerabilities list / top lists (unit-testable without a
 * component harness). Severity shown in the UI is the CVSS-derived bucket, never NVD's label. */

export function formatCvss(cvss: number | null | undefined): string {
  return cvss != null ? cvss.toFixed(1) : '-';
}

export type SeverityBand = 'critical' | 'high' | 'medium' | 'low' | 'unscored';

/** Same 9 / 7 / 4 CVSS thresholds as the backend's severity_bucket(); no score → unscored. */
export function severityBand(cvss: number | null | undefined): SeverityBand {
  if (cvss == null) return 'unscored';
  if (cvss >= 9) return 'critical';
  if (cvss >= 7) return 'high';
  if (cvss >= 4) return 'medium';
  return 'low';
}

export function formatEpss(epss: number | null | undefined): string {
  if (epss == null) return '';
  return `EPSS ${(epss * 100).toFixed(0)}%`;
}

export function formatEpssPct(epss: number | null | undefined): string {
  if (epss == null) return '-';
  return `${(epss * 100).toFixed(0)}%`;
}

export function findingRowKey(row: {
  cve_id: string;
  device_uuid: string;
  protocol: string;
  port: number;
}): string {
  return `${row.cve_id}|${row.device_uuid}|${row.protocol}|${row.port}`;
}

export function dismissBusyKey(deviceUuid: string, cveId: string): string {
  return `${deviceUuid}:${cveId}`;
}
