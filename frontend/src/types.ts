export type Role = 'admin' | 'viewer';

export interface User {
  id: number;
  username: string;
  display_name: string | null;
  role: Role;
  source: 'local' | 'ldap';
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface SetupStatus {
  needs_admin: boolean;
  setup_completed: boolean;
  dev_mode: boolean;
  scanner_mode: 'nmap' | 'mock' | 'unavailable';
  version: string;
}

export type ScanStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancelled';
export type ScanType = 'discovery' | 'standard' | 'full';

export interface Scan {
  id: number;
  scan_type: ScanType;
  trigger: 'manual' | 'scheduled' | 'presence';
  status: ScanStatus;
  scanner_mode: 'nmap' | 'mock' | null;
  network_id: number | null;
  network_name: string | null;
  targets: string | null;
  target_count: number;
  criteria: string | null;
  requested_by: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  stage: string | null;
  progress: number;
  hosts_discovered: number;
  hosts_scanned: number;
  hosts_failed: number;
  events_count: number;
  is_baseline: boolean;
  error: string | null;
  notes: string | null;
  /** Filled by the Scans page from GET /scans/{id}/events; not part of the scan resource. */
  events?: ChangeEvent[];
}

export interface ScanSummary {
  current: Scan | null;
  queued: number;
  last_completed: Scan | null;
  last_successful: Scan | null;
  last_failed: Scan | null;
  next_scheduled: string | null;
  schedule: ScheduleSettings;
}

export interface SystemStatus {
  app: {
    status: string; version: string; env: string; dev_mode: boolean; uptime_seconds: number;
    worker_running: boolean; scheduler_running: boolean; setup_completed: boolean; mock_data_hidden: boolean;
  };
  database: { type: 'sqlite' | 'postgresql'; ok: boolean; message: string; location: string | null };
  scanner: {
    configured_mode: string; mode: 'nmap' | 'mock' | 'unavailable'; mock_active: boolean; nmap_detected: boolean;
    nmap_version: string | null; nmap_path: string; privileged: boolean; message: string;
  };
  scans: ScanSummary;
}

export type EventType =
  | 'device_discovered' | 'device_disappeared' | 'device_reappeared' | 'ip_changed'
  | 'port_opened' | 'port_closed' | 'service_detected' | 'service_changed' | 'version_changed'
  | 'tag_added' | 'tag_removed' | 'watch_match' | 'policy_violation' | 'banner_changed'
  | 'os_changed' | 'monitor_change';

export interface ChangeEvent {
  id: number;
  created_at: string;
  scan_id: number | null;
  device_uuid: string | null;
  device_label: string | null;
  event_type: EventType;
  severity: 'high' | 'medium' | 'low' | 'info';
  ip: string | null;
  protocol: string | null;
  port: number | null;
  old_value: string | null;
  new_value: string | null;
  message: string;
  notify: boolean;
  notified_at: string | null;
}

export type DeviceStatus = 'active' | 'unknown' | 'not_detected';

export interface DeviceSummary {
  uuid: string;
  current_ip: string;
  mac: string | null;
  /** Where the MAC came from: the scanner's own ARP, the site router's ARP table (SNMP), or NetBIOS. */
  mac_source: 'arp' | 'snmp' | 'netbios' | null;
  vendor: string | null;
  hostname: string | null;
  os_name: string | null;
  os_accuracy: number | null;
  os_detected_at: string | null;
  os_source: string | null;
  ip_assignment: 'static' | 'dynamic' | 'unknown' | null;
  last_rtt_ms: number | null;
  continuous_since: string | null;
  score?: number | null;
  risk_score: number;
  combined_score: number;
  risk_scored_at: string | null;
  discovery_name: string | null;
  discovery_source: 'mdns' | 'ssdp' | 'netbios' | null;
  status: DeviceStatus;
  network_id: number | null;
  network_name: string | null;
  first_seen: string;
  last_seen: string;
  port_scan_failed: boolean;
  open_port_count: number;
  open_ports: { port: number; protocol: string; service: string | null; product: string | null; version: string | null }[];
}

export interface DevicePort {
  protocol: string;
  port: number;
  is_open: boolean;
  service: string | null;
  product: string | null;
  version: string | null;
  extra_info: string | null;
  method: string | null;
  confidence: number | null;
  first_seen: string;
  last_seen: string;
  opened_at: string;
  closed_at: string | null;
  cpe?: string[];
  tunnel?: string | null;
  http?: PortHttp | null;
}

export type ScoreLevel = 'high' | 'medium' | 'low';
export type Criticality = 'low' | 'medium' | 'high' | 'critical';

export interface PortHttp {
  scheme: string | null;
  status: number | null;
  title: string | null;
  server: string | null;
  content_type: string | null;
  location: string | null;
  login: boolean;
  default_page: boolean;
  last_seen: string;
}

export interface DeviceTag {
  tag: string;
  source: 'rule' | 'manual' | 'suppressed';
  reason: string | null;
  created_at: string;
}

export interface ExposureFactor {
  factor: string;
  points: number;
  detail: string;
}

export interface DeviceProfile {
  owner: string | null;
  location: string | null;
  criticality: Criticality | null;
  notes: string | null;
  exposure_factors: ExposureFactor[];
  risk_factors: ExposureFactor[];
  type_evidence: ExposureFactor[];
  updated_at: string | null;
}

export interface DeviceDetail extends DeviceSummary {
  dns_name: string | null;
  missed_scans: number;
  last_port_scan_at: string | null;
  full_scanned_at: string | null;
  availability_pct: number | null;
  availability_window_days: number;
  rtt_samples: { rtt_ms: number; sampled_at: string }[];
  risk_level: ScoreLevel;
  combined_level: ScoreLevel;
  type_confidence: number | null;
  vuln_job: VulnJobSummary | null;
  ports: DevicePort[];
  ips: { ip: string; first_seen: string; last_seen: string }[];
  previous_ips: string[];
  type: string | null;
  score: number;
  score_level: ScoreLevel;
  classified_at: string | null;
  zone: string | null;
  vpn_s2s: boolean;
  tags: DeviceTag[];
  profile: DeviceProfile;
}

export type TimelineItem =
  | ({ kind: 'event'; at: string } & ChangeEvent)
  | { kind: 'scan'; at: string; scan_id: number; scan_type: ScanType; scan_status: ScanStatus; ip: string; status: string; open_ports: number | null }
  | { kind: 'web_capture'; at: string; capture_id: number; status: WebCaptureStatus; pages: number; screenshots: number };

// --- inventory search ---------------------------------------------------------------------------
export interface SearchService {
  port: number;
  protocol: string;
  service: string | null;
  product: string | null;
  version: string | null;
  extra_info: string | null;
  cpe: string[];
  tunnel: string | null;
  http: PortHttp | null;
}

export interface SearchHost {
  uuid: string;
  ip: string;
  hostname: string | null;
  mac: string | null;
  vendor: string | null;
  os: string | null;
  status: DeviceStatus;
  network: string | null;
  type: string | null;
  score: number;
  tags: string[];
  first_seen: string;
  last_seen: string;
  open_ports: { port: number; protocol: string; service: string | null }[];
  services: SearchService[];
  matched_services: number;
  screenshot: { page_id: number; port: number; title: string | null; captured_at: string } | null;
}

export interface SearchServiceRow extends SearchService {
  host: { uuid: string; ip: string; hostname: string | null; type: string | null; score: number; network: string | null; status: DeviceStatus };
}

export interface FacetValue {
  value: string | number;
  count: number;
  term: string;
}

export type Facets = Record<string, FacetValue[]>;

export interface FieldDoc {
  name: string;
  level: 'host' | 'port';
  kind: string;
  group: string;
  help: string;
  example: string;
  aliases: string[];
  historical: boolean;
}

export interface SavedSearch {
  id: number;
  name: string;
  query: string;
  description: string | null;
  kind: 'watch' | 'policy' | 'monitor';
  alert: boolean;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  last_run_at: string | null;
  last_count: number;
  last_error: string | null;
  initialized: boolean;
  can_edit: boolean;
}

export interface ApiToken {
  id: number;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked: boolean;
  token?: string;
}

export interface ReportHost {
  uuid: string;
  ip: string;
  hostname: string | null;
  type: string | null;
  score: number;
  network: string | null;
}

export type WebCaptureStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancelled';
export type WebPageKind = 'home' | 'login' | 'register' | 'other' | 'stream';

export interface WebPage {
  id: number;
  uuid: string;
  capture_id: number;
  device_uuid: string | null;
  ip: string;
  port: number;
  scheme: string;
  host_used: string;
  kind: WebPageKind;
  url: string;
  final_url: string | null;
  redirect_target: string | null;
  external_redirect: boolean;
  http_status: number | null;
  title: string | null;
  content_type: string | null;
  server_header: string | null;
  tls_verified: boolean | null;
  screenshot_status: string;
  has_screenshot: boolean;
  /** Set when the page is an error response (HTTP 4xx/5xx, no response, or an error title). */
  error_reason: string | null;
  capture_error: string | null;
  auth_scheme?: string | null;
  captured_at: string;
  /** True for RTSP/RTSPS pages that can be watched live via the MJPEG proxy. */
  can_live?: boolean;
}

/** One capture run that includes pages of a given device. */
export interface WebCaptureRun {
  id: number;
  status: WebCaptureStatus;
  requested_by: string | null;
  finished_at: string | null;
  captured_at: string | null;
  page_count: number;
  screenshot_count: number;
}

export interface DeviceWebInterfaces {
  device_uuid: string;
  capture_id: number | null;
  captures: WebCaptureRun[];
  pages: WebPage[];
}

/** A device with captured pages, summarised from its latest capture. */
export interface WebHost {
  device_uuid: string;
  hostname: string | null;
  ip: string;
  device_status: DeviceStatus;
  capture_id: number;
  captured_at: string;
  ports: number[];
  page_count: number;
  reachable_count: number;
  screenshot_count: number;
  has_login: boolean;
  auth_required: boolean;
  tls_unverified: boolean;
  external_redirect: boolean;
  hero: WebPage;
  /** Usable web services of the host (errors / blank pages left out; http→https duplicates merged). */
  services: WebService[];
}

/** GET /web-hosts: one page of hosts (ordered with screenshots first). */
export interface WebHostPage {
  hosts: WebHost[];
  total: number;
  page: number;
  page_size: number;
}

export interface WebService {
  scheme: string;
  port: number;
  /** Every port that lands on this page (e.g. 80 redirecting to 443). */
  ports: number[];
  page_count: number;
  has_login: boolean;
  page: WebPage;
}

export interface WebCapture {
  id: number;
  uuid: string;
  status: WebCaptureStatus;
  targets: string;
  /** all | remote (RDP/VNC) | web (HTTP/RTSP). Older jobs omit this (treat as all). */
  scope?: 'all' | 'remote' | 'web';
  target_count: number;
  requested_by: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  stage: string | null;
  progress: number;
  endpoints_found: number;
  pages_captured: number;
  screenshots_captured: number;
  error: string | null;
  notes: string | null;
  mock_mode: boolean;
  pages?: WebPage[];
}

export interface WebCaptureSettings {
  enabled: boolean;
  auto_after_scan: boolean;
  auto_only_new_or_changed: boolean;
  max_addresses: number;
  max_endpoints: number;
  max_pages_per_endpoint: number;
  max_screenshots_per_job: number;
  max_candidate_probes: number;
  max_discovery_paths: number;
  discovery_wordlist: string;
  max_response_bytes: number;
  max_job_minutes: number;
  http_timeout_seconds: number;
  browser_timeout_seconds: number;
  page_settle_seconds: number;
  http_concurrency: number;
  screenshot_concurrency: number;
  force_mock: boolean;
}

/** Gateway whose ARP table (read over SNMP) supplies MACs across a routed / VPN path. Secrets are write-only. */
export interface ArpSnmp {
  host: string;
  port: number;
  version: '2c' | '3';
  user: string | null;
  auth_protocol: string | null;
  priv_protocol: string | null;
  community_set: boolean;
  auth_key_set: boolean;
  priv_key_set: boolean;
}

export interface Network {
  id: number;
  name: string;
  cidr: string;
  description: string | null;
  enabled: boolean;
  zone: string | null;
  vpn_s2s: boolean;
  arp_snmp: ArpSnmp | null;
  baseline_scan_id: number | null;
  baseline_at: string | null;
  archived_at: string | null;
  created_at: string;
  device_count: number | null;
  active_count: number | null;
  scan_active?: boolean;
}

export interface Exclusion {
  id: number;
  value: string;
  description: string | null;
  enabled: boolean;
  address_count: number;
  created_at: string;
  updated_at: string;
}

export interface WindowCounts {
  changes: number;
  new_hosts: number;
  new_ports: number;
  closed_ports: number;
  service_changes: number;
  by_type: Partial<Record<EventType, number>>;
}

export interface Dashboard {
  devices: { total: number; active: number; unknown: number; not_detected: number; exposed: number };
  open_ports_total: number;
  last_24h: WindowCounts;
  last_7d: WindowCounts;
  recent_events: ChangeEvent[];
  top_services: { service: string; count: number }[];
  top_ports: { protocol: string; port: number; count: number; service: string | null }[];
  exposed_ports_total: number;
  trend: { date: string; hosts_active: number; open_ports: number }[];
  networks: Network[];
  scans: ScanSummary;
  exposure: { high: number; medium: number; low: number; top: ReportHost[] };
  device_types: { type: string; count: number }[];
  watch_alerts: { last_7d: number; recent: ChangeEvent[] };
  new_hosts_7d: number;
}

export interface ExposedPort {
  protocol: string;
  port: number;
  count: number;
  service: string;
  services: { service: string; count: number }[];
}

export interface ScheduleSettings {
  enabled: boolean;
  time: string;
  days: number[];
  discovery_before_standard: boolean;
  next_run?: string | null;
}

export interface PresenceSettings {
  enabled: boolean;
  times: string[];
  days: number[];
  absence_days: number;
  next_run?: string | null;
}

export interface ScanSettings {
  top_ports: number;
  timing: 'polite' | 'normal' | 'fast';
  parallelism: number;
  discovery_chunk_size: number;
  port_batch_size: number;
  host_timeout_minutes: number;
  full_host_timeout_minutes: number;
  os_detection: boolean;
  os_refresh_days: number;
  os_min_accuracy_display: number;
  os_detection_enabled_notice: boolean;
  disappear_after_missed: number;
  mass_change_guard_percent: number;
  keep_raw_xml: boolean;
  raw_retention_days: number;
}

export interface NotificationSettings {
  enabled: boolean;
  smtp_host: string;
  smtp_port: number;
  security: 'none' | 'starttls' | 'ssl';
  username: string;
  password_set: boolean;
  sender: string;
  recipients: string[];
  event_types: EventType[];
  digest_time: string;
  available_event_types: EventType[];
}

export interface LdapSettings {
  enabled: boolean;
  server_uri: string;
  start_tls: boolean;
  verify_tls: boolean;
  bind_dn: string;
  bind_password_set: boolean;
  user_base_dn: string;
  user_filter: string;
  admin_group_dn: string;
  viewer_group_dn: string;
  timeout_seconds: number;
}

export interface VulnSettings {
  enabled: boolean;
  sources: ('nvd' | 'kev' | 'epss')[];
  sync_interval_hours: number;
  sync_time: string;
  offline_mode: boolean;
  nvd_api_key_set: boolean;
  nvd_api_key?: string | null;
  include_potential: boolean;
  min_cvss_display: number;
  epss_high_threshold: number;
  scripts_enabled: boolean;
}

export interface VulnFeedStatus {
  source: 'nvd' | 'kev' | 'epss';
  last_synced_at: string | null;
  record_count: number;
  last_error: string | null;
  mirror_complete: boolean | null;
  mirror_next_year: number | null;
}

export interface VulnStatus {
  sync_running: boolean;
  cve_count: number;
  mirror_start_year: number;
  feeds: VulnFeedStatus[];
}

export interface DiscoverySettings {
  enabled: boolean;
  mdns: boolean;
  ssdp: boolean;
  netbios: boolean;
  timeout_seconds: number;
}

export type VulnMatchState = 'confirmed' | 'potential' | 'dismissed';

export interface DeviceVuln {
  cve_id: string;
  port: number;
  protocol: string;
  service: string | null;
  product: string | null;
  version: string | null;
  matched_cpe: string | null;
  state: VulnMatchState;
  source: 'cache' | 'nmap_script';
  cvss_base: number | null;
  cvss_vector: string | null;
  severity: string | null;
  kev: boolean;
  epss: number | null;
  epss_percentile: number | null;
  summary: string | null;
  matched_at: string;
}

export type AgeBucket = 'under_30d' | '30_90d' | '90_365d' | 'over_365d' | 'unknown';

export interface FacetBucket {
  key: string | number;
  count: number;
  /** Display label, when it differs from `key` (e.g. the network facet is keyed by id). */
  label?: string;
}

export interface VulnWeeklyPoint {
  week_start: string;
  new: number;
  resolved: number;
  dismissed: number;
}

export interface VulnSnapshotPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  avg_risk_score: number | null;
  avg_combined_score: number | null;
}

export interface VulnTopDevice {
  uuid: string;
  ip: string;
  hostname: string | null;
  device_type: string | null;
  network_name: string | null;
  exposure_score: number;
  risk_score: number;
  combined_score: number;
}

export interface VulnTopCve {
  cve_id: string;
  cvss_base: number | null;
  kev: boolean;
  epss: number | null;
  device_count: number;
}

export interface VulnNewFinding {
  cve_id: string;
  device_uuid: string;
  device_ip: string;
  cvss_base: number | null;
  kev: boolean;
  first_seen_at: string | null;
}

export interface VulnSummary {
  generated_at: string;
  epss_threshold: number;
  severity_counts: { critical: number; high: number; medium: number; low: number; unknown: number };
  kev_count: number;
  epss_high_count: number;
  confirmed_count: number;
  potential_count: number;
  risk_device_levels: { high: number; medium: number; low: number };
  feed: {
    oldest_synced_at: string | null;
    newest_synced_at: string | null;
    stale: boolean;
    stale_threshold_hours: number;
  };
  facets: {
    os: FacetBucket[];
    service: FacetBucket[];
    port: FacetBucket[];
    network: FacetBucket[];
    device_type: FacetBucket[];
    vendor_product: FacetBucket[];
    cve_age: Record<AgeBucket, number>;
    exposure_duration: Record<AgeBucket, number>;
  };
  severity_by_network: {
    network_id: number | null; network: string; critical: number; high: number; medium: number; low: number;
  }[];
  weekly: VulnWeeklyPoint[];
  snapshot_trend: VulnSnapshotPoint[];
  top_devices: VulnTopDevice[];
  top_cves: VulnTopCve[];
  new_since_last_scan: VulnNewFinding[];
  new_since_last_db_update: VulnNewFinding[];
}

/** One (device, port, cve) finding row from the CVE-centric list (GET /api/vulns); an
 * intersection over DeviceVuln, which already carries the per-match fields. */
export interface VulnFindingListItem extends DeviceVuln {
  device_uuid: string;
  device_ip: string;
  device_hostname: string | null;
  network: string | null;
  os_name: string | null;
  device_type: string | null;
  first_seen_at: string | null;
}

export interface CveAffectedDevice {
  device_uuid: string;
  device_ip: string;
  device_hostname: string | null;
  network: string | null;
  port: number;
  protocol: string;
  service: string | null;
  product: string | null;
  version: string | null;
  state: VulnMatchState;
  matched_at: string;
  first_seen_at: string | null;
}

export interface CveDetail {
  cve_id: string;
  cvss_base: number | null;
  cvss_vector: string | null;
  severity: string | null;
  published_at: string | null;
  last_modified: string | null;
  kev: boolean;
  kev_added_at: string | null;
  epss: number | null;
  epss_percentile: number | null;
  summary: string | null;
  first_seen_at: string | null;
  affected_devices: CveAffectedDevice[];
}

export type VulnJobStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancelled';

export interface VulnJobSummary {
  id: number;
  status: VulnJobStatus;
  stage: string | null;
  finished_at: string | null;
}

export interface VulnJob {
  id: number;
  uuid: string;
  status: VulnJobStatus;
  trigger: 'after_scan' | 'manual';
  scan_id: number | null;
  network_id: number | null;
  device_count: number;
  requested_by: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  stage: string | null;
  progress: number;
  error: string | null;
  stats: Record<string, number> | null;
  notes: string | null;
}

export interface AuditEntry {
  id: number;
  created_at: string;
  username: string | null;
  action: string;
  target: string | null;
  details: string | null;
  ip: string | null;
}

export interface SnapshotInfo {
  id: number;
  network_id: number;
  network_name: string | null;
  snapshot_date: string;
  scan_id: number | null;
  created_at: string;
  hosts_total: number;
  hosts_active: number;
  open_ports: number;
  size_bytes: number;
}
