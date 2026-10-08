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
  trigger: 'manual' | 'scheduled';
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
  | 'port_opened' | 'port_closed' | 'service_detected' | 'service_changed' | 'version_changed';

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
  vendor: string | null;
  hostname: string | null;
  os_name: string | null;
  status: DeviceStatus;
  network_id: number | null;
  network_name: string | null;
  first_seen: string;
  last_seen: string;
  port_scan_failed: boolean;
  open_port_count: number;
  open_ports: { port: number; protocol: string; service: string | null }[];
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
}

export interface DeviceDetail extends DeviceSummary {
  dns_name: string | null;
  missed_scans: number;
  last_port_scan_at: string | null;
  full_scanned_at: string | null;
  ports: DevicePort[];
  ips: { ip: string; first_seen: string; last_seen: string }[];
  previous_ips: string[];
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

export interface Network {
  id: number;
  name: string;
  cidr: string;
  description: string | null;
  enabled: boolean;
  baseline_scan_id: number | null;
  baseline_at: string | null;
  created_at: string;
  device_count: number | null;
  active_count: number | null;
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
  trend: { date: string; hosts_active: number; open_ports: number }[];
  networks: Network[];
  scans: ScanSummary;
}

export interface ScheduleSettings {
  enabled: boolean;
  time: string;
  days: number[];
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
  max_individual: number;
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
