export type Role = 'admin' | 'viewer';

export interface User {
  id: number;
  username: string;
  display_name: string | null;
  role: Role;
  source: 'local' | 'ldap';
  is_active: boolean;
  /** Per-user UI prefs (dashboard layout). null = built-in defaults. */
  preferences: Record<string, unknown> | null;
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
  domain_scans?: { worker_running: boolean; running: number; queued: number; tools: Record<DomainToolName, DomainToolStatus> };
}

export type EventType =
  | 'device_discovered' | 'device_disappeared' | 'device_reappeared' | 'ip_changed'
  | 'port_opened' | 'port_closed' | 'service_detected' | 'service_changed' | 'version_changed'
  | 'tag_added' | 'tag_removed' | 'watch_match' | 'policy_violation' | 'banner_changed'
  | 'os_changed' | 'monitor_change' | 'geo_mismatch' | 'cve_watch_match'
  | 'subdomain_new' | 'subdomain_gone' | 'subdomain_ip_changed' | 'subdomain_exposure_changed'
  | 'internal_name_exposed' | 'wildcard_detected' | 'wildcard_removed' | 'zone_transfer_open';

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
  /** Domain-scan events: no device; the domain and the host name instead. */
  domain_id?: number | null;
  hostname?: string | null;
}

export type DeviceStatus = 'active' | 'unknown' | 'not_detected';
export type GeoStatus = 'ok' | 'mismatch' | 'mismatch_cdn' | 'not_checked' | 'unavailable';

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
  /** Current IP is an address of the machine PortReveal scans from (list + detail only). */
  scanner_host?: boolean;
  /** Not active, and an active device seen more recently now holds this IP (list + detail only). */
  superseded_by?: { uuid: string; label: string } | null;
  open_port_count: number;
  open_ports: { port: number; protocol: string; service: string | null; product: string | null; version: string | null }[];
  geo_mismatch?: boolean;
  geo_status?: GeoStatus | null;
  geo_country?: string | null;
  geo_cdn?: boolean;
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
  expected_countries: string[];
  geo_status: GeoStatus | null;
  geo_country: string | null;
  geo_ip: string | null;
  geo_asn: number | null;
  geo_as_org: string | null;
  geo_cdn: boolean;
  geo_source: 'published_name' | 'device_ip' | null;
  geo_name: string | null;
  geo_checked_at: string | null;
  geo_mismatch: boolean;
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

/**
 * GET /web-previews: one Web gallery card. `ok` = usable service with a screenshot, `no_preview` = usable
 * service without one (failed / timed out / skipped), `error` = host with no usable service (its best page).
 */
export interface WebPreviewCard {
  key: string;
  device_uuid: string;
  hostname: string | null;
  ip: string;
  status: 'ok' | 'no_preview' | 'error';
  scheme: string;
  port: number;
  ports: number[];
  page_count: number;
  has_login: boolean;
  captured_at: string;
  page: WebPage;
}

export interface WebPreviewPage {
  items: WebPreviewCard[];
  total: number;
  page: number;
  page_size: number;
  /** Cards per status under the other filters. */
  counts: Record<WebPreviewCard['status'], number>;
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
  /** Stored "paths" wordlist; null = built-in list. */
  discovery_wordlist_id: number | null;
  max_response_bytes: number;
  max_job_minutes: number;
  http_timeout_seconds: number;
  browser_timeout_seconds: number;
  page_settle_seconds: number;
  http_concurrency: number;
  screenshot_concurrency: number;
  force_mock: boolean;
}

export type WordlistKind = 'paths' | 'subdomains';

/** Admin-managed wordlist (Settings > Web capture > Wordlists). Entries are stored sanitized server-side. */
export interface Wordlist {
  id: number;
  name: string;
  kind: WordlistKind;
  source: 'upload' | 'url';
  source_url: string | null;
  original_filename: string | null;
  entries: number;
  skipped: number;
  size_bytes: number;
  sha256: string;
  created_at: string;
  updated_at: string;
  created_by: string | null;
  in_use: boolean;
  /** Domains whose wordlist brute force uses this list: deleting it is refused while any remain. */
  domains: { id: number; name: string }[];
}

export interface WordlistLimits {
  max_upload_bytes: number;
  max_decompressed_bytes: number;
  max_entries: number;
  allow_http: boolean;
  extensions: string[];
}

export interface WordlistLibrary {
  items: Wordlist[];
  builtin: { name: string; kind: 'paths'; source: 'builtin'; entries: number; in_use: boolean };
  limits: WordlistLimits;
  /** True: subdomain lists feed Domain scans (dnsx wordlist brute force). */
  subdomain_discovery: boolean;
}

export interface WordlistImportSummary {
  accepted: number;
  skipped: number;
  reasons: Record<string, number>;
  samples: string[];
}

export interface WordlistImportResult {
  wordlist: Wordlist;
  summary: WordlistImportSummary;
  /** Re-import only. */
  previous_entries?: number;
  changed?: boolean;
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
  expected_countries: string[];
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
  /** Event types always included in the daily digest (locked in the Email tab). */
  always_notify_types: EventType[];
  /** Master switch for outbound webhooks (all sources). In-app events are always on. */
  webhooks_enabled: boolean;
  /** Immediate email when a watched CVE is found (does not wait for the daily digest). */
  watchlist_email_enabled: boolean;
  /** Deliver cve_watch_match through configured webhooks. */
  watchlist_webhooks_enabled: boolean;
}

export interface WebhookEndpoint {
  id: number;
  name: string;
  url: string;
  enabled: boolean;
  has_secret: boolean;
  event_types: EventType[];
  include_record_events: boolean;
  /** Attached to a recipient group — only receives that group's routed events. */
  group_managed: boolean;
  created_at: string;
  last_success_at: string | null;
  last_error: string | null;
  last_error_at: string | null;
  /** Present only immediately after create or rotate; never stored client-side after dismiss. */
  secret?: string;
}

export type RecipientDeliveryMode = 'immediate' | 'hourly' | 'daily';
export type RecipientDestKind = 'email' | 'webhook' | 'slack' | 'teams';
export type RecipientMinSeverity = 'info' | 'low' | 'medium' | 'high';

export interface RecipientDestination {
  id: number;
  kind: RecipientDestKind;
  enabled: boolean;
  target: string | null;
  webhook_id: number | null;
  has_url: boolean;
  url_hint: string | null;
}

export interface RecipientGroup {
  id: number;
  name: string;
  enabled: boolean;
  is_default: boolean;
  event_types: EventType[];
  min_severity: RecipientMinSeverity;
  network_ids: number[];
  /** Domain-scan events: empty = all domains. Device events use network_ids. */
  domain_ids: number[];
  delivery_mode: RecipientDeliveryMode;
  digest_time: string | null;
  max_per_hour: number;
  dedupe_seconds: number;
  quiet_start: string | null;
  quiet_end: string | null;
  quiet_bypass_critical: boolean;
  summary: string;
  destination_kinds: string[];
  destinations: RecipientDestination[];
  created_at: string;
  updated_at: string;
  last_success_at: string | null;
  last_error: string | null;
  last_error_at: string | null;
  last_error_friendly: string | null;
}

export interface RecipientGroupTestResult {
  ok: boolean;
  error: string | null;
}

export interface WebhookTestResult {
  ok: boolean;
  status_code: number | null;
  error: string | null;
  latency_ms: number;
  host: string;
}

export type CveWatchlistStatus = 'pending' | 'not_found' | 'found' | 'only_dismissed';

export interface CveWatchlistEntry {
  id: number;
  cve_id: string;
  note: string | null;
  created_by: string | null;
  created_at: string;
  enabled: boolean;
  status: CveWatchlistStatus;
  affected_devices: number;
  finding_count: number;
  confirmed_count: number;
  potential_count: number;
  dismissed_count: number;
  last_alert_at: string | null;
  cve_known: boolean;
  /** Present on pending rows: estimated next CVE feed sync. */
  next_sync_at: string | null;
}

export interface CveWatchlistAddResult {
  added: string[];
  already_watched: string[];
  entries: CveWatchlistEntry[];
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

export interface CdnAsnEntry {
  asn: number;
  label: string;
}

export interface GeoFeedStatus {
  source: string;
  last_synced_at: string | null;
  file_month: string | null;
  last_error: string | null;
}

export interface GeoSettings {
  cache_ttl_hours: number;
  offline_mode: boolean;
  maxmind_country_path: string;
  cdn_asns: CdnAsnEntry[];
  attribution: string;
  license: string;
  country_db_loaded: boolean;
  asn_db_loaded: boolean;
  maxmind_loaded: boolean;
  files_ready: boolean;
  sync_running: boolean;
  feeds: GeoFeedStatus[];
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
  network_id: number | null;
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
  /** Total findings matching the active filters (parity with GET /api/vulns total). */
  findings_total: number;
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
  /** Present when snapshot charts cannot honor every active filter (history is network-scoped only). */
  snapshot_trend_note: string | null;
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
  network_id: number | null;
  os_name: string | null;
  device_type: string | null;
  first_seen_at: string | null;
  /** Present when listing with `q`: why this row is hidden from the default (non-search) view. */
  hidden_reasons?: string[];
}

/** GET /api/vulns list envelope; `hidden_total` / `total_matches` appear when `q` is set. */
export interface VulnFindingsPage extends Paged<VulnFindingListItem> {
  hidden_total?: number;
  total_matches?: number;
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

// --- Domain scans -------------------------------------------------------------------------------
export type DomainToolName = 'subfinder' | 'dnsx';
export interface DomainToolStatus {
  name: DomainToolName;
  found: boolean;
  path: string | null;
  version: string | null;
  configured: string;
  message: string;
}

export type Exposure = 'external' | 'internal' | 'both' | 'unresolved';
export type SubdomainSource = 'passive' | 'wordlist' | 'axfr' | 'manual';
export type SubdomainFlag = 'internal_authorized' | 'internal_name_exposed' | 'private_ip_public';
export type DomainWordlistMode = 'none' | 'library' | 'custom';

export interface DomainSchedule { enabled: boolean; time: string; days: number[] }

export type DomainPhaseKey = 'passive' | 'wordlist_internal' | 'wordlist_public' | 'axfr' | 'public_axfr'
  | 'resolve' | 'diff' | 'port_scan';
export type DomainPhaseStatus = 'pending' | 'running' | 'done' | 'skipped' | 'failed';
export interface DomainScanPhase {
  key: DomainPhaseKey;
  label: string;
  status: DomainPhaseStatus;
  started_at: string | null;
  finished_at: string | null;
  processed: number;
  total: number | null;
  found: number;
  queries: number;
  unit: string | null;
  reason: string | null;
  duration_s: number | null;
  /** DNS queries per second while running. */
  rate: number | null;
  eta_s: number | null;
}

export interface DomainScanJob {
  id: number;
  domain_id: number;
  domain_name: string | null;
  status: ScanStatus;
  trigger: 'manual' | 'scheduled';
  requested_by: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  stage: string | null;
  progress: number;
  error: string | null;
  notes: string | null;
  /** Counts, plus partial_reasons (string[]) and checks (per source / resolver outcome). */
  stats: (Record<string, number | boolean> & { partial_reasons?: string[]; checks?: Record<string, string | null> }) | null;
  wildcard: { internal: string[]; public: string[] } | null;
  axfr: { authorized: Record<string, { status: string; names?: number; detail?: string }>;
    public: Record<string, { status: string; names?: number }> } | null;
  phases: DomainScanPhase[];
  port_scan_id: number | null;
}

export interface Domain {
  id: number;
  name: string;
  enabled: boolean;
  notes: string | null;
  wordlist_mode: DomainWordlistMode;
  wordlist_id: number | null;
  wordlist_name: string | null;
  /** Entries in the selected list, and Settings > Domain discovery > Max wordlist entries (scans use the first N). */
  wordlist_entries: number;
  wordlist_limit: number;
  custom_words: string[];
  passive_enabled: boolean;
  axfr_enabled: boolean;
  axfr_servers: string[];
  internal_resolvers: string[];
  public_resolvers: string[];
  schedule: DomainSchedule;
  created_at: string;
  updated_at: string;
  created_by: string | null;
  counts: { active: number; wildcard: number } & Record<Exposure, number>;
  wildcard: { internal: string[]; public: string[] };
  zone_transfer_open: string[];
  last_scan: DomainScanJob | null;
}

export interface DnsView { a: string[]; aaaa: string[]; cname: string[]; status?: string }

export interface HostingEntry {
  ip: string;
  kind: 'network' | 'external' | 'private';
  network: string | null;
  device_uuid: string | null;
  device_label: string | null;
  asn: number | null;
  as_org: string | null;
}

export interface Subdomain {
  id: number;
  domain_id: number;
  name: string;
  exposure: Exposure;
  records: { internal?: DnsView; public?: DnsView };
  records_summary: string;
  ips: string[];
  hosting: HostingEntry[];
  sources: SubdomainSource[];
  wildcard: boolean;
  flags: SubdomainFlag[];
  device_uuid: string | null;
  status: 'active' | 'gone';
  /** The latest scan could not check it (resolver error / timeout / not reached): state kept as is. */
  unverified: boolean;
  /** Written by a running scan, classification not final yet. */
  in_progress: boolean;
  missed_scans: number;
  /** When a scan last verified the name; null = never verified. */
  last_verified_at: string | null;
  first_seen: string;
  last_seen: string;
}

export interface LookupResult {
  hostname: string;
  domain_id: number;
  domain: string;
  internal: DnsView;
  public: DnsView;
  ips: string[];
  exposure: Exposure;
  wildcard: boolean;
  flags: SubdomainFlag[];
  hosting: HostingEntry[];
  in_inventory: boolean;
}

export interface MaskedKey { set: boolean; masked: string }
export interface DomainDiscoverySettings {
  concurrency: number;
  dns_rate_per_second: number;
  subfinder_timeout_minutes: number;
  dnsx_timeout_minutes: number;
  dns_timeout_seconds: number;
  axfr_timeout_seconds: number;
  max_wordlist_entries: number;
  max_job_minutes: number;
  auto_port_scan: boolean;
  port_scan_type: 'discovery' | 'standard' | 'full';
  other_provider: string;
  keys: { virustotal: MaskedKey; securitytrails: MaskedKey; shodan: MaskedKey; other: MaskedKey & { provider: string } };
}
