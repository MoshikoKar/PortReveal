export type Breakpoint = 'lg' | 'md' | 'sm';

export type WidgetId =
  | 'kpis'
  | 'recent_changes'
  | 'scan_status'
  | 'changes_by_type'
  | 'exposure_scores'
  | 'device_types'
  | 'watch_alerts'
  | 'exposure_trend'
  | 'networks'
  | 'top_ports'
  | 'top_services';

export type KpiId =
  | 'known_hosts'
  | 'active'
  | 'new_hosts_24h'
  | 'new_ports_24h'
  | 'service_changes_24h'
  | 'open_ports'
  | 'high_exposure'
  | 'alerts_7d';

export interface LayoutItem {
  i: string;
  x: number;
  y: number;
  w: number;
  h: number;
  minW?: number;
  minH?: number;
  maxW?: number;
  maxH?: number;
}

export type Layouts = Record<Breakpoint, LayoutItem[]>;

export interface DashboardPrefs {
  v: number;
  layouts: Layouts;
  hidden: WidgetId[];
  kpiVisible: KpiId[];
}

export interface WidgetLimits {
  minW: number;
  minH: number;
  maxW?: number;
  maxH: number;
}

export interface WidgetMeta {
  id: WidgetId;
  title: string;
  /** One line for the widget library. */
  description: string;
  limits: WidgetLimits;
  /** Default size on lg; md/sm derived when missing. */
  defaultSize: { w: number; h: number };
  /** Height follows the rendered content; only width is user-resizable. */
  autoHeight?: boolean;
  /** Whether "Fit height to content" makes sense (false for charts that fill any height). */
  fit?: boolean;
}
