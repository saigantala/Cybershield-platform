export type SubsystemStatus =
  | 'Healthy'
  | 'Degraded'
  | 'Unhealthy'
  | 'Not Configured';

export interface SubsystemHealth {
  name: string;
  category: string;
  status: SubsystemStatus;
  latency_ms: number | null;
  details: string;
  last_checked_at: string;
}

export interface SystemResourceMetrics {
  cpu_percent: number;
  memory_percent: number;
  memory_used_mb: number;
  memory_total_mb: number;
  disk_percent: number;
  platform_os: string;
  python_version: string;
  process_uptime_seconds: number;
}

export interface SystemHealthOverview {
  status: 'Healthy' | 'Degraded' | 'Unhealthy';
  environment: string;
  version: string;
  service: string;
  timestamp: string;
  subsystems: SubsystemHealth[];
  resources: SystemResourceMetrics;
  security_features: {
    rate_limiting_enabled: boolean;
    security_headers_enabled: boolean;
    max_request_size_bytes: number;
  };
}

export type ReadinessCheckStatus =
  | 'Passed'
  | 'Failed'
  | 'Warning'
  | 'Not Configured'
  | 'Not Verified';

export interface ReadinessCheckItem {
  id: string;
  category: string;
  title: string;
  status: ReadinessCheckStatus;
  impact: 'Critical' | 'High' | 'Medium' | 'Low';
  description: string;
  recommendation: string | null;
  verified_at: string;
}

export interface ProductionReadinessReport {
  readiness_score: number;
  total_checks: number;
  passed_count: number;
  warning_count: number;
  failed_count: number;
  not_configured_count: number;
  evaluated_at: string;
  environment: string;
  checklist: ReadinessCheckItem[];
}
