export interface OverviewAnalytics {
  posture_score: number;
  posture_grade: "A" | "B" | "C" | "D" | "F";
  total_assets: number;
  active_assets: number;
  critical_assets: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  cisa_kev_vulnerabilities: number;
  open_alerts: number;
  critical_alerts: number;
  open_incidents: number;
  mean_time_to_detect_minutes: number;
  mean_time_to_resolve_minutes: number;
  calculated_at: string;
}

export interface AssetAnalytics {
  total_assets: number;
  device_type_distribution: Array<{ name: string; count: number }>;
  risk_distribution: Array<{ severity: string; count: number }>;
  os_distribution: Array<{ os: string; count: number }>;
  highest_risk_assets: Array<{
    id: string;
    name: string;
    ip: string;
    risk_level: string;
    device_type: string;
  }>;
}

export interface VulnerabilityAnalytics {
  total_findings: number;
  cisa_kev_count: number;
  severity_distribution: Array<{ severity: string; count: number }>;
  status_distribution: Array<{ status: string; count: number }>;
  remediation_rate_percent: number;
  trend: Array<{
    date: string;
    new: number;
    resolved: number;
    critical: number;
  }>;
}

export interface AlertAnalytics {
  total_alerts: number;
  false_positive_rate: number;
  mean_time_to_acknowledge_minutes: number;
  severity_distribution: Array<{ severity: string; count: number }>;
  status_distribution: Array<{ status: string; count: number }>;
  source_distribution: Array<{ source: string; count: number }>;
}

export interface IncidentAnalytics {
  total_incidents: number;
  open_incidents: number;
  resolved_incidents: number;
  mean_time_to_resolution_hours: number;
  status_distribution: Array<{ status: string; count: number }>;
  type_distribution: Array<{ type: string; count: number }>;
  severity_distribution: Array<{ severity: string; count: number }>;
}

export interface ThreatIntelAnalytics {
  total_indicators: number;
  high_confidence_count: number;
  type_distribution: Array<{ type: string; count: number }>;
  feed_source_distribution: Array<{ source: string; count: number }>;
  confidence_ratio: number;
}
