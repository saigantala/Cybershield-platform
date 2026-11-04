export type IndicatorType = "ipv4" | "ipv6" | "domain" | "url" | "md5" | "sha1" | "sha256";
export type ThreatCategory = "c2" | "malware" | "phishing" | "ransomware" | "botnet" | "scanner" | "exploit";
export type SeverityLevel = "Critical" | "High" | "Medium" | "Low" | "Info";
export type AlertStatus = "New" | "Investigating" | "Escalated" | "Resolved" | "False Positive";
export type DetectionRuleType =
  | "brute_force"
  | "threat_intel_match"
  | "vuln_risk_correlation"
  | "activity_anomaly"
  | "repeated_suspicious";

export interface ThreatIndicator {
  id: string;
  organization_id: string;
  indicator_type: IndicatorType;
  indicator_value: string;
  source: string;
  threat_category: ThreatCategory;
  confidence: number;
  severity: SeverityLevel;
  first_seen: string;
  last_seen: string;
  expires_at?: string | null;
  description?: string | null;
  reference_url?: string | null;
  created_at: string;
}

export interface ThreatFeed {
  id: string;
  organization_id: string;
  feed_name: string;
  feed_provider: string;
  feed_url: string;
  sync_interval_hours: number;
  last_synced_at?: string | null;
  sync_status: "Active" | "Syncing" | "Error" | "Disabled";
  indicator_count: number;
  error_message?: string | null;
  is_enabled: boolean;
  created_at: string;
}

export interface ThreatIntelOverview {
  total_indicators: number;
  malicious_ips: number;
  malicious_domains: number;
  malicious_urls: number;
  malicious_hashes: number;
  high_confidence_count: number;
  feed_updates_count: number;
  type_distribution: Record<string, number>;
  recent_indicators: ThreatIndicator[];
}

export interface SecurityEvent {
  id: string;
  organization_id: string;
  source: string;
  event_type: string;
  severity: SeverityLevel;
  source_ip?: string | null;
  destination_ip?: string | null;
  hostname?: string | null;
  username?: string | null;
  asset_id?: string | null;
  event_description: string;
  event_timestamp: string;
  metadata?: Record<string, any>;
  created_at: string;
}

export interface DetectionRule {
  id: string;
  organization_id: string;
  rule_name: string;
  rule_type: DetectionRuleType;
  severity: SeverityLevel;
  threshold: number;
  time_window_seconds: number;
  condition_logic: Record<string, any>;
  description: string;
  is_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AlertNote {
  id: string;
  alert_id: string;
  author_id: string;
  note: string;
  created_at: string;
}

export interface AlertHistory {
  id: string;
  alert_id: string;
  actor_id?: string | null;
  action: string;
  previous_state?: Record<string, any> | null;
  new_state?: Record<string, any> | null;
  notes?: string | null;
  created_at: string;
}

export interface SecurityAlert {
  id: string;
  organization_id: string;
  title: string;
  description: string;
  alert_type: string;
  severity: SeverityLevel;
  status: AlertStatus;
  source: string;
  asset_id?: string | null;
  indicator_id?: string | null;
  rule_id?: string | null;
  related_event_ids?: string[];
  assigned_to?: string | null;
  linked_incident_id?: string | null;
  confidence: number;
  first_detected_at: string;
  last_detected_at: string;
  created_at: string;
  updated_at: string;
  notes?: AlertNote[];
  history?: AlertHistory[];
}
