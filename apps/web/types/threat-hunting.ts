export type ThreatHuntingCaseStatus =
  | 'Draft'
  | 'Active'
  | 'Investigating'
  | 'Suspicious Activity Found'
  | 'No Threat Identified'
  | 'Escalated'
  | 'Completed';

export type ThreatHuntingPriority = 'P1' | 'P2' | 'P3' | 'P4';

export type ThreatHuntingFindingType =
  | 'anomalous_traffic'
  | 'ioc_match'
  | 'behavioral_anomaly'
  | 'credential_misuse'
  | 'unauthorized_service';

export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export type IOCType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256';

export interface ThreatHuntingCase {
  id: string;
  organization_id: string;
  case_number: string;
  title: string;
  objective: string;
  hypothesis?: string;
  status: ThreatHuntingCaseStatus;
  priority: ThreatHuntingPriority;
  assigned_to?: string;
  created_by?: string;
  start_time?: string;
  end_time?: string;
  selected_asset_ids: string[];
  filter_criteria: Record<string, any>;
  summary_findings?: string;
  created_at: string;
  updated_at: string;
  findings_count: number;
  queries_count: number;
}

export interface ThreatHuntingCaseCreate {
  title: string;
  objective: string;
  hypothesis?: string;
  priority?: ThreatHuntingPriority;
  assigned_to?: string;
  start_time?: string;
  end_time?: string;
  selected_asset_ids?: string[];
  filter_criteria?: Record<string, any>;
}

export interface ThreatHuntingCaseUpdate {
  title?: string;
  objective?: string;
  hypothesis?: string;
  status?: ThreatHuntingCaseStatus;
  priority?: ThreatHuntingPriority;
  assigned_to?: string;
  start_time?: string;
  end_time?: string;
  selected_asset_ids?: string[];
  filter_criteria?: Record<string, any>;
  summary_findings?: string;
}

export interface ThreatHuntingFinding {
  id: string;
  organization_id: string;
  hunting_case_id: string;
  title: string;
  finding_type: ThreatHuntingFindingType;
  severity: SeverityLevel;
  is_confirmed: boolean;
  affected_asset_id?: string;
  evidence_summary: string;
  mitre_tactic_name?: string;
  mitre_technique_id?: string;
  recommendations?: string;
  created_at: string;
}

export interface ThreatHuntingFindingCreate {
  hunting_case_id: string;
  title: string;
  finding_type: ThreatHuntingFindingType;
  severity: SeverityLevel;
  is_confirmed?: boolean;
  affected_asset_id?: string;
  evidence_summary: string;
  mitre_tactic_name?: string;
  mitre_technique_id?: string;
  recommendations?: string;
}

export interface ThreatHuntingQueryParam {
  source_ip?: string;
  destination_ip?: string;
  port?: number;
  protocol?: string;
  asset_id?: string;
  hostname?: string;
  event_category?: string;
  severity?: string;
  ioc_type?: string;
  ioc_value?: string;
  detection_rule?: string;
  time_range_hours?: number;
  start_time?: string;
  end_time?: string;
  operator?: 'AND' | 'OR';
  limit?: number;
  offset?: number;
}

export interface ThreatHuntingQueryResultItem {
  id: string;
  timestamp: string;
  event_category: string;
  event_type: string;
  severity: string;
  source_ip?: string;
  destination_ip?: string;
  port?: number;
  protocol?: string;
  asset_id?: string;
  asset_name?: string;
  summary: string;
  raw_payload: Record<string, any>;
  matched_ioc?: string;
}

export interface ThreatHuntingQueryResult {
  total_matches: number;
  page: number;
  page_size: number;
  events: ThreatHuntingQueryResultItem[];
  execution_time_ms: number;
}

export interface ThreatHuntingQueryResponse {
  id: string;
  organization_id: string;
  hunting_case_id?: string;
  name: string;
  description?: string;
  filter_params: Record<string, any>;
  match_count: number;
  is_saved: boolean;
  created_by?: string;
  created_at: string;
}

export interface ThreatHuntingQuerySave {
  hunting_case_id?: string;
  name: string;
  description?: string;
  filter_params: Record<string, any>;
}

export interface IOCInvestigationResponse {
  ioc_value: string;
  ioc_type: string;
  is_known_threat: boolean;
  threat_status: 'known_malicious' | 'suspicious' | 'unknown_unverified' | 'clean';
  confidence_score: number;
  threat_types: string[];
  reputation_provider: string;
  first_seen?: string;
  last_seen?: string;
  related_alerts: any[];
  related_assets: any[];
  related_incidents: any[];
  related_hunting_cases: any[];
  analyst_notes: string[];
}

export interface ThreatHuntingDashboardStats {
  total_cases: number;
  active_investigations: number;
  suspicious_found: number;
  escalated_to_incidents: number;
  total_findings: number;
  confirmed_threats: number;
}
