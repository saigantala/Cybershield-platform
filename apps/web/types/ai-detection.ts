export type DetectionCategory =
  | 'network_anomaly'
  | 'suspicious_outbound'
  | 'unusual_port'
  | 'repeated_auth_failures'
  | 'ueba_deviation'
  | 'threat_intel_match'
  | 'vulnerability_exposure'
  | 'unusual_traffic_volume';

export type DetectionSeverity = 'Critical' | 'High' | 'Medium' | 'Low';

export type DetectionMethod =
  | 'ml_isolation_forest'
  | 'statistical_baseline'
  | 'deterministic_rule'
  | 'ueba_behavioral';

export type RuleType =
  | 'statistical_threshold'
  | 'behavioral_deviation'
  | 'ioc_matching'
  | 'event_correlation';

export type InvestigationStatus =
  | 'New'
  | 'Reviewing'
  | 'Confirmed Suspicious'
  | 'False Positive'
  | 'Escalated'
  | 'Resolved';

export interface AIDetectionModel {
  id: string;
  organization_id: string;
  model_name: string;
  model_type: string;
  description?: string;
  active_version: string;
  status: string;
  is_production_ready: boolean;
  evaluation_metrics: Record<string, number>;
  created_at: string;
  updated_at: string;
}

export interface AIModelVersion {
  id: string;
  model_id: string;
  version: string;
  dataset_reference?: string;
  training_samples_count: number;
  hyperparameters: Record<string, any>;
  evaluation_metrics: Record<string, number>;
  is_active: boolean;
  trained_at: string;
  deployed_at?: string;
}

export interface AIDetectionRule {
  id: string;
  organization_id: string;
  rule_name: string;
  rule_type: RuleType;
  description?: string;
  severity: DetectionSeverity;
  data_sources: string[];
  threshold_config: Record<string, any>;
  evaluation_interval_seconds: number;
  is_enabled: boolean;
  matched_events_count: number;
  false_positive_count: number;
  created_at: string;
  updated_at: string;
}

export interface AIDetectionRuleCreatePayload {
  rule_name: string;
  rule_type: RuleType;
  description?: string;
  severity?: DetectionSeverity;
  data_sources?: string[];
  threshold_config?: Record<string, any>;
  evaluation_interval_seconds?: number;
  is_enabled?: boolean;
}

export interface AIDetectionResult {
  id: string;
  organization_id: string;
  source_asset_id?: string;
  source_asset_name?: string;
  detection_category: DetectionCategory;
  severity: DetectionSeverity;
  confidence_score: number;
  anomaly_score: number;
  detection_method: DetectionMethod;
  supporting_evidence: Record<string, any>;
  recommended_investigation?: string;
  model_version: string;
  status: string;
  detected_at: string;
  created_at: string;
}

export interface AIDetectionInvestigation {
  id: string;
  organization_id: string;
  detection_id: string;
  detection?: AIDetectionResult;
  status: InvestigationStatus;
  assigned_analyst?: string;
  analyst_notes?: string;
  findings_summary?: string;
  timeline_events: Array<{ timestamp: string; actor: string; action: string; notes?: string }>;
  confirmed_at?: string;
  resolved_at?: string;
  created_at: string;
  updated_at: string;
}

export interface AIFeedbackPayload {
  detection_id: string;
  verdict: 'true_positive' | 'false_positive' | 'benign_anomaly';
  notes?: string;
}

export interface AIRiskPrediction {
  id: string;
  organization_id: string;
  asset_id: string;
  asset_name?: string;
  asset_ip?: string;
  risk_score: number;
  risk_level: DetectionSeverity;
  risk_trend: 'increasing' | 'stable' | 'decreasing';
  contributing_factors: Array<{ factor: string; impact: string; detail: string }>;
  confidence_score: number;
  data_coverage_score: number;
  recommended_remediation_priority: string;
  predicted_at: string;
}

export interface AIThreatAnalytics {
  total_detections_count: number;
  critical_detections_count: number;
  active_anomalies_count: number;
  false_positive_rate_percent: number;
  mean_confidence_score: number;
  investigations_in_progress: number;
  detections_by_category: Record<string, number>;
  daily_anomaly_volume: Array<{ date: string; anomalies: number; baseline: number }>;
  model_health_overview: Array<{
    model_name: string;
    model_type: string;
    status: string;
    f1_score: number;
    is_production_ready: boolean;
  }>;
}

export interface AIThreatInvestigationQueryResponse {
  conversation_id: string;
  message_id: string;
  answer: string;
  evidence_citations: Array<Record<string, any>>;
  related_records: Record<string, string[]>;
  recommended_next_steps: string[];
  confidence_and_uncertainty: string;
  created_at: string;
}
