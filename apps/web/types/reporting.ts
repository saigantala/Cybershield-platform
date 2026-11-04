export type ReportType =
  | 'vulnerability_assessment'
  | 'asset_inventory'
  | 'incident_summary'
  | 'threat_intelligence'
  | 'compliance_assessment'
  | 'security_posture'
  | 'executive_summary';

export type ReportFormat = 'pdf' | 'csv' | 'json';
export type ReportStatus = 'Pending' | 'Processing' | 'Completed' | 'Failed';

export interface SecurityReport {
  id: string;
  organization_id: string;
  title: string;
  report_type: ReportType;
  format: ReportFormat;
  status: ReportStatus;
  parameters: Record<string, any>;
  summary_metrics: Record<string, any>;
  file_size_bytes: number;
  download_url?: string;
  generated_by?: string;
  created_at: string;
  completed_at?: string;
}

export interface ReportPreview {
  title: string;
  report_type: ReportType;
  format: ReportFormat;
  generated_at: string;
  organization_name: string;
  executive_summary: string;
  key_metrics: Record<string, any>;
  sample_records: any[];
  recommended_actions: string[];
}

export interface PostureCategoryScores {
  vulnerability_management: number;
  perimeter_exposure: number;
  incident_readiness: number;
  threat_intel_coverage: number;
  compliance_posture: number;
}

export interface SecurityPosture {
  organization_id: string;
  overall_score: number;
  risk_level: 'Critical Risk' | 'High Risk' | 'Moderate Risk' | 'Low Risk' | 'Hardened';
  category_scores: PostureCategoryScores;
  score_factors: Array<{
    factor: string;
    impact: string;
    category: string;
    severity: string;
  }>;
  recommended_improvements: string[];
  score_history: Array<{
    date: string;
    score: number;
  }>;
  calculated_at: string;
  methodology_notes: string;
}

export interface ExecutiveDashboardData {
  organization_id: string;
  organization_name: string;
  date_range: string;
  security_score: number;
  risk_classification: string;
  critical_vulnerabilities: number;
  high_risk_assets: number;
  open_incidents: number;
  compliance_completion_percentage: number;
  remediation_progress_percentage: number;
  security_trend: Array<{
    date: string;
    score: number;
    incidents?: number;
  }>;
  top_5_security_risks: Array<{
    title: string;
    severity: string;
    cve_id?: string;
    cvss_score?: number;
    affected_asset?: string;
    cisa_kev?: boolean;
  }>;
  recent_security_events: any[];
  recommended_actions: string[];
}
