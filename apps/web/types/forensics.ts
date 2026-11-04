export type ForensicCaseStatus =
  | 'Open'
  | 'Evidence Collection'
  | 'Analysis'
  | 'Review'
  | 'Completed'
  | 'Archived';

export type ForensicPriority = 'P1' | 'P2' | 'P3' | 'P4';

export type ForensicAssetRole =
  | 'compromised_target'
  | 'pivot_host'
  | 'command_control_hop'
  | 'unauthorized_scanner'
  | 'witness_system';

export type EvidenceCategory =
  | 'log_file'
  | 'network_metadata_pcap'
  | 'memory_dump_metadata'
  | 'disk_artifact'
  | 'screenshot'
  | 'config_export'
  | 'pdf_report'
  | 'csv_export'
  | 'other';

export type CustodyAction =
  | 'Collected'
  | 'Uploaded'
  | 'Viewed'
  | 'Downloaded'
  | 'Integrity_Verified'
  | 'Transferred'
  | 'Archived';

export type AnalysisJobType =
  | 'log_normalization'
  | 'ioc_extraction'
  | 'pcap_metadata'
  | 'string_extraction';

export type CaseNoteType =
  | 'Analyst_Hypothesis'
  | 'Confirmed_Observation'
  | 'Investigative_Lead'
  | 'Evidence_Custody_Note';

export interface ForensicCaseAsset {
  id: string;
  asset_id: string;
  asset_name?: string;
  asset_type?: string;
  ip_address?: string;
  role_in_case: ForensicAssetRole;
  linked_at: string;
}

export interface ForensicCase {
  id: string;
  organization_id: string;
  case_number: string;
  title: string;
  description: string;
  investigation_objective: string;
  status: ForensicCaseStatus;
  priority: ForensicPriority;
  assigned_investigator_id?: string;
  related_incident_id?: string;
  related_hunting_case_id?: string;
  conclusion_summary?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
  evidence_count: number;
  notes_count: number;
  reports_count: number;
  assets: ForensicCaseAsset[];
}

export interface ForensicCaseCreate {
  title: string;
  description: string;
  investigation_objective: string;
  priority?: ForensicPriority;
  assigned_investigator_id?: string;
  related_incident_id?: string;
  related_hunting_case_id?: string;
  assets?: Array<{ asset_id: string; role_in_case: ForensicAssetRole }>;
}

export interface ForensicCaseUpdate {
  title?: string;
  description?: string;
  investigation_objective?: string;
  status?: ForensicCaseStatus;
  priority?: ForensicPriority;
  assigned_investigator_id?: string;
  conclusion_summary?: string;
}

export interface ForensicEvidenceItem {
  id: string;
  organization_id: string;
  forensic_case_id: string;
  evidence_name: string;
  category: EvidenceCategory;
  original_filename: string;
  storage_path: string;
  mime_type: string;
  file_size: number;
  sha256_hash: string;
  md5_hash?: string;
  uploaded_by?: string;
  description?: string;
  is_derived: boolean;
  parent_evidence_id?: string;
  transformation_notes?: string;
  integrity_status: 'Verified' | 'Tampered' | 'Unverified';
  last_verified_at: string;
  created_at: string;
}

export interface ForensicEvidenceItemCreate {
  forensic_case_id: string;
  evidence_name: string;
  category: EvidenceCategory;
  original_filename: string;
  file_content_base64?: string;
  description?: string;
  is_derived?: boolean;
  parent_evidence_id?: string;
  transformation_notes?: string;
}

export interface ForensicCustodyEvent {
  id: string;
  organization_id: string;
  evidence_id: string;
  actor_id?: string;
  actor_name: string;
  action: CustodyAction;
  timestamp: string;
  previous_record_hash: string;
  current_record_hash: string;
  metadata: Record<string, any>;
}

export interface CustodyChainVerificationResponse {
  evidence_id: string;
  evidence_name: string;
  is_chain_valid: boolean;
  total_events: number;
  genesis_hash: string;
  latest_hash: string;
  verified_at: string;
  broken_at_event_id?: string;
  details: string;
}

export interface ForensicAnalysisJob {
  id: string;
  organization_id: string;
  forensic_case_id: string;
  evidence_id: string;
  analysis_type: AnalysisJobType;
  status: 'Queued' | 'Processing' | 'Completed' | 'Failed';
  extracted_metadata: Record<string, any>;
  matched_iocs: any[];
  suspicious_indicators: any[];
  error_message?: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
}

export interface ForensicCaseNote {
  id: string;
  organization_id: string;
  forensic_case_id: string;
  author_id?: string;
  author_name?: string;
  note_type: CaseNoteType;
  content: string;
  created_at: string;
}

export interface ForensicCaseNoteCreate {
  note_type: CaseNoteType;
  content: string;
}

export interface ForensicReport {
  id: string;
  organization_id: string;
  forensic_case_id: string;
  report_number: string;
  title: string;
  author_id?: string;
  author_name?: string;
  scope_and_authorization: string;
  executive_summary: string;
  evidence_inventory_summary: any[];
  chain_of_custody_verified: boolean;
  analysis_methodology: string;
  confirmed_findings: any[];
  analyst_hypotheses: any[];
  mitre_attack_mappings: any[];
  limitations?: string;
  recommendations: any[];
  conclusion: string;
  file_format: 'json' | 'markdown' | 'pdf';
  created_at: string;
}

export interface ForensicReportCreate {
  title: string;
  scope_and_authorization: string;
  executive_summary: string;
  analysis_methodology: string;
  confirmed_findings: any[];
  analyst_hypotheses: any[];
  mitre_attack_mappings: any[];
  limitations?: string;
  recommendations: any[];
  conclusion: string;
  file_format?: 'json' | 'markdown' | 'pdf';
}

export interface ForensicTimelineEvent {
  id: string;
  timestamp: string;
  event_source: string;
  event_type: string;
  severity: string;
  title: string;
  description: string;
  asset_id?: string;
  asset_name?: string;
  indicators: string[];
  raw_details: Record<string, any>;
}

export interface ForensicTimelineResponse {
  total_count: number;
  page: number;
  page_size: number;
  events: ForensicTimelineEvent[];
}

export interface ForensicTimelineFilter {
  forensic_case_id?: string;
  asset_id?: string;
  event_category?: string;
  severity?: string;
  start_time?: string;
  end_time?: string;
  limit?: number;
  offset?: number;
}

export interface ForensicsDashboardStats {
  total_cases: number;
  open_cases: number;
  in_analysis: number;
  total_evidence_items: number;
  verified_evidence_items: number;
  total_reports: number;
}
