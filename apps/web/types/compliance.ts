export type AssessmentStatus =
  | 'Not Assessed'
  | 'Partially Implemented'
  | 'Implemented'
  | 'Not Applicable';

export interface ComplianceFramework {
  id: string;
  framework_code: string;
  name: string;
  version: string;
  description?: string;
  category: string;
  total_controls: number;
  implemented_controls: number;
  partially_implemented: number;
  not_assessed: number;
  completion_percentage: number;
}

export interface ComplianceControl {
  id: string;
  framework_id: string;
  framework_code: string;
  control_id: string;
  title: string;
  description: string;
  domain?: string;
  remediation_guidance?: string;
  current_status: AssessmentStatus;
  assigned_owner?: string;
  review_date?: string;
  notes?: string;
  evidence_count: number;
}

export interface ComplianceAssessment {
  id: string;
  organization_id: string;
  control_id: string;
  framework_id: string;
  framework_code: string;
  control_code: string;
  control_title: string;
  status: AssessmentStatus;
  assigned_owner?: string;
  review_date?: string;
  notes?: string;
  remediation_notes?: string;
  evidence_count: number;
  created_at: string;
  updated_at: string;
}

export interface ComplianceEvidence {
  id: string;
  organization_id: string;
  control_id?: string;
  assessment_id?: string;
  file_name: string;
  file_size: number;
  mime_type: string;
  sha256_hash: string;
  storage_path: string;
  description?: string;
  uploaded_by?: string;
  uploaded_at: string;
}

export interface ComplianceSummary {
  organization_id: string;
  overall_compliance_score: number;
  total_controls: number;
  implemented_count: number;
  partially_implemented_count: number;
  not_assessed_count: number;
  not_applicable_count: number;
  framework_breakdown: ComplianceFramework[];
  overdue_assessments_count: number;
  recent_activity: ComplianceAssessment[];
}
