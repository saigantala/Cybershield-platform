export type AssessmentType = "application" | "api" | "dependencies" | "containers" | "configuration" | "full_suite";
export type AssessmentStatus = "pending" | "running" | "completed" | "failed";
export type CheckStatus = "pass" | "fail" | "warn" | "skipped";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "informational";
export type FindingStatus = "open" | "acknowledged" | "in_progress" | "fixed" | "accepted_risk" | "false_positive" | "verified";

export interface SecurityComponentInventory {
  id: string;
  organization_id: string;
  component_name: string;
  component_type: "frontend" | "api" | "database" | "worker" | "cache" | "infra";
  technology_stack: string;
  attack_surface_rating: "low" | "medium" | "high" | "critical";
  last_tested_at: string;
  open_findings_count: number;
  status: "secure" | "at_risk" | "needs_review";
}

export interface SecurityCheck {
  id: string;
  assessment_id: string;
  check_code: string;
  category: string;
  owasp_category?: string;
  name: string;
  description: string;
  target_component: string;
  severity: FindingSeverity;
  status: CheckStatus;
  evidence_data?: Record<string, any>;
  remediation?: string;
  tested_at: string;
}

export interface SecurityAssessment {
  id: string;
  organization_id: string;
  assessment_name: string;
  assessment_type: AssessmentType;
  target_environment: string;
  status: AssessmentStatus;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  warning_checks: number;
  posture_score: number;
  created_at: string;
  completed_at?: string;
  assessed_by: string;
}

export interface SecurityTestResult {
  id: string;
  run_id: string;
  test_name: string;
  endpoint: string;
  http_method: string;
  test_category: string;
  expected_status: number;
  actual_status: number;
  passed: boolean;
  request_payload?: Record<string, any>;
  response_summary: string;
  failure_reason?: string;
  execution_time_ms: number;
}

export interface SecurityTestRun {
  id: string;
  organization_id: string;
  suite_name: string;
  trigger_source: string;
  status: AssessmentStatus;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  duration_ms: number;
  created_at: string;
  completed_at?: string;
  results?: SecurityTestResult[];
}

export interface SecurityFindingNote {
  id: string;
  finding_id: string;
  author_email: string;
  content: string;
  created_at: string;
}

export interface SecurityRiskAcceptanceRequest {
  justification: string;
  compensating_controls?: string;
  duration_days: number;
}

export interface SecurityFindingHistory {
  id: string;
  finding_id: string;
  actor_email: string;
  previous_status: FindingStatus;
  new_status: FindingStatus;
  change_notes?: string;
  created_at: string;
}

export interface SecurityFinding {
  id: string;
  organization_id: string;
  finding_code: string;
  title: string;
  description: string;
  category: string;
  owasp_category?: string;
  source_scanner: string;
  severity: FindingSeverity;
  status: FindingStatus;
  affected_component: string;
  affected_url_or_file?: string;
  cve_id?: string;
  cvss_score?: number;
  remediation_recommendation?: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  notes_count: number;
  notes?: SecurityFindingNote[];
  history?: SecurityFindingHistory[];
}

export interface DependencyPackageItem {
  package_name: string;
  current_version: string;
  ecosystem: "python" | "npm";
  vulnerable: boolean;
  vulnerabilities_count: number;
  highest_severity: FindingSeverity;
  fixed_version?: string;
  cve_list: string[];
}

export interface ContainerScanResult {
  image_name: string;
  tag: string;
  base_os: string;
  vulnerabilities_total: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  runs_as_root: boolean;
  scanned_at: string;
  status: "pass" | "warn" | "fail";
}

export interface SecurityConfigurationCheck {
  category: string;
  check_name: string;
  description: string;
  status: "compliant" | "non_compliant" | "warning";
  severity: FindingSeverity;
  recommendation: string;
}

export interface SecurityScannerConfig {
  id: string;
  organization_id: string;
  scanner_name: string;
  scanner_type: string;
  is_enabled: boolean;
  scan_frequency: string;
  target_scope: string[];
  parameters: Record<string, any>;
  last_run_at?: string;
  next_run_at?: string;
}

export interface SecurityAssuranceOverview {
  posture_score: number;
  risk_score: number;
  test_coverage_pct: number;
  compliance_pct: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  open_findings: number;
  fixed_findings: number;
  accepted_risk_findings: number;
  verified_findings: number;
  components: SecurityComponentInventory[];
  recent_assessments: SecurityAssessment[];
  failed_checks_sample: SecurityCheck[];
  scoring_breakdown: {
    base_score: number;
    critical_deductions: number;
    high_deductions: number;
    medium_deductions: number;
    failed_tests_deductions: number;
    formula: string;
  };
}

export interface SecurityReportExport {
  report_id: string;
  report_title: string;
  generated_at: string;
  report_type: AssessmentType;
  format: "json" | "csv";
  posture_score: number;
  data: any;
}
