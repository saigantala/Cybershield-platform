"""
Security Validation, Penetration Testing & Continuous Assurance Schemas
CyberShield Sprint 19
"""

from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime

AssessmentType = Literal[
    "full_suite",
    "application",
    "api",
    "dependencies",
    "containers",
    "configuration",
    "owasp_top10",
]

TargetEnvironment = Literal[
    "development",
    "staging",
    "preproduction",
    "production_isolated",
]

AssessmentStatus = Literal["pending", "running", "completed", "failed", "cancelled"]
CheckStatus = Literal["pass", "fail", "warn", "info", "skipped"]
FindingSeverity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal[
    "open",
    "acknowledged",
    "in_progress",
    "fixed",
    "accepted_risk",
    "false_positive",
    "verified",
]
SourceScanner = Literal[
    "api_security_engine",
    "owasp_zap",
    "semgrep",
    "pip_audit",
    "npm_audit",
    "trivy",
    "gitleaks",
    "config_audit",
    "manual_pentest",
]

# ------------------------------------------------------------------------------
# 1. SECURITY ASSESSMENTS & CHECKS
# ------------------------------------------------------------------------------

class SecurityAssessmentCreate(BaseModel):
    assessment_name: str = Field(..., min_length=3, max_length=120)
    assessment_type: AssessmentType = "full_suite"
    target_environment: TargetEnvironment = "staging"

class SecurityCheckResponse(BaseModel):
    id: str
    assessment_id: str
    organization_id: str
    check_id: str
    category: str
    name: str
    description: Optional[str] = None
    framework_ref: Optional[str] = None
    status: CheckStatus
    severity: FindingSeverity
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None
    execution_time_ms: int = 0
    created_at: str

class SecurityAssessmentResponse(BaseModel):
    id: str
    organization_id: str
    assessment_name: str
    assessment_type: AssessmentType
    target_environment: TargetEnvironment
    status: AssessmentStatus
    posture_score: float
    risk_score: float
    test_coverage_pct: float
    compliance_pct: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    warning_checks: int
    critical_findings_count: int
    high_findings_count: int
    medium_findings_count: int
    low_findings_count: int
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    initiated_by_email: Optional[str] = None
    execution_logs: List[str] = Field(default_factory=list)
    created_at: str

# ------------------------------------------------------------------------------
# 2. API SECURITY TEST RUNS & RESULTS
# ------------------------------------------------------------------------------

class SecurityTestResultItem(BaseModel):
    id: str
    test_run_id: str
    test_name: str
    endpoint: str
    http_method: str
    test_category: str
    expected_status: int
    actual_status: int
    passed: bool
    request_payload: Dict[str, Any] = Field(default_factory=dict)
    response_summary: Optional[str] = None
    failure_reason: Optional[str] = None
    execution_time_ms: int = 0
    created_at: str

class SecurityTestRunResponse(BaseModel):
    id: str
    organization_id: str
    suite_name: str
    status: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    execution_duration_sec: float
    target_host: str
    executed_by: Optional[str] = None
    results: List[SecurityTestResultItem] = Field(default_factory=list)
    created_at: str

class APISecuritySuiteDispatchRequest(BaseModel):
    target_host: Optional[str] = "http://localhost:8000"
    categories: List[str] = Field(
        default_factory=lambda: [
            "authentication",
            "authorization",
            "tenant_isolation",
            "input_injection",
            "rate_limiting",
            "security_headers",
            "step_up_mfa",
        ]
    )

# ------------------------------------------------------------------------------
# 3. UNIFIED SECURITY FINDINGS & REMEDIATION
# ------------------------------------------------------------------------------

class SecurityFindingNoteCreate(BaseModel):
    content: str = Field(..., min_length=2, max_length=2000)

class SecurityFindingNoteResponse(BaseModel):
    id: str
    finding_id: str
    author_name: str
    content: str
    created_at: str

class SecurityFindingHistoryItem(BaseModel):
    id: str
    actor_name: str
    old_status: Optional[str] = None
    new_status: str
    change_summary: Optional[str] = None
    created_at: str

class SecurityFindingCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=150)
    description: str = Field(..., min_length=5)
    category: str
    source_scanner: SourceScanner
    severity: FindingSeverity
    affected_component: str
    cve_reference: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation_recommendation: str
    assigned_to_user_id: Optional[str] = None
    assigned_to_name: Optional[str] = None

class SecurityFindingUpdate(BaseModel):
    status: Optional[FindingStatus] = None
    assigned_to_user_id: Optional[str] = None
    assigned_to_name: Optional[str] = None
    remediation_recommendation: Optional[str] = None
    remediation_pr_url: Optional[str] = None
    verification_notes: Optional[str] = None

class SecurityFindingResponse(BaseModel):
    id: str
    organization_id: str
    finding_code: str
    title: str
    description: str
    category: str
    source_scanner: SourceScanner
    severity: FindingSeverity
    affected_component: str
    cve_reference: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation_recommendation: str
    remediation_pr_url: Optional[str] = None
    assigned_to_user_id: Optional[str] = None
    assigned_to_name: Optional[str] = None
    status: FindingStatus
    first_detected_at: str
    last_detected_at: str
    resolved_at: Optional[str] = None
    verified_at: Optional[str] = None
    notes: List[SecurityFindingNoteResponse] = Field(default_factory=list)
    history: List[SecurityFindingHistoryItem] = Field(default_factory=list)
    created_at: str
    updated_at: str

class SecurityRiskAcceptanceRequest(BaseModel):
    justification: str = Field(..., min_length=10)
    compensating_controls: str = Field(..., min_length=10)
    duration_days: int = Field(default=90, ge=1, le=365)

# ------------------------------------------------------------------------------
# 4. DEPENDENCIES, CONTAINERS & CONFIGURATION
# ------------------------------------------------------------------------------

class DependencyPackageItem(BaseModel):
    package_name: str
    current_version: str
    fixed_version: Optional[str] = None
    ecosystem: str  # "pypi", "npm"
    cve_id: Optional[str] = None
    severity: FindingSeverity
    vulnerability_title: str
    remediation_command: str

class ContainerScanResult(BaseModel):
    image_tag: str
    base_os: str
    total_cves: int
    critical_cves: int
    high_cves: int
    medium_cves: int
    root_user_check: bool
    read_only_rootfs_check: bool
    privileged_mode_check: bool
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)

class SecurityConfigurationCheck(BaseModel):
    check_code: str
    setting_name: str
    expected_value: str
    actual_value: str
    compliant: bool
    severity: FindingSeverity
    remediation_guidance: str

# ------------------------------------------------------------------------------
# 5. SCANNER CONFIGS & SCHEDULES
# ------------------------------------------------------------------------------

class SecurityScannerConfigUpdate(BaseModel):
    is_enabled: Optional[bool] = None
    approved_targets: Optional[List[str]] = None
    scan_mode: Optional[Literal["passive", "baseline", "authenticated_safe", "active_approved"]] = None
    max_requests_per_second: Optional[int] = Field(None, ge=1, le=50)
    timeout_seconds: Optional[int] = Field(None, ge=30, le=1800)
    headers: Optional[Dict[str, str]] = None

class SecurityScannerConfigResponse(BaseModel):
    id: str
    organization_id: str
    scanner_type: str
    is_enabled: bool
    approved_targets: List[str]
    scan_mode: str
    max_requests_per_second: int
    timeout_seconds: int
    headers: Dict[str, str]
    created_at: str
    updated_at: str

class SecurityComponentInventoryResponse(BaseModel):
    id: str
    organization_id: str
    component_name: str
    component_type: str
    version: Optional[str] = None
    health_score: float
    last_scanned_at: Optional[str] = None
    open_vulnerabilities_count: int
    misconfigurations_count: int
    security_gate_status: str

# ------------------------------------------------------------------------------
# 6. OVERVIEW & SCORING
# ------------------------------------------------------------------------------

class SecurityAssuranceOverviewResponse(BaseModel):
    posture_score: float
    risk_score: float
    test_coverage_pct: float
    compliance_pct: float
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    open_findings: int
    fixed_findings: int
    accepted_risk_findings: int
    verified_findings: int
    components: List[SecurityComponentInventoryResponse]
    recent_assessments: List[SecurityAssessmentResponse]
    failed_checks_sample: List[SecurityCheckResponse]
    scoring_breakdown: Dict[str, Any]

class SecurityReportExportRequest(BaseModel):
    report_type: Literal[
        "application",
        "api",
        "dependencies",
        "containers",
        "owasp_verification",
        "executive_summary",
    ]
    format: Literal["json", "csv"] = "json"

class SecurityReportExportResponse(BaseModel):
    report_title: str
    report_type: str
    format: str
    generated_at: str
    data: Any
