from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime

ForensicCaseStatus = Literal[
    "Open",
    "Evidence Collection",
    "Analysis",
    "Review",
    "Completed",
    "Archived",
]

ForensicPriority = Literal["P1", "P2", "P3", "P4"]

ForensicAssetRole = Literal[
    "compromised_target",
    "pivot_host",
    "command_control_hop",
    "unauthorized_scanner",
    "witness_system",
]

EvidenceCategory = Literal[
    "log_file",
    "network_metadata_pcap",
    "memory_dump_metadata",
    "disk_artifact",
    "screenshot",
    "config_export",
    "pdf_report",
    "csv_export",
    "other",
]

CustodyAction = Literal[
    "Collected",
    "Uploaded",
    "Viewed",
    "Downloaded",
    "Integrity_Verified",
    "Transferred",
    "Archived",
]

AnalysisJobType = Literal[
    "log_normalization",
    "ioc_extraction",
    "pcap_metadata",
    "string_extraction",
]

AnalysisJobStatus = Literal["Queued", "Processing", "Completed", "Failed"]

CaseNoteType = Literal[
    "Analyst_Hypothesis",
    "Confirmed_Observation",
    "Investigative_Lead",
    "Evidence_Custody_Note",
]

ReportFormat = Literal["json", "markdown", "pdf"]


class ForensicAssetLink(BaseModel):
    asset_id: str
    role_in_case: ForensicAssetRole = "compromised_target"


class ForensicCaseCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=256)
    description: str = Field(..., min_length=5)
    investigation_objective: str = Field(..., min_length=5)
    priority: ForensicPriority = "P2"
    assigned_investigator_id: Optional[str] = None
    related_incident_id: Optional[str] = None
    related_hunting_case_id: Optional[str] = None
    assets: List[ForensicAssetLink] = []


class ForensicCaseUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=256)
    description: Optional[str] = None
    investigation_objective: Optional[str] = None
    status: Optional[ForensicCaseStatus] = None
    priority: Optional[ForensicPriority] = None
    assigned_investigator_id: Optional[str] = None
    conclusion_summary: Optional[str] = None


class ForensicCaseAssetResponse(BaseModel):
    id: str
    asset_id: str
    asset_name: Optional[str] = None
    asset_type: Optional[str] = None
    ip_address: Optional[str] = None
    role_in_case: ForensicAssetRole
    linked_at: datetime


class ForensicCaseResponse(BaseModel):
    id: str
    organization_id: str
    case_number: str
    title: str
    description: str
    investigation_objective: str
    status: ForensicCaseStatus
    priority: ForensicPriority
    assigned_investigator_id: Optional[str] = None
    related_incident_id: Optional[str] = None
    related_hunting_case_id: Optional[str] = None
    conclusion_summary: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    evidence_count: int = 0
    notes_count: int = 0
    reports_count: int = 0
    assets: List[ForensicCaseAssetResponse] = []


class ForensicEvidenceItemCreate(BaseModel):
    forensic_case_id: str
    evidence_name: str = Field(..., min_length=3, max_length=256)
    category: EvidenceCategory
    original_filename: str = Field(..., min_length=1)
    file_content_base64: Optional[str] = None  # Raw bytes encoded or simulated for ingestion
    description: Optional[str] = None
    is_derived: bool = False
    parent_evidence_id: Optional[str] = None
    transformation_notes: Optional[str] = None


class ForensicEvidenceItemResponse(BaseModel):
    id: str
    organization_id: str
    forensic_case_id: str
    evidence_name: str
    category: EvidenceCategory
    original_filename: str
    storage_path: str
    mime_type: str
    file_size: int
    sha256_hash: str
    md5_hash: Optional[str] = None
    uploaded_by: Optional[str] = None
    description: Optional[str] = None
    is_derived: bool = False
    parent_evidence_id: Optional[str] = None
    transformation_notes: Optional[str] = None
    integrity_status: Literal["Verified", "Tampered", "Unverified"]
    last_verified_at: datetime
    created_at: datetime


class ForensicCustodyEventCreate(BaseModel):
    action: CustodyAction
    metadata: Dict[str, Any] = {}


class ForensicCustodyEventResponse(BaseModel):
    id: str
    organization_id: str
    evidence_id: str
    actor_id: Optional[str] = None
    actor_name: str
    action: CustodyAction
    timestamp: datetime
    previous_record_hash: str
    current_record_hash: str
    metadata: Dict[str, Any] = {}


class CustodyChainVerificationResponse(BaseModel):
    evidence_id: str
    evidence_name: str
    is_chain_valid: bool
    total_events: int
    genesis_hash: str
    latest_hash: str
    verified_at: datetime
    broken_at_event_id: Optional[str] = None
    details: str


class ForensicAnalysisJobCreate(BaseModel):
    analysis_type: AnalysisJobType = "log_normalization"


class ForensicAnalysisJobResponse(BaseModel):
    id: str
    organization_id: str
    forensic_case_id: str
    evidence_id: str
    analysis_type: AnalysisJobType
    status: AnalysisJobStatus
    extracted_metadata: Dict[str, Any] = {}
    matched_iocs: List[Dict[str, Any]] = []
    suspicious_indicators: List[Dict[str, Any]] = []
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None


class ForensicCaseNoteCreate(BaseModel):
    note_type: CaseNoteType = "Confirmed_Observation"
    content: str = Field(..., min_length=3)


class ForensicCaseNoteResponse(BaseModel):
    id: str
    organization_id: str
    forensic_case_id: str
    author_id: Optional[str] = None
    author_name: Optional[str] = None
    note_type: CaseNoteType
    content: str
    created_at: datetime


class ForensicReportCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=256)
    scope_and_authorization: str = Field(..., min_length=5)
    executive_summary: str = Field(..., min_length=5)
    analysis_methodology: str = Field(..., min_length=5)
    confirmed_findings: List[Dict[str, Any]] = []
    analyst_hypotheses: List[Dict[str, Any]] = []
    mitre_attack_mappings: List[Dict[str, Any]] = []
    limitations: Optional[str] = None
    recommendations: List[Dict[str, Any]] = []
    conclusion: str = Field(..., min_length=5)
    file_format: ReportFormat = "json"


class ForensicReportResponse(BaseModel):
    id: str
    organization_id: str
    forensic_case_id: str
    report_number: str
    title: str
    author_id: Optional[str] = None
    author_name: Optional[str] = None
    scope_and_authorization: str
    executive_summary: str
    evidence_inventory_summary: List[Dict[str, Any]] = []
    chain_of_custody_verified: bool = True
    analysis_methodology: str
    confirmed_findings: List[Dict[str, Any]] = []
    analyst_hypotheses: List[Dict[str, Any]] = []
    mitre_attack_mappings: List[Dict[str, Any]] = []
    limitations: Optional[str] = None
    recommendations: List[Dict[str, Any]] = []
    conclusion: str
    file_format: ReportFormat
    created_at: datetime


class ForensicTimelineFilter(BaseModel):
    forensic_case_id: Optional[str] = None
    asset_id: Optional[str] = None
    event_category: Optional[str] = None
    severity: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(100, ge=1, le=500)
    offset: int = Field(0, ge=0)


class ForensicTimelineEvent(BaseModel):
    id: str
    timestamp: datetime
    event_source: str  # 'auth', 'network', 'asset', 'vulnerability', 'threat_intel', 'alert', 'incident', 'evidence'
    event_type: str
    severity: str
    title: str
    description: str
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    indicators: List[str] = []
    raw_details: Dict[str, Any] = {}


class ForensicTimelineResponse(BaseModel):
    total_count: int
    page: int
    page_size: int
    events: List[ForensicTimelineEvent]


class ForensicsDashboardStats(BaseModel):
    total_cases: int
    open_cases: int
    in_analysis: int
    total_evidence_items: int
    verified_evidence_items: int
    total_reports: int
