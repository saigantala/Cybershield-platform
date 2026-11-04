from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime

ThreatHuntingCaseStatus = Literal[
    "Draft",
    "Active",
    "Investigating",
    "Suspicious Activity Found",
    "No Threat Identified",
    "Escalated",
    "Completed",
]

ThreatHuntingPriority = Literal["P1", "P2", "P3", "P4"]

ThreatHuntingFindingType = Literal[
    "anomalous_traffic",
    "ioc_match",
    "behavioral_anomaly",
    "credential_misuse",
    "unauthorized_service",
]

SeverityLevel = Literal["Critical", "High", "Medium", "Low", "Informational"]

IOCType = Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]


class ThreatHuntingCaseCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=256)
    objective: str = Field(..., min_length=5)
    hypothesis: Optional[str] = None
    priority: ThreatHuntingPriority = "P3"
    assigned_to: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    selected_asset_ids: List[str] = []
    filter_criteria: Dict[str, Any] = {}


class ThreatHuntingCaseUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=256)
    objective: Optional[str] = None
    hypothesis: Optional[str] = None
    status: Optional[ThreatHuntingCaseStatus] = None
    priority: Optional[ThreatHuntingPriority] = None
    assigned_to: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    selected_asset_ids: Optional[List[str]] = None
    filter_criteria: Optional[Dict[str, Any]] = None
    summary_findings: Optional[str] = None


class ThreatHuntingCaseResponse(BaseModel):
    id: str
    organization_id: str
    case_number: str
    title: str
    objective: str
    hypothesis: Optional[str] = None
    status: ThreatHuntingCaseStatus
    priority: ThreatHuntingPriority
    assigned_to: Optional[str] = None
    created_by: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    selected_asset_ids: List[str] = []
    filter_criteria: Dict[str, Any] = {}
    summary_findings: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    findings_count: int = 0
    queries_count: int = 0


class ThreatHuntingFindingCreate(BaseModel):
    hunting_case_id: str
    title: str = Field(..., min_length=3, max_length=256)
    finding_type: ThreatHuntingFindingType
    severity: SeverityLevel
    is_confirmed: bool = False
    affected_asset_id: Optional[str] = None
    evidence_summary: str = Field(..., min_length=5)
    mitre_tactic_name: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    recommendations: Optional[str] = None


class ThreatHuntingFindingResponse(BaseModel):
    id: str
    organization_id: str
    hunting_case_id: str
    title: str
    finding_type: ThreatHuntingFindingType
    severity: SeverityLevel
    is_confirmed: bool
    affected_asset_id: Optional[str] = None
    evidence_summary: str
    mitre_tactic_name: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    recommendations: Optional[str] = None
    created_at: datetime


class ThreatHuntingQueryParam(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    asset_id: Optional[str] = None
    hostname: Optional[str] = None
    event_category: Optional[str] = None
    severity: Optional[str] = None
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    detection_rule: Optional[str] = None
    time_range_hours: Optional[int] = 24
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    operator: Literal["AND", "OR"] = "AND"
    limit: int = Field(50, ge=1, le=500)
    offset: int = Field(0, ge=0)


class ThreatHuntingQuerySave(BaseModel):
    hunting_case_id: Optional[str] = None
    name: str = Field(..., min_length=2, max_length=128)
    description: Optional[str] = None
    filter_params: Dict[str, Any] = {}


class ThreatHuntingQueryResponse(BaseModel):
    id: str
    organization_id: str
    hunting_case_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    filter_params: Dict[str, Any]
    match_count: int = 0
    is_saved: bool = True
    created_by: Optional[str] = None
    created_at: datetime


class ThreatHuntingQueryResultItem(BaseModel):
    id: str
    timestamp: datetime
    event_category: str
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    summary: str
    raw_payload: Dict[str, Any] = {}
    matched_ioc: Optional[str] = None


class ThreatHuntingQueryResult(BaseModel):
    total_matches: int
    page: int
    page_size: int
    events: List[ThreatHuntingQueryResultItem]
    execution_time_ms: int


class IOCInvestigationRequest(BaseModel):
    ioc_value: str = Field(..., min_length=2, max_length=256)
    ioc_type: Optional[IOCType] = None


class IOCInvestigationResponse(BaseModel):
    ioc_value: str
    ioc_type: str
    is_known_threat: bool
    threat_status: Literal["known_malicious", "suspicious", "unknown_unverified", "clean"]
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    threat_types: List[str] = []
    reputation_provider: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    related_alerts: List[Dict[str, Any]] = []
    related_assets: List[Dict[str, Any]] = []
    related_incidents: List[Dict[str, Any]] = []
    related_hunting_cases: List[Dict[str, Any]] = []
    analyst_notes: List[str] = []


class ThreatHuntingDashboardStats(BaseModel):
    total_cases: int
    active_investigations: int
    suspicious_found: int
    escalated_to_incidents: int
    total_findings: int
    confirmed_threats: int
