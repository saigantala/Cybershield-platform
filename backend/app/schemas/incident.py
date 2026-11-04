from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID
from pydantic import BaseModel, Field

# Types
IncidentType = Literal[
    "Malware",
    "Phishing",
    "Unauthorized Access",
    "Suspicious Network Activity",
    "Vulnerability Exploitation",
    "Data Exposure",
    "Account Compromise",
    "IoT Security Incident",
    "Other",
]

IncidentSeverity = Literal["Critical", "High", "Medium", "Low"]
IncidentPriority = Literal["P1", "P2", "P3", "P4"]
IncidentStatus = Literal[
    "New",
    "Acknowledged",
    "Investigating",
    "Containment",
    "Eradication",
    "Recovery",
    "Resolved",
    "Closed",
]

# ------------------------------------------------------------------------------
# Incident Core Schemas
# ------------------------------------------------------------------------------
class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=5)
    incident_type: IncidentType = "Other"
    severity: IncidentSeverity = "Medium"
    priority: IncidentPriority = "P3"
    source: str = "Analyst Manual"
    assigned_to: Optional[UUID] = None
    affected_assets: List[str] = Field(default_factory=list)
    initial_alert_ids: List[UUID] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    incident_type: Optional[IncidentType] = None
    severity: Optional[IncidentSeverity] = None
    priority: Optional[IncidentPriority] = None
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[UUID] = None
    affected_assets: Optional[List[str]] = None
    resolution_summary: Optional[str] = None


class IncidentAssignRequest(BaseModel):
    assigned_to: UUID


class IncidentResponse(BaseModel):
    id: UUID
    organization_id: UUID
    incident_number: str
    title: str
    description: str
    incident_type: IncidentType
    severity: IncidentSeverity
    status: IncidentStatus
    priority: IncidentPriority
    source: str
    assigned_to: Optional[UUID] = None
    created_by: Optional[UUID] = None
    affected_assets: List[str] = Field(default_factory=list)
    detected_at: datetime
    acknowledged_at: Optional[datetime] = None
    investigation_started_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    resolution_summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    linked_alerts_count: int = 0
    notes_count: int = 0
    evidence_count: int = 0
    attack_mappings_count: int = 0


# ------------------------------------------------------------------------------
# Alert Linking Schemas
# ------------------------------------------------------------------------------
class IncidentLinkAlertRequest(BaseModel):
    alert_id: UUID


class IncidentAlertResponse(BaseModel):
    id: UUID
    incident_id: UUID
    alert_id: UUID
    linked_by: Optional[UUID] = None
    linked_at: datetime
    alert_title: Optional[str] = None
    alert_severity: Optional[str] = None
    alert_status: Optional[str] = None


# ------------------------------------------------------------------------------
# Note & Timeline Schemas
# ------------------------------------------------------------------------------
class IncidentNoteCreate(BaseModel):
    note: str = Field(..., min_length=1, max_length=5000)


class IncidentNoteResponse(BaseModel):
    id: UUID
    incident_id: UUID
    author_id: Optional[UUID] = None
    note: str
    created_at: datetime
    updated_at: datetime


class IncidentTimelineResponse(BaseModel):
    id: UUID
    incident_id: UUID
    event_type: str
    description: str
    actor_id: Optional[UUID] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


# ------------------------------------------------------------------------------
# MITRE ATT&CK Schemas
# ------------------------------------------------------------------------------
class AttackTacticResponse(BaseModel):
    id: str
    name: str
    description: str
    reference_url: str


class AttackTechniqueResponse(BaseModel):
    id: str
    name: str
    tactic_id: str
    tactic_name: str
    description: str
    platforms: List[str] = Field(default_factory=list)
    reference_url: str


class IncidentAttackMappingCreate(BaseModel):
    technique_id: str
    confidence: int = Field(80, ge=1, le=100)
    evidence: Optional[str] = None


class IncidentAttackMappingResponse(BaseModel):
    id: UUID
    incident_id: UUID
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    confidence: int
    evidence: Optional[str] = None
    created_by: Optional[UUID] = None
    created_at: datetime


# ------------------------------------------------------------------------------
# Evidence Schemas
# ------------------------------------------------------------------------------
EvidenceType = Literal["log", "document", "screenshot", "network_capture", "forensic_artifact", "other"]

class IncidentEvidenceCreate(BaseModel):
    evidence_name: str = Field(..., min_length=2, max_length=255)
    evidence_type: EvidenceType = "document"
    original_filename: str
    mime_type: str
    file_bytes_base64: Optional[str] = None
    file_size: Optional[int] = None
    description: Optional[str] = None


class IncidentEvidenceResponse(BaseModel):
    id: UUID
    incident_id: UUID
    organization_id: UUID
    evidence_name: str
    evidence_type: EvidenceType
    original_filename: str
    mime_type: str
    file_size: int
    sha256_hash: str
    storage_path: str
    download_url: Optional[str] = None
    uploaded_by: Optional[UUID] = None
    description: Optional[str] = None
    uploaded_at: datetime


# ------------------------------------------------------------------------------
# Playbook Schemas
# ------------------------------------------------------------------------------
PlaybookCategory = Literal[
    "authentication",
    "malware",
    "phishing",
    "vulnerability",
    "ransomware",
    "network",
    "custom",
]

class PlaybookStepItem(BaseModel):
    step_number: int
    step_title: str
    step_description: str
    is_required: bool = True


class PlaybookCreate(BaseModel):
    playbook_name: str = Field(..., min_length=3, max_length=255)
    category: PlaybookCategory
    description: str
    steps: List[PlaybookStepItem] = Field(default_factory=list)


class PlaybookStepResponse(BaseModel):
    id: UUID
    step_number: int
    step_title: str
    step_description: str
    is_required: bool


class PlaybookResponse(BaseModel):
    id: UUID
    organization_id: UUID
    playbook_name: str
    category: PlaybookCategory
    description: str
    is_enabled: bool
    created_at: datetime
    updated_at: datetime
    steps: List[PlaybookStepResponse] = Field(default_factory=list)


class IncidentPlaybookAttachRequest(BaseModel):
    playbook_id: UUID
    assigned_to: Optional[UUID] = None


class StepProgressUpdate(BaseModel):
    status: Literal["Pending", "In Progress", "Completed", "Skipped"]
    notes: Optional[str] = None


class StepProgressResponse(BaseModel):
    id: UUID
    step_id: UUID
    step_number: int
    step_title: str
    status: str
    notes: Optional[str] = None
    completed_by: Optional[UUID] = None
    completed_at: Optional[datetime] = None


class IncidentPlaybookResponse(BaseModel):
    id: UUID
    incident_id: UUID
    playbook_id: UUID
    playbook_name: str
    category: str
    status: str
    assigned_to: Optional[UUID] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    step_progress: List[StepProgressResponse] = Field(default_factory=list)


# ------------------------------------------------------------------------------
# Response Request & Approval Schemas
# ------------------------------------------------------------------------------
ResponseActionType = Literal[
    "isolate_asset",
    "disable_account",
    "block_firewall_rule",
    "remediate_vulnerability",
    "escalate_incident",
]

class ResponseRequestCreate(BaseModel):
    action_type: ResponseActionType
    target_resource: str = Field(..., min_length=1, max_length=255)
    justification: str = Field(..., min_length=5, max_length=2000)


class ResponseDecisionRequest(BaseModel):
    decision_notes: str = Field(..., min_length=3, max_length=2000)


class ResponseApprovalResponse(BaseModel):
    id: UUID
    request_id: UUID
    decision: Literal["Approved", "Rejected"]
    decision_notes: str
    decided_by: Optional[UUID] = None
    decided_at: datetime


class ResponseRequestResponse(BaseModel):
    id: UUID
    incident_id: UUID
    organization_id: UUID
    action_type: ResponseActionType
    target_resource: str
    justification: str
    status: Literal["Pending", "Approved", "Rejected"]
    requested_by: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime
    approval: Optional[ResponseApprovalResponse] = None
