from datetime import date, datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID
from pydantic import BaseModel, Field

AssessmentStatus = Literal["Not Assessed", "Partially Implemented", "Implemented", "Not Applicable"]


class ComplianceFrameworkResponse(BaseModel):
    id: str
    framework_code: str
    name: str
    version: str
    description: Optional[str] = None
    category: str = "Cybersecurity"
    total_controls: int = 0
    implemented_controls: int = 0
    partially_implemented: int = 0
    not_assessed: int = 0
    completion_percentage: float = 0.0


class ComplianceControlResponse(BaseModel):
    id: str
    framework_id: str
    framework_code: str
    control_id: str
    title: str
    description: str
    domain: Optional[str] = None
    remediation_guidance: Optional[str] = None
    current_status: AssessmentStatus = "Not Assessed"
    assigned_owner: Optional[str] = None
    review_date: Optional[str] = None
    notes: Optional[str] = None
    evidence_count: int = 0


class ComplianceAssessmentCreate(BaseModel):
    control_id: UUID
    status: AssessmentStatus = "Not Assessed"
    assigned_owner: Optional[str] = None
    review_date: Optional[date] = None
    notes: Optional[str] = None
    remediation_notes: Optional[str] = None


class ComplianceAssessmentUpdate(BaseModel):
    status: Optional[AssessmentStatus] = None
    assigned_owner: Optional[str] = None
    review_date: Optional[date] = None
    notes: Optional[str] = None
    remediation_notes: Optional[str] = None


class ComplianceAssessmentResponse(BaseModel):
    id: str
    organization_id: str
    control_id: str
    framework_id: str
    framework_code: str
    control_code: str
    control_title: str
    status: AssessmentStatus
    assigned_owner: Optional[str] = None
    review_date: Optional[str] = None
    notes: Optional[str] = None
    remediation_notes: Optional[str] = None
    evidence_count: int = 0
    created_at: str
    updated_at: str


class ComplianceEvidenceCreate(BaseModel):
    control_id: Optional[UUID] = None
    assessment_id: Optional[UUID] = None
    file_name: str = Field(..., min_length=1, max_length=255)
    file_size: int = Field(..., gt=0, le=26214400)  # max 25MB
    mime_type: str
    description: Optional[str] = None


class ComplianceEvidenceResponse(BaseModel):
    id: str
    organization_id: str
    control_id: Optional[str] = None
    assessment_id: Optional[str] = None
    file_name: str
    file_size: int
    mime_type: str
    sha256_hash: str
    storage_path: str
    description: Optional[str] = None
    uploaded_by: Optional[str] = None
    uploaded_at: str


class ComplianceSummaryResponse(BaseModel):
    organization_id: str
    overall_compliance_score: float
    total_controls: int
    implemented_count: int
    partially_implemented_count: int
    not_assessed_count: int
    not_applicable_count: int
    framework_breakdown: List[Dict[str, Any]]
    overdue_assessments_count: int
    recent_activity: List[Dict[str, Any]]
