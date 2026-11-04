from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID
from pydantic import BaseModel, Field

ReportType = Literal[
    "vulnerability_assessment",
    "asset_inventory",
    "incident_summary",
    "threat_intelligence",
    "compliance_assessment",
    "security_posture",
    "executive_summary",
]

ReportFormat = Literal["pdf", "csv", "json"]
ReportStatus = Literal["Pending", "Processing", "Completed", "Failed"]


class ReportGenerateRequest(BaseModel):
    report_type: ReportType
    title: Optional[str] = Field(None, max_length=200)
    format: ReportFormat = "pdf"
    date_range: Optional[str] = "30d"  # 7d, 30d, 90d, custom
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    severity_filter: Optional[List[str]] = None
    asset_id: Optional[UUID] = None
    incident_status: Optional[str] = None


class SecurityReportResponse(BaseModel):
    id: str
    organization_id: str
    title: str
    report_type: str
    format: str
    status: ReportStatus
    parameters: Dict[str, Any] = Field(default_factory=dict)
    summary_metrics: Dict[str, Any] = Field(default_factory=dict)
    file_size_bytes: int = 0
    download_url: Optional[str] = None
    generated_by: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None


class ReportPreviewResponse(BaseModel):
    title: str
    report_type: str
    format: str
    generated_at: str
    organization_name: str
    executive_summary: str
    key_metrics: Dict[str, Any]
    sample_records: List[Dict[str, Any]]
    recommended_actions: List[str]
