from datetime import datetime
from typing import Any, Dict, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

ScanType = Literal[
    "network_discovery",
    "vulnerability_assessment",
    "web_baseline",
]

ScanProfile = Literal[
    "fast_discovery",
    "comprehensive_audit",
    "web_baseline_safe",
    "full_compliance",
]

ScanStatus = Literal[
    "queued",
    "running",
    "completed",
    "failed",
    "cancelled",
]


class ScanCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200, description="Name or label for this scan operation")
    type: ScanType = Field(default="network_discovery", description="Operational scan category")
    profile: ScanProfile = Field(default="fast_discovery", description="Execution profile & intensity")
    scope_id: Optional[UUID] = Field(None, description="Approved network scope UUID (source of truth)")
    target_scope: Optional[str] = Field(None, max_length=255, description="Target CIDR, IP or hostname")
    description: Optional[str] = None


class ScanEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: UUID
    event_type: str
    message: str
    created_at: datetime


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    scope_id: Optional[UUID] = None
    title: str
    type: ScanType
    profile: ScanProfile
    target_scope: str
    status: ScanStatus
    progress: int = 0
    hosts_discovered: int = 0
    findings_count: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    task_id: Optional[str] = None
    message: Optional[str] = None
