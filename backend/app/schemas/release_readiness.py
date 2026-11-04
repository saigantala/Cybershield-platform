"""
Enterprise Release Readiness Schemas
CyberShield Sprint 20
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

ReleaseCheckStatus = Literal["passed", "failed", "warning", "not_tested", "requires_configuration"]
ReleaseGateStatus = Literal["ready_for_release", "release_blocked", "conditionally_ready"]

class ReleaseCheckItem(BaseModel):
    check_id: str
    category: str
    name: str
    description: str
    status: ReleaseCheckStatus
    evidence_or_details: str
    remediation_or_action: Optional[str] = None
    tested_at: datetime = Field(default_factory=datetime.utcnow)

class SecurityEngineStatus(BaseModel):
    engine_name: str
    engine_type: str
    classification: Literal[
        "configured",
        "connected_and_verified",
        "disconnected",
        "configuration_required",
        "mock_demo",
        "error"
    ]
    details: str
    version_or_provider: Optional[str] = None
    execution_mode: str = "automated"

class EnterpriseReleaseOverview(BaseModel):
    release_version: str = "v1.0.0-enterprise"
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
    gate_status: ReleaseGateStatus
    readiness_score: float = Field(..., ge=0.0, le=100.0)
    total_checks: int
    passed_checks: int
    failed_checks: int
    warning_checks: int
    config_required_checks: int
    checks_by_category: Dict[str, List[ReleaseCheckItem]]
    security_engines: List[SecurityEngineStatus]
    system_metrics: Dict[str, Any]
    active_environment: str = "enterprise_release"
    summary_verdict: str
