from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

RiskClassification = Literal["Critical Risk", "High Risk", "Moderate Risk", "Low Risk", "Hardened"]


class PostureCategoryScores(BaseModel):
    vulnerability_management: float = Field(..., ge=0.0, le=100.0)
    perimeter_exposure: float = Field(..., ge=0.0, le=100.0)
    incident_readiness: float = Field(..., ge=0.0, le=100.0)
    threat_intel_coverage: float = Field(..., ge=0.0, le=100.0)
    compliance_posture: float = Field(..., ge=0.0, le=100.0)


class SecurityPostureResponse(BaseModel):
    organization_id: str
    overall_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: RiskClassification
    category_scores: PostureCategoryScores
    score_factors: List[Dict[str, Any]]
    recommended_improvements: List[str]
    score_history: List[Dict[str, Any]]
    calculated_at: str
    methodology_notes: str


class ExecutiveDashboardResponse(BaseModel):
    organization_id: str
    organization_name: str
    date_range: str
    security_score: float
    risk_classification: RiskClassification
    critical_vulnerabilities: int
    high_risk_assets: int
    open_incidents: int
    compliance_completion_percentage: float
    remediation_progress_percentage: float
    security_trend: List[Dict[str, Any]]
    top_5_security_risks: List[Dict[str, Any]]
    recent_security_events: List[Dict[str, Any]]
    recommended_actions: List[str]
