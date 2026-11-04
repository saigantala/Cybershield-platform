from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field

DetectionCategory = Literal[
    "network_anomaly",
    "suspicious_outbound",
    "unusual_port",
    "repeated_auth_failures",
    "ueba_deviation",
    "threat_intel_match",
    "vulnerability_exposure",
    "unusual_traffic_volume",
]

DetectionSeverity = Literal["Critical", "High", "Medium", "Low"]

DetectionMethod = Literal[
    "ml_isolation_forest",
    "statistical_baseline",
    "deterministic_rule",
    "ueba_behavioral",
]

RuleType = Literal[
    "statistical_threshold",
    "behavioral_deviation",
    "ioc_matching",
    "event_correlation",
]

InvestigationStatus = Literal[
    "New",
    "Reviewing",
    "Confirmed Suspicious",
    "False Positive",
    "Escalated",
    "Resolved",
]

# ------------------------------------------------------------------------------
# 1. MODELS & VERSIONS
# ------------------------------------------------------------------------------
class AIModelVersionResponse(BaseModel):
    id: str
    model_id: str
    version: str
    dataset_reference: Optional[str] = None
    training_samples_count: int
    hyperparameters: Dict[str, Any] = {}
    evaluation_metrics: Dict[str, float] = {}  # precision, recall, f1, false_positive_rate, detection_rate
    is_active: bool
    trained_at: str
    deployed_at: Optional[str] = None

class AIDetectionModelResponse(BaseModel):
    id: str
    organization_id: str
    model_name: str
    model_type: str  # isolation_forest, statistical_baseline, ueba_ensemble, rule_engine
    description: Optional[str] = None
    active_version: str
    status: str  # active, deprecated, training, evaluating
    is_production_ready: bool
    evaluation_metrics: Dict[str, float] = {}
    created_at: str
    updated_at: str

class AIDetectionModelCreate(BaseModel):
    model_name: str = Field(..., min_length=2, max_length=128)
    model_type: str
    description: Optional[str] = None
    version: str = "1.0.0"
    hyperparameters: Dict[str, Any] = {}
    is_production_ready: bool = False

# ------------------------------------------------------------------------------
# 2. DETECTION RULES
# ------------------------------------------------------------------------------
class AIDetectionRuleCreate(BaseModel):
    rule_name: str = Field(..., min_length=2, max_length=128)
    rule_type: RuleType
    description: Optional[str] = None
    severity: DetectionSeverity = "High"
    data_sources: List[str] = ["network_monitoring", "auth_events"]
    threshold_config: Dict[str, Any] = {}
    evaluation_interval_seconds: int = 300
    is_enabled: bool = True

class AIDetectionRuleUpdate(BaseModel):
    rule_name: Optional[str] = None
    rule_type: Optional[RuleType] = None
    description: Optional[str] = None
    severity: Optional[DetectionSeverity] = None
    data_sources: Optional[List[str]] = None
    threshold_config: Optional[Dict[str, Any]] = None
    evaluation_interval_seconds: Optional[int] = None
    is_enabled: Optional[bool] = None

class AIDetectionRuleResponse(BaseModel):
    id: str
    organization_id: str
    rule_name: str
    rule_type: RuleType
    description: Optional[str] = None
    severity: DetectionSeverity
    data_sources: List[str]
    threshold_config: Dict[str, Any]
    evaluation_interval_seconds: int
    is_enabled: bool
    matched_events_count: int
    false_positive_count: int
    created_at: str
    updated_at: str

# ------------------------------------------------------------------------------
# 3. DETECTION RESULTS & ANALYZE
# ------------------------------------------------------------------------------
class AIDetectionAnalyzeRequest(BaseModel):
    asset_id: Optional[str] = None
    telemetry_window_minutes: int = 60
    force_model_type: Optional[DetectionMethod] = None
    synthetic_telemetry: Optional[Dict[str, Any]] = None

class AIDetectionResultResponse(BaseModel):
    id: str
    organization_id: str
    source_asset_id: Optional[str] = None
    source_asset_name: Optional[str] = None
    detection_category: DetectionCategory
    severity: DetectionSeverity
    confidence_score: float
    anomaly_score: float
    detection_method: DetectionMethod
    supporting_evidence: Dict[str, Any]
    recommended_investigation: Optional[str] = None
    model_version: str
    status: str
    detected_at: str
    created_at: str

# ------------------------------------------------------------------------------
# 4. INVESTIGATIONS & FEEDBACK
# ------------------------------------------------------------------------------
class AIDetectionInvestigationCreate(BaseModel):
    detection_id: str
    analyst_notes: Optional[str] = None
    status: InvestigationStatus = "Reviewing"

class AIDetectionInvestigationUpdate(BaseModel):
    status: Optional[InvestigationStatus] = None
    analyst_notes: Optional[str] = None
    findings_summary: Optional[str] = None

class AIDetectionInvestigationResponse(BaseModel):
    id: str
    organization_id: str
    detection_id: str
    detection: Optional[AIDetectionResultResponse] = None
    status: InvestigationStatus
    assigned_analyst: Optional[str] = None
    analyst_notes: Optional[str] = None
    findings_summary: Optional[str] = None
    timeline_events: List[Dict[str, Any]] = []
    confirmed_at: Optional[str] = None
    resolved_at: Optional[str] = None
    created_at: str
    updated_at: str

class AIFeedbackCreate(BaseModel):
    detection_id: str
    verdict: Literal["true_positive", "false_positive", "benign_anomaly"]
    notes: Optional[str] = None

class AIFeedbackResponse(BaseModel):
    id: str
    organization_id: str
    detection_id: str
    analyst_id: Optional[str] = None
    verdict: str
    notes: Optional[str] = None
    created_at: str

# ------------------------------------------------------------------------------
# 5. RISK PREDICTION & ANALYTICS
# ------------------------------------------------------------------------------
class AIRiskPredictionResponse(BaseModel):
    id: str
    organization_id: str
    asset_id: str
    asset_name: Optional[str] = None
    asset_ip: Optional[str] = None
    risk_score: int  # 0 to 100
    risk_level: DetectionSeverity
    risk_trend: Literal["increasing", "stable", "decreasing"]
    contributing_factors: List[Dict[str, Any]]
    confidence_score: float
    data_coverage_score: float
    recommended_remediation_priority: str  # P1, P2, P3, P4
    predicted_at: str

class AIThreatAnalyticsResponse(BaseModel):
    total_detections_count: int
    critical_detections_count: int
    active_anomalies_count: int
    false_positive_rate_percent: float
    mean_confidence_score: float
    investigations_in_progress: int
    detections_by_category: Dict[str, int]
    daily_anomaly_volume: List[Dict[str, Any]]
    model_health_overview: List[Dict[str, Any]]

# ------------------------------------------------------------------------------
# 6. AI THREAT INVESTIGATION ASSISTANT
# ------------------------------------------------------------------------------
class AIThreatInvestigationQueryRequest(BaseModel):
    query: str = Field(..., min_length=3, max_length=1000)
    detection_id: Optional[str] = None
    asset_id: Optional[str] = None
    conversation_id: Optional[str] = None

class AIThreatInvestigationQueryResponse(BaseModel):
    conversation_id: str
    message_id: str
    answer: str
    evidence_citations: List[Dict[str, Any]]
    related_records: Dict[str, List[str]]  # asset_ids, alert_ids, vuln_ids, cve_ids
    recommended_next_steps: List[str]
    confidence_and_uncertainty: str
    created_at: str
