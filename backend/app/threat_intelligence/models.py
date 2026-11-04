from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


IOCType = Literal["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5"]
ThreatCategory = Literal[
    "malware", "phishing", "c2", "botnet", "exploit", "suspicious", "ransomware"
]
SeverityLevel = Literal["Critical", "High", "Medium", "Low", "Informational"]
EventSourceType = Literal[
    "network_discovery",
    "vulnerability_scanner",
    "auth",
    "app_audit",
    "telemetry",
    "manual",
]
AlertStatus = Literal["New", "Investigating", "Escalated", "Resolved", "False Positive"]
RuleType = Literal[
    "auth_failure_threshold",
    "threat_intel_match",
    "vuln_risk_correlation",
    "asset_anomaly",
    "repeated_suspicious_events",
]


# ------------------------------------------------------------------------------
# 1. Threat Indicator Models
# ------------------------------------------------------------------------------
class ThreatIndicatorCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    indicator_type: IOCType
    indicator_value: str
    source: str = "Manual Ingestion"
    threat_category: ThreatCategory = "suspicious"
    confidence: int = Field(80, ge=0, le=100)
    severity: SeverityLevel = "High"
    description: Optional[str] = None
    reference_url: Optional[str] = None
    expires_in_days: Optional[int] = Field(90, ge=1, le=365)


class ThreatIndicatorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    indicator_type: IOCType
    indicator_value: str
    source: str
    threat_category: ThreatCategory
    confidence: int
    severity: SeverityLevel
    first_seen: datetime
    last_seen: datetime
    expires_at: Optional[datetime] = None
    description: Optional[str] = None
    reference_url: Optional[str] = None
    created_at: datetime


# ------------------------------------------------------------------------------
# 2. Threat Feed Models
# ------------------------------------------------------------------------------
class ThreatFeedResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    feed_name: str
    feed_provider: str
    feed_url: Optional[str] = None
    is_enabled: bool
    sync_interval_hours: int
    last_sync_at: Optional[datetime] = None
    last_sync_status: str
    indicators_count: int = 0
    error_message: Optional[str] = None
    created_at: datetime


# ------------------------------------------------------------------------------
# 3. Security Event Models
# ------------------------------------------------------------------------------
class SecurityEventCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source: EventSourceType
    event_type: str
    severity: SeverityLevel = "Informational"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    asset_id: Optional[UUID] = None
    event_description: str
    event_timestamp: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    source: EventSourceType
    event_type: str
    severity: SeverityLevel
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    asset_id: Optional[UUID] = None
    event_description: str
    event_timestamp: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


# ------------------------------------------------------------------------------
# 4. Detection Rule Models
# ------------------------------------------------------------------------------
class DetectionRuleCreate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rule_name: str
    description: Optional[str] = None
    severity: SeverityLevel = "High"
    rule_type: RuleType
    is_enabled: bool = True
    threshold: int = Field(5, ge=1)
    time_window_seconds: int = Field(300, ge=10, le=86400)
    event_conditions: Dict[str, Any] = Field(default_factory=dict)


class DetectionRuleUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rule_name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[SeverityLevel] = None
    threshold: Optional[int] = Field(None, ge=1)
    time_window_seconds: Optional[int] = Field(None, ge=10, le=86400)
    event_conditions: Optional[Dict[str, Any]] = None
    is_enabled: Optional[bool] = None


class DetectionRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    rule_name: str
    description: Optional[str] = None
    severity: SeverityLevel
    rule_type: RuleType
    is_enabled: bool
    threshold: int
    time_window_seconds: int
    event_conditions: Dict[str, Any]
    last_triggered_at: Optional[datetime] = None
    created_by: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime


# ------------------------------------------------------------------------------
# 5. Alert Models
# ------------------------------------------------------------------------------
class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    title: str
    description: str
    alert_type: str
    severity: SeverityLevel
    status: AlertStatus
    source: str
    asset_id: Optional[UUID] = None
    indicator_id: Optional[UUID] = None
    rule_id: Optional[UUID] = None
    related_event_ids: List[UUID] = Field(default_factory=list)
    assigned_to: Optional[UUID] = None
    linked_incident_id: Optional[UUID] = None
    confidence: int = 80
    first_detected_at: datetime
    last_detected_at: datetime
    created_at: datetime
    updated_at: datetime


class AlertUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    status: Optional[AlertStatus] = None
    severity: Optional[SeverityLevel] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)


class AlertAssignRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    assigned_to: UUID


class AlertNoteRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    note: str = Field(..., min_length=1)


class AlertLinkIncidentRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: UUID


class AlertNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_id: UUID
    author_id: Optional[UUID] = None
    note: str
    created_at: datetime


# ------------------------------------------------------------------------------
# 6. Overview & Stats
# ------------------------------------------------------------------------------
class ThreatIntelOverviewResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total_indicators: int = 0
    malicious_ips: int = 0
    malicious_domains: int = 0
    malicious_urls: int = 0
    malicious_hashes: int = 0
    high_confidence_count: int = 0
    feed_updates_count: int = 0
    type_distribution: Dict[str, int] = Field(default_factory=dict)
    recent_indicators: List[ThreatIndicatorResponse] = Field(default_factory=list)
