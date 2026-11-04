from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID
from pydantic import BaseModel, Field


# ------------------------------------------------------------------------------
# Grounded Citation Reference Model
# ------------------------------------------------------------------------------
class SourceReference(BaseModel):
    source_type: Literal[
        "asset",
        "vulnerability",
        "cve",
        "cisa_kev",
        "threat_indicator",
        "security_event",
        "alert",
        "incident",
        "mitre_attack",
        "playbook",
    ]
    id: str
    name: str
    summary: Optional[str] = None
    severity: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


# ------------------------------------------------------------------------------
# Conversation & Chat Models
# ------------------------------------------------------------------------------
class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str
    source_references: List[SourceReference] = Field(default_factory=list)
    created_at: Optional[str] = None


class AIChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    conversation_id: Optional[UUID] = None
    context_filters: Optional[Dict[str, Any]] = Field(default_factory=dict)


class AIChatResponse(BaseModel):
    conversation_id: str
    message_id: str
    response: str
    source_references: List[SourceReference] = Field(default_factory=list)
    model: str
    provider: str
    is_mock: bool = True
    input_tokens: int = 0
    output_tokens: int = 0
    created_at: str


class AIConversationSummary(BaseModel):
    id: str
    organization_id: str
    user_id: str
    title: str
    message_count: int = 0
    created_at: str
    updated_at: str


class AIConversationDetail(BaseModel):
    id: str
    organization_id: str
    user_id: str
    title: str
    messages: List[ChatMessage] = Field(default_factory=list)
    created_at: str
    updated_at: str


# ------------------------------------------------------------------------------
# Alert AI Analyzer Models
# ------------------------------------------------------------------------------
class AlertAnalysisResponse(BaseModel):
    alert_id: str
    alert_title: str
    summary: str
    trigger_cause: str
    related_assets: List[str] = Field(default_factory=list)
    related_indicators: List[str] = Field(default_factory=list)
    severity_assessment: str
    false_positive_considerations: str
    investigation_steps: List[str] = Field(default_factory=list)
    suggested_priority: str
    supporting_evidence: List[str] = Field(default_factory=list)
    source_references: List[SourceReference] = Field(default_factory=list)
    model: str
    provider: str
    is_mock: bool = True
    generated_at: str


# ------------------------------------------------------------------------------
# Incident AI Summarizer Models
# ------------------------------------------------------------------------------
class IncidentSummaryResponse(BaseModel):
    incident_id: str
    incident_number: str
    overview: str
    timeline_summary: List[str] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    related_alerts: List[str] = Field(default_factory=list)
    mitre_mappings: List[str] = Field(default_factory=list)
    investigation_progress: str
    outstanding_questions: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)
    source_references: List[SourceReference] = Field(default_factory=list)
    model: str
    provider: str
    is_mock: bool = True
    generated_at: str


# ------------------------------------------------------------------------------
# AI Remediation Advisor Models
# ------------------------------------------------------------------------------
class RemediationResponse(BaseModel):
    id: str
    title: str
    explanation: str
    related_entity_type: str
    related_entity_id: str
    priority: str
    suggested_steps: List[str] = Field(default_factory=list)
    potential_impact: str
    verification_steps: List[str] = Field(default_factory=list)
    supporting_references: List[str] = Field(default_factory=list)
    confidence_notes: str
    status: str = "Pending Review"
    model: str
    provider: str
    is_mock: bool = True
    created_at: str


class RecommendationReviewRequest(BaseModel):
    decision: Literal["Approved", "Rejected"]
    review_notes: str = Field(..., min_length=3, max_length=1000)


# ------------------------------------------------------------------------------
# AI Usage & Analytics Models
# ------------------------------------------------------------------------------
class AIUsageSummary(BaseModel):
    organization_id: str
    total_requests: int
    total_input_tokens: int
    total_output_tokens: int
    total_tokens: int
    estimated_cost_usd: float
    provider_breakdown: Dict[str, Any] = Field(default_factory=dict)
    recent_logs: List[Dict[str, Any]] = Field(default_factory=list)
