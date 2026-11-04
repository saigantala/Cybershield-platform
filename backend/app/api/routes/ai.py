from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.ai.assistant import AIAssistant
from app.ai.alert_analyzer import AlertAIAnalyzer
from app.ai.incident_summarizer import IncidentAISummarizer
from app.ai.remediation_advisor import RemediationAdvisor
from app.ai.schemas import (
    AIChatRequest,
    AIChatResponse,
    AIConversationDetail,
    AIConversationSummary,
    AIUsageSummary,
    AlertAnalysisResponse,
    IncidentSummaryResponse,
    RecommendationReviewRequest,
    RemediationResponse,
)
from app.core.security import AuthenticatedUser, get_current_user
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/ai", tags=["AI SOC Assistant & Analytics"])


async def _resolve_org(
    db_service: SupabaseService,
    user: AuthenticatedUser,
    org_id_param: Optional[UUID] = None,
    allowed_roles: Optional[List[str]] = None,
) -> str:
    memberships = await db_service.get_user_org_membership(user.user_id)
    if not memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User does not belong to any authorized organization",
        )

    target_org_id = str(org_id_param) if org_id_param else str(memberships[0]["organization_id"])
    has_access, role = await db_service.verify_org_access(user.user_id, target_org_id, allowed_roles)

    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {role}",
        )
    return target_org_id


# ------------------------------------------------------------------------------
# Chat & Conversations
# ------------------------------------------------------------------------------
@router.post("/chat", response_model=AIChatResponse)
async def chat_with_assistant(
    payload: AIChatRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Interactive conversational chat with AI SOC Assistant with grounded context."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    conv_id_str = str(payload.conversation_id) if payload.conversation_id else None
    return await AIAssistant.chat(
        db_service=db_service,
        org_id=org_id,
        user_id=current_user.user_id,
        message=payload.message,
        conversation_id=conv_id_str,
    )


@router.get("/conversations", response_model=List[AIConversationSummary])
async def list_conversations(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List historical AI consultation conversations for the current user."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_ai_conversations(org_id=org_id, user_id=current_user.user_id)


@router.get("/conversations/{conversation_id}", response_model=AIConversationDetail)
async def get_conversation(
    conversation_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve full conversation message history."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    conv = await db_service.get_ai_conversation(org_id=org_id, conversation_id=str(conversation_id))
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found.")
    return conv


@router.delete("/conversations/{conversation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_conversation(
    conversation_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Delete an AI consultation conversation."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    deleted = await db_service.delete_ai_conversation(org_id=org_id, conversation_id=str(conversation_id))
    if not deleted:
        raise HTTPException(status_code=404, detail="Conversation not found.")
    return None


@router.post("/conversations/{conversation_id}/messages", response_model=AIChatResponse)
async def post_message_to_conversation(
    conversation_id: UUID,
    payload: AIChatRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Append user message to existing conversation and retrieve AI response."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await AIAssistant.chat(
        db_service=db_service,
        org_id=org_id,
        user_id=current_user.user_id,
        message=payload.message,
        conversation_id=str(conversation_id),
    )


# ------------------------------------------------------------------------------
# Alert AI Analyzer
# ------------------------------------------------------------------------------
@router.post("/analyze-alert/{alert_id}", response_model=AlertAnalysisResponse)
async def analyze_alert(
    alert_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Synthesize alert telemetry, false-positive considerations, and triage guidance."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service, current_user, organization_id, allowed_roles=["owner", "admin", "analyst"]
    )

    try:
        return await AlertAIAnalyzer.analyze_alert(
            db_service=db_service,
            org_id=org_id,
            alert_id=str(alert_id),
            user_id=current_user.user_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ------------------------------------------------------------------------------
# Incident AI Summarizer
# ------------------------------------------------------------------------------
@router.post("/summarize-incident/{incident_id}", response_model=IncidentSummaryResponse)
async def summarize_incident(
    incident_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Synthesize incident blast radius, timeline events, and remaining questions."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service, current_user, organization_id, allowed_roles=["owner", "admin", "analyst"]
    )

    try:
        return await IncidentAISummarizer.summarize_incident(
            db_service=db_service,
            org_id=org_id,
            incident_id=str(incident_id),
            user_id=current_user.user_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ------------------------------------------------------------------------------
# Remediation Advisor
# ------------------------------------------------------------------------------
@router.post("/recommend-remediation/{finding_id}", response_model=RemediationResponse)
async def recommend_remediation(
    finding_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Generate vendor-aligned remediation steps and testing procedures for a vulnerability."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service, current_user, organization_id, allowed_roles=["owner", "admin", "analyst"]
    )

    try:
        return await RemediationAdvisor.recommend_remediation(
            db_service=db_service,
            org_id=org_id,
            finding_id=str(finding_id),
            user_id=current_user.user_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/recommendations", response_model=List[Dict[str, Any]])
async def list_recommendations(
    recommendation_type: Optional[str] = Query(None),
    related_entity_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List AI security recommendations within the organization."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_ai_recommendations(
        org_id=org_id,
        recommendation_type=recommendation_type,
        related_entity_id=related_entity_id,
        status=status,
    )


@router.post("/recommendations/{recommendation_id}/review", response_model=Dict[str, Any])
async def review_recommendation(
    recommendation_id: UUID,
    payload: RecommendationReviewRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Approve or reject an AI-generated security recommendation."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service, current_user, organization_id, allowed_roles=["owner", "admin"]
    )

    rec = await db_service.review_ai_recommendation(
        org_id=org_id,
        recommendation_id=str(recommendation_id),
        reviewer_id=current_user.user_id,
        decision=payload.decision,
        notes=payload.review_notes,
    )
    if not rec:
        raise HTTPException(status_code=404, detail="Recommendation not found.")
    return rec


# ------------------------------------------------------------------------------
# AI Usage & Governance
# ------------------------------------------------------------------------------
@router.get("/usage", response_model=AIUsageSummary)
async def get_ai_usage(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve AI token consumption, request counts, and cost telemetry."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service, current_user, organization_id, allowed_roles=["owner", "admin"]
    )

    return await db_service.get_ai_usage_summary(org_id=org_id)
