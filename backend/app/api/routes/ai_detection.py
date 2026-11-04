from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.ai_detection import (
    AIDetectionAnalyzeRequest,
    AIDetectionModelCreate,
    AIDetectionModelResponse,
    AIDetectionResultResponse,
    AIDetectionRuleCreate,
    AIDetectionRuleResponse,
    AIDetectionRuleUpdate,
    AIDetectionInvestigationCreate,
    AIDetectionInvestigationResponse,
    AIDetectionInvestigationUpdate,
    AIFeedbackCreate,
    AIFeedbackResponse,
    AIModelVersionResponse,
    AIRiskPredictionResponse,
    AIThreatAnalyticsResponse,
    AIThreatInvestigationQueryRequest,
    AIThreatInvestigationQueryResponse,
)
from app.services.ai_threat_service import ai_threat_service
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/ai-detection", tags=["AI Threat Detection & Predictive Security Intelligence"])


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
# 1. DETECTION RESULTS & REAL-TIME ML INFERENCE
# ------------------------------------------------------------------------------
@router.get("/results", response_model=List[AIDetectionResultResponse])
async def list_detection_results(
    category: Optional[str] = Query(None, description="Filter by detection category"),
    severity: Optional[str] = Query(None, description="Filter by Critical, High, Medium, Low"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists threat detection results identified by ML Isolation Forest, UEBA baselines, and rules."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await ai_threat_service.list_results(db_service, target_org_id, category, severity)


@router.post("/analyze", response_model=AIDetectionResultResponse, status_code=status.HTTP_201_CREATED)
async def analyze_security_telemetry(
    req: AIDetectionAnalyzeRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Runs ML feature extraction, Isolation Forest inference, and UEBA variance evaluation on asset telemetry."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    return await ai_threat_service.analyze_telemetry(db_service, target_org_id, req, user.user_id)


@router.get("/results/{result_id}", response_model=AIDetectionResultResponse)
async def get_detection_result(
    result_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Retrieves full supporting evidence, feature weights, and anomaly scores for a detection."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    res = await ai_threat_service.get_result_by_id(db_service, target_org_id, str(result_id))
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection record not found")
    return res


# ------------------------------------------------------------------------------
# 2. DETECTION RULES
# ------------------------------------------------------------------------------
@router.get("/rules", response_model=List[AIDetectionRuleResponse])
async def list_detection_rules(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists statistical threshold, behavioral deviation, and IOC matching detection rules."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await ai_threat_service.list_rules(db_service, target_org_id)


@router.post("/rules", response_model=AIDetectionRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_detection_rule(
    req: AIDetectionRuleCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Creates a deterministic detection rule or behavioral threshold."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    return await ai_threat_service.create_rule(db_service, target_org_id, req, user.user_id)


@router.patch("/rules/{rule_id}", response_model=AIDetectionRuleResponse)
async def update_detection_rule(
    rule_id: UUID,
    req: AIDetectionRuleUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Updates rule thresholds, severity, enabled state, or evaluation interval."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    updated = await ai_threat_service.update_rule(db_service, target_org_id, str(rule_id), req)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return updated


# ------------------------------------------------------------------------------
# 3. INVESTIGATION WORKSPACE & FEEDBACK
# ------------------------------------------------------------------------------
@router.get("/investigations", response_model=List[AIDetectionInvestigationResponse])
async def list_investigations(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter: New, Reviewing, Confirmed Suspicious, False Positive, Resolved"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists detection investigations in the analyst triage workspace."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await ai_threat_service.list_investigations(db_service, target_org_id, status_filter)


@router.post("/investigations", response_model=AIDetectionInvestigationResponse, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    req: AIDetectionInvestigationCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Opens a formal investigation workspace case for an AI detection result."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    return await ai_threat_service.create_investigation(db_service, target_org_id, req, user.user_id)


@router.patch("/investigations/{inv_id}", response_model=AIDetectionInvestigationResponse)
async def update_investigation(
    inv_id: UUID,
    req: AIDetectionInvestigationUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Updates investigation findings, status, or confirmation notes."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    updated = await ai_threat_service.update_investigation(db_service, target_org_id, str(inv_id), req, user.user_id)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation case not found")
    return updated


@router.post("/feedback", response_model=AIFeedbackResponse, status_code=status.HTTP_201_CREATED)
async def submit_detection_feedback(
    req: AIFeedbackCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Submits analyst true/false positive feedback to calibrate models and tune rules."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    return await ai_threat_service.submit_feedback(db_service, target_org_id, req, user.user_id)


# ------------------------------------------------------------------------------
# 4. MODELS & VERSIONS REGISTRY
# ------------------------------------------------------------------------------
@router.get("/models", response_model=List[AIDetectionModelResponse])
async def list_models(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists registered anomaly detection and behavioral ML models with deployment status."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await ai_threat_service.list_models(db_service, target_org_id)


@router.post("/models", response_model=AIDetectionModelResponse, status_code=status.HTTP_201_CREATED)
async def register_model(
    req: AIDetectionModelCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Registers an ML model version with evaluation metrics."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    return await ai_threat_service.register_model(db_service, target_org_id, req)


@router.get("/models/{model_id}/versions", response_model=List[AIModelVersionResponse])
async def get_model_versions(
    model_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Retrieves revision history and evaluation metrics (Precision, Recall, F1) for a model."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await ai_threat_service.get_model_versions(db_service, target_org_id, str(model_id))


# ------------------------------------------------------------------------------
# 5. RISK PREDICTIONS & ANALYTICS
# ------------------------------------------------------------------------------
@router.get("/risk-predictions", response_model=List[AIRiskPredictionResponse])
async def get_risk_predictions(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns predictive asset risk scores, trends, and key contributing factor breakdowns."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await ai_threat_service.get_risk_predictions(db_service, target_org_id)


@router.get("/analytics", response_model=AIThreatAnalyticsResponse)
async def get_ai_threat_analytics(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns AI detection velocity, false-positive rates, model health, and category breakdowns."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await ai_threat_service.get_analytics(db_service, target_org_id)


# ------------------------------------------------------------------------------
# 6. AI THREAT INVESTIGATION ASSISTANT
# ------------------------------------------------------------------------------
@router.post("/investigation-assistant/chat", response_model=AIThreatInvestigationQueryResponse)
async def query_investigation_assistant(
    req: AIThreatInvestigationQueryRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Queries the AI SOC Investigation Assistant for evidence, CVE correlations, and next steps."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await ai_threat_service.query_investigation_assistant(db_service, target_org_id, req, user.user_id)
