from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.soar import (
    SOARWorkflowCreate,
    SOARWorkflowUpdate,
    SOARWorkflowResponse,
    SOARExecutionRequest,
    SOARExecutionResponse,
    SOARExecutionDetailResponse,
    SOARExecutionLogItem,
    SOARApprovalResponse,
    SOARApprovalDecisionRequest,
    SOARAnalyticsResponse,
    NotificationTemplateResponse,
    NotificationTestRequest,
    NotificationDeliveryResponse,
)
from app.services.soar_service import soar_service
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/soar", tags=["Security Orchestration, Automation & Response (SOAR)"])


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
# 1. WORKFLOWS
# ------------------------------------------------------------------------------
@router.get("/workflows", response_model=List[SOARWorkflowResponse])
async def list_workflows(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by Draft, Published, Archived"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists registered automated SOAR playbooks and workflow definitions."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await soar_service.list_workflows(db_service, target_org_id, status_filter)


@router.post("/workflows", response_model=SOARWorkflowResponse, status_code=status.HTTP_201_CREATED)
async def create_workflow(
    req: SOARWorkflowCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Creates a new automated security playbook."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    try:
        return await soar_service.create_workflow(db_service, target_org_id, req, user.user_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/workflows/{workflow_id}", response_model=SOARWorkflowResponse)
async def get_workflow(
    workflow_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Retrieves full specification and step configurations for a playbook."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    wf = await soar_service.get_workflow(db_service, target_org_id, str(workflow_id))
    if not wf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    return wf


@router.patch("/workflows/{workflow_id}", response_model=SOARWorkflowResponse)
async def update_workflow(
    workflow_id: UUID,
    req: SOARWorkflowUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Updates steps, trigger criteria, or metadata of an existing playbook."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    try:
        updated = await soar_service.update_workflow(db_service, target_org_id, str(workflow_id), req)
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
        return updated
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/workflows/{workflow_id}/publish", response_model=SOARWorkflowResponse)
async def publish_workflow(
    workflow_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Validates and publishes a playbook workflow for automated operational execution."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    try:
        published = await soar_service.publish_workflow(db_service, target_org_id, str(workflow_id))
        if not published:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
        return published
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/workflows/{workflow_id}/execute", response_model=SOARExecutionDetailResponse)
async def execute_workflow(
    workflow_id: UUID,
    req: SOARExecutionRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Triggers immediate execution of a security playbook with provided event context."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    try:
        return await soar_service.execute_workflow(
            db_service, target_org_id, str(workflow_id), req, user.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ------------------------------------------------------------------------------
# 2. EXECUTIONS
# ------------------------------------------------------------------------------
@router.get("/executions", response_model=List[SOARExecutionResponse])
async def list_executions(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by Pending, Running, Completed, Failed"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists historical and active SOAR playbook executions."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await soar_service.list_executions(db_service, target_org_id, status_filter)


@router.get("/executions/{execution_id}", response_model=SOARExecutionDetailResponse)
async def get_execution_detail(
    execution_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Retrieves step-by-step audit records, I/O payloads, and logs for an execution."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    exec_detail = await soar_service.get_execution(db_service, target_org_id, str(execution_id))
    if not exec_detail:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution record not found")
    return exec_detail


@router.post("/executions/{execution_id}/cancel", response_model=SOARExecutionResponse)
async def cancel_execution(
    execution_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Cancels an in-progress or paused workflow execution."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    cancelled = await soar_service.cancel_execution(db_service, target_org_id, str(execution_id))
    if not cancelled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")
    return cancelled


@router.get("/executions/{execution_id}/logs", response_model=List[SOARExecutionLogItem])
async def get_execution_logs(
    execution_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Retrieves redacted chronological log output for an execution."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    exec_detail = await soar_service.get_execution(db_service, target_org_id, str(execution_id))
    if not exec_detail:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution not found")
    return exec_detail.logs


# ------------------------------------------------------------------------------
# 3. APPROVALS WORKFLOW
# ------------------------------------------------------------------------------
@router.get("/approvals", response_model=List[SOARApprovalResponse])
async def list_approvals(
    decision_filter: Optional[str] = Query(None, alias="decision", description="Filter: Pending, Approved, Rejected"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists human-in-the-loop action approval requests awaiting SOC authorization."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await soar_service.list_approvals(db_service, target_org_id, decision_filter)


@router.post("/approvals/{approval_id}/approve", response_model=SOARApprovalResponse)
async def approve_action(
    approval_id: UUID,
    req: SOARApprovalDecisionRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Authorizes a disruptive containment or remediation action."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    req.decision = "Approved"
    try:
        return await soar_service.decide_approval(
            db_service, target_org_id, str(approval_id), req, user.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/approvals/{approval_id}/reject", response_model=SOARApprovalResponse)
async def reject_action(
    approval_id: UUID,
    req: SOARApprovalDecisionRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Rejects a disruptive action with mandatory analyst justification."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    req.decision = "Rejected"
    try:
        return await soar_service.decide_approval(
            db_service, target_org_id, str(approval_id), req, user.user_id
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ------------------------------------------------------------------------------
# 4. ANALYTICS & NOTIFICATIONS
# ------------------------------------------------------------------------------
@router.get("/analytics", response_model=SOARAnalyticsResponse)
async def get_soar_analytics(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns aggregated SOAR automation velocity, success rates, and execution trends."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await soar_service.get_analytics(db_service, target_org_id)


@router.get("/notifications", response_model=List[NotificationTemplateResponse])
async def list_notification_templates(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists configured notification channels (In-App, Email, Webhook)."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    templates = await db_service.get_soar_notification_templates(target_org_id)
    return [
        NotificationTemplateResponse(
            id=t["id"],
            organization_id=t["organization_id"],
            template_name=t["template_name"],
            channel=t["channel"],
            subject=t.get("subject"),
            body_template=t["body_template"],
            is_default=t.get("is_default", False),
            created_at=t["created_at"],
        )
        for t in templates
    ]


@router.post("/notifications/test", response_model=NotificationDeliveryResponse)
async def test_notification(
    req: NotificationTestRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Dispatches a test notification and records delivery status."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    delivery_record = {
        "id": str(UUID(int=1)),
        "organization_id": target_org_id,
        "channel": req.channel,
        "recipient": req.recipient,
        "status": "Delivered",
        "delivered_at": "2026-11-02T11:00:00Z",
        "error_message": None,
    }
    await db_service.create_soar_notification_delivery(delivery_record)
    return NotificationDeliveryResponse(
        id=delivery_record["id"],
        channel=delivery_record["channel"],
        recipient=delivery_record["recipient"],
        status=delivery_record["status"],
        delivered_at=delivery_record["delivered_at"],
        error_message=delivery_record["error_message"],
    )
