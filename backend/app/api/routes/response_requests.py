import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.incident import (
    ResponseRequestCreate,
    ResponseRequestResponse,
    ResponseDecisionRequest,
)
from app.services.supabase_service import SupabaseService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Response Approval Workflow"])


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

    target_org_id = (
        str(org_id_param) if org_id_param else str(memberships[0]["organization_id"])
    )
    has_access, role = await db_service.verify_org_access(
        user.user_id, target_org_id, allowed_roles
    )

    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {role}",
        )
    return target_org_id


@router.get("/response-requests", response_model=List[ResponseRequestResponse])
async def list_response_requests(
    incident_id: Optional[UUID] = Query(None),
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List response requests submitted across the organization."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_response_requests(
        org_id=org_id,
        incident_id=str(incident_id) if incident_id else None,
    )


@router.post(
    "/incidents/{incident_id}/response-requests",
    response_model=ResponseRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_response_request(
    incident_id: UUID,
    payload: ResponseRequestCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Submit a response action request (e.g. isolate asset, disable account) requiring admin approval."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    try:
        return await db_service.create_response_request(
            org_id=org_id,
            incident_id=str(incident_id),
            action_type=payload.action_type,
            target_resource=payload.target_resource,
            justification=payload.justification,
            requested_by=current_user.user_id,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.post("/response-requests/{request_id}/approve", response_model=ResponseRequestResponse)
async def approve_response_request(
    request_id: UUID,
    payload: ResponseDecisionRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Authorize a response action with mandatory approval notes. Strictly reserved for Owners and Admins."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin"],
    )

    decided = await db_service.decide_response_request(
        org_id=org_id,
        request_id=str(request_id),
        decision="Approved",
        decision_notes=payload.decision_notes,
        decided_by=current_user.user_id,
    )
    if not decided:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Response request not found",
        )
    return decided


@router.post("/response-requests/{request_id}/reject", response_model=ResponseRequestResponse)
async def reject_response_request(
    request_id: UUID,
    payload: ResponseDecisionRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Reject a response action request with mandatory justification notes."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin"],
    )

    decided = await db_service.decide_response_request(
        org_id=org_id,
        request_id=str(request_id),
        decision="Rejected",
        decision_notes=payload.decision_notes,
        decided_by=current_user.user_id,
    )
    if not decided:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Response request not found",
        )
    return decided
