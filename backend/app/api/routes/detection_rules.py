import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.services.supabase_service import SupabaseService
from app.threat_intelligence.models import (
    DetectionRuleCreate,
    DetectionRuleResponse,
    DetectionRuleUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/detection-rules", tags=["Detection Rules"])


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


@router.get("", response_model=List[DetectionRuleResponse])
async def list_rules(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List all correlation detection rules configured for the organization."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await db_service.get_detection_rules(org_id)


@router.post("", response_model=DetectionRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: DetectionRuleCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Create a new detection rule. Requires role 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin"],
    )

    return await db_service.create_detection_rule(org_id, current_user.user_id, payload)


@router.patch("/{rule_id}", response_model=DetectionRuleResponse)
async def update_rule(
    rule_id: UUID,
    payload: DetectionRuleUpdate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Update rule thresholds, parameters or severity. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin"],
    )

    rule = await db_service.update_detection_rule(org_id, str(rule_id), payload)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found",
        )
    return rule


@router.post("/{rule_id}/enable", response_model=DetectionRuleResponse)
async def enable_rule(
    rule_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Enable a detection rule."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin"],
    )

    rule = await db_service.toggle_detection_rule(org_id, str(rule_id), is_enabled=True)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found",
        )
    return rule


@router.post("/{rule_id}/disable", response_model=DetectionRuleResponse)
async def disable_rule(
    rule_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Disable a detection rule."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin"],
    )

    rule = await db_service.toggle_detection_rule(org_id, str(rule_id), is_enabled=False)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection rule not found",
        )
    return rule
