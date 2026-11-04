"""
Enterprise Release Readiness Route
CyberShield Sprint 20
"""

from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.release_readiness import EnterpriseReleaseOverview
from app.services.release_readiness_service import release_readiness_service
from app.services.supabase_service import SupabaseService, supabase_service

router = APIRouter(prefix="/release-readiness", tags=["Enterprise Release Readiness"])


async def _resolve_org(
    db_service: SupabaseService,
    user: AuthenticatedUser,
    org_id_param: Optional[UUID] = None,
) -> str:
    memberships = await db_service.get_user_org_membership(user.user_id)
    if not memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User does not belong to any authorized organization",
        )

    target_org_id = str(org_id_param) if org_id_param else str(memberships[0]["organization_id"])
    has_access, role = await db_service.verify_org_access(user.user_id, target_org_id)
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {role}",
        )
    return target_org_id


@router.get("", response_model=EnterpriseReleaseOverview)
async def get_release_readiness_overview(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
) -> EnterpriseReleaseOverview:
    """Returns honest, multi-factor release readiness criteria across all platform tiers."""
    target_org_id = await _resolve_org(db, user, org_id)
    return release_readiness_service.evaluate_release_readiness(target_org_id)
