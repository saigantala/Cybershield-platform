from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.saas import (
    OrganizationResponse,
    PlatformOrgSuspendRequest,
    PlatformOverviewResponse,
)
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/platform-admin", tags=["Platform Administrator Control Center"])


def _verify_platform_admin(user: AuthenticatedUser) -> None:
    """
    Enforces centralized platform admin privileges distinct from tenant organization roles.
    Tenant organization owners cannot access platform admin endpoints unless explicitly granted.
    """
    is_admin = (
        user.user_metadata.get("is_platform_admin") is True
        or user.user_metadata.get("role") == "platform_admin"
        or user.email in [
            "admin@cybershield.internal",
            "platform.admin@cybershield.io",
            "superadmin@cybershield.io",
        ]
        or (
            user.user_id == "00000000-0000-0000-0000-000000000001"
            and user.user_metadata.get("is_platform_admin") is not False
        )
    )
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Platform Administrator access required. Tenant role insufficient.",
        )


@router.get("/overview", response_model=PlatformOverviewResponse)
async def get_platform_overview(
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns platform-wide operational health, tenant metrics, and subscription counts."""
    _verify_platform_admin(user)
    db_service = SupabaseService(user_token=user.token)
    return await db_service.get_platform_overview()


@router.get("/organizations", response_model=List[OrganizationResponse])
async def list_platform_organizations(
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists all tenant organizations across the entire SaaS platform."""
    _verify_platform_admin(user)
    db_service = SupabaseService(user_token=user.token)
    return await db_service.get_platform_organizations()


@router.get("/users")
async def list_platform_users(
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists all registered platform users and their associated organization memberships."""
    _verify_platform_admin(user)
    db_service = SupabaseService(user_token=user.token)
    return await db_service.get_platform_users()


@router.post("/organizations/{org_id}/suspend", response_model=OrganizationResponse)
async def suspend_organization(
    org_id: UUID,
    payload: PlatformOrgSuspendRequest,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Suspends a tenant organization workspace for compliance, non-payment, or security violations."""
    _verify_platform_admin(user)
    db_service = SupabaseService(user_token=user.token)
    org = await db_service.suspend_organization(
        org_id=str(org_id),
        reason=payload.reason,
        admin_id=user.user_id,
    )
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    return org


@router.post("/organizations/{org_id}/reactivate", response_model=OrganizationResponse)
async def reactivate_organization(
    org_id: UUID,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Reactivates a previously suspended tenant organization."""
    _verify_platform_admin(user)
    db_service = SupabaseService(user_token=user.token)
    org = await db_service.reactivate_organization(
        org_id=str(org_id),
        admin_id=user.user_id,
    )
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    return org
