from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.saas import OrganizationCreate, OrganizationResponse, OrganizationUpdate
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/organizations", tags=["Organizations & Multi-Tenancy"])


@router.get("", response_model=List[OrganizationResponse])
async def list_organizations(
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists all organizations where the authenticated user is an active member."""
    db_service = SupabaseService(user_token=user.token)
    orgs = await db_service.get_user_organizations(user.user_id)
    return orgs


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Creates a new organization tenant workspace and designates the creator as Owner."""
    db_service = SupabaseService(user_token=user.token)
    org = await db_service.create_organization(
        name=payload.name,
        user_id=user.user_id,
        slug=payload.slug,
        description=payload.description,
        website=payload.website,
        industry=payload.industry,
        organization_size=payload.organization_size,
        country=payload.country,
        time_zone=payload.time_zone,
    )
    return org


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: UUID,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Retrieves metadata and subscription state for a specific organization."""
    db_service = SupabaseService(user_token=user.token)
    has_access, role = await db_service.verify_org_access(user.user_id, str(org_id))
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {role}",
        )

    org = await db_service.get_organization(str(org_id))
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    return org


@router.patch("/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: UUID,
    payload: OrganizationUpdate,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Updates organization profile. Requires 'owner' or 'admin' role."""
    db_service = SupabaseService(user_token=user.token)
    has_access, role = await db_service.verify_org_access(
        user.user_id, str(org_id), allowed_roles=["owner", "admin"]
    )
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {role}",
        )

    updated = await db_service.update_organization(str(org_id), payload.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    return updated


@router.post("/{org_id}/switch", response_model=OrganizationResponse)
async def switch_organization_context(
    org_id: UUID,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Validates user membership and switches active organization tenant context."""
    db_service = SupabaseService(user_token=user.token)
    has_access, role = await db_service.verify_org_access(user.user_id, str(org_id))
    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cannot switch to organization: {role}",
        )

    org = await db_service.get_organization(str(org_id))
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    return org
