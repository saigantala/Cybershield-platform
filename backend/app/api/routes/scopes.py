from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.scope import ScopeApprove, ScopeCreate, ScopeResponse
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/scopes", tags=["Scopes"])


async def _resolve_org(
    db_service: SupabaseService,
    user: AuthenticatedUser,
    org_id_param: Optional[UUID] = None,
    allowed_roles: Optional[List[str]] = None,
) -> tuple[str, str]:
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
    return target_org_id, role


@router.get("", response_model=List[ScopeResponse])
async def list_scopes(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    List registered assessment scopes for an organization.
    Available to all organization members (owner, admin, analyst, viewer).
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id, _ = await _resolve_org(db_service, current_user, organization_id)

    scopes = await db_service.get_scopes(org_id)
    return [ScopeResponse.model_validate(s) for s in scopes]


@router.post("", response_model=ScopeResponse, status_code=status.HTTP_201_CREATED)
async def create_scope(
    payload: ScopeCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Submit a network boundary scope for authorization review.
    Permitted roles: owner, admin, analyst. Viewers are blocked.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id, role = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    created = await db_service.create_scope(
        org_id=org_id,
        user_id=current_user.user_id,
        data=payload,
    )
    return ScopeResponse.model_validate(created)


@router.get("/{scope_id}", response_model=ScopeResponse)
async def get_scope(
    scope_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Retrieve single scope authorization record.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id, _ = await _resolve_org(db_service, current_user, organization_id)

    scope = await db_service.get_scope_by_id(org_id, str(scope_id))
    if not scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scope {scope_id} not found",
        )
    return ScopeResponse.model_validate(scope)


@router.post("/{scope_id}/approve", response_model=ScopeResponse)
async def approve_scope(
    scope_id: UUID,
    payload: Optional[ScopeApprove] = None,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Grant authorization for active discovery scanning against this subnet.
    Strictly restricted to organization Owners and Admins. Analysts cannot self-approve.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id, role = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin"],  # Strict least privilege
    )

    expires_at = payload.expires_at if payload else None
    approved = await db_service.approve_scope(
        org_id=org_id,
        scope_id=str(scope_id),
        approved_by_id=current_user.user_id,
        expires_at=expires_at,
    )

    if not approved:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scope {scope_id} not found",
        )

    return ScopeResponse.model_validate(approved)
