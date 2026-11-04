from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.saas import (
    InvitationCreate,
    InvitationResponse,
    MemberRoleUpdate,
    OrganizationMemberResponse,
)
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/team", tags=["Team Management & RBAC"])


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


@router.get("/members", response_model=List[OrganizationMemberResponse])
async def list_members(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists all team members of the organization."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    members = await db_service.get_organization_members(target_org_id)
    return members


@router.patch("/members/{member_id}/role", response_model=OrganizationMemberResponse)
async def update_member_role(
    member_id: UUID,
    payload: MemberRoleUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Updates a team member's role. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    try:
        updated = await db_service.update_member_role(
            target_org_id, str(member_id), payload.role
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found in organization",
        )
    return updated


@router.delete("/members/{member_id}")
async def remove_member(
    member_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Removes a team member from the organization. Cannot remove last owner."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    success, msg = await db_service.remove_organization_member(target_org_id, str(member_id))
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    return {"status": "success", "message": msg}


@router.get("/invitations", response_model=List[InvitationResponse])
async def list_invitations(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists organization invitations. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    return await db_service.get_invitations(target_org_id)


@router.post("/invitations", response_model=InvitationResponse, status_code=status.HTTP_201_CREATED)
async def invite_member(
    payload: InvitationCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Sends an invitation to a new team member. Enforces seat quota."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    try:
        invitation = await db_service.create_invitation(
            org_id=target_org_id,
            email=payload.email,
            role=payload.role,
            invited_by=user.user_id,
        )
        return invitation
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/invitations/{inv_id}/resend", response_model=InvitationResponse)
async def resend_invitation(
    inv_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Resends a pending invitation, renewing its expiration timestamp."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    inv = await db_service.resend_invitation(target_org_id, str(inv_id))
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )
    return inv


@router.delete("/invitations/{inv_id}")
async def cancel_invitation(
    inv_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Revokes or cancels a pending organization invitation."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    success = await db_service.cancel_invitation(target_org_id, str(inv_id))
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )
    return {"status": "success", "message": "Invitation cancelled"}
