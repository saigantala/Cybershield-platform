from typing import Any, Dict, List
from uuid import UUID
from fastapi import APIRouter, Depends
from app.core.security import AuthenticatedUser, get_current_user
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/me")
async def get_current_user_profile(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns current authenticated operator identity, Supabase metadata, and organization memberships.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    memberships = await db_service.get_user_org_membership(current_user.user_id)

    primary_org = memberships[0] if memberships else None

    return {
        "id": current_user.user_id,
        "email": current_user.email,
        "role": current_user.role,
        "full_name": current_user.user_metadata.get("full_name", current_user.email.split("@")[0]),
        "avatar_url": current_user.user_metadata.get("avatar_url"),
        "primary_organization_id": primary_org["organization_id"] if primary_org else None,
        "primary_role": primary_org["role"] if primary_org else "analyst",
        "organizations": memberships,
    }
