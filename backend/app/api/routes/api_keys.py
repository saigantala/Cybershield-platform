from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.saas import APIKeyCreate, APIKeyCreatedResponse, APIKeyResponse
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/api-keys", tags=["API Key Management"])


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


@router.get("", response_model=List[APIKeyResponse])
async def list_api_keys(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists generated API keys for the organization. Sensitive hash is never returned."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    return await db_service.get_api_keys(target_org_id)


@router.post("", response_model=APIKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: APIKeyCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """
    Generates a new programmatic API key.
    IMPORTANT: The raw_api_key is returned ONLY ONCE upon creation and is never stored.
    """
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    record, raw_key = await db_service.create_api_key(
        org_id=target_org_id,
        key_name=payload.key_name,
        scopes=payload.scopes,
        expires_in_days=payload.expires_in_days,
        created_by=user.user_id,
    )
    return {**record, "raw_api_key": raw_key}


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Immediately revokes an active API key."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    success = await db_service.revoke_api_key(target_org_id, str(key_id))
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API Key not found",
        )
    return {"status": "success", "message": "API key revoked"}


@router.post("/{key_id}/rotate", response_model=APIKeyCreatedResponse)
async def rotate_api_key(
    key_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Revokes the current API key and issues a newly generated credential."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    new_record, raw_key = await db_service.rotate_api_key(target_org_id, str(key_id))
    if not new_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API Key not found",
        )
    return {**new_record, "raw_api_key": raw_key}
