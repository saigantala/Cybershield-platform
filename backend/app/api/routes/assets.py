from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.asset import AssetCreate, AssetResponse, AssetUpdate
from app.schemas.common import MessageResponse, PaginatedList
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/assets", tags=["Assets"])


async def _resolve_target_org(
    db_service: SupabaseService,
    user: AuthenticatedUser,
    requested_org_id: Optional[UUID] = None,
    allowed_roles: Optional[List[str]] = None,
) -> tuple[str, str]:
    """Verifies user's organization access and role."""
    memberships = await db_service.get_user_org_membership(user.user_id)
    if not memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User does not belong to any authorized organization",
        )

    target_org_id = str(requested_org_id) if requested_org_id else str(memberships[0]["organization_id"])
    has_access, role = await db_service.verify_org_access(user.user_id, target_org_id, allowed_roles)

    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {role}",
        )

    return target_org_id, role


@router.get("", response_model=PaginatedList[AssetResponse])
async def list_assets(
    organization_id: Optional[UUID] = Query(None, description="Target organization UUID"),
    search: Optional[str] = Query(None, description="Search term for name, IP, MAC, hostname"),
    device_type: Optional[str] = Query("all"),
    risk_level: Optional[str] = Query("all"),
    status_filter: Optional[str] = Query("all", alias="status"),
    sort_by: str = Query("updated_at"),
    sort_order: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    List infrastructure assets for an authorized organization with filtering, sorting, and pagination.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id, _ = await _resolve_target_org(db_service, current_user, organization_id)

    items, total = await db_service.get_assets(
        org_id=org_id,
        search=search,
        device_type=device_type,
        risk_level=risk_level,
        status_filter=status_filter,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedList[AssetResponse](
        items=[AssetResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Fetch a single asset by UUID with organization-level access control.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id, _ = await _resolve_target_org(db_service, current_user, organization_id)

    asset = await db_service.get_asset_by_id(org_id, str(asset_id))
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found in this organization",
        )

    return AssetResponse.model_validate(asset)


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Register a new network infrastructure endpoint.
    Restricted to organization owners, admins, and analysts. Viewers are blocked.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id, role = await _resolve_target_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    created = await db_service.create_asset(
        org_id=org_id,
        user_id=current_user.user_id,
        user_email=current_user.email,
        data=payload,
    )

    return AssetResponse.model_validate(created)


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: UUID,
    payload: AssetUpdate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Update telemetry, classification, or posture state of an asset.
    Restricted to organization owners, admins, and analysts.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id, _ = await _resolve_target_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    updated = await db_service.update_asset(org_id, str(asset_id), payload)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found",
        )

    return AssetResponse.model_validate(updated)


@router.delete("/{asset_id}", response_model=MessageResponse)
async def delete_asset(
    asset_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Decommission an endpoint permanently from inventory.
    Restricted to organization owners, admins, and analysts.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id, _ = await _resolve_target_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    success = await db_service.delete_asset(org_id, str(asset_id))
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found or could not be removed",
        )

    return MessageResponse(
        success=True,
        message=f"Asset {asset_id} successfully decommissioned from inventory.",
    )
