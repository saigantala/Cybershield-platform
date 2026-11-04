import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.services.supabase_service import SupabaseService
from app.threat_intelligence.models import (
    AlertResponse,
    SecurityEventCreate,
    SecurityEventResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/security-events", tags=["Security Events"])


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


@router.get("")
async def list_security_events(
    source: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    asset_id: Optional[UUID] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List, search, and paginate normalized security event logs."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_security_events(
        org_id=org_id,
        source=source,
        severity=severity,
        event_type=event_type,
        asset_id=str(asset_id) if asset_id else None,
        search=search,
        page=page,
        page_size=page_size,
    )


@router.post("", status_code=status.HTTP_201_CREATED)
async def ingest_security_event(
    payload: SecurityEventCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Ingest a security event into the centralized event collection pipeline.
    Immediately triggers real-time correlation against active detection rules
    and threat intelligence indicators.
    Requires role 'owner', 'admin', or 'analyst'.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    event, new_alerts = await db_service.create_security_event(org_id, payload)
    return {
        "event": SecurityEventResponse.model_validate(event),
        "alerts_triggered": [AlertResponse.model_validate(a) for a in new_alerts],
    }


@router.get("/{event_id}", response_model=SecurityEventResponse)
async def get_security_event(
    event_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve full details of a specific security event."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    event = await db_service.get_security_event_by_id(org_id, str(event_id))
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security event not found",
        )
    return event
