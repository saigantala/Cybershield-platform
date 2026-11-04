import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.services.supabase_service import SupabaseService
from app.threat_intelligence.models import (
    ThreatFeedResponse,
    ThreatIndicatorCreate,
    ThreatIndicatorResponse,
    ThreatIntelOverviewResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence"])


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


@router.get("/overview", response_model=ThreatIntelOverviewResponse)
async def get_overview(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve IOC counts by type, malicious entities, and recent intelligence feeds."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await db_service.get_threat_intel_overview(org_id)


@router.get("/indicators")
async def list_indicators(
    indicator_type: Optional[str] = Query(None, alias="type"),
    severity: Optional[str] = Query(None),
    threat_category: Optional[str] = Query(None, alias="category"),
    source: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    min_confidence: Optional[int] = Query(None, ge=0, le=100),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List, filter, and paginate Threat Intelligence indicators (IOCs)."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_threat_indicators(
        org_id=org_id,
        indicator_type=indicator_type,
        severity=severity,
        threat_category=threat_category,
        source=source,
        search=search,
        min_confidence=min_confidence,
        page=page,
        page_size=page_size,
    )


@router.post(
    "/indicators",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_indicator(
    payload: ThreatIndicatorCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Manually register or update an Indicator of Compromise (IOC).
    Requires role 'owner', 'admin', or 'analyst'.
    Validates and normalizes IP, domain, URL, or hash formats.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    try:
        return await db_service.create_threat_indicator(org_id, payload)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )


@router.get("/indicators/{indicator_id}", response_model=ThreatIndicatorResponse)
async def get_indicator(
    indicator_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve details of a single threat indicator."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    ind = await db_service.get_threat_indicator_by_id(org_id, str(indicator_id))
    if not ind:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat indicator not found",
        )
    return ind


@router.delete("/indicators/{indicator_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_indicator(
    indicator_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Delete an indicator. Requires role 'owner', 'admin', or 'analyst'."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    deleted = await db_service.delete_threat_indicator(org_id, str(indicator_id))
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat indicator not found",
        )


@router.get("/feeds", response_model=List[ThreatFeedResponse])
async def list_feeds(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List configured threat intelligence feeds and their synchronization health."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await db_service.get_threat_feeds(org_id)


@router.post("/feeds/{feed_id}/sync")
async def sync_feed(
    feed_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Trigger on-demand synchronization for a threat feed. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin"],
    )

    res = await db_service.sync_threat_feed(org_id, str(feed_id))
    if res.get("status") == "error":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=res["message"])
    return res
