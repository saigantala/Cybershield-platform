import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.services.supabase_service import SupabaseService
from app.threat_intelligence.models import (
    AlertAssignRequest,
    AlertLinkIncidentRequest,
    AlertNoteRequest,
    AlertNoteResponse,
    AlertResponse,
    AlertUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["Alerts"])


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
async def list_alerts(
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    source: Optional[str] = Query(None),
    asset_id: Optional[UUID] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List, search, filter, and paginate security alerts."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_alerts(
        org_id=org_id,
        severity=severity,
        status=status_filter,
        source=source,
        asset_id=str(asset_id) if asset_id else None,
        search=search,
        page=page,
        page_size=page_size,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve details of a single security alert."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    alert = await db_service.get_alert_by_id(org_id, str(alert_id))
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: UUID,
    payload: AlertUpdate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Update alert triage status or severity. Requires role 'owner', 'admin', or 'analyst'."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
    updated = await db_service.update_alert(
        org_id, str(alert_id), update_data, changed_by=current_user.user_id
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return updated


@router.post("/{alert_id}/assign", response_model=AlertResponse)
async def assign_alert(
    alert_id: UUID,
    payload: AlertAssignRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Assign alert to a designated security analyst."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    assigned = await db_service.assign_alert(
        org_id, str(alert_id), str(payload.assigned_to), changed_by=current_user.user_id
    )
    if not assigned:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return assigned


@router.post("/{alert_id}/notes", response_model=AlertNoteResponse, status_code=status.HTTP_201_CREATED)
async def add_note(
    alert_id: UUID,
    payload: AlertNoteRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Append an investigation note to the alert timeline."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    note = await db_service.add_alert_note(
        org_id, str(alert_id), author_id=current_user.user_id, note=payload.note
    )
    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return note


@router.get("/{alert_id}/notes", response_model=List[AlertNoteResponse])
async def list_notes(
    alert_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List all investigation notes recorded for an alert."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_alert_notes(org_id, str(alert_id))


@router.post("/{alert_id}/link-incident", response_model=AlertResponse)
async def link_incident(
    alert_id: UUID,
    payload: AlertLinkIncidentRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Escalate and link an alert to an Incident Response case."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    linked = await db_service.link_alert_incident(
        org_id, str(alert_id), str(payload.incident_id), changed_by=current_user.user_id
    )
    if not linked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return linked
