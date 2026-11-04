import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.incident import (
    PlaybookCreate,
    PlaybookResponse,
    IncidentPlaybookAttachRequest,
    IncidentPlaybookResponse,
    StepProgressUpdate,
    StepProgressResponse,
)
from app.services.supabase_service import SupabaseService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Response Playbooks"])


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


@router.get("/playbooks", response_model=List[PlaybookResponse])
async def list_playbooks(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List standard and custom response playbooks for this tenant."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_playbooks(org_id)


@router.post("/playbooks", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
async def create_playbook(
    payload: PlaybookCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Create a new custom response playbook with checklist steps."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    return await db_service.create_playbook(
        org_id=org_id,
        data=payload,
        created_by=current_user.user_id,
    )


@router.get("/playbooks/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(
    playbook_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Get single playbook with full step checklist."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    pb = await db_service.get_playbook_by_id(org_id, str(playbook_id))
    if not pb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found",
        )
    return pb


@router.patch("/playbooks/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: UUID,
    payload: Dict[str, Any],
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Enable, disable, or update playbook metadata."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    pb = await db_service.update_playbook(org_id, str(playbook_id), payload)
    if not pb:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found",
        )
    return pb


@router.get("/incidents/{incident_id}/playbooks", response_model=List[IncidentPlaybookResponse])
async def list_incident_playbooks(
    incident_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve active playbooks attached to this incident with step progress."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_incident_playbooks(org_id, str(incident_id))


@router.post("/incidents/{incident_id}/playbooks", response_model=IncidentPlaybookResponse, status_code=status.HTTP_201_CREATED)
async def attach_playbook(
    incident_id: UUID,
    payload: IncidentPlaybookAttachRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Attach a playbook to an incident and initialize checklist step progress."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    try:
        await db_service.attach_playbook_to_incident(
            org_id=org_id,
            incident_id=str(incident_id),
            playbook_id=str(payload.playbook_id),
            assigned_to=str(payload.assigned_to) if payload.assigned_to else current_user.user_id,
        )
        pbs = await db_service.get_incident_playbooks(org_id, str(incident_id))
        attached = next((p for p in pbs if str(p["playbook_id"]) == str(payload.playbook_id)), None)
        return attached or pbs[0]
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.patch(
    "/incidents/{incident_id}/playbooks/{assignment_id}/steps/{step_id}",
    response_model=StepProgressResponse,
)
async def update_step_progress(
    incident_id: UUID,
    assignment_id: UUID,
    step_id: UUID,
    payload: StepProgressUpdate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Update checklist completion status and analyst notes for a playbook step."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    res = await db_service.update_step_progress(
        org_id=org_id,
        incident_id=str(incident_id),
        assignment_id=str(assignment_id),
        step_id=str(step_id),
        status=payload.status,
        notes=payload.notes,
        actor_id=current_user.user_id,
    )
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook step not found",
        )
    return res
