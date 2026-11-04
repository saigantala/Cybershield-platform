import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.incident import (
    IncidentCreate,
    IncidentUpdate,
    IncidentAssignRequest,
    IncidentResponse,
    IncidentLinkAlertRequest,
    IncidentAlertResponse,
    IncidentNoteCreate,
    IncidentNoteResponse,
    IncidentTimelineResponse,
)
from app.services.supabase_service import SupabaseService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/incidents", tags=["Incident Management"])


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


@router.get("", response_model=Dict[str, Any])
async def list_incidents(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    incident_type: Optional[str] = Query(None),
    assigned_to: Optional[UUID] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve paginated incidents for the tenant organization."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_incidents(
        org_id=org_id,
        severity=severity,
        status=status,
        incident_type=incident_type,
        assigned_to=str(assigned_to) if assigned_to else None,
        search=search,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    payload: IncidentCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Create a new incident case with unique incident number."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    return await db_service.create_incident(
        org_id=org_id,
        data=payload,
        created_by=current_user.user_id,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Get single incident details with sub-resource counts."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    inc = await db_service.get_incident_by_id(org_id, str(incident_id))
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    return inc


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: UUID,
    payload: IncidentUpdate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Update incident status, severity, priority, or resolution."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    inc = await db_service.update_incident(
        org_id=org_id,
        incident_id=str(incident_id),
        data=payload,
        actor_id=current_user.user_id,
    )
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    return inc


@router.post("/{incident_id}/assign", response_model=IncidentResponse)
async def assign_incident(
    incident_id: UUID,
    payload: IncidentAssignRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Assign incident to designated security analyst."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    inc = await db_service.assign_incident(
        org_id=org_id,
        incident_id=str(incident_id),
        assigned_to=str(payload.assigned_to),
        actor_id=current_user.user_id,
    )
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    return inc


@router.get("/{incident_id}/alerts", response_model=List[IncidentAlertResponse])
async def list_incident_alerts(
    incident_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List all correlation alerts linked to this incident."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_incident_alerts(org_id, str(incident_id))


@router.post("/{incident_id}/alerts", response_model=IncidentAlertResponse, status_code=status.HTTP_201_CREATED)
async def link_alert(
    incident_id: UUID,
    payload: IncidentLinkAlertRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Link an alert to this incident and escalate its status."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    res = await db_service.link_alert_to_incident(
        org_id=org_id,
        incident_id=str(incident_id),
        alert_id=str(payload.alert_id),
        actor_id=current_user.user_id,
    )
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident or Alert not found",
        )
    return res


@router.delete("/{incident_id}/alerts/{alert_id}", status_code=status.HTTP_200_OK)
async def unlink_alert(
    incident_id: UUID,
    alert_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Unlink an alert from this incident with timeline audit trail."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    unlinked = await db_service.unlink_alert_from_incident(
        org_id=org_id,
        incident_id=str(incident_id),
        alert_id=str(alert_id),
        actor_id=current_user.user_id,
    )
    if not unlinked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert link not found",
        )
    return {"message": "Alert unlinked successfully"}


@router.get("/{incident_id}/timeline", response_model=List[IncidentTimelineResponse])
async def get_timeline(
    incident_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve full chronological investigation timeline."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_incident_timeline(org_id, str(incident_id))


@router.get("/{incident_id}/notes", response_model=List[IncidentNoteResponse])
async def list_notes(
    incident_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List all notes logged on this incident."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_incident_notes(org_id, str(incident_id))


@router.post("/{incident_id}/notes", response_model=IncidentNoteResponse, status_code=status.HTTP_201_CREATED)
async def add_note(
    incident_id: UUID,
    payload: IncidentNoteCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Add an analyst investigation note to the incident."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    res = await db_service.add_incident_note(
        org_id=org_id,
        incident_id=str(incident_id),
        author_id=current_user.user_id,
        note=payload.note,
    )
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )
    return res


@router.get("/{incident_id}/export")
async def export_incident_report(
    incident_id: UUID,
    format: str = Query("json", pattern="^(json|csv)$"),
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Generate comprehensive incident report metadata for export."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    inc = await db_service.get_incident_by_id(org_id, str(incident_id))
    if not inc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    alerts = await db_service.get_incident_alerts(org_id, str(incident_id))
    timeline = await db_service.get_incident_timeline(org_id, str(incident_id))
    notes = await db_service.get_incident_notes(org_id, str(incident_id))
    evidence = await db_service.get_incident_evidence(org_id, str(incident_id))
    attack = await db_service.get_incident_attack_mappings(org_id, str(incident_id))
    requests = await db_service.get_response_requests(org_id, str(incident_id))

    report = {
        "report_title": f"Incident Summary Report: {inc['incident_number']}",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "generated_by": current_user.email,
        "incident": inc,
        "linked_alerts": alerts,
        "timeline": timeline,
        "notes": notes,
        "evidence_artifacts": evidence,
        "mitre_attack_mappings": attack,
        "response_actions": requests,
    }

    if format == "csv":
        import io
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Section", "Key", "Value"])
        writer.writerow(["Incident", "Number", inc["incident_number"]])
        writer.writerow(["Incident", "Title", inc["title"]])
        writer.writerow(["Incident", "Severity", inc["severity"]])
        writer.writerow(["Incident", "Status", inc["status"]])
        writer.writerow(["Incident", "Type", inc["incident_type"]])
        writer.writerow(["Incident", "Detected At", inc["detected_at"]])
        for a in alerts:
            writer.writerow(["Linked Alert", a["alert_title"], a["alert_severity"]])
        for e in evidence:
            writer.writerow(["Evidence", e["evidence_name"], e["sha256_hash"]])
        for m in attack:
            writer.writerow(["MITRE ATT&CK", m["technique_id"], m["technique_name"]])
        return JSONResponse(content={"csv_data": output.getvalue()})

    return report
