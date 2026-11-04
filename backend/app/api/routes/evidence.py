import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.incident import IncidentEvidenceCreate, IncidentEvidenceResponse
from app.services.supabase_service import SupabaseService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/incidents/{incident_id}/evidence", tags=["Incident Evidence Vault"])


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


@router.get("", response_model=List[IncidentEvidenceResponse])
async def list_evidence(
    incident_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List forensic evidence records attached to this incident."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_incident_evidence(org_id, str(incident_id))


@router.post("", response_model=IncidentEvidenceResponse, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    incident_id: UUID,
    payload: IncidentEvidenceCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Store, validate, and hash forensic evidence artifact."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    try:
        return await db_service.add_incident_evidence(
            org_id=org_id,
            incident_id=str(incident_id),
            data=payload,
            uploaded_by=current_user.user_id,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/{evidence_id}", response_model=IncidentEvidenceResponse)
async def get_evidence(
    incident_id: UUID,
    evidence_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve single evidence metadata and SHA-256 hash."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    evidence = await db_service.get_evidence_by_id(org_id, str(incident_id), str(evidence_id))
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence artifact not found",
        )
    return evidence


@router.delete("/{evidence_id}", status_code=status.HTTP_200_OK)
async def delete_evidence(
    incident_id: UUID,
    evidence_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Remove evidence artifact from incident vault."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    deleted = await db_service.delete_incident_evidence(org_id, str(incident_id), str(evidence_id))
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence artifact not found",
        )
    return {"message": "Evidence removed successfully"}
