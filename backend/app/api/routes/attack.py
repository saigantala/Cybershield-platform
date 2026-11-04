import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.incident import (
    AttackTacticResponse,
    AttackTechniqueResponse,
    IncidentAttackMappingCreate,
    IncidentAttackMappingResponse,
)
from app.services.attack_service import attack_service
from app.services.supabase_service import SupabaseService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["MITRE ATT&CK"])


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


@router.get("/attack/tactics", response_model=List[AttackTacticResponse])
async def list_attack_tactics(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List all official MITRE ATT&CK Enterprise Tactics."""
    return attack_service.get_tactics()


@router.get("/attack/techniques", response_model=List[AttackTechniqueResponse])
async def list_attack_techniques(
    tactic_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List MITRE ATT&CK Enterprise Techniques with optional tactic and search filter."""
    return attack_service.get_techniques(tactic_id=tactic_id, search=search)


@router.get("/incidents/{incident_id}/attack-mappings", response_model=List[IncidentAttackMappingResponse])
async def get_incident_attack_mappings(
    incident_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve all MITRE ATT&CK techniques mapped to this incident."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_incident_attack_mappings(org_id, str(incident_id))


@router.post(
    "/incidents/{incident_id}/attack-mappings",
    response_model=IncidentAttackMappingResponse,
    status_code=status.HTTP_201_CREATED,
)
async def map_attack_technique(
    incident_id: UUID,
    payload: IncidentAttackMappingCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Manually map an observed ATT&CK technique to an incident with evidence and confidence."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    try:
        mapping = await db_service.add_incident_attack_mapping(
            org_id=org_id,
            incident_id=str(incident_id),
            technique_id=payload.technique_id,
            confidence=payload.confidence,
            evidence=payload.evidence,
            created_by=current_user.user_id,
        )
        if not mapping:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Incident not found",
            )
        return mapping
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.delete("/incidents/{incident_id}/attack-mappings/{mapping_id}", status_code=status.HTTP_200_OK)
async def unmap_attack_technique(
    incident_id: UUID,
    mapping_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Remove a mapped ATT&CK technique from an incident."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    removed = await db_service.delete_incident_attack_mapping(org_id, str(incident_id), str(mapping_id))
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attack mapping not found",
        )
    return {"message": "ATT&CK mapping removed successfully"}
