from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.threat_hunting import (
    ThreatHuntingCaseCreate,
    ThreatHuntingCaseResponse,
    ThreatHuntingCaseUpdate,
    ThreatHuntingFindingCreate,
    ThreatHuntingFindingResponse,
    ThreatHuntingQueryParam,
    ThreatHuntingQueryResult,
    ThreatHuntingQuerySave,
    ThreatHuntingQueryResponse,
    ThreatHuntingDashboardStats,
    IOCInvestigationRequest,
    IOCInvestigationResponse,
)
from app.services.threat_hunting_service import threat_hunting_service
from app.services.supabase_service import SupabaseService, supabase_service

router = APIRouter(prefix="/threat-hunting", tags=["Advanced Threat Hunting Center"])


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


# ------------------------------------------------------------------------------
# 1. DASHBOARD STATS
# ------------------------------------------------------------------------------
@router.get("/stats", response_model=ThreatHuntingDashboardStats)
async def get_threat_hunting_stats(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await threat_hunting_service.get_dashboard_stats(target_org_id)


# ------------------------------------------------------------------------------
# 2. HUNTING CASES
# ------------------------------------------------------------------------------
@router.get("/cases", response_model=List[ThreatHuntingCaseResponse])
async def list_hunting_cases(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by case status"),
    priority_filter: Optional[str] = Query(None, alias="priority", description="Filter by priority"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await threat_hunting_service.get_cases(target_org_id, status=status_filter, priority=priority_filter)


@router.post("/cases", response_model=ThreatHuntingCaseResponse, status_code=status.HTTP_201_CREATED)
async def create_hunting_case(
    payload: ThreatHuntingCaseCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return await threat_hunting_service.create_case(target_org_id, payload, user_id=user.user_id)


@router.get("/cases/{case_id}", response_model=ThreatHuntingCaseResponse)
async def get_hunting_case(
    case_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    case_obj = await threat_hunting_service.get_case_by_id(target_org_id, case_id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat hunting case {case_id} not found")
    return case_obj


@router.patch("/cases/{case_id}", response_model=ThreatHuntingCaseResponse)
async def update_hunting_case(
    case_id: str,
    payload: ThreatHuntingCaseUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    updated = await threat_hunting_service.update_case(target_org_id, case_id, payload)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat hunting case {case_id} not found")
    return updated


@router.delete("/cases/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_hunting_case(
    case_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin"])
    deleted = await threat_hunting_service.delete_case(target_org_id, case_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Threat hunting case {case_id} not found")
    return None


# ------------------------------------------------------------------------------
# 3. HUNTING FINDINGS
# ------------------------------------------------------------------------------
@router.get("/findings", response_model=List[ThreatHuntingFindingResponse])
async def list_findings(
    case_id: Optional[str] = Query(None, description="Filter findings by hunting case ID"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await threat_hunting_service.get_findings(target_org_id, case_id=case_id)


@router.post("/findings", response_model=ThreatHuntingFindingResponse, status_code=status.HTTP_201_CREATED)
async def create_finding(
    payload: ThreatHuntingFindingCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return await threat_hunting_service.create_finding(target_org_id, payload)


@router.delete("/findings/{finding_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_finding(
    finding_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    deleted = await threat_hunting_service.delete_finding(target_org_id, finding_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding {finding_id} not found")
    return None


# ------------------------------------------------------------------------------
# 4. STRUCTURED QUERY ENGINE & SAVED SEARCHES
# ------------------------------------------------------------------------------
@router.post("/search", response_model=ThreatHuntingQueryResult)
async def execute_hunting_query(
    payload: ThreatHuntingQueryParam,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await threat_hunting_service.execute_query(target_org_id, payload)


@router.get("/queries", response_model=List[ThreatHuntingQueryResponse])
async def list_saved_queries(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await threat_hunting_service.get_saved_queries(target_org_id)


@router.post("/queries", response_model=ThreatHuntingQueryResponse, status_code=status.HTTP_201_CREATED)
async def save_hunting_query(
    payload: ThreatHuntingQuerySave,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return await threat_hunting_service.save_query(target_org_id, payload, user_id=user.user_id)


@router.delete("/queries/{query_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved_query(
    query_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    deleted = await threat_hunting_service.delete_saved_query(target_org_id, query_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Query {query_id} not found")
    return None


# ------------------------------------------------------------------------------
# 5. MULTI-TYPE IOC CORRELATION & INVESTIGATION
# ------------------------------------------------------------------------------
@router.post("/ioc-investigation", response_model=IOCInvestigationResponse)
async def investigate_ioc_indicator(
    payload: IOCInvestigationRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await threat_hunting_service.investigate_ioc(target_org_id, payload.ioc_value, payload.ioc_type)
