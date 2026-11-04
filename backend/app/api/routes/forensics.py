from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.forensics import (
    ForensicCaseCreate,
    ForensicCaseResponse,
    ForensicCaseUpdate,
    ForensicAssetLink,
    ForensicCaseAssetResponse,
    ForensicEvidenceItemCreate,
    ForensicEvidenceItemResponse,
    ForensicCustodyEventCreate,
    ForensicCustodyEventResponse,
    CustodyChainVerificationResponse,
    ForensicAnalysisJobCreate,
    ForensicAnalysisJobResponse,
    ForensicCaseNoteCreate,
    ForensicCaseNoteResponse,
    ForensicReportCreate,
    ForensicReportResponse,
    ForensicTimelineFilter,
    ForensicTimelineResponse,
    ForensicsDashboardStats,
)
from app.services.forensics_service import forensics_service
from app.services.supabase_service import SupabaseService, supabase_service

router = APIRouter(prefix="/forensics", tags=["Digital Forensics & Tamper-Evident Evidence Vault"])


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
@router.get("/stats", response_model=ForensicsDashboardStats)
async def get_forensics_stats(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await forensics_service.get_dashboard_stats(target_org_id)


# ------------------------------------------------------------------------------
# 2. FORENSIC CASES
# ------------------------------------------------------------------------------
@router.get("/cases", response_model=List[ForensicCaseResponse])
async def list_forensic_cases(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by case status"),
    priority_filter: Optional[str] = Query(None, alias="priority", description="Filter by priority"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await forensics_service.get_cases(target_org_id, status=status_filter, priority=priority_filter)


@router.post("/cases", response_model=ForensicCaseResponse, status_code=status.HTTP_201_CREATED)
async def create_forensic_case(
    payload: ForensicCaseCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return await forensics_service.create_case(target_org_id, payload, user_id=user.user_id)


@router.get("/cases/{case_id}", response_model=ForensicCaseResponse)
async def get_forensic_case(
    case_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    case_obj = await forensics_service.get_case_by_id(target_org_id, case_id)
    if not case_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Forensic case {case_id} not found")
    return case_obj


@router.patch("/cases/{case_id}", response_model=ForensicCaseResponse)
async def update_forensic_case(
    case_id: str,
    payload: ForensicCaseUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    updated = await forensics_service.update_case(target_org_id, case_id, payload)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Forensic case {case_id} not found")
    return updated


@router.delete("/cases/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_forensic_case(
    case_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin"])
    deleted = await forensics_service.delete_case(target_org_id, case_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Forensic case {case_id} not found")
    return None


@router.post("/cases/{case_id}/assets", response_model=ForensicCaseAssetResponse)
async def link_case_asset(
    case_id: str,
    payload: ForensicAssetLink,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return await forensics_service.link_asset(target_org_id, case_id, payload.asset_id, payload.role_in_case)


# ------------------------------------------------------------------------------
# 3. EVIDENCE VAULT & IMMUTABLE RECORDS
# ------------------------------------------------------------------------------
@router.get("/evidence", response_model=List[ForensicEvidenceItemResponse])
async def list_evidence(
    case_id: Optional[str] = Query(None, description="Filter by forensic case ID"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await forensics_service.get_evidence(target_org_id, case_id=case_id)


@router.post("/evidence", response_model=ForensicEvidenceItemResponse, status_code=status.HTTP_201_CREATED)
async def upload_evidence_item(
    payload: ForensicEvidenceItemCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return await forensics_service.create_evidence(
        target_org_id,
        payload,
        user_id=user.user_id,
        user_name=user.email or "Lead Forensic Analyst",
    )


@router.get("/evidence/{evidence_id}", response_model=ForensicEvidenceItemResponse)
async def get_evidence_item(
    evidence_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    item = await forensics_service.get_evidence_by_id(target_org_id, evidence_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence item {evidence_id} not found")
    return item


# ------------------------------------------------------------------------------
# 4. TAMPER-EVIDENT CHAIN OF CUSTODY & CRYPTOGRAPHIC VERIFICATION
# ------------------------------------------------------------------------------
@router.get("/evidence/{evidence_id}/custody", response_model=List[ForensicCustodyEventResponse])
async def get_evidence_custody_chain(
    evidence_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await forensics_service.get_custody_events(target_org_id, evidence_id)


@router.post("/evidence/{evidence_id}/custody", response_model=ForensicCustodyEventResponse, status_code=status.HTTP_201_CREATED)
async def append_custody_record(
    evidence_id: str,
    payload: ForensicCustodyEventCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return await forensics_service.append_custody_event(
        org_id=target_org_id,
        evidence_id=evidence_id,
        action=payload.action,
        metadata=payload.metadata,
        user_id=user.user_id,
        user_name=user.email or "Forensic Analyst",
    )


@router.post("/evidence/{evidence_id}/verify-chain", response_model=CustodyChainVerificationResponse)
async def verify_custody_chain(
    evidence_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await forensics_service.verify_chain_of_custody(target_org_id, evidence_id)


# ------------------------------------------------------------------------------
# 5. SAFE STATIC ARTIFACT ANALYSIS (NO EXECUTION)
# ------------------------------------------------------------------------------
@router.post("/cases/{case_id}/analysis", response_model=ForensicAnalysisJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def run_static_artifact_analysis(
    case_id: str,
    payload: ForensicAnalysisJobCreate,
    evidence_id: str = Query(..., description="Evidence artifact ID to analyze"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    try:
        return await forensics_service.run_analysis_job(
            org_id=target_org_id,
            case_id=case_id,
            evidence_id=evidence_id,
            analysis_type=payload.analysis_type,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/cases/{case_id}/analysis", response_model=List[ForensicAnalysisJobResponse])
async def list_analysis_jobs(
    case_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await forensics_service.get_analysis_jobs(target_org_id, case_id)


# ------------------------------------------------------------------------------
# 6. CASE NOTES & HYPOTHESES
# ------------------------------------------------------------------------------
@router.get("/cases/{case_id}/notes", response_model=List[ForensicCaseNoteResponse])
async def list_case_notes(
    case_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await forensics_service.get_case_notes(target_org_id, case_id)


@router.post("/cases/{case_id}/notes", response_model=ForensicCaseNoteResponse, status_code=status.HTTP_201_CREATED)
async def add_case_note(
    case_id: str,
    payload: ForensicCaseNoteCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return await forensics_service.create_case_note(
        org_id=target_org_id,
        case_id=case_id,
        data=payload,
        user_id=user.user_id,
        user_name=user.email or "Lead Forensic Analyst",
    )


@router.delete("/cases/{case_id}/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case_note(
    case_id: str,
    note_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    deleted = await forensics_service.delete_case_note(target_org_id, note_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case note {note_id} not found")
    return None


# ------------------------------------------------------------------------------
# 7. FORENSIC TIMELINE CORRELATION
# ------------------------------------------------------------------------------
@router.post("/timeline", response_model=ForensicTimelineResponse)
async def query_forensic_timeline(
    payload: ForensicTimelineFilter,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await forensics_service.get_timeline(target_org_id, payload)


# ------------------------------------------------------------------------------
# 8. FORENSIC REPORTS
# ------------------------------------------------------------------------------
@router.get("/cases/{case_id}/reports", response_model=List[ForensicReportResponse])
async def list_case_reports(
    case_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    return await forensics_service.get_reports(target_org_id, case_id)


@router.post("/cases/{case_id}/reports", response_model=ForensicReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_forensic_report(
    case_id: str,
    payload: ForensicReportCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return await forensics_service.create_report(
        org_id=target_org_id,
        case_id=case_id,
        data=payload,
        user_id=user.user_id,
        user_name=user.email or "Lead Forensic Investigator",
    )


@router.get("/reports/{report_id}", response_model=ForensicReportResponse)
async def get_report_by_id(
    report_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    db: SupabaseService = Depends(lambda: supabase_service),
):
    target_org_id = await _resolve_org(db, user, org_id)
    rep = await forensics_service.get_report_by_id(target_org_id, report_id)
    if not rep:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Forensic report {report_id} not found")
    return rep
