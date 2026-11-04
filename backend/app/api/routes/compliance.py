from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.compliance import (
    ComplianceAssessmentCreate,
    ComplianceAssessmentResponse,
    ComplianceAssessmentUpdate,
    ComplianceControlResponse,
    ComplianceEvidenceCreate,
    ComplianceEvidenceResponse,
    ComplianceFrameworkResponse,
    ComplianceSummaryResponse,
)
from app.services.compliance_service import compliance_service
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/compliance", tags=["Compliance Management & Auditing"])


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


@router.get("/frameworks", response_model=List[ComplianceFrameworkResponse])
async def list_frameworks(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists supported compliance frameworks with tenant completion metrics."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await compliance_service.get_frameworks(db_service, target_org_id)


@router.get("/controls", response_model=List[ComplianceControlResponse])
async def list_controls(
    framework_code: Optional[str] = Query(None, description="e.g. NIST_CSF_2_0, CIS_CONTROLS_V8"),
    domain: Optional[str] = Query(None, description="Domain/category filter"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists compliance controls with current organization assessment status and evidence counts."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await compliance_service.get_controls(
        db_service, target_org_id, framework_code=framework_code, domain=domain
    )


@router.get("/assessments", response_model=List[ComplianceAssessmentResponse])
async def list_assessments(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists all active control assessments for the organization."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await db_service.get_compliance_assessments(target_org_id)


@router.post("/assessments", response_model=ComplianceAssessmentResponse, status_code=status.HTTP_201_CREATED)
async def create_assessment(
    payload: ComplianceAssessmentCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Creates or upserts a compliance assessment. Requires 'owner', 'admin', or 'analyst' role."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    try:
        return await compliance_service.create_assessment(db_service, target_org_id, payload)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch("/assessments/{assessment_id}", response_model=ComplianceAssessmentResponse)
async def update_assessment(
    assessment_id: UUID,
    payload: ComplianceAssessmentUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Updates an existing compliance assessment. Requires 'owner', 'admin', or 'analyst' role."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    updated = await compliance_service.update_assessment(
        db_service, target_org_id, str(assessment_id), payload
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assessment record not found",
        )
    return updated


@router.get("/evidence", response_model=List[ComplianceEvidenceResponse])
async def list_evidence(
    control_id: Optional[UUID] = Query(None, description="Filter by control"),
    assessment_id: Optional[UUID] = Query(None, description="Filter by assessment"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists compliance evidence files with calculated SHA-256 integrity hashes."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await db_service.get_compliance_evidence(
        target_org_id,
        control_id=str(control_id) if control_id else None,
        assessment_id=str(assessment_id) if assessment_id else None,
    )


@router.post("/evidence", response_model=ComplianceEvidenceResponse, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    file: UploadFile = File(...),
    control_id: Optional[UUID] = Form(None),
    assessment_id: Optional[UUID] = Form(None),
    description: Optional[str] = Form(None),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Uploads and verifies an evidence artifact in the compliance vault."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )

    contents = await file.read()
    try:
        record = await compliance_service.upload_evidence(
            db_service=db_service,
            org_id=target_org_id,
            user_id=user.user_id,
            file_name=file.filename or "evidence.pdf",
            file_bytes=contents,
            mime_type=file.content_type or "application/octet-stream",
            control_id=str(control_id) if control_id else None,
            assessment_id=str(assessment_id) if assessment_id else None,
            description=description,
        )
        return record
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/evidence/{evidence_id}")
async def delete_evidence(
    evidence_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Deletes an evidence artifact. Requires 'owner' or 'admin' role."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    success = await db_service.delete_compliance_evidence(target_org_id, str(evidence_id))
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence artifact not found",
        )
    return {"status": "success", "message": "Evidence artifact deleted"}
