import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.vulnerability import (
    RemediationActionRequest,
    RemediationHistoryResponse,
    VulnerabilityFindingResponse,
    VulnerabilityFindingUpdate,
    VulnerabilityOverviewResponse,
    VulnerabilityScanCreate,
    VulnerabilityScanResponse,
)
from app.services.cve_service import cve_service
from app.services.kev_service import kev_service
from app.services.supabase_service import SupabaseService
from app.workers.tasks import start_vulnerability_assessment

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


async def _resolve_org(
    db_service: SupabaseService,
    user: AuthenticatedUser,
    org_id_param: Optional[UUID] = None,
    allowed_roles: Optional[List[str]] = None,
) -> str:
    """Verifies organization membership, role privileges, and tenant isolation."""
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


# ------------------------------------------------------------------------------
# 1. Overview Dashboard Metrics
# ------------------------------------------------------------------------------
@router.get("/overview", response_model=VulnerabilityOverviewResponse)
async def get_overview(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve aggregate vulnerability counts, severity breakdown, and top affected hosts."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await db_service.get_vulnerability_overview(org_id)


# ------------------------------------------------------------------------------
# 2. Findings Inventory
# ------------------------------------------------------------------------------
@router.get("/findings")
async def list_findings(
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    is_kev: Optional[bool] = Query(None),
    asset_id: Optional[UUID] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List, filter, and paginate normalized security findings."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    return await db_service.get_vulnerability_findings(
        org_id=org_id,
        severity=severity,
        status=status_filter,
        is_kev=is_kev,
        asset_id=str(asset_id) if asset_id else None,
        search=search,
        page=page,
        page_size=page_size,
    )


# ------------------------------------------------------------------------------
# 3. CVE & KEV Intelligence Endpoints
# ------------------------------------------------------------------------------
@router.get("/cves/{cve_id}")
async def get_cve_intel(
    cve_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve detailed CVE intelligence from official NVD records or local catalog."""
    cve_data = await cve_service.get_cve_details(cve_id)
    if not cve_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE identifier '{cve_id}' not found in NVD or local intelligence base.",
        )
    # Check if also weaponized in CISA KEV
    cve_data["is_in_kev"] = kev_service.is_in_kev(cve_id)
    cve_data["kev_metadata"] = kev_service.get_kev_metadata(cve_id)
    return cve_data


@router.get("/kev")
async def get_kev_catalog(
    limit: int = Query(50, ge=1, le=500),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve CISA Known Exploited Vulnerabilities (KEV) catalog entries."""
    return {
        "catalog_size": len(kev_service._catalog),
        "last_refreshed": kev_service._last_refreshed,
        "items": kev_service.get_all_kev(limit=limit),
    }


# ------------------------------------------------------------------------------
# 4. Vulnerability Scans (Assessment Orchestrator)
# ------------------------------------------------------------------------------
@router.get("/scans", response_model=List[VulnerabilityScanResponse])
async def list_vulnerability_scans(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List historical and active vulnerability assessment scans."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await db_service.get_vulnerability_scans(org_id)


@router.post(
    "/scans",
    response_model=VulnerabilityScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_vulnerability_scan(
    payload: VulnerabilityScanCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Launch an authorized vulnerability assessment.
    Requires role 'owner', 'admin', or 'analyst'.
    Strictly verifies approved network scope and expiration before launching.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    # 1. Validate Scope Existence and Approval
    scopes = await db_service.get_scopes(org_id)
    target_scope = next((s for s in scopes if str(s["id"]) == str(payload.scan_scope_id)), None)

    if not target_scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Specified scan scope does not exist in this organization",
        )

    if target_scope.get("authorization_status") != "Approved":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot assess unapproved scope. Current status is '{target_scope.get('authorization_status')}'.",
        )

    if target_scope.get("is_expired"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot assess expired scope. Re-authorization from Organization Owner is required.",
        )

    scanner_names = {
        "openvas": "Greenbone OpenVAS Community Engine",
        "zap_baseline": "OWASP ZAP Baseline Engine",
        "mock": "CyberShield Diagnostic Mock Engine",
        "comprehensive": "CyberShield Multi-Engine Suite",
    }

    # 2. Register Scan Job
    scan_record = await db_service.create_vulnerability_scan_record(
        org_id=org_id,
        user_id=current_user.user_id,
        scope_id=str(payload.scan_scope_id),
        scan_type=payload.scan_type,
        scanner_name=scanner_names.get(payload.scan_type, "CyberShield Engine"),
    )

    # 3. Dispatch to Celery Background Worker
    target_assets_str = (
        [str(aid) for aid in payload.target_asset_ids]
        if payload.target_asset_ids
        else None
    )

    try:
        start_vulnerability_assessment.delay(
            scan_id=scan_record["id"],
            organization_id=org_id,
            user_id=current_user.user_id,
            scope_id=str(payload.scan_scope_id),
            scan_type=payload.scan_type,
            target_asset_ids=target_assets_str,
        )
    except Exception as e:
        logger.warning(
            f"Celery dispatch failed (Redis offline?), executing in background thread: {e}"
        )
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                lambda: start_vulnerability_assessment(
                    scan_id=scan_record["id"],
                    organization_id=org_id,
                    user_id=current_user.user_id,
                    scope_id=str(payload.scan_scope_id),
                    scan_type=payload.scan_type,
                    target_asset_ids=target_assets_str,
                ),
            )
            updated = await db_service.get_vulnerability_scan_by_id(
                org_id, scan_record["id"]
            )
            if updated:
                scan_record = updated
        except Exception as inner_e:
            logger.error(f"Execution fallback failed: {inner_e}")

    return scan_record


@router.get("/scans/{scan_id}", response_model=VulnerabilityScanResponse)
async def get_vulnerability_scan(
    scan_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Get the live status and progress of a vulnerability assessment."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    scan = await db_service.get_vulnerability_scan_by_id(org_id, str(scan_id))
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability scan not found",
        )
    return scan


@router.post("/scans/{scan_id}/cancel", response_model=VulnerabilityScanResponse)
async def cancel_vulnerability_scan(
    scan_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Cancel an active vulnerability assessment scan."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    cancelled = await db_service.cancel_vulnerability_scan(org_id, str(scan_id))
    if not cancelled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability scan not found",
        )
    return cancelled


# ------------------------------------------------------------------------------
# 5. Asset Correlation
# ------------------------------------------------------------------------------
@router.get("/assets/{asset_id}", response_model=List[VulnerabilityFindingResponse])
async def get_asset_vulnerabilities(
    asset_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve all findings correlated with a specific asset."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    asset = await db_service.get_asset_by_id(org_id, str(asset_id))
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found in organization inventory",
        )

    return await db_service.get_vulnerability_findings_by_asset(org_id, str(asset_id))


# ------------------------------------------------------------------------------
# 6. Single Finding Details & Triage
# ------------------------------------------------------------------------------
@router.get("/findings/{finding_id}", response_model=VulnerabilityFindingResponse)
async def get_finding(
    finding_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Get single finding details including proof of concept evidence and remediation."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    finding = await db_service.get_vulnerability_finding_by_id(org_id, str(finding_id))
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability finding not found",
        )
    return finding


@router.patch("/findings/{finding_id}", response_model=VulnerabilityFindingResponse)
async def update_finding(
    finding_id: UUID,
    payload: VulnerabilityFindingUpdate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Update finding status or metadata. Requires role 'owner', 'admin', or 'analyst'."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    finding = await db_service.get_vulnerability_finding_by_id(org_id, str(finding_id))
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability finding not found",
        )

    old_status = finding["status"]
    update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
    updated = await db_service.update_vulnerability_finding(
        org_id, str(finding_id), update_data
    )

    if payload.status and payload.status != old_status:
        await db_service.add_remediation_history(
            org_id=org_id,
            finding_id=str(finding_id),
            previous_status=old_status,
            new_status=payload.status,
            notes=payload.notes or "Status updated via API",
            changed_by=current_user.user_id,
        )

    return updated


# ------------------------------------------------------------------------------
# 7. Remediation Workflow & History
# ------------------------------------------------------------------------------
@router.post(
    "/findings/{finding_id}/remediation",
    response_model=VulnerabilityFindingResponse,
)
async def apply_remediation_action(
    finding_id: UUID,
    action: RemediationActionRequest,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Execute a formal remediation lifecycle transition (e.g. Acknowledge, In Progress,
    Resolved, Accepted Risk, False Positive).
    Enforces mandatory justification notes for Accepted Risk and False Positive.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    finding = await db_service.get_vulnerability_finding_by_id(org_id, str(finding_id))
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability finding not found",
        )

    old_status = finding["status"]

    # Prevent no-op transitions
    if old_status == action.new_status:
        return finding

    # Update finding
    updated = await db_service.update_vulnerability_finding(
        org_id, str(finding_id), {"status": action.new_status}
    )

    # Record remediation history audit
    await db_service.add_remediation_history(
        org_id=org_id,
        finding_id=str(finding_id),
        previous_status=old_status,
        new_status=action.new_status,
        notes=action.notes,
        changed_by=current_user.user_id,
    )

    return updated


@router.get(
    "/findings/{finding_id}/history",
    response_model=List[RemediationHistoryResponse],
)
async def get_finding_history(
    finding_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Get the complete remediation audit trail for a vulnerability finding."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    finding = await db_service.get_vulnerability_finding_by_id(org_id, str(finding_id))
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability finding not found",
        )

    return await db_service.get_remediation_history(org_id, str(finding_id))
