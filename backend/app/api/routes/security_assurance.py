"""
Security Validation, Penetration Testing & Continuous Assurance API Routes
CyberShield Sprint 19
"""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.security_assurance import (
    SecurityAssessmentCreate,
    SecurityAssessmentResponse,
    SecurityCheckResponse,
    SecurityTestRunResponse,
    APISecuritySuiteDispatchRequest,
    SecurityFindingCreate,
    SecurityFindingUpdate,
    SecurityFindingResponse,
    SecurityFindingNoteCreate,
    SecurityFindingNoteResponse,
    SecurityRiskAcceptanceRequest,
    DependencyPackageItem,
    ContainerScanResult,
    SecurityConfigurationCheck,
    SecurityScannerConfigResponse,
    SecurityScannerConfigUpdate,
    SecurityComponentInventoryResponse,
    SecurityAssuranceOverviewResponse,
    SecurityReportExportRequest,
    SecurityReportExportResponse,
)
from app.services.security_assurance_service import security_assurance_service
from app.services.supabase_service import SupabaseService, supabase_service

router = APIRouter(prefix="/security-assurance", tags=["Continuous Security Validation & Pentesting"])


async def _resolve_org_and_role(
    db_service: SupabaseService,
    user: AuthenticatedUser,
    org_id_param: Optional[UUID] = None,
    allowed_roles: Optional[List[str]] = None,
) -> tuple[str, str]:
    """Verify organization membership, access permissions, and return target org_id and user role."""
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
    return target_org_id, role


# ------------------------------------------------------------------------------
# 1. OVERVIEW & POSTURE DASHBOARD
# ------------------------------------------------------------------------------

@router.get("/overview", response_model=SecurityAssuranceOverviewResponse)
async def get_security_assurance_overview(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve continuous security assurance posture, coverage metrics, and sample failed checks."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return security_assurance_service.get_overview(target_org_id)


# ------------------------------------------------------------------------------
# 2. ASSESSMENTS & OWASP VALIDATIONS
# ------------------------------------------------------------------------------

@router.get("/assessments", response_model=List[SecurityAssessmentResponse])
async def list_security_assessments(
    limit: int = Query(50, ge=1, le=100),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """List historical security validation assessments."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    assessments = supabase_service.list_security_assessments(target_org_id, limit)
    return [SecurityAssessmentResponse(**a) for a in assessments]


@router.post("/assessments/run", response_model=SecurityAssessmentResponse)
async def run_security_assessment(
    payload: SecurityAssessmentCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Dispatch an automated security assessment (OWASP, API, or full suite). Requires 'owner', 'admin', or 'analyst'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return security_assurance_service.run_assessment(
        org_id=target_org_id,
        data=payload,
        actor_email=user.email,
    )


@router.get("/assessments/{assessment_id}/checks", response_model=List[SecurityCheckResponse])
async def list_assessment_checks(
    assessment_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve individual checklist verification items (e.g. OWASP Top 10 rules) for an assessment."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    checks = supabase_service.list_assessment_checks(target_org_id, assessment_id)
    return [SecurityCheckResponse(**c) for c in checks]


# ------------------------------------------------------------------------------
# 3. API SECURITY TESTING ENGINE
# ------------------------------------------------------------------------------

@router.get("/tests/runs", response_model=List[SecurityTestRunResponse])
async def list_security_test_runs(
    limit: int = Query(20, ge=1, le=50),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """List historical automated API security test execution runs."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    runs = supabase_service.list_security_test_runs(target_org_id, limit)
    res = []
    for r in runs:
        detailed = supabase_service.get_security_test_run(target_org_id, r["id"]) or r
        res.append(SecurityTestRunResponse(
            id=detailed["id"],
            organization_id=detailed["organization_id"],
            suite_name=detailed["suite_name"],
            status=detailed["status"],
            total_tests=detailed["total_tests"],
            passed_tests=detailed["passed_tests"],
            failed_tests=detailed["failed_tests"],
            execution_duration_sec=detailed["execution_duration_sec"],
            target_host=detailed["target_host"],
            executed_by=detailed.get("executed_by"),
            results=detailed.get("results", []),
            created_at=detailed["created_at"],
        ))
    return res


@router.get("/tests/runs/{run_id}", response_model=SecurityTestRunResponse)
async def get_security_test_run(
    run_id: str,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve detailed results of a specific API security test execution run."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    run = supabase_service.get_security_test_run(target_org_id, run_id)
    if not run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Test run not found.")
    return SecurityTestRunResponse(
        id=run["id"],
        organization_id=run["organization_id"],
        suite_name=run["suite_name"],
        status=run["status"],
        total_tests=run["total_tests"],
        passed_tests=run["passed_tests"],
        failed_tests=run["failed_tests"],
        execution_duration_sec=run["execution_duration_sec"],
        target_host=run["target_host"],
        executed_by=run.get("executed_by"),
        results=run.get("results", []),
        created_at=run["created_at"],
    )


@router.post("/tests/run-api-suite", response_model=SecurityTestRunResponse)
async def dispatch_api_security_tests(
    payload: APISecuritySuiteDispatchRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Execute dynamic API security validation against authorized target endpoints. Requires 'owner', 'admin', or 'analyst'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return security_assurance_service.dispatch_api_security_suite(
        org_id=target_org_id,
        request=payload,
        actor_email=user.email,
    )


# ------------------------------------------------------------------------------
# 4. UNIFIED FINDINGS & REMEDIATION MANAGEMENT
# ------------------------------------------------------------------------------

@router.get("/findings", response_model=List[SecurityFindingResponse])
async def list_security_findings(
    finding_status: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    source_scanner: Optional[str] = Query(None),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Query unified security findings with filtering by status, severity, category, or scanner."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return security_assurance_service.list_findings(
        org_id=target_org_id,
        status=finding_status,
        severity=severity,
        category=category,
        source_scanner=source_scanner,
    )


@router.post("/findings", response_model=SecurityFindingResponse)
async def create_security_finding(
    payload: SecurityFindingCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Log an ad-hoc or manual penetration test finding. Requires 'owner', 'admin', or 'analyst'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    item = supabase_service.create_security_finding(target_org_id, payload.model_dump())
    return SecurityFindingResponse(
        id=item["id"],
        organization_id=item["organization_id"],
        finding_code=item["finding_code"],
        title=item["title"],
        description=item["description"],
        category=item["category"],
        source_scanner=item["source_scanner"],
        severity=item["severity"],
        affected_component=item["affected_component"],
        cve_reference=item.get("cve_reference"),
        cwe_id=item.get("cwe_id"),
        cvss_score=item.get("cvss_score"),
        evidence=item.get("evidence", {}),
        remediation_recommendation=item["remediation_recommendation"],
        remediation_pr_url=item.get("remediation_pr_url"),
        assigned_to_user_id=item.get("assigned_to_user_id"),
        assigned_to_name=item.get("assigned_to_name"),
        status=item["status"],
        first_detected_at=item["first_detected_at"],
        last_detected_at=item["last_detected_at"],
        resolved_at=item.get("resolved_at"),
        verified_at=item.get("verified_at"),
        notes=[],
        history=[],
        created_at=item["created_at"],
        updated_at=item["updated_at"],
    )


@router.put("/findings/{finding_id}", response_model=SecurityFindingResponse)
async def update_security_finding(
    finding_id: str,
    payload: SecurityFindingUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Update finding triage status, assignee, or remediation notes. Requires 'owner', 'admin', or 'analyst'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"])
    return security_assurance_service.update_finding(
        org_id=target_org_id,
        finding_id=finding_id,
        data=payload,
        actor_name=user.email,
    )


@router.post("/findings/{finding_id}/notes", response_model=SecurityFindingNoteResponse)
async def add_finding_note(
    finding_id: str,
    payload: SecurityFindingNoteCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Add an analyst note to a security finding."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return security_assurance_service.add_finding_note(
        org_id=target_org_id,
        finding_id=finding_id,
        author_id=str(user.user_id),
        author_name=user.email,
        content=payload.content,
    )


@router.post("/findings/{finding_id}/accept-risk", response_model=SecurityFindingResponse)
async def accept_finding_risk(
    finding_id: str,
    payload: SecurityRiskAcceptanceRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Document accepted security risk with operational justification and expiry date. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin"])
    return security_assurance_service.accept_finding_risk(
        org_id=target_org_id,
        finding_id=finding_id,
        payload=payload,
        user_id=str(user.user_id),
        user_name=user.email,
    )


# ------------------------------------------------------------------------------
# 5. SUPPLY CHAIN, CONTAINERS & CONFIGURATION AUDITS
# ------------------------------------------------------------------------------

@router.get("/dependencies", response_model=List[DependencyPackageItem])
async def get_dependencies_audit(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Software Supply Chain package inventory, known CVE advisories, and recommended upgrades."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return security_assurance_service.get_dependency_inventory(target_org_id)


@router.get("/containers", response_model=List[ContainerScanResult])
async def get_containers_audit(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Docker container fleet image scan results, base OS vulnerabilities, and privilege posture."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return security_assurance_service.get_container_scan_results(target_org_id)


@router.get("/configuration", response_model=List[SecurityConfigurationCheck])
async def get_configuration_audit(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Automated 17-point secure configuration checklist (HSTS, Cookies, CORS, Debug flags, Docker privileges)."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return security_assurance_service.get_configuration_checks(target_org_id)


# ------------------------------------------------------------------------------
# 6. SCANNER CONFIGURATIONS & COMPONENT INVENTORY
# ------------------------------------------------------------------------------

@router.get("/settings", response_model=List[SecurityScannerConfigResponse])
async def list_scanner_configurations(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve security scanner settings, approved targets, and rate limits."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    scanners = supabase_service.list_security_scan_configurations(target_org_id)
    return [SecurityScannerConfigResponse(**s) for s in scanners]


@router.put("/settings/{scanner_type}", response_model=SecurityScannerConfigResponse)
async def update_scanner_configuration(
    scanner_type: str,
    payload: SecurityScannerConfigUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Update scanner configuration, target boundaries, or rate limit. Requires 'owner' or 'admin'."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id, allowed_roles=["owner", "admin"])
    updated = supabase_service.update_security_scan_configuration(
        target_org_id,
        scanner_type,
        payload.model_dump(exclude_unset=True),
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scanner configuration not found.")
    return SecurityScannerConfigResponse(**updated)


@router.get("/inventory", response_model=List[SecurityComponentInventoryResponse])
async def list_component_inventory(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """List architecture component security health inventory."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    components = supabase_service.list_security_component_inventory(target_org_id)
    return [SecurityComponentInventoryResponse(**c) for c in components]


# ------------------------------------------------------------------------------
# 7. REPORT EXPORT
# ------------------------------------------------------------------------------

@router.post("/reports/export", response_model=SecurityReportExportResponse)
async def export_security_report(
    payload: SecurityReportExportRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
):
    """Generate and export a security validation and assurance report in JSON or CSV format."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id, _ = await _resolve_org_and_role(db_service, user, org_id)
    return security_assurance_service.export_report(
        org_id=target_org_id,
        report_type=payload.report_type,
        export_format=payload.format,
    )
