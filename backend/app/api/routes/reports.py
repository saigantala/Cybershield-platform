from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.reporting import (
    ReportGenerateRequest,
    ReportPreviewResponse,
    SecurityReportResponse,
)
from app.services.csv_service import CSVExportService
from app.services.pdf_service import PDFDocumentBuilder
from app.services.posture_service import posture_service
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/reports", tags=["Security Compliance & Executive Reports"])

# In-memory storage of generated report binary content (keyed by report ID)
_report_content_store: Dict[str, bytes] = {}


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


async def _fetch_report_records(
    db_service: SupabaseService,
    org_id: str,
    report_type: str,
    parameters: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Helper retrieving domain records based on report type and filters."""
    if report_type == "vulnerability_assessment":
        res = await db_service.get_vulnerability_findings(org_id=org_id, page=1, page_size=500)
        items = res[0] if isinstance(res, tuple) else res.get("items", [])
        sev_filter = parameters.get("severity_filter")
        if sev_filter:
            items = [f for f in items if f.get("severity") in sev_filter]
        return items

    elif report_type == "asset_inventory":
        res = await db_service.get_assets(org_id=org_id, page=1, page_size=500)
        return res[0] if isinstance(res, tuple) else res.get("items", [])

    elif report_type == "incident_summary":
        res = await db_service.get_incidents(org_id=org_id, page=1, page_size=500)
        return res[0] if isinstance(res, tuple) else res.get("items", [])

    elif report_type == "threat_intelligence":
        res = await db_service.get_threat_indicators(org_id=org_id, page=1, page_size=500)
        return res[0] if isinstance(res, tuple) else res.get("items", [])

    elif report_type == "compliance_assessment":
        return await db_service.get_compliance_controls_with_status(org_id=org_id)

    else:
        # Default security posture records
        posture = await posture_service.calculate_posture_score(db_service, org_id)
        return [
            {
                "category": k.replace("_", " ").title(),
                "score": v,
                "status": "Evaluated",
            }
            for k, v in posture.category_scores.model_dump().items()
        ]


@router.get("", response_model=List[SecurityReportResponse])
async def list_reports(
    report_type: Optional[str] = Query(None, description="Filter by report type"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists previously generated security reports for the organization."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await db_service.get_security_reports(target_org_id, report_type=report_type)


@router.post("/preview", response_model=ReportPreviewResponse)
async def preview_report(
    payload: ReportGenerateRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Generates a structured real-time preview of report findings before exporting."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)

    org = await db_service.get_organization(target_org_id)
    org_name = org.get("name", "Apex CyberDefense") if org else "Apex CyberDefense"

    records = await _fetch_report_records(db_service, target_org_id, payload.report_type, payload.model_dump())
    posture = await posture_service.calculate_posture_score(db_service, target_org_id)

    title = payload.title or f"{payload.report_type.replace('_', ' ').title()} Executive Brief"
    summary = (
        f"Automated evaluation completed across {len(records)} records for tenant {org_name}. "
        f"Overall Security Posture Score currently rated at {posture.overall_score}/100 ({posture.risk_level})."
    )

    metrics = {
        "total_records": len(records),
        "posture_score": posture.overall_score,
        "risk_level": posture.risk_level,
    }

    return ReportPreviewResponse(
        title=title,
        report_type=payload.report_type,
        format=payload.format,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        organization_name=org_name,
        executive_summary=summary,
        key_metrics=metrics,
        sample_records=records[:5],
        recommended_actions=posture.recommended_improvements[:3],
    )


@router.post("/generate", response_model=SecurityReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(
    payload: ReportGenerateRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Generates an enterprise PDF or CSV report and registers it in the tenant report catalog."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)

    org = await db_service.get_organization(target_org_id)
    org_name = org.get("name", "Apex CyberDefense") if org else "Apex CyberDefense"

    records = await _fetch_report_records(db_service, target_org_id, payload.report_type, payload.model_dump())
    posture = await posture_service.calculate_posture_score(db_service, target_org_id)

    report_id = str(uuid4())
    title = payload.title or f"{payload.report_type.replace('_', ' ').title()} - {datetime.utcnow().strftime('%B %Y')}"

    summary = (
        f"Comprehensive automated audit for {org_name}. "
        f"Evaluated {len(records)} active telemetry records. "
        f"Overall security posture evaluated at {posture.overall_score}/100 ({posture.risk_level})."
    )

    metrics = {
        "evaluated_records": len(records),
        "posture_score": posture.overall_score,
        "risk_classification": posture.risk_level,
    }

    # Generate document bytes
    if payload.format == "csv":
        csv_str = CSVExportService.export_report_csv(payload.report_type, records)
        content_bytes = csv_str.encode("utf-8")
    else:
        # Standard PDF
        builder = PDFDocumentBuilder(title=title, organization_name=org_name)
        content_bytes = builder.generate_report_pdf(
            report_type=payload.report_type,
            executive_summary=summary,
            metrics=metrics,
            findings_or_records=records,
            recommendations=posture.recommended_improvements,
        )

    # Store binary in memory cache for immediate download
    _report_content_store[report_id] = content_bytes

    now = datetime.utcnow().isoformat() + "Z"
    record = {
        "id": report_id,
        "organization_id": target_org_id,
        "title": title,
        "report_type": payload.report_type,
        "format": payload.format,
        "status": "Completed",
        "parameters": payload.model_dump(),
        "summary_metrics": metrics,
        "file_size_bytes": len(content_bytes),
        "download_url": f"/api/v1/reports/{report_id}/download",
        "generated_by": user.user_id,
        "created_at": now,
        "completed_at": now,
    }
    return await db_service.create_security_report(record)


@router.get("/{report_id}", response_model=SecurityReportResponse)
async def get_report(
    report_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Retrieves metadata and summary metrics for a specific report."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)

    report = await db_service.get_security_report_by_id(target_org_id, str(report_id))
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security report not found",
        )
    return report


@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    format: Optional[str] = Query(None, description="pdf or csv"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Downloads the generated report binary artifact (PDF or CSV). Enforces tenant isolation."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)

    report = await db_service.get_security_report_by_id(target_org_id, str(report_id))
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security report not found",
        )

    # Retrieve cached bytes or generate on the fly
    content_bytes = _report_content_store.get(str(report_id))
    if not content_bytes:
        # Re-generate from telemetry
        records = await _fetch_report_records(db_service, target_org_id, report["report_type"], report.get("parameters", {}))
        posture = await posture_service.calculate_posture_score(db_service, target_org_id)
        builder = PDFDocumentBuilder(title=report["title"], organization_name="Apex CyberDefense")
        content_bytes = builder.generate_report_pdf(
            report_type=report["report_type"],
            executive_summary=f"Report export for {report['title']}",
            metrics={"total_records": len(records), "score": posture.overall_score},
            findings_or_records=records,
            recommendations=posture.recommended_improvements,
        )

    fmt = format or report.get("format", "pdf")
    if fmt == "csv":
        media_type = "text/csv"
        filename = f"{report['report_type']}_{str(report_id)[:8]}.csv"
    else:
        media_type = "application/pdf"
        filename = f"{report['report_type']}_{str(report_id)[:8]}.pdf"

    return Response(
        content=content_bytes,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
