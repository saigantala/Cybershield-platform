from typing import Any, Dict, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.services.analytics_service import AnalyticsService
from app.services.compliance_service import compliance_service
from app.services.posture_service import posture_service
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/analytics", tags=["Advanced Security Analytics"])


async def _resolve_org(
    db_service: SupabaseService,
    user: AuthenticatedUser,
    org_id_param: Optional[UUID] = None,
) -> str:
    memberships = await db_service.get_user_org_membership(user.user_id)
    if not memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User does not belong to any authorized organization",
        )

    target_org_id = str(org_id_param) if org_id_param else str(memberships[0]["organization_id"])
    has_access, role = await db_service.verify_org_access(user.user_id, target_org_id)

    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {role}",
        )
    return target_org_id


@router.get("/overview", response_model=Dict[str, Any])
async def get_overview(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve holistic security posture rating, asset metrics, and active threats."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await AnalyticsService.get_overview_analytics(db_service, org_id)


@router.get("/assets", response_model=Dict[str, Any])
async def get_assets_analytics(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve device types, OS breakdown, and risk severity distributions."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await AnalyticsService.get_asset_analytics(db_service, org_id)


@router.get("/vulnerabilities", response_model=Dict[str, Any])
async def get_vulnerabilities_analytics(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve open findings breakdown, CISA KEV counts, and resolution velocity."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await AnalyticsService.get_vulnerability_analytics(db_service, org_id)


@router.get("/alerts", response_model=Dict[str, Any])
async def get_alerts_analytics(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve alert source distribution, false-positive ratios, and triage speed."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await AnalyticsService.get_alert_analytics(db_service, org_id)


@router.get("/incidents", response_model=Dict[str, Any])
async def get_incidents_analytics(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve incident status counts, incident types, and MTTR telemetry."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await AnalyticsService.get_incident_analytics(db_service, org_id)


@router.get("/threat-intelligence", response_model=Dict[str, Any])
async def get_threat_intel_analytics(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve IOC observable types, threat feed health, and confidence scores."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await AnalyticsService.get_threat_intel_analytics(db_service, org_id)


@router.get("/posture")
async def get_posture_analytics(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Calculates deterministic 0-100 security posture score, categories, and factors."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await posture_service.calculate_posture_score(db_service, org_id)


@router.get("/executive-summary")
async def get_executive_summary_analytics(
    date_range: Optional[str] = Query("30d", description="7d, 30d, 90d, custom"),
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Returns aggregated executive scorecard, top 5 risks, and trend lines."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await posture_service.get_executive_summary(db_service, org_id, date_range=date_range or "30d")


@router.get("/compliance")
async def get_compliance_analytics(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Returns tenant-wide compliance scores, framework completion, and overdue metrics."""
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)
    return await compliance_service.get_compliance_summary(db_service, org_id)

