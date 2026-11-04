from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.monitoring import (
    TrafficAnalyticsResponse,
    ProtocolBreakdown,
    TopTalkerItem,
    NetworkAnomalyResponse,
)
from app.services.monitoring_service import monitoring_service
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/network", tags=["Network Traffic Analytics & Anomalies"])


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


@router.get("/traffic", response_model=TrafficAnalyticsResponse)
async def get_network_traffic(
    time_window_seconds: int = Query(3600, ge=60, le=86400),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns network traffic telemetry summary, upload/download volumes, and historical trend."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await monitoring_service.get_traffic_analytics(db_service, target_org_id, time_window_seconds)


@router.get("/protocols", response_model=List[ProtocolBreakdown])
async def get_protocol_distribution(
    time_window_seconds: int = Query(3600, ge=60, le=86400),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns breakdown of observed network protocols by volume and packet percentage."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    analytics = await monitoring_service.get_traffic_analytics(db_service, target_org_id, time_window_seconds)
    return analytics.protocol_breakdown


@router.get("/top-talkers", response_model=List[TopTalkerItem])
async def get_top_talkers(
    time_window_seconds: int = Query(3600, ge=60, le=86400),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns top communicating IP addresses by total transmitted bytes and packet count."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    analytics = await monitoring_service.get_traffic_analytics(db_service, target_org_id, time_window_seconds)
    return analytics.top_talkers


@router.get("/anomalies", response_model=List[NetworkAnomalyResponse])
async def get_network_anomalies(
    status_filter: Optional[str] = Query(None, description="Filter by status: Open, Investigating, Resolved"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns rule-based network anomalies with evidentiary telemetry and recommended actions."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    anomalies = await db_service.get_network_anomalies(target_org_id, status=status_filter)
    return [
        NetworkAnomalyResponse(
            id=a["id"],
            detected_at=a["detected_at"],
            source_asset=a.get("source_asset", "Unknown"),
            event_category=a["event_category"],
            severity=a["severity"],
            rule_name=a["rule_name"],
            evidence=a.get("evidence", {}),
            confidence=a.get("confidence", 85),
            recommended_investigation=a.get("recommended_investigation", "Inspect flow telemetry"),
            status=a.get("status", "Open"),
            asset_id=a.get("asset_id"),
        )
        for a in anomalies
    ]
