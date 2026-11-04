from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user, get_optional_current_user
from app.schemas.monitoring import (
    AgentRegisterRequest,
    AgentResponse,
    IngestTelemetryPayload,
    MonitoringStatusResponse,
    DeviceHealthSummary,
    MonitoringRuleCreate,
    MonitoringRuleUpdate,
    MonitoringRuleResponse,
    MonitoringEventItem,
)
from app.services.monitoring_service import monitoring_service
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/monitoring", tags=["Real-Time SOC & Device Monitoring"])


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


@router.get("/status", response_model=MonitoringStatusResponse)
async def get_monitoring_status(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns real-time SOC monitoring status, active agent count, and network health."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await monitoring_service.get_monitoring_status(db_service, target_org_id)


@router.get("/events", response_model=List[MonitoringEventItem])
async def list_monitoring_events(
    limit: int = Query(50, ge=1, le=200),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns the unified timeline of monitoring and security events."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    events = await db_service.get_monitoring_events(target_org_id, limit)
    return [
        MonitoringEventItem(
            id=e["id"],
            timestamp=e["timestamp"],
            event_type=e["event_type"],
            severity=e["severity"],
            title=e["title"],
            details=e.get("details", {}),
            agent_id=e.get("agent_id"),
            asset_id=e.get("asset_id"),
        )
        for e in events
    ]


@router.get("/agents", response_model=List[AgentResponse])
async def list_monitoring_agents(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists registered endpoint and sensor monitoring agents."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await monitoring_service.list_agents(db_service, target_org_id)


@router.post("/agents/register", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def register_monitoring_agent(
    req: AgentRegisterRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Enrolls a new authorized monitoring agent and returns the one-time secret API key."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    return await monitoring_service.register_agent(db_service, target_org_id, req)


@router.post("/telemetry")
async def ingest_telemetry(
    payload: IngestTelemetryPayload,
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    user: Optional[AuthenticatedUser] = Depends(get_optional_current_user),
) -> Any:
    """Ingests authorized network flows and host metrics from an enrolled monitoring agent."""
    db_service = SupabaseService(user_token=user.token if user else None)
    target_org_id: Optional[str] = None

    if x_agent_key:
        agent = await monitoring_service.authenticate_agent(db_service, payload.agent_id, x_agent_key)
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked monitoring agent credentials",
            )
        target_org_id = str(agent["organization_id"])
    elif user:
        target_org_id = await _resolve_org(
            db_service, user, allowed_roles=["owner", "admin", "analyst"]
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: provide valid X-Agent-Key or Bearer token",
        )

    try:
        return await monitoring_service.ingest_telemetry(db_service, target_org_id, payload)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))


@router.get("/telemetry")
async def get_recent_telemetry(
    time_window_seconds: int = Query(3600, ge=60, le=86400),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns recent network flow telemetry records for the organization."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await db_service.get_network_telemetry(target_org_id, time_window_seconds)


@router.get("/device-health", response_model=List[DeviceHealthSummary])
async def list_device_health(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns device health status, agent availability, and system metrics for registered assets."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await monitoring_service.get_device_health(db_service, target_org_id)


@router.get("/device-health/{asset_id}", response_model=DeviceHealthSummary)
async def get_single_device_health(
    asset_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns detailed health status and telemetry for a specific asset."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    health_list = await monitoring_service.get_device_health(db_service, target_org_id)
    matched = next((d for d in health_list if str(d.asset_id) == str(asset_id)), None)
    if not matched:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return matched


@router.get("/rules", response_model=List[MonitoringRuleResponse])
async def list_monitoring_rules(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists configured anomaly detection and monitoring threshold rules."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await monitoring_service.list_rules(db_service, target_org_id)


@router.post("/rules", response_model=MonitoringRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_monitoring_rule(
    req: MonitoringRuleCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Creates a new rule for evaluating network traffic anomalies and threshold breaches."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    return await monitoring_service.create_rule(db_service, target_org_id, req)


@router.patch("/rules/{rule_id}", response_model=MonitoringRuleResponse)
async def update_monitoring_rule(
    rule_id: UUID,
    req: MonitoringRuleUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Updates parameters or status for an existing monitoring rule."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    updated = await monitoring_service.update_rule(db_service, target_org_id, str(rule_id), req)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Monitoring rule not found")
    return updated
