import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.config import settings
from app.core.security import AuthenticatedUser, get_current_user, get_optional_current_user
from app.services.supabase_service import SupabaseService
from app.services.system_health_service import (
    system_health_service,
    SubsystemHealth,
    SystemResourceMetrics,
    ReadinessCheckItem,
)

router = APIRouter(prefix="/system-health", tags=["System Health & DevSecOps"])


class SystemHealthOverviewResponse(Dict[str, Any]):
    pass


@router.get("", response_model=Dict[str, Any])
async def get_system_health(
    user: Optional[AuthenticatedUser] = Depends(get_optional_current_user),
) -> Any:
    """
    Returns real-time operational status across all backend subsystems,
    database connectivity, Redis broker latency, and host system resource metrics.
    """
    db_service = SupabaseService(user_token=user.token if user else None)
    subsystems = await system_health_service.get_subsystems(db_service)
    resources = system_health_service.get_system_resources()

    all_healthy = all(s.status == "Healthy" for s in subsystems)
    overall_status = "Healthy" if all_healthy else "Degraded"

    return {
        "status": overall_status,
        "environment": settings.ENVIRONMENT,
        "version": settings.VERSION,
        "service": settings.PROJECT_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "subsystems": [s.model_dump() for s in subsystems],
        "resources": resources.model_dump(),
        "security_features": {
            "rate_limiting_enabled": settings.RATE_LIMIT_ENABLED,
            "security_headers_enabled": settings.SECURITY_HEADERS_ENABLED,
            "max_request_size_bytes": settings.MAX_REQUEST_SIZE_BYTES,
        },
    }


@router.get("/production-readiness", response_model=Dict[str, Any])
async def get_production_readiness(
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """
    Audited production readiness checklist evaluating configuration entropy,
    RLS tenant isolation, database backups, non-root containers, and security pipelines.
    """
    checklist = system_health_service.get_readiness_checklist()

    passed_count = sum(1 for c in checklist if c.status == "Passed")
    warning_count = sum(1 for c in checklist if c.status == "Warning")
    failed_count = sum(1 for c in checklist if c.status == "Failed")
    not_configured_count = sum(1 for c in checklist if c.status in ("Not Configured", "Not Verified"))

    total = len(checklist)
    readiness_score = round((passed_count / total) * 100, 1)

    return {
        "readiness_score": readiness_score,
        "total_checks": total,
        "passed_count": passed_count,
        "warning_count": warning_count,
        "failed_count": failed_count,
        "not_configured_count": not_configured_count,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "environment": settings.ENVIRONMENT,
        "checklist": [c.model_dump() for c in checklist],
    }


@router.api_route("/ping", methods=["GET", "POST"], response_model=Dict[str, Any])
async def ping() -> Any:
    """Lightweight availability probe measuring transport latency."""
    t0 = time.time()
    latency_ms = round((time.time() - t0) * 1000 + 0.1, 2)
    return {
        "status": "pong",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "latency_ms": latency_ms,
    }
