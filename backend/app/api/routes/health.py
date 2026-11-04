from datetime import datetime
from fastapi import APIRouter
from app.core.config import settings
from app.schemas.common import HealthResponse
from app.workers.celery_app import check_redis_connection

router = APIRouter(prefix="", tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def get_health():
    """Service liveness, configuration and Redis connectivity probe."""
    redis_ok = check_redis_connection()
    return HealthResponse(
        status="healthy",
        service=settings.PROJECT_NAME,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        redis_connected=redis_ok,
        timestamp=datetime.utcnow(),
    )
