import logging
from celery import Celery
import redis

from app.core.config import settings

logger = logging.getLogger(__name__)

celery_app = Celery(
    "cybershield_workers",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.SCAN_DEFAULT_TIMEOUT_SECONDS,
    worker_concurrency=4,
    worker_prefetch_multiplier=1,
)


def check_redis_connection() -> bool:
    """Verifies Redis connectivity with ping."""
    try:
        r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.2, socket_timeout=0.2)
        return bool(r.ping())
    except Exception as e:
        logger.debug(f"Redis connection check failed: {e}")
        return False
