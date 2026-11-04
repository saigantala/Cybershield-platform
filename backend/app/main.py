import logging
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import api_router
from app.core.config import settings
from app.core.middleware import (
    RequestCorrelationMiddleware,
    SecurityHeadersMiddleware,
    RateLimiterMiddleware,
    RequestSizeLimiterMiddleware,
    SensitiveDataRedactor,
    SensitiveLogFilter,
)

# Structured logging configuration
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cybershield")
logger.addFilter(SensitiveLogFilter())


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and graceful shutdown lifecycle."""
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION} [{settings.ENVIRONMENT}]")
    logger.info(f"Allowed CORS origins: {settings.ALLOWED_ORIGINS}")

    # Sprint 16: Automated Production Configuration Validation
    config_issues = settings.validate_production_configuration()
    for issue in config_issues:
        if "CRITICAL" in issue:
            logger.error(f"[PRODUCTION READINESS CHECK] {issue}")
        else:
            logger.warning(f"[PRODUCTION READINESS CHECK] {issue}")

    yield
    logger.info("Shutting down CyberShield API gateway cleanly.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="CyberShield Central REST API - Intelligent Network Monitoring & Posture Assessment",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan,
)

# ------------------------------------------------------------------------------
# MIDDLEWARE STACK (Applied in reverse order of addition)
# ------------------------------------------------------------------------------
# 1. CORS Security Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With", "X-Correlation-ID", "X-Request-ID"],
    max_age=settings.CORS_MAX_AGE_SECONDS,
)

# 2. Defense-in-depth Security Response Headers
app.add_middleware(SecurityHeadersMiddleware)

# 3. Distributed Request Correlation ID & Latency Tracking
app.add_middleware(RequestCorrelationMiddleware)

# 4. Request Body Size Limiter (25MB Guardrail)
app.add_middleware(RequestSizeLimiterMiddleware)

# 5. Adaptive Sliding-Window Rate Limiter
app.add_middleware(
    RateLimiterMiddleware,
    requests_per_minute=settings.RATE_LIMIT_DEFAULT_PER_MINUTE,
)


# Consistent Request Validation Error Response
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        field = " -> ".join(str(loc) for loc in err["loc"] if loc != "body")
        errors.append({"field": field or "body", "message": err["msg"]})

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "detail": "The request payload failed schema validation.",
            "validation_errors": errors,
            "correlation_id": getattr(request.state, "correlation_id", None),
        },
    )


# Consistent Generic Error Response
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    corr_id = getattr(request.state, "correlation_id", "req_unknown")
    logger.error(f"[{corr_id}] Unhandled exception during {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "detail": str(exc) if settings.DEBUG else "An unexpected operational error occurred.",
            "correlation_id": corr_id,
        },
    )


# Include API v1 Router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", tags=["Root"])
def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": f"{settings.API_V1_STR}/docs",
        "health": f"{settings.API_V1_STR}/health",
        "system_health": f"{settings.API_V1_STR}/system-health",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)
