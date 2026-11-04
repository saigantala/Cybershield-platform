import os
import logging
from typing import Dict, List, Optional, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("cybershield.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "CyberShield Security API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"  # development, staging, production
    DEBUG: bool = True

    SECRET_KEY: str = "cybershield-dev-secret-key-change-in-production-min-32-chars"

    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # Supabase PostgreSQL & Auth
    SUPABASE_URL: str = "https://your-project.supabase.co"
    SUPABASE_ANON_KEY: str = "your-anon-key"
    SUPABASE_JWT_SECRET: str = ""
    SUPABASE_JWT_ALGORITHM: str = "HS256"

    # Redis & Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # Scanner Guardrails
    SCAN_DEFAULT_TIMEOUT_SECONDS: int = 1800
    SCAN_MAX_CONCURRENCY_PER_ORG: int = 2

    # Sprint 6: Vulnerability Scanner & Intel Integrations
    NVD_API_KEY: str = ""
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    KEV_CATALOG_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    OPENVAS_HOST: str = "localhost"
    OPENVAS_PORT: int = 9390
    OPENVAS_USERNAME: str = "admin"
    OPENVAS_PASSWORD: str = ""

    ZAP_API_URL: str = "http://localhost:8080"
    ZAP_API_KEY: str = ""
    SCANNER_TIMEOUT_SECONDS: int = 1800

    # --------------------------------------------------------------------------
    # SPRINT 16: PRODUCTION HARDENING, RATE LIMITING & DEVSECOPS
    # --------------------------------------------------------------------------
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT_PER_MINUTE: int = 120
    RATE_LIMIT_AUTH_PER_MINUTE: int = 15
    RATE_LIMIT_BURST_ALLOWANCE: int = 20

    MAX_REQUEST_SIZE_BYTES: int = 26214400  # 25 MB (Evidence upload limit)
    JSON_BODY_MAX_BYTES: int = 2097152       # 2 MB general JSON limit

    SECURITY_HEADERS_ENABLED: bool = True
    CORS_MAX_AGE_SECONDS: int = 600

    # Trusted proxy CIDRs (Cloudflare, AWS ALB, internal container bridge)
    TRUSTED_PROXIES: List[str] = ["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12"]

    # Observability & Error Tracking
    SENTRY_DSN: Optional[str] = None
    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = None
    LOG_FORMAT_JSON: bool = False

    def validate_production_configuration(self) -> List[str]:
        """
        Validates environment configuration for production safety.
        Returns a list of critical security warnings / failure messages.
        """
        issues = []
        is_prod = self.ENVIRONMENT.lower() in ("production", "prod")

        if is_prod:
            if self.DEBUG:
                issues.append("CRITICAL: DEBUG=True is enabled in production environment.")
            if "change-in-production" in self.SECRET_KEY or len(self.SECRET_KEY) < 32:
                issues.append("CRITICAL: SECRET_KEY is using default placeholder or is under 32 characters.")
            if "your-project" in self.SUPABASE_URL:
                issues.append("CRITICAL: SUPABASE_URL is unconfigured or using template default.")
            if "your-anon" in self.SUPABASE_ANON_KEY:
                issues.append("CRITICAL: SUPABASE_ANON_KEY is using template default.")
            if not self.SUPABASE_JWT_SECRET:
                issues.append("WARNING: SUPABASE_JWT_SECRET is unset; asymmetric JWKS fallback will be required.")
            if any("localhost" in origin or "127.0.0.1" in origin for origin in self.ALLOWED_ORIGINS):
                issues.append("WARNING: Localhost origins detected in production ALLOWED_ORIGINS.")
        return issues


settings = Settings()
