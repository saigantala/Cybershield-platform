"""
FastAPI Core Configuration and Environment Settings
"""

from typing import List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberShield Security Platform API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    SECRET_KEY: str = "cybershield-dev-secret-key-change-in-production"
    DEBUG: bool = True
    
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "https://app.cybershield.internal",
    ]
    
    # Supabase PostgreSQL & Auth
    SUPABASE_URL: str = "https://your-project.supabase.co"
    SUPABASE_ANON_KEY: str = "your-anon-key"
    SUPABASE_SERVICE_ROLE_KEY: str = "your-service-role-key"
    
    # Celery & Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    
    # Scanner Limits
    SCAN_DEFAULT_TIMEOUT_SECONDS: int = 1800
    SCAN_MAX_CONCURRENCY_PER_ORG: int = 2

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
