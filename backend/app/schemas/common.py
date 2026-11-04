from datetime import datetime
from typing import Any, Generic, List, Optional, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")


class HealthResponse(BaseModel):
    status: str = "healthy"
    service: str = "CyberShield Security API"
    version: str = "1.0.0"
    environment: str = "development"
    redis_connected: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class MessageResponse(BaseModel):
    success: bool = True
    message: str
    detail: Optional[str] = None


class PaginatedList(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int
