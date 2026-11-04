from typing import Any, Dict, Optional
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field


class UserResponse(BaseModel):
    id: UUID
    email: EmailStr
    full_name: Optional[str] = None
    role: str = "analyst"
    organization_id: Optional[UUID] = None
    avatar_url: Optional[str] = None


class UserProfileResponse(BaseModel):
    id: UUID
    email: EmailStr
    full_name: str
    avatar_url: Optional[str] = None
    organization_id: Optional[UUID] = None
    organization_name: Optional[str] = None
    organization_role: Optional[str] = None
