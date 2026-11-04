from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID
from pydantic import BaseModel, Field


# ------------------------------------------------------------------------------
# Organization Models
# ------------------------------------------------------------------------------
class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    slug: Optional[str] = Field(None, max_length=50)
    description: Optional[str] = None
    website: Optional[str] = None
    industry: Optional[str] = "Technology"
    organization_size: Optional[str] = "11-50 employees"
    country: Optional[str] = "US"
    time_zone: Optional[str] = "UTC"


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    website: Optional[str] = None
    industry: Optional[str] = None
    organization_size: Optional[str] = None
    country: Optional[str] = None
    time_zone: Optional[str] = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: Optional[str] = None
    description: Optional[str] = None
    website: Optional[str] = None
    industry: Optional[str] = "Technology"
    organization_size: Optional[str] = "11-50 employees"
    country: Optional[str] = "US"
    time_zone: Optional[str] = "UTC"
    status: Literal["Active", "Suspended"] = "Active"
    suspension_reason: Optional[str] = None
    created_at: str
    member_count: int = 1
    current_plan: Optional[str] = "Professional"


# ------------------------------------------------------------------------------
# Team Management & Members
# ------------------------------------------------------------------------------
class OrganizationMemberResponse(BaseModel):
    id: str
    user_id: str
    organization_id: str
    email: str
    role: Literal["owner", "admin", "analyst", "viewer"]
    full_name: Optional[str] = None
    joined_at: str
    last_active: Optional[str] = None


class MemberRoleUpdate(BaseModel):
    role: Literal["owner", "admin", "analyst", "viewer"]


class InvitationCreate(BaseModel):
    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    role: Literal["admin", "analyst", "viewer"] = "analyst"


class InvitationResponse(BaseModel):
    id: str
    organization_id: str
    email: str
    role: str
    status: Literal["Pending", "Accepted", "Expired", "Cancelled"]
    invited_by: Optional[str] = None
    expires_at: str
    created_at: str


# ------------------------------------------------------------------------------
# Subscriptions & Plans
# ------------------------------------------------------------------------------
class SubscriptionPlanResponse(BaseModel):
    id: str
    plan_name: str
    plan_code: str
    description: str
    price: float
    currency: str = "USD"
    billing_interval: str = "monthly"
    max_members: int
    max_assets: int
    monthly_scan_limit: int
    ai_usage_limit: int
    feature_flags: Dict[str, bool] = Field(default_factory=dict)
    is_active: bool = True


class OrganizationSubscriptionResponse(BaseModel):
    id: str
    organization_id: str
    plan_id: str
    plan_name: str
    plan_code: str
    status: Literal["Trial", "Active", "Past Due", "Cancelled", "Expired", "Suspended"]
    billing_provider: str
    current_period_start: str
    current_period_end: str
    cancel_at_period_end: bool = False
    price: float = 0.0


class SubscriptionUsageResponse(BaseModel):
    organization_id: str
    plan_code: str
    assets_used: int
    assets_limit: int
    members_used: int
    members_limit: int
    monthly_scans_used: int
    monthly_scans_limit: int
    ai_requests_used: int
    ai_requests_limit: int
    period_start: str
    period_end: str


class CheckoutRequest(BaseModel):
    plan_code: str
    billing_interval: Literal["monthly", "yearly"] = "monthly"


# ------------------------------------------------------------------------------
# API Keys
# ------------------------------------------------------------------------------
class APIKeyCreate(BaseModel):
    key_name: str = Field(..., min_length=2, max_length=50)
    scopes: List[str] = Field(default=["read:assets", "read:scans"])
    expires_in_days: Optional[int] = Field(90, ge=1, le=365)


class APIKeyResponse(BaseModel):
    id: str
    organization_id: str
    key_name: str
    key_prefix: str
    scopes: List[str]
    created_at: str
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    is_revoked: bool = False


class APIKeyCreatedResponse(APIKeyResponse):
    raw_api_key: str  # Only displayed once on creation!


# ------------------------------------------------------------------------------
# Platform Admin
# ------------------------------------------------------------------------------
class PlatformOverviewResponse(BaseModel):
    total_users: int
    total_organizations: int
    active_subscriptions: int
    trial_organizations: int
    suspended_organizations: int
    total_assets_monitored: int
    background_worker_health: str = "Operational"
    api_gateway_health: str = "Operational"
    db_connectivity: str = "Connected"


class PlatformOrgSuspendRequest(BaseModel):
    reason: str = Field(..., min_length=5, max_length=500)
