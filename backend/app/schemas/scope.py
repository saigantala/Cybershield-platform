from datetime import datetime, timedelta
from ipaddress import ip_network
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

ScopeStatus = Literal["Pending", "Approved", "Rejected", "Expired"]

# Configurable Private Network Allowlist (RFC 1918 & Loopback)
PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
]


class ScopeCreate(BaseModel):
    scope_name: str = Field(..., min_length=2, max_length=100, description="Descriptive identifier for this subnet boundary")
    cidr_range: str = Field(..., description="Target IPv4 CIDR range (e.g. 192.168.10.0/24)")
    authorization_basis: str = Field(..., min_length=5, max_length=500, description="Recorded justification, authorization ticket, or asset ownership basis")
    max_scan_rate: int = Field(default=1000, ge=10, le=5000, description="Max packets per second throttle limit")
    expires_in_days: int = Field(default=90, ge=1, le=365, description="Validity period in days")

    @field_validator("cidr_range")
    @classmethod
    def validate_cidr_range(cls, v: str) -> str:
        trimmed = v.strip()
        try:
            net = ip_network(trimmed, strict=False)
        except ValueError:
            raise ValueError(f"'{trimmed}' is not a valid IPv4 CIDR specification (e.g. 192.168.1.0/24)")

        # Enforce private network allowlist: reject public internet ranges
        is_private = any(net.subnet_of(private_net) for private_net in PRIVATE_NETWORKS)
        if not is_private:
            raise ValueError(
                f"CIDR '{trimmed}' is a public internet address. "
                "CyberShield discovery engine strictly restricts scans to authorized internal private RFC 1918 subnets."
            )

        # Enforce maximum scope size boundary (/16 minimum prefix length) to prevent accidental internet-scale sweeps
        if net.prefixlen < 16:
            raise ValueError(f"CIDR prefix /{net.prefixlen} is too broad. Minimum allowed prefix length is /16.")

        return str(net)


class ScopeApprove(BaseModel):
    expires_at: Optional[datetime] = None
    notes: Optional[str] = None


class ScopeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    scope_name: str
    cidr_range: str
    authorization_status: ScopeStatus
    authorization_basis: Optional[str] = None
    approved_by: Optional[UUID] = None
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    max_scan_rate: int = 1000
    created_at: datetime
    is_expired: bool = False
