import re
from datetime import datetime
from typing import Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

DeviceType = Literal[
    "Laptop",
    "Desktop",
    "Server",
    "Router",
    "Mobile",
    "IoT",
    "Other",
]

RiskLevel = Literal[
    "Critical",
    "High",
    "Medium",
    "Low",
    "Unassessed",
]

AssetStatus = Literal[
    "Active",
    "Inactive",
    "Unknown",
]

IPV4_PATTERN = re.compile(
    r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


class AssetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Device hostname or asset name")
    ip_address: str = Field(..., description="Valid IPv4 address")
    mac_address: Optional[str] = Field(None, description="MAC address format XX:XX:XX:XX:XX:XX")
    hostname: Optional[str] = Field(None, max_length=255)
    device_type: DeviceType = Field(default="Other")
    operating_system: Optional[str] = Field(None, max_length=100)
    manufacturer: Optional[str] = Field(None, max_length=100)
    risk_level: RiskLevel = Field(default="Unassessed")
    status: AssetStatus = Field(default="Active")
    description: Optional[str] = Field(None, max_length=1000)

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, v: str) -> str:
        trimmed = v.strip()
        if not IPV4_PATTERN.match(trimmed):
            raise ValueError(f"Invalid IPv4 address format: '{v}'")
        return trimmed

    @field_validator("mac_address")
    @classmethod
    def validate_mac_address(cls, v: Optional[str]) -> Optional[str]:
        if not v or not v.strip():
            return None
        trimmed = v.strip()
        if not MAC_PATTERN.match(trimmed):
            raise ValueError(f"Invalid MAC address format: '{v}' (expected XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)")
        return trimmed.upper()

    @field_validator("device_type", mode="before")
    @classmethod
    def normalize_device_type(cls, v: Any) -> str:
        valid = {"Laptop", "Desktop", "Server", "Router", "Mobile", "IoT", "Other"}
        if isinstance(v, str):
            v_title = v.capitalize()
            if v_title in valid:
                return v_title
            if v in valid:
                return v
            v_lower = v.lower()
            if any(k in v_lower for k in ["server", "linux", "bsd", "unix"]):
                return "Server"
            if any(k in v_lower for k in ["router", "cisco", "fortinet", "gateway", "switch"]):
                return "Router"
            if any(k in v_lower for k in ["iot", "printer", "camera", "sensor", "embedded"]):
                return "IoT"
            if any(k in v_lower for k in ["laptop", "macbook"]):
                return "Laptop"
            if any(k in v_lower for k in ["desktop", "workstation"]):
                return "Desktop"
            if any(k in v_lower for k in ["mobile", "android", "iphone", "ipad"]):
                return "Mobile"
        return "Other"



class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[DeviceType] = None
    operating_system: Optional[str] = None
    manufacturer: Optional[str] = None
    risk_level: Optional[RiskLevel] = None
    status: Optional[AssetStatus] = None
    description: Optional[str] = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        trimmed = v.strip()
        if not IPV4_PATTERN.match(trimmed):
            raise ValueError(f"Invalid IPv4 address format: '{v}'")
        return trimmed

    @field_validator("mac_address")
    @classmethod
    def validate_mac_address(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        trimmed = v.strip()
        if not MAC_PATTERN.match(trimmed):
            raise ValueError(f"Invalid MAC address format: '{v}'")
        return trimmed.upper()


class AssetResponse(AssetBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    created_at: datetime
    updated_at: datetime
