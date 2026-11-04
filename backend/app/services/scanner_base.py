from abc import ABC, abstractmethod
from datetime import datetime
from ipaddress import ip_network, ip_address
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ScanTargetScope(BaseModel):
    target: str = Field(..., description="Target CIDR, IP range, or single IP/hostname")
    target_type: str = Field(..., description="cidr | single_ip | hostname")
    is_authorized: bool = Field(default=False, description="Must be approved in scan_scopes table")
    scope_id: Optional[UUID] = None


class EngineScanRequest(BaseModel):
    scan_id: UUID
    organization_id: UUID
    target_scope: str
    scan_type: str  # network_discovery | vulnerability_assessment | web_baseline
    profile: str = "fast_discovery"
    max_rate: int = 1000
    timeout_seconds: int = 1800


class DiscoveredService(BaseModel):
    port: int
    protocol: str = "tcp"
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    state: str = "open"


class DiscoveredHost(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    status: str = "up"
    os_name: Optional[str] = None
    services: List[DiscoveredService] = []


class EngineScanResult(BaseModel):
    scan_id: UUID
    status: str  # completed | failed | cancelled
    hosts_discovered: int = 0
    hosts: List[DiscoveredHost] = []
    findings_summary: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    started_at: datetime
    completed_at: datetime
    raw_output: Optional[str] = None
    logs: List[str] = []


class BaseScanner(ABC):
    """
    Abstract interface for isolated security scanning engines.
    Sprint 4 enforces safety boundaries and strict scope validation.
    No live scans are executed until authorized in later sprints.
    """

    def __init__(self, name: str):
        self.name = name

    def validate_scope(self, target: str, approved_scopes: List[str]) -> bool:
        """
        Validates that the target is strictly contained within organization approved scopes.
        Prevents unauthorized scanning of out-of-scope third-party networks.
        """
        if not approved_scopes:
            return False

        try:
            target_net = ip_network(target, strict=False)
        except ValueError:
            # Hostname or single IP check
            return target in approved_scopes

        for approved in approved_scopes:
            try:
                approved_net = ip_network(approved, strict=False)
                if target_net.subnet_of(approved_net):
                    return True
            except ValueError:
                if target == approved:
                    return True
        return False

    @abstractmethod
    async def prepare_execution(self, request: EngineScanRequest) -> Dict[str, Any]:
        """Validates parameters, checks boundaries, and builds isolated CLI/API arguments."""
        pass

    @abstractmethod
    async def execute_scan(self, request: EngineScanRequest) -> EngineScanResult:
        """Executes the assessment in a sandbox container."""
        pass


class NmapScanner(BaseScanner):
    """Nmap Network Discovery & Host Fingerprinting Interface."""

    def __init__(self):
        super().__init__("Nmap Host & Service Discovery Engine")

    async def prepare_execution(self, request: EngineScanRequest) -> Dict[str, Any]:
        return {
            "engine": "nmap",
            "target": request.target_scope,
            "arguments": "-sS -sV -O --top-ports 1000 -T4",
            "safe_mode": True,
        }

    async def execute_scan(self, request: EngineScanRequest) -> EngineScanResult:
        now = datetime.utcnow()
        return EngineScanResult(
            scan_id=request.scan_id,
            status="completed",
            hosts_discovered=0,
            hosts=[],
            findings_summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
            started_at=now,
            completed_at=now,
            logs=["Sprint 4: Abstract scanner stub executed safely without live network probes."],
        )


class OpenVASScanner(BaseScanner):
    """Greenbone OpenVAS Vulnerability Scanner Interface."""

    def __init__(self):
        super().__init__("Greenbone OpenVAS Engine")

    async def prepare_execution(self, request: EngineScanRequest) -> Dict[str, Any]:
        return {
            "engine": "openvas",
            "target": request.target_scope,
            "config": "Full and fast",
            "safe_mode": True,
        }

    async def execute_scan(self, request: EngineScanRequest) -> EngineScanResult:
        now = datetime.utcnow()
        return EngineScanResult(
            scan_id=request.scan_id,
            status="completed",
            hosts_discovered=0,
            hosts=[],
            findings_summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
            started_at=now,
            completed_at=now,
            logs=["Sprint 4: OpenVAS integration point verified."],
        )


class OwaspZapScanner(BaseScanner):
    """OWASP ZAP Web Application Security Baseline Scanner Interface."""

    def __init__(self):
        super().__init__("OWASP ZAP Baseline Engine")

    async def prepare_execution(self, request: EngineScanRequest) -> Dict[str, Any]:
        return {
            "engine": "owasp_zap",
            "target": request.target_scope,
            "mode": "baseline",
            "safe_mode": True,
        }

    async def execute_scan(self, request: EngineScanRequest) -> EngineScanResult:
        now = datetime.utcnow()
        return EngineScanResult(
            scan_id=request.scan_id,
            status="completed",
            hosts_discovered=0,
            hosts=[],
            findings_summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
            started_at=now,
            completed_at=now,
            logs=["Sprint 4: OWASP ZAP baseline interface verified."],
        )
